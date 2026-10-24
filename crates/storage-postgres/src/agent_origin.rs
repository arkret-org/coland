//! Durable Origin intent and immutable verified sibling retention.
//! This module uses the sole formal carrier; rows are not authority bypasses.
use arkret_models_identity::AgentProducerEvidence;
use arkret_wire::{Event, RequestId};
use chrono::{DateTime, Utc};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::Value;

use crate::{AsyncPgConnection, PersistenceError, PersistenceResult};

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct TextRow {
    #[diesel(sql_type = Text)]
    value: String,
}

fn missing(reason: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("dependency_missing: {reason}"))
}
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

/// Held under the same producer lock used by key and lifecycle writers.
/// Compare original accepted witnesses, not newly signed observation dates.
pub(crate) async fn check_origin_cut(
    conn: &mut AsyncPgConnection,
    event: &Event,
    state: &arkret_models_identity::AgentAuthorityState,
) -> PersistenceResult<()> {
    let account = event
        .actual_signer()
        .as_account_id()
        .ok_or_else(|| missing("Origin producer is not an Account"))?;
    state.validate_binding(account).map_err(invalid)?;
    if state.authority_id != account.station_id {
        return Err(missing("Origin Account Station differs"));
    }
    crate::agent_current_states::lock_agent_producer_current(
        conn,
        &state.pcr_genesis_event.realm_id,
        &account.principal_id,
    )
    .await?;
    let realm = state.pcr_genesis_event.realm_id.as_str();
    let owning = sql_query("SELECT p.value AS value FROM agent_provisioning_current_states p JOIN pcr_genesis_units g ON g.realm_id=p.realm_id WHERE p.agent_id=$1 AND g.station_id=$2 AND p.value->>'controller_principal_id'=g.principal_id AND p.value->>'principal_control_realm_id'=$3 FOR SHARE OF p,g")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).bind::<Text,_>(realm)
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| missing("Origin controller provision changed"))?;
    if owning
        .value
        .get("controller_principal_id")
        .and_then(Value::as_str)
        != Some(state.authorization.controller_principal_id.as_str())
    {
        return Err(missing("Origin controller identity changed"));
    }

    let actual_head = sql_query("SELECT commit_id AS value FROM realm_commits WHERE realm_id=$1 AND stream_ref=jsonb_build_object('kind','realm','realm_id',$1) ORDER BY stream_position DESC LIMIT 1 FOR SHARE")
        .bind::<Text,_>(realm).get_result::<TextRow>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)?.ok_or_else(|| missing("Origin source head missing"))?;
    if actual_head.value != state.source_commit_id.as_str() {
        return Err(missing("Origin source cut changed"));
    }
    let status = sql_query("SELECT jsonb_build_object('selector',jsonb_build_object('kind','agent_status','agent_id',s.agent_id),'source_stream_ref',c.stream_ref,'revision',jsonb_build_object('commit_id',s.current_commit_id,'stream_position',s.current_stream_position),'value',s.value) AS value FROM agent_status_current_states s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.agent_id=$2 FOR SHARE OF s,c")
        .bind::<Text,_>(realm).bind::<Text,_>(account.principal_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| missing("Origin lifecycle current missing"))?;
    let actual_status: arkret_wire::CurrentState =
        serde_json::from_value(status.value).map_err(invalid)?;
    if actual_status != state.agent_lifecycle_witness.current_state {
        return Err(missing("Origin lifecycle witness changed"));
    }
    let key = sql_query("SELECT jsonb_build_object('selector',jsonb_build_object('kind','agent_key','agent_id',s.agent_id,'agent_key_id',s.agent_key_id),'source_stream_ref',c.stream_ref,'revision',jsonb_build_object('commit_id',s.current_commit_id,'stream_position',s.current_stream_position),'value',s.value) AS value FROM agent_key_current_states s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.agent_id=$2 AND s.agent_key_id=$3 FOR SHARE OF s,c")
        .bind::<Text,_>(realm).bind::<Text,_>(account.principal_id.as_str())
        .bind::<Text,_>(state.authorization.agent_key_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| missing("Origin key current missing"))?;
    let actual_key: arkret_wire::CurrentState =
        serde_json::from_value(key.value).map_err(invalid)?;
    if actual_key != state.key_state_witness.current_state {
        return Err(missing("Origin authorization witness changed"));
    }
    // Every immutable Event/Commit in the asserted state must be the original
    // accepted bytes in this Origin database; no today's projection can fill it.
    for commit in &state.commits {
        let row = sql_query("SELECT commit_json AS value FROM realm_commits WHERE commit_id=$1 AND realm_id=$2 AND commit_json->>'event_ref'=$3 FOR SHARE")
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(realm)
            .bind::<Text,_>(commit.event_ref.as_str()).get_result::<JsonRow>(&mut *conn).await.optional()
            .map_err(PersistenceError::database)?.ok_or_else(|| missing("Origin accepted Commit unavailable"))?;
        let stored: arkret_wire::RealmCommit =
            serde_json::from_value(row.value).map_err(invalid)?;
        if stored != *commit {
            return Err(missing("Origin accepted Commit changed"));
        }
    }
    for original in [
        &state.pcr_genesis_event,
        &state.key_authorization_event,
        &state.agent_lifecycle_witness.accepted_status_event,
    ] {
        let row = sql_query("SELECT envelope AS value FROM canonical_events WHERE id=$1 AND state='committed' FOR SHARE")
            .bind::<Binary,_>(original.event_id.token_bytes().to_vec()).get_result::<JsonRow>(&mut *conn).await.optional()
            .map_err(PersistenceError::database)?.ok_or_else(|| missing("Origin accepted Event unavailable"))?;
        let stored: Event = serde_json::from_value(row.value).map_err(invalid)?;
        if stored != *original {
            return Err(missing("Origin accepted Event changed"));
        }
    }
    Ok(())
}

/// One durable canonical AA intent per Event and complete immutable state.
/// The caller owns the enclosing transaction; returned IDs survive retry.
pub(crate) async fn gate_request_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    state: &arkret_models_identity::AgentAuthorityState,
) -> PersistenceResult<RequestId> {
    check_origin_cut(conn, event, state).await?;
    let intent = arkret_canonical::canonical_sha256(&serde_json::json!({
        "event":event, "state":state, "controller":state.authorization.controller_principal_id,
        "origin":state.authority_id,
    }))
    .map_err(invalid)?;
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("agent-origin-gate:{}", event.event_id))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    if let Some(row) = sql_query("SELECT request_id AS value FROM agent_origin_gate_intents WHERE event_id=$1 AND intent_digest=$2 AND retry_expires_at>now() ORDER BY retry_expires_at DESC LIMIT 1 FOR UPDATE")
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(&intent)
        .get_result::<TextRow>(&mut *conn).await.optional().map_err(PersistenceError::database)? {
        return RequestId::new(row.value).map_err(invalid);
    }
    let request = RequestId::new_v7_at(Utc::now().timestamp_millis() as u64);
    sql_query(
        "INSERT INTO agent_origin_gate_intents(event_id,intent_digest,request_id,retry_expires_at) VALUES($1,$2,$3,now()+interval '300 seconds')",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(&intent)
    .bind::<Text, _>(request.as_str())
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(request)
}

pub(crate) async fn retain_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    evidence: &AgentProducerEvidence,
    at: DateTime<Utc>,
) -> PersistenceResult<()> {
    let account = event
        .actual_signer()
        .as_account_id()
        .ok_or_else(|| missing("Agent account missing"))?;
    let verified = arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
        event,
        evidence,
        &account.station_id,
        at,
        None,
    )
    .map_err(invalid)?;
    check_origin_cut(
        conn,
        event,
        verified
            .evidence()
            .agent_authority_state_evidence
            .state
            .as_ref()
            .unwrap(),
    )
    .await?;
    let full = serde_json::to_value(verified.evidence()).map_err(invalid)?;
    let digest = arkret_canonical::canonical_sha256(&full).map_err(invalid)?;
    sql_query("INSERT INTO agent_origin_forward_evidence(event_id,carrier_digest,evidence_ref,evidence_json) VALUES($1,$2,$3,$4) ON CONFLICT(event_id,carrier_digest) DO NOTHING")
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(&digest)
        .bind::<Text,_>(verified.reference().as_ref()).bind::<Jsonb,_>(full.clone())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let retained = sql_query("SELECT evidence_json AS value FROM agent_origin_forward_evidence WHERE event_id=$1 AND carrier_digest=$2 FOR SHARE")
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(&digest)
        .get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if retained.value != full {
        return Err(missing("Origin evidence digest collision"));
    }
    Ok(())
}

/// Freeze one accepted control producer root in the original transaction.
/// The required Directory sibling must have been obtained before acceptance;
/// a later projection or a Forward sibling is not interchangeable with it.
fn validate_control_source(
    full: &arkret_wire::CommittedEventFullView,
    dependency: &arkret_models_identity::AgentSignerDependency,
    history: &arkret_models_identity::AuthenticatedServiceResolution,
) -> PersistenceResult<Value> {
    use arkret_models_identity::AgentSignerDependency;
    full.validate_shape().map_err(invalid)?;
    let event = &full.event;
    let commit = &full.commit;
    commit.validate_content_address().map_err(invalid)?;
    if commit.event_ref != event.event_id || commit.realm_id != event.realm_id {
        return Err(invalid("control source Event/Commit mismatch"));
    }
    if dependency.computed_reference().map_err(invalid)? != *dependency.reference() {
        return Err(invalid("control source dependency ref mismatch"));
    }
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| missing("control producer proof missing"))?;
    let key = match dependency {
        AgentSignerDependency::AccountDevice {
            account_device_signer_evidence: root,
            ..
        } => {
            let producer = event
                .account_device_producer()
                .map_err(invalid)?
                .ok_or_else(|| invalid("control source is not a Human device"))?;
            arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(
                root,&producer.account_id,&producer.device_id,
            ).map_err(invalid)?;
            let core = &root.device_projection_attestation.attestation;
            let covers = |t| {
                t >= core.authorization_window.not_before
                    && core
                        .authorization_window
                        .expires_at
                        .is_none_or(|end| t < end)
            };
            if !core.device_status.is_active()
                || !covers(event.created_at)
                || !covers(commit.committed_at)
                || core.attested_at > commit.committed_at
                || commit.committed_at >= core.expires_at
            {
                return Err(invalid("control original root does not cover acceptance"));
            }
            arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                value: core
                    .device_signing_key_did
                    .as_str()
                    .strip_prefix("did:key:")
                    .ok_or_else(|| invalid("control device key is not did:key"))?
                    .to_owned(),
            }
        }
        AgentSignerDependency::Agent { agent_evidence, .. } => {
            let account = event
                .actual_signer()
                .as_account_id()
                .ok_or_else(|| invalid("control Agent account missing"))?;
            arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
                event,
                agent_evidence,
                &account.station_id,
                commit.committed_at,
                None,
            )
            .map_err(invalid)?
            .key()
            .clone()
        }
        AgentSignerDependency::Service {
            authenticated_signer_evidence: signer,
            service_resolution,
            ..
        } => {
            if event.actual_signer().as_account_id().is_some()
                || signer.signer_kind != arkret_models_identity::AuthenticatedSignerKind::Service
                || signer.subject_id != *event.actual_signer().signing_principal_id()
                || signer.verification_method != proof.verification_method
            {
                return Err(invalid("control Service identity differs"));
            }
            let document = arkret_identity::authenticated_service_document_at(
                service_resolution,
                &signer.subject_id,
                proof.created_at,
            )
            .map_err(invalid)?;
            arkret_identity::validate_verification_method_relationship(
                &document,
                &proof.verification_method,
                &document.id,
                arkret_identity::DidVerificationRelationship::AssertionMethod,
            )
            .map_err(invalid)?;
            arkret_identity::public_key_material_from_document(
                &document,
                &proof.verification_method,
            )
            .map_err(invalid)?
        }
    };
    let suite = event.event_id.digest_suite_code().digest_suite();
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(invalid)?;
    event
        .verify_producer_proof_self_consistency(suite)
        .map_err(invalid)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(invalid)?,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(invalid)?;
    // Governance historical material is independently checked at its original
    // signature time, before being persisted for later offline assembly.
    let station = arkret_wire::project_did_to_core_id(
        &arkret_wire::Did::new(
            commit
                .signature
                .verification_method
                .as_str()
                .split_once('#')
                .ok_or_else(|| invalid("control Commit method missing fragment"))?
                .0
                .to_owned(),
        )
        .map_err(invalid)?,
    )
    .map_err(invalid)?;
    let document = arkret_identity::authenticated_service_document_at(
        history,
        &station,
        commit.signature.created_at,
    )
    .map_err(invalid)?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &commit.signature.verification_method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(invalid)?;
    let governance_key = arkret_identity::public_key_material_from_document(
        &document,
        &commit.signature.verification_method,
    )
    .map_err(invalid)?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &commit.signature,
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).map_err(invalid)?,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &governance_key,
    )
    .map_err(invalid)?;
    Ok(serde_json::json!({"full":full,"dependency":dependency,"history":history}))
}

/// Stage a signed candidate without treating it as accepted authority.
pub(crate) async fn stage_control_source_in_connection(
    conn: &mut AsyncPgConnection,
    full: &arkret_wire::CommittedEventFullView,
    dependency: &arkret_models_identity::AgentSignerDependency,
    history: &arkret_models_identity::AuthenticatedServiceResolution,
) -> PersistenceResult<()> {
    let body = validate_control_source(full, dependency, history)?;
    // A candidate is a non-authoritative, bounded retry intent. Expiring it
    // cannot delete an accepted source: acceptance copies into another table
    // in the original admission transaction. A later retry must restage and
    // reverify the complete original; it cannot consume an expired intent.
    let bytes = arkret_canonical::canonical_json_bytes(&body).map_err(invalid)?;
    if bytes.len() > arkret_models_identity::AGENT_AUTHORITY_EVIDENCE_MAX_CANONICAL_BYTES {
        return Err(missing("control candidate exceeds formal material bound"));
    }
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("agent-origin-stage:{}", full.event.realm_id))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    sql_query("DELETE FROM agent_origin_control_source_candidates WHERE realm_id=$1 AND staged_at<=now()-interval '24 hours'")
        .bind::<Text,_>(full.event.realm_id.as_str()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    #[derive(QueryableByName)]
    struct CandidateCount {
        #[diesel(sql_type=BigInt)]
        count: i64,
    }
    let count=sql_query("SELECT count(*) AS count FROM agent_origin_control_source_candidates WHERE realm_id=$1 AND NOT(event_id=$2 AND commit_id=$3)")
        .bind::<Text,_>(full.event.realm_id.as_str()).bind::<Text,_>(full.event.event_id.as_str())
        .bind::<Text,_>(full.commit.commit_id.as_str()).get_result::<CandidateCount>(&mut *conn).await.map_err(PersistenceError::database)?;
    // This is a local storage budget, not an authorization or protocol limit.
    // It never evicts accepted evidence or an unexpired in-flight candidate.
    if count.count >= 1024 {
        return Err(missing("control candidate retry storage exhausted"));
    }
    sql_query("INSERT INTO agent_origin_control_source_candidates(event_id,commit_id,realm_id,source_json) VALUES($1,$2,$3,$4) ON CONFLICT(event_id,commit_id) DO NOTHING")
        .bind::<Text,_>(full.event.event_id.as_str()).bind::<Text,_>(full.commit.commit_id.as_str())
        .bind::<Text,_>(full.event.realm_id.as_str()).bind::<Jsonb,_>(body.clone()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let stored = sql_query("SELECT source_json AS value FROM agent_origin_control_source_candidates WHERE event_id=$1 AND commit_id=$2 FOR SHARE")
        .bind::<Text,_>(full.event.event_id.as_str()).bind::<Text,_>(full.commit.commit_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if stored.value != body {
        return Err(invalid("control candidate original conflicts"));
    }
    Ok(())
}

/// Called only after the exact Event and Commit have been inserted by the
/// original admission unit, before its transaction can commit.
pub(crate) async fn accept_staged_control_source_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let candidate = sql_query("SELECT source_json AS value FROM agent_origin_control_source_candidates WHERE event_id=$1 AND commit_id=$2 FOR UPDATE")
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let required = matches!(
        event.kind,
        arkret_wire::EventKind::AgentKeyAuthorize
            | arkret_wire::EventKind::AgentKeyRevoke
            | arkret_wire::EventKind::SelfAgentPause
            | arkret_wire::EventKind::SelfAgentResume
            | arkret_wire::EventKind::SelfAgentDeactivate
    ) || (event.kind == arkret_wire::EventKind::RealmCreate
        && event
            .payload
            .get("object")
            .and_then(|o| o.get("purpose"))
            .and_then(Value::as_str)
            == Some("agent_control"));
    let Some(candidate) = candidate else {
        return if required {
            Err(missing(
                "control original candidate was not frozen before acceptance",
            ))
        } else {
            Ok(())
        };
    };
    let full: arkret_wire::CommittedEventFullView =
        serde_json::from_value(candidate.value["full"].clone()).map_err(invalid)?;
    let dependency: arkret_models_identity::AgentSignerDependency =
        serde_json::from_value(candidate.value["dependency"].clone()).map_err(invalid)?;
    let history: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(candidate.value["history"].clone()).map_err(invalid)?;
    if full.event != *event || full.commit != *commit {
        return Err(invalid(
            "staged control original differs from accepted bytes",
        ));
    }
    let body = validate_control_source(&full, &dependency, &history)?;
    sql_query("INSERT INTO agent_origin_control_sources(event_id,commit_id,source_json) VALUES($1,$2,$3) ON CONFLICT(event_id,commit_id) DO NOTHING")
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
        .bind::<Jsonb,_>(body.clone()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let stored = sql_query("SELECT source_json AS value FROM agent_origin_control_sources WHERE event_id=$1 AND commit_id=$2 FOR SHARE")
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if stored.value != body {
        return Err(invalid("accepted control immutable source conflicts"));
    }
    let history_json = serde_json::to_value(&history).map_err(invalid)?;
    sql_query("INSERT INTO agent_origin_commit_histories(commit_id,history_json) VALUES($1,$2) ON CONFLICT(commit_id) DO NOTHING")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Jsonb,_>(history_json.clone())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let stored_history = sql_query("SELECT history_json AS value FROM agent_origin_commit_histories WHERE commit_id=$1 FOR SHARE")
        .bind::<Text,_>(commit.commit_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if stored_history.value != history_json {
        return Err(invalid("accepted issuer history conflicts"));
    }
    sql_query(
        "DELETE FROM agent_origin_control_source_candidates WHERE event_id=$1 AND commit_id=$2",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

async fn original_event(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<Event> {
    let row=sql_query("SELECT e.envelope AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.commit_id=$1 AND e.id=$2 AND e.state='committed' FOR SHARE OF c,e")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Binary,_>(commit.event_ref.token_bytes().to_vec()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| missing("Agent original accepted Event unavailable"))?;
    let event: Event = serde_json::from_value(row.value).map_err(invalid)?;
    if arkret_canonical::canonical_json_bytes(&event)
        .map_err(invalid)?
        .len()
        > arkret_models_identity::AGENT_AUTHORITY_EVIDENCE_MAX_CANONICAL_BYTES
    {
        return Err(invalid("Agent original exceeds formal carrier byte bound"));
    }
    arkret_wire::CommittedEventFullView {
        event: event.clone(),
        commit: commit.clone(),
    }
    .validate_shape()
    .map_err(invalid)?;
    Ok(event)
}

/// Assemble complete state only from immutable accepted roots and locked current.
/// No remote request or current DID discovery exists in this function.
pub(crate) async fn assemble_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<arkret_models_identity::AgentAuthorityState> {
    use arkret_models_identity::*;
    let account = event
        .actual_signer()
        .as_account_id()
        .ok_or_else(|| missing("Agent Account missing"))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| missing("Agent proof missing"))?;
    let provision = sql_query("SELECT p.value AS value FROM agent_provisioning_current_states p JOIN pcr_genesis_units g ON g.realm_id=p.realm_id WHERE p.agent_id=$1 AND g.station_id=$2 AND p.value->>'controller_principal_id'=g.principal_id FOR SHARE OF p,g")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| missing("Agent owning provision unavailable"))?;
    let realm = arkret_wire::RealmId::new(
        provision
            .value
            .get("principal_control_realm_id")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("Agent provision PCR missing"))?,
    )
    .map_err(invalid)?;
    crate::agent_current_states::lock_agent_producer_current(conn, &realm, &account.principal_id)
        .await?;
    // Read only the indispensable Commit prefix. Intermediate Event bodies
    // are not part of this carrier and must not make the source read unbounded.
    let mut commits = Vec::new();
    let mut after = -1i64;
    let mut canonical_bytes = 0usize;
    loop {
        let row=sql_query("SELECT commit_json AS value FROM realm_commits WHERE realm_id=$1 AND stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND stream_position>$2 ORDER BY stream_position LIMIT 1 FOR SHARE")
            .bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(after).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let Some(row) = row else {
            break;
        };
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.value).map_err(invalid)?;
        canonical_bytes = canonical_bytes.saturating_add(
            arkret_canonical::canonical_json_bytes(&commit)
                .map_err(invalid)?
                .len(),
        );
        if canonical_bytes > AGENT_AUTHORITY_EVIDENCE_MAX_CANONICAL_BYTES {
            return Err(invalid(
                "Agent accepted prefix exceeds formal carrier byte bound",
            ));
        }
        after = i64::try_from(commit.stream_position).map_err(invalid)?;
        commits.push(commit);
    }
    let genesis_commit = commits
        .as_slice()
        .first()
        .ok_or_else(|| missing("Agent accepted Genesis missing"))?
        .clone();
    let source = commits
        .as_slice()
        .last()
        .ok_or_else(|| missing("Agent source Commit missing"))?
        .clone();
    let genesis = (original_event(conn, &genesis_commit).await?, genesis_commit);
    let key = sql_query("SELECT jsonb_build_object('selector',jsonb_build_object('kind','agent_key','agent_id',s.agent_id,'agent_key_id',s.agent_key_id),'source_stream_ref',c.stream_ref,'revision',jsonb_build_object('commit_id',s.current_commit_id,'stream_position',s.current_stream_position),'value',s.value) AS value FROM agent_key_current_states s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.agent_id=$2 AND EXISTS(SELECT 1 FROM jsonb_array_elements(s.value->'authorizations') a WHERE a->'value'->>'verification_method'=$3) FOR SHARE OF s,c")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(account.principal_id.as_str())
        .bind::<Text,_>(proof.verification_method.as_str()).get_result::<JsonRow>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)?.ok_or_else(|| missing("Agent runtime method is not active"))?;
    let key_result: arkret_wire::CurrentState =
        serde_json::from_value(key.value).map_err(invalid)?;
    let arkret_wire::CurrentState::Value {
        revision: key_revision,
        ..
    } = &key_result;
    let key_witness = commits
        .iter()
        .find(|c| c.commit_id == key_revision.commit_id)
        .ok_or_else(|| missing("Agent key current covering Commit missing"))?;
    let arkret_wire::CurrentState::Value {
        value: key_value, ..
    } = &key_result;
    let entries = key_value
        .get("authorizations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Agent key current authorizations missing"))?;
    let matching = entries
        .iter()
        .filter(|entry| {
            entry
                .get("value")
                .and_then(|v| v.get("verification_method"))
                .and_then(Value::as_str)
                == Some(proof.verification_method.as_str())
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(missing("Agent runtime method is not one exact active dot"));
    }
    let dot = matching[0]
        .get("tag_id")
        .and_then(Value::as_str)
        .and_then(|v| v.strip_suffix(":1"))
        .ok_or_else(|| invalid("Agent authorization dot has no original Event"))?;
    let original_id = arkret_wire::EventId::new(dot).map_err(invalid)?;
    let authorized_commit = commits
        .iter()
        .find(|c| c.event_ref == original_id)
        .ok_or_else(|| missing("Agent authorization original missing"))?
        .clone();
    let authorized = (
        original_event(conn, &authorized_commit).await?,
        authorized_commit,
    );
    if matching[0].get("value")
        != Some(&serde_json::to_value(&authorized.0.payload).map_err(invalid)?)
    {
        return Err(invalid(
            "Agent key current payload differs from accepted authorization",
        ));
    }
    let parsed = agent_signer_evidence::AgentAuthorizedSigningKey::from_event(&authorized.0)
        .map_err(invalid)?;
    if parsed.verification_method != proof.verification_method
        || parsed.agent_id != account.principal_id
    {
        return Err(missing("Agent runtime and exact key witness differ"));
    }
    let status = sql_query("SELECT jsonb_build_object('selector',jsonb_build_object('kind','agent_status','agent_id',s.agent_id),'source_stream_ref',c.stream_ref,'revision',jsonb_build_object('commit_id',s.current_commit_id,'stream_position',s.current_stream_position),'value',s.value) AS value FROM agent_status_current_states s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.agent_id=$2 AND s.value='\"active\"'::jsonb FOR SHARE OF s,c")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(account.principal_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| missing("Agent current lifecycle is not active"))?;
    let status_result: arkret_wire::CurrentState =
        serde_json::from_value(status.value).map_err(invalid)?;
    let arkret_wire::CurrentState::Value {
        revision: status_revision,
        ..
    } = &status_result;
    let lifecycle_commit = commits
        .iter()
        .find(|c| c.commit_id == status_revision.commit_id)
        .ok_or_else(|| missing("Agent lifecycle original missing"))?
        .clone();
    let lifecycle = (
        original_event(conn, &lifecycle_commit).await?,
        lifecycle_commit,
    );
    let provenance = match lifecycle.0.kind {
        arkret_wire::EventKind::RealmCreate => AgentLifecycleProvenance::Genesis {
            realm_create_event_id: lifecycle.0.event_id.clone(),
        },
        arkret_wire::EventKind::SelfAgentResume => AgentLifecycleProvenance::Resume {
            resume_event_id: lifecycle.0.event_id.clone(),
        },
        _ => {
            return Err(missing(
                "Agent active lifecycle has no registered provenance",
            ));
        }
    };
    let mut dependencies = std::collections::BTreeMap::new();
    let mut bindings = Vec::new();
    for original in [&genesis, &authorized, &lifecycle] {
        let frozen = sql_query("SELECT source_json AS value FROM agent_origin_control_sources WHERE event_id=$1 AND commit_id=$2 FOR SHARE")
            .bind::<Text,_>(original.0.event_id.as_str()).bind::<Text,_>(original.1.commit_id.as_str())
            .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| missing("control producer original dependency was never retained"))?;
        let dep: AgentSignerDependency =
            serde_json::from_value(frozen.value["dependency"].clone()).map_err(invalid)?;
        let expected = serde_json::json!({"event":&original.0,"commit":&original.1});
        let actual = &frozen.value["full"];
        if actual["event"] != expected["event"] || actual["commit"] != expected["commit"] {
            return Err(invalid("control dependency original differs"));
        }
        let reference = dep.computed_reference().map_err(invalid)?;
        if let Some(old) = dependencies.insert(reference.clone(), dep.clone())
            && old != dep
        {
            return Err(invalid("same dependency ref has conflicting content"));
        }
        let binding = AgentProducerBinding {
            event_ref: original.0.event_id.clone(),
            accepted_commit_id: original.1.commit_id.clone(),
            signer_resolution_evidence_ref: reference,
        };
        if let Some(previous) = bindings
            .iter()
            .find(|previous: &&AgentProducerBinding| previous.event_ref == binding.event_ref)
        {
            if previous != &binding {
                return Err(invalid(
                    "same producer Event has conflicting accepted binding",
                ));
            }
        } else {
            bindings.push(binding);
        }
    }
    bindings.sort_by(|left, right| left.event_ref.cmp(&right.event_ref));
    // Select only an immutable history captured before an actual control
    // acceptance. It must independently verify every Commit at that Commit's
    // signature time. This never discovers today's DID to repair old material.
    let stored = sql_query("SELECT h.history_json AS value FROM agent_origin_commit_histories h JOIN realm_commits c ON c.commit_id=h.commit_id WHERE c.realm_id=$1 ORDER BY c.stream_position DESC LIMIT 1 FOR SHARE OF h,c")
        .bind::<Text,_>(realm.as_str()).get_result::<JsonRow>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)?.ok_or_else(|| missing("accepted governance history was never retained"))?;
    let history: AuthenticatedServiceResolution =
        serde_json::from_value(stored.value).map_err(invalid)?;
    if history.service_id != account.station_id {
        return Err(missing(
            "Origin governance history differs from Account Station",
        ));
    }
    for commit in &commits {
        let document = arkret_identity::authenticated_service_document_at(
            &history,
            &account.station_id,
            commit.signature.created_at,
        )
        .map_err(invalid)?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            &commit.signature.verification_method,
            &document.id,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )
        .map_err(invalid)?;
        let key = arkret_identity::public_key_material_from_document(
            &document,
            &commit.signature.verification_method,
        )
        .map_err(invalid)?;
        commit.validate_content_address().map_err(invalid)?;
        arkret_signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret_canonical::canonical::unsigned_value(commit, &["signature"])
                .map_err(invalid)?,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &key,
        )
        .map_err(invalid)?;
    }
    // This initial Origin implementation supports the existing own-governed
    // generation-zero PCR. Handoff material must be retained and assembled by
    // its registered importer before a later generation is admitted here.
    if commits.iter().any(|c| c.governance_generation != 0) {
        return Err(missing("Origin PCR authority transitions are not retained"));
    }
    let mut lineages = Vec::new();
    for witness in [key_witness, &lifecycle.1] {
        if lineages
            .iter()
            .any(|l: &AgentCommitLineage| l.witness_commit_id == witness.commit_id)
        {
            continue;
        }
        let start = commits
            .iter()
            .position(|c| c.commit_id == witness.commit_id)
            .unwrap();
        lineages.push(AgentCommitLineage {
            witness_commit_id: witness.commit_id.clone(),
            predecessor_commit_ids: commits[start..]
                .iter()
                .map(|c| c.commit_id.clone())
                .collect(),
        });
    }
    let state = AgentAuthorityState {
        authority_id: account.station_id.clone(),
        agent_id: account.principal_id.clone(),
        source_commit_id: source.commit_id.clone(),
        pcr_genesis_event: genesis.0.clone(),
        key_authorization_event: authorized.0.clone(),
        authorization: AgentKeyAuthorization {
            agent_id: parsed.agent_id.clone(),
            agent_key_id: parsed.agent_key_id.clone(),
            verification_method: parsed.verification_method.clone(),
            public_key: AgentRuntimePublicKey {
                kty: parsed.public_key.kty.clone(),
                kid: arkret_wire::NonEmptyString::new(parsed.verification_method.to_string())
                    .map_err(invalid)?,
                algorithm: parsed.public_key.algorithm.clone(),
                key: parsed.public_key.key.clone(),
            },
            public_key_digest: parsed.public_key_digest.clone(),
            controller_principal_id: parsed.controller_principal_id.clone(),
            accepted_commit_id: authorized.1.commit_id.clone(),
            accepted_at: authorized.1.committed_at,
            issued_at: parsed.issued_at,
            expires_at: parsed.expires_at,
        },
        key_state_witness: AgentKeyStateWitness {
            commit_id: key_witness.commit_id.clone(),
            commit: key_witness.clone(),
            current_state: key_result,
        },
        agent_lifecycle_witness: AgentLifecycleWitness {
            commit_id: lifecycle.1.commit_id.clone(),
            commit: lifecycle.1.clone(),
            current_state: status_result,
            accepted_status_event: lifecycle.0.clone(),
            provenance,
        },
        authority_bundle: AgentAcceptedAuthorityBundle {
            realm_id: realm,
            genesis_event: genesis.0.clone(),
            genesis_commit: genesis.1.clone(),
            signer_histories: vec![history],
        },
        commits,
        commit_lineages: lineages,
        signer_dependencies: dependencies.into_values().collect(),
        producer_bindings: bindings,
    };
    state.validate_binding(account).map_err(invalid)?;
    if arkret_canonical::canonical_json_bytes(&state)
        .map_err(invalid)?
        .len()
        > AGENT_AUTHORITY_EVIDENCE_MAX_CANONICAL_BYTES
    {
        return Err(invalid("Agent state exceeds formal carrier byte bound"));
    }
    Ok(state)
}
