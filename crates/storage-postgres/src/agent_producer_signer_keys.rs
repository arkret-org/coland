//! Historical producer keys frozen in the original admission transaction.
//!
//! The legacy table name is retained; its closed result now holds either
//! registered Agent, account-device or Applet Service selectors, never inferred live keys.

use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
use arkret_models_identity::{
    HistoricalSignerKeyQuerySender, ResolvedSignerKey, SignerKeyQuerySelector, SignerKeyResolution,
};

use super::*;

fn historical_fact_diagnostic(stage: &'static str, branch: &'static str) {
    #[cfg(feature = "conformance-harness")]
    tracing::warn!(target: "conformance_harness", stage, diag_branch = branch,
        "historical signer fact fixed diagnostic");
    #[cfg(not(feature = "conformance-harness"))]
    let _ = (stage, branch);
}

#[derive(QueryableByName)]
struct SourceRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

#[derive(QueryableByName)]
struct AccountDeviceSourceRole {
    #[diesel(sql_type = Bool)]
    human: bool,
}

pub(crate) async fn retain_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    guard: Option<&SelfProducerCommitGuard>,
) -> PersistenceResult<()> {
    if let Some(selector) = guard.and_then(SelfProducerCommitGuard::human_device_selector) {
        // PCR-local commits are not ordinary signer-query targets. Their own
        // domain validates producer authority and may project after this hook.
        if guard_matches_pcr_target(event, selector) {
            return Ok(());
        }
        let outcome = human_outcome_in_connection(conn, event, commit, selector).await?;
        return retain_outcome_in_connection(conn, event, commit, outcome).await;
    }
    let Some(SelfProducerCommitGuard::Agent {
        pcr_realm_id,
        agent_id,
        authorization_ref,
        verification_method,
    }) = guard
    else {
        return Ok(());
    };
    let actor = event.actual_signer();
    if actor.as_account_id().map(|account| &account.principal_id) != Some(agent_id)
        || event
            .producer_proof
            .as_ref()
            .map(|proof| &proof.verification_method)
            != Some(verification_method)
    {
        return Err(PersistenceError::Conflict(
            "Agent historical producer differs from admission guard".into(),
        ));
    }
    let source = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND c.commit_id=$2")
        .bind::<Text,_>(authorization_ref.event_id.as_str()).bind::<Text,_>(authorization_ref.commit_id.as_str())
        .get_result::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let source_event: arkret_wire::Event =
        serde_json::from_value(source.envelope).map_err(PersistenceError::database)?;
    let payload = AgentKeyAuthorizePayload::try_from(&source_event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let source_commit: arkret_wire::RealmCommit =
        serde_json::from_value(source.commit_json).map_err(PersistenceError::database)?;
    if source_event.event_id != authorization_ref.event_id
        || source_event.realm_id != *pcr_realm_id
        || source_commit.commit_id != authorization_ref.commit_id
        || source_commit.stream_ref != authorization_ref.stream_ref
        || source_commit.stream_position != authorization_ref.stream_position
        || source_commit.event_ref != source_event.event_id
        || payload.agent_id != *agent_id
        || payload.verification_method != *verification_method
    {
        return Err(PersistenceError::Conflict(
            "Agent historical authorization coordinate differs".into(),
        ));
    }
    let revision = sql_query("SELECT e.envelope,c.commit_json FROM agent_key_current_states k JOIN realm_commits c ON c.commit_id=k.current_commit_id AND c.stream_position=k.current_stream_position AND c.realm_id=k.realm_id JOIN canonical_events e ON e.pk=c.event_pk WHERE k.realm_id=$1 AND k.agent_id=$2 AND k.agent_key_id=$3")
        .bind::<Text,_>(pcr_realm_id.as_str()).bind::<Text,_>(agent_id.as_str()).bind::<Text,_>(payload.key_id.as_str())
        .get_result::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let revision_commit: arkret_wire::RealmCommit =
        serde_json::from_value(revision.commit_json).map_err(PersistenceError::database)?;
    if revision_commit.stream_ref != authorization_ref.stream_ref
        || revision_commit.stream_position < authorization_ref.stream_position
    {
        return Err(PersistenceError::Conflict(
            "Agent historical key revision does not cover authorization".into(),
        ));
    }
    let key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &payload.public_key,
        verification_method,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let selector = SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::Agent {
            actor: actor.clone(),
            verification_method: verification_method.clone(),
            committed_event_ref: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            },
        },
    };
    let outcome = SignerKeyResolution::HistoricalResolved {
        selector,
        key: ResolvedSignerKey {
            public_key_base64url: arkret_wire::Base64UrlString::new(
                arkret_canonical::base64url_encode(key.raw_public_key),
            )
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            authorization_ref: authorization_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: revision_commit.commit_id,
                stream_position: revision_commit.stream_position,
            },
            governance_generation: revision_commit.governance_generation,
        },
        accepted_at: source_commit.committed_at,
    };
    retain_outcome_in_connection(conn, event, commit, outcome).await
}

async fn retain_outcome_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    outcome: SignerKeyResolution,
) -> PersistenceResult<()> {
    retain_outcome_with_self_admission(conn, event, commit, outcome, None).await
}

pub(crate) struct PreparedSelfHistoricalFact {
    outcome: SignerKeyResolution,
    kind: &'static str,
    provenance: Value,
}

pub(crate) async fn retain_self_outcome_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: PreparedSelfHistoricalFact,
) -> PersistenceResult<()> {
    let account = event.actual_signer().as_account_id().ok_or_else(|| {
        PersistenceError::Conflict("self historical producer is not an Account".into())
    })?;
    let target = arkret_wire::CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    if prepared.outcome.selector().actor().as_account_id() != Some(account)
        || prepared.outcome.selector().committed_event_ref() != Some(&target)
    {
        return Err(PersistenceError::Conflict(
            "prepared self history differs from original admitted target".into(),
        ));
    }
    retain_outcome_with_self_admission(
        conn,
        event,
        commit,
        prepared.outcome,
        Some((account, prepared.kind, &prepared.provenance)),
    )
    .await
}

async fn retain_outcome_with_self_admission(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    outcome: SignerKeyResolution,
    provenance: Option<(&arkret_wire::AccountId, &'static str, &Value)>,
) -> PersistenceResult<()> {
    outcome
        .validate(&event.realm_id)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    sql_query("INSERT INTO agent_producer_signer_keys(commit_id,outcome,self_admission_account,self_admission_kind,self_admission_provenance) VALUES($1,$2,$3,$4,$5)")
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(outcome).map_err(PersistenceError::database)?)
        .bind::<diesel::sql_types::Nullable<Jsonb>, _>(provenance.map(|(account, _, _)| serde_json::to_value(account)).transpose().map_err(PersistenceError::database)?)
        .bind::<diesel::sql_types::Nullable<Text>, _>(provenance.map(|(_, kind, _)| kind))
        .bind::<diesel::sql_types::Nullable<Jsonb>, _>(provenance.map(|(_, _, source)| source))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

/// Freeze before the PCR writer changes its cut; persist only after its Commit.
pub(crate) async fn prepare_self_pcr_outcome_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    guard: Option<&SelfProducerCommitGuard>,
) -> PersistenceResult<Option<PreparedSelfHistoricalFact>> {
    let Some(guard) = guard.and_then(SelfProducerCommitGuard::human_device_selector) else {
        return Ok(None);
    };
    if !guard_matches_pcr_target(event, guard) {
        return Ok(None);
    }
    // Registration cannot use its not-yet-accepted authorization as history.
    if event.kind == arkret_wire::EventKind::DeviceAuthorize
        && guard.authorization_ref.event_id == event.event_id
        && guard.authorization_ref.commit_id == commit.commit_id
        && guard.authorization_ref.stream_ref == commit.stream_ref
        && guard.authorization_ref.stream_position == commit.stream_position
    {
        return Ok(None);
    }
    human_outcome_in_connection(conn, event, commit, guard)
        .await
        .map(|outcome| {
            Some(PreparedSelfHistoricalFact {
                outcome,
                kind: "own_pcr",
                provenance: serde_json::json!({"accepted_pcr_realm_id": event.realm_id}),
            })
        })
}

async fn confirmed_human_outcome_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    status: &crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut,
    account: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
) -> PersistenceResult<SignerKeyResolution> {
    let authorization = status.authority.authorization.as_ref().ok_or_else(|| {
        PersistenceError::Conflict("self historical authorization is absent".into())
    })?;
    let row = sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND c.realm_id=$2 AND e.state='committed'")
        .bind::<Text,_>(authorization.source_commit_id.as_str()).bind::<Text,_>(status.authority.realm_id.as_str())
        .get_result::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let source: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    let source_event: arkret_wire::Event =
        serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
    if source.event_ref != authorization.event_id || source_event.event_id != authorization.event_id
    {
        return Err(PersistenceError::Conflict(
            "self historical authorization source differs".into(),
        ));
    }
    let guard = coland_storage::DeviceRevocationGateSelector {
        principal_id: account.principal_id.clone(),
        station_id: account.station_id.clone(),
        device_id: device.to_string(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: source.event_ref,
            commit_id: source.commit_id,
            stream_ref: source.stream_ref,
            stream_position: source.stream_position,
        },
    };
    human_outcome_in_connection(conn, event, commit, &guard).await
}

fn guard_matches_pcr_target(
    event: &arkret_wire::Event,
    guard: &coland_storage::DeviceRevocationGateSelector,
) -> bool {
    &event.realm_id == guard.authorization_ref.stream_ref.realm_id()
}

async fn human_outcome_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    guard: &coland_storage::DeviceRevocationGateSelector,
) -> PersistenceResult<SignerKeyResolution> {
    if commit.event_ref != event.event_id || commit.realm_id != event.realm_id {
        return Err(PersistenceError::Conflict(
            "Human historical target differs".into(),
        ));
    }
    let fact = prepare_account_device_source_in_connection(conn, event, commit.committed_at, guard)
        .await?;
    Ok(human_fact_outcome(&fact, commit))
}

fn human_fact_outcome(
    fact: &arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
    commit: &arkret_wire::RealmCommit,
) -> SignerKeyResolution {
    SignerKeyResolution::HistoricalResolved {
        selector: SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::AccountDevice {
                actor: fact.actor.clone(),
                device_id: fact.device_id.clone(),
                verification_method: fact.verification_method.clone(),
                committed_event_ref: arkret_wire::CommittedEventRef {
                    event_id: fact.event_id.clone(),
                    commit_id: commit.commit_id.clone(),
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                },
            },
        },
        key: fact.key.clone(),
        accepted_at: fact.accepted_at,
    }
}

/// Source-only candidate: no target Commit or synthetic target coordinates.
/// The accepting transaction must repeat this read under its original locks.
pub(crate) async fn native_control_target_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<bool> {
    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type = Bool)]
        present: bool,
    }
    let own = sql_query(
        "SELECT EXISTS(SELECT 1 FROM principal_resolutions WHERE pcr_realm_id=$1) AS present",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<Present>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if own.present {
        return Ok(true);
    }
    Ok(
        crate::agent_provisioning::declared_agent_provision_in_connection(conn, realm)
            .await
            .map_err(PgTransactionError::into_persistence)?
            .is_some(),
    )
}

pub(crate) fn prepare_local_account_device_source_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a arkret_wire::Event,
    admitted_at: chrono::DateTime<chrono::Utc>,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = PersistenceResult<
                    Option<
                        arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
                    >,
                >,
            > + Send
            + 'a,
    >,
>{
    Box::pin(prepare_local_account_device_source_inner(
        conn,
        event,
        admitted_at,
    ))
}

async fn prepare_local_account_device_source_inner(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    admitted_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<
    Option<arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact>,
> {
    let Some(producer) = event
        .account_device_producer()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?
    else {
        return Ok(None);
    };
    // Role comes from accepted native control-Realm material, including an
    // Agent PCR declared by its original provision. The controller's Human
    // PCR is different from that target and cannot classify it as ordinary.
    if native_control_target_in_connection(conn, &event.realm_id).await? {
        return Ok(None);
    }
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &producer.account_id,
        &producer.device_id,
        admitted_at,
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    .ok_or_else(|| PersistenceError::Conflict("Human source PCR cut is unavailable".into()))?;
    // Native PCR authoring keeps its separately registered historical contract.
    if cut.authority.realm_id == event.realm_id {
        return Ok(None);
    }
    let accepted =
        cut.authority.authorization.as_ref().ok_or_else(|| {
            PersistenceError::Conflict("Human source authorization is absent".into())
        })?;
    let row = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND c.commit_id=$2 AND e.state='committed'")
        .bind::<Text,_>(accepted.event_id.as_str()).bind::<Text,_>(accepted.source_commit_id.as_str())
        .get_result::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let source: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    let guard = coland_storage::DeviceRevocationGateSelector {
        principal_id: producer.account_id.principal_id.clone(),
        station_id: producer.account_id.station_id.clone(),
        device_id: producer.device_id.to_string(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: accepted.event_id.clone(),
            commit_id: accepted.source_commit_id.clone(),
            stream_ref: source.stream_ref,
            stream_position: source.stream_position,
        },
    };
    prepare_account_device_source_in_connection(conn, event, admitted_at, &guard)
        .await
        .map(Some)
}

pub(crate) async fn prepare_account_device_source_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    admitted_at: chrono::DateTime<chrono::Utc>,
    guard: &coland_storage::DeviceRevocationGateSelector,
) -> PersistenceResult<
    arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
> {
    let reject = |message: &str| PersistenceError::Conflict(message.to_owned());
    let producer = event
        .verify_producer_proof_self_consistency(event.realm_id.digest_suite_code().digest_suite())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        .ok_or_else(|| reject("Account Device historical producer is not an account device"))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| reject("Account Device historical producer proof is missing"))?;
    if producer.account_id.principal_id != guard.principal_id
        || producer.account_id.station_id != guard.station_id
        || producer.device_id.as_str() != guard.device_id
    {
        return Err(reject(
            "Account Device historical producer differs from admission guard or target",
        ));
    }
    let device = &producer.device_id;
    // Resolve only the local accepted PCR of this exact Account. A forwarded
    // foreign attestation is not local PCR lineage and cannot enter here.
    let first = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &producer.account_id,
        device,
        admitted_at,
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    .ok_or_else(|| reject("Account Device historical local PCR cut is unavailable"))?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &first.authority.realm_id)
        .await?;
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &producer.account_id,
        device,
        admitted_at,
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    .ok_or_else(|| reject("Account Device historical locked PCR cut is unavailable"))?;
    if cut.authority.realm_id != first.authority.realm_id
        || cut.admission() != arkret_wire::DeviceRevocationAdmissionDecision::Allow
    {
        return Err(reject(
            "Account Device historical device is not active at the locked PCR cut",
        ));
    }
    let accepted = cut
        .authority
        .authorization
        .as_ref()
        .ok_or_else(|| reject("Account Device historical authorization is unavailable"))?;
    if accepted.event_id != guard.authorization_ref.event_id
        || accepted.source_commit_id != guard.authorization_ref.commit_id
        || cut.authority.current_generation != Some(accepted.payload.authorized_generation_ref)
    {
        return Err(reject(
            "Account Device historical authorization differs from admission guard",
        ));
    }
    let role = sql_query("SELECT EXISTS(SELECT 1 FROM pcr_genesis_units g WHERE g.realm_id=p.pcr_realm_id AND g.principal_id=p.principal_id AND g.station_id=p.station_id) AS human FROM principal_resolutions p WHERE p.principal_id=$1 AND p.station_id=$2 AND p.pcr_realm_id=$3")
        .bind::<Text,_>(producer.account_id.principal_id.as_str())
        .bind::<Text,_>(producer.account_id.station_id.as_str())
        .bind::<Text,_>(cut.authority.realm_id.as_str())
        .get_result::<AccountDeviceSourceRole>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| reject("Account Device historical source has no accepted PCR role"))?;
    if !role.human {
        return Err(reject(
            "Account Device historical source is not a confirmed Account PCR",
        ));
    }
    let source = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND c.commit_id=$2 AND e.state='committed'")
        .bind::<Text,_>(guard.authorization_ref.event_id.as_str()).bind::<Text,_>(guard.authorization_ref.commit_id.as_str())
        .get_result::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let source_event: arkret_wire::Event =
        serde_json::from_value(source.envelope).map_err(PersistenceError::database)?;
    let source_commit: arkret_wire::RealmCommit =
        serde_json::from_value(source.commit_json).map_err(PersistenceError::database)?;
    source_event
        .verify_event_id_matches_content_with_digest_suite(
            source_event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(|e| reject(&e.to_string()))?;
    source_commit
        .verify_commit_id_matches_content()
        .map_err(|e| reject(&e.to_string()))?;
    if source_commit.committed_at > admitted_at {
        return Err(reject(
            "Account Device source was not accepted at the admission cut",
        ));
    }
    let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(
            serde_json::to_value(&source_event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
    if source_event.kind != arkret_wire::EventKind::DeviceAuthorize
        || source_event.actor_id != arkret_wire::ActorId::account(producer.account_id.clone())
        || source_event.event_id != guard.authorization_ref.event_id
        || source_event.realm_id != cut.authority.realm_id
        || source_commit.event_ref != source_event.event_id
        || source_commit.commit_id != guard.authorization_ref.commit_id
        || source_commit.stream_ref != guard.authorization_ref.stream_ref
        || source_commit.stream_position != guard.authorization_ref.stream_position
        || serde_json::to_value(&payload).map_err(PersistenceError::database)?
            != serde_json::to_value(&accepted.payload).map_err(PersistenceError::database)?
        || payload.device_id != *device
    {
        return Err(reject(
            "Account Device historical accepted authorization coordinate or payload differs",
        ));
    }
    let revision = sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND c.realm_id=$2 AND e.state='committed'")
        .bind::<Text,_>(cut.authority.authority_commit_id.as_str()).bind::<Text,_>(cut.authority.realm_id.as_str())
        .get_result::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let revision_event: arkret_wire::Event =
        serde_json::from_value(revision.envelope).map_err(PersistenceError::database)?;
    let revision_commit: arkret_wire::RealmCommit =
        serde_json::from_value(revision.commit_json).map_err(PersistenceError::database)?;
    revision_event
        .verify_event_id_matches_content_with_digest_suite(
            revision_event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(|e| reject(&e.to_string()))?;
    revision_commit
        .verify_commit_id_matches_content()
        .map_err(|e| reject(&e.to_string()))?;
    if revision_commit.committed_at > admitted_at {
        return Err(reject(
            "Account Device source revision is after the admission cut",
        ));
    }
    if revision_commit.commit_id != cut.authority.authority_commit_id
        || revision_commit.event_ref != revision_event.event_id
        || revision_event.realm_id != cut.authority.realm_id
        || revision_commit.stream_ref != source_commit.stream_ref
        || revision_commit.stream_position < source_commit.stream_position
    {
        return Err(reject(
            "Account Device historical PCR revision does not cover authorization",
        ));
    }
    if [event.created_at, proof.created_at, admitted_at]
        .into_iter()
        .any(|instant| {
            instant < payload.not_before
                || payload
                    .expires_at
                    .flatten()
                    .is_some_and(|expiry| instant >= expiry)
        })
    {
        return Err(reject(
            "Account Device historical producer is outside its accepted authorization window",
        ));
    }
    let multibase = payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| reject("Account Device historical accepted key is not did:key"))?;
    let raw = arkret_canonical::decode_ed25519_multibase(multibase)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    let suite = event.realm_id.digest_suite_code().digest_suite();
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(|_| {
        reject("Account Device historical producer signature differs from accepted authorization")
    })?;
    Ok(
        arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact {
            event_id: event.event_id.clone(),
            actor: event.actual_signer().clone(),
            device_id: device.clone(),
            verification_method: proof.verification_method.clone(),
            key: ResolvedSignerKey {
                public_key_base64url: arkret_wire::Base64UrlString::new(
                    arkret_canonical::base64url_encode(raw),
                )
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
                authorization_ref: guard.authorization_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: revision_commit.commit_id,
                    stream_position: revision_commit.stream_position,
                },
                governance_generation: revision_commit.governance_generation,
            },
            accepted_at: source_commit.committed_at,
        },
    )
}

/// Reprove the source at the actual locked acceptance cut, before any Event write.
/// Exact accepted replay supplies its original canonical witness instead.
pub(crate) async fn validate_prepared_local_account_device_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &coland_storage::AuthorityCommitTransaction,
) -> PersistenceResult<
    Option<arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact>,
> {
    if crate::authority_commit::is_exact_accepted_event_replay(
        conn,
        &transaction.event,
        &transaction.commit,
    )
    .await?
    {
        return Ok(None);
    }
    if transaction.event.actor_id.as_realm_actor_id().is_some() {
        let fact = crate::realm_actor_device_authority::signer_fact(
            conn,
            &transaction.event,
            transaction.commit.committed_at,
        )
        .await
        .map_err(PgTransactionError::into_persistence)?;
        let fact = arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::RealmDevice(fact);
        if transaction.producer_signer_fact.as_ref() != Some(&fact) {
            return Err(PersistenceError::Conflict(
                "Realm Device signer source changed before acceptance".into(),
            ));
        }
        validate_producer_fact_binding(&transaction.event, &transaction.commit, Some(&fact))?;
        return Ok(None);
    }
    let prepared = prepare_local_account_device_source_in_connection(
        conn,
        &transaction.event,
        transaction.commit.committed_at,
    )
    .await?;
    if prepared.as_ref()
        != transaction
            .producer_signer_fact
            .as_ref()
            .and_then(|fact| fact.as_account_device())
    {
        return Err(PersistenceError::Conflict(
            "Account Device signer source changed before acceptance".into(),
        ));
    }
    if transaction.producer_signer_fact.as_ref().is_some_and(|fact| matches!(fact, arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(_))) {
        return Ok(None);
    }
    validate_account_device_fact_binding(
        &transaction.event,
        &transaction.commit,
        prepared.as_ref(),
    )?;
    Ok(prepared)
}

pub(crate) fn validate_account_device_fact_binding(
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    fact: Option<&arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact>,
) -> PersistenceResult<()> {
    let reject = |e: arkret_wire::WireError| PersistenceError::SchemaViolation(e.to_string());
    match (commit.producer_signer_fact_digest.as_ref(), fact) {
        (Some(_), Some(fact)) => {
            let suite = event.realm_id.digest_suite_code().digest_suite();
            fact.validate_commit_binding(
                &arkret_wire::CommittedEventFullView {
                    event: event.clone(),
                    commit: commit.clone(),
                },
                suite,
            )
            .map_err(reject)?;
            arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(event, fact, suite)
                .map_err(|e| PersistenceError::Conflict(format!("Human source signature is invalid: {e}")))?;
        }
        (None, None) => {}
        _ => {
            return Err(PersistenceError::Conflict(
                "Human source and signed Commit digest differ".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn retain_prepared_account_device_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    fact: &arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
) -> PersistenceResult<()> {
    validate_account_device_fact_binding(event, commit, Some(fact))?;
    if matches!(
        commit.stream_ref,
        arkret_wire::CommitStreamRef::RealmControl { .. }
    ) {
        return retain_prepared_applet_in_connection(conn, event, commit, &fact.clone().into())
            .await;
    }
    retain_outcome_in_connection(conn, event, commit, human_fact_outcome(fact, commit)).await?;
    let written = sql_query("UPDATE agent_producer_signer_keys SET producer_source_fact=$2 WHERE commit_id=$1 AND producer_source_fact IS NULL")
        .bind::<Text,_>(commit.commit_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(fact).map_err(PersistenceError::database)?)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "Human original source was already frozen".into(),
        ));
    }
    Ok(())
}

fn service_fact_outcome(
    fact: &arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact,
    commit: &arkret_wire::RealmCommit,
) -> SignerKeyResolution {
    SignerKeyResolution::HistoricalServiceResolved {
        selector: SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::Service {
                actor: fact.actor.clone(),
                verification_method: fact.verification_method.clone(),
                committed_event_ref: arkret_wire::CommittedEventRef {
                    event_id: fact.event_id.clone(),
                    commit_id: commit.commit_id.clone(),
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                },
            },
        },
        key: fact.key.clone(),
        accepted_at: fact.accepted_at,
    }
}

fn producer_fact_outcome(
    fact: &arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<SignerKeyResolution> {
    use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact as Fact;
    match fact {
        Fact::AccountDevice(fact) => Ok(human_fact_outcome(fact, commit)),
        Fact::Service(fact) => Ok(service_fact_outcome(fact, commit)),
        Fact::RealmDevice(fact) => Ok(SignerKeyResolution::HistoricalRealmDeviceResolved {
            selector: SignerKeyQuerySelector::HistoricalRealmDevice {
                sender_kind: arkret_models_identity::RealmDeviceSignerKind::RealmDevice,
                actor_id: fact.actor_id.clone(),
                device_id: fact.device_id.clone(),
                verification_method: fact.verification_method.clone(),
                committed_event_ref: arkret_wire::CommittedEventRef {
                    event_id: fact.event_id.clone(),
                    commit_id: commit.commit_id.clone(),
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                },
            },
            key: arkret_models_identity::CurrentDeviceSigningKey {
                public_key_base64url: fact.public_key_base64url.clone(),
            },
            accepted_at: fact.accepted_at,
        }),
        Fact::RealmControl(_) | Fact::RealmRecoveryService(_) => Err(PersistenceError::Conflict(
            "not_found: private control signer facts are unavailable through public signer queries"
                .into(),
        )),
    }
}

pub(crate) fn validate_producer_fact_binding(
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    fact: Option<&arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
) -> PersistenceResult<()> {
    match (commit.producer_signer_fact_digest.as_ref(), fact) {
        (Some(_), Some(fact)) => {
            let suite = event.realm_id.digest_suite_code().digest_suite();
            fact.validate_commit_binding(
                &arkret_wire::CommittedEventFullView {
                    event: event.clone(),
                    commit: commit.clone(),
                },
                suite,
            )
            .map_err(PersistenceError::database)?;
            arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(event, fact, suite).map_err(PersistenceError::database)?;
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(PersistenceError::Conflict(
            "original producer source and Commit digest differ".into(),
        )),
    }
}
pub(crate) async fn retain_prepared_service_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    fact: &arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact,
) -> PersistenceResult<()> {
    validate_producer_fact_binding(event, commit, Some(&fact.clone().into()))?;
    retain_outcome_in_connection(conn, event, commit, service_fact_outcome(fact, commit)).await?;
    let written = sql_query("UPDATE agent_producer_signer_keys SET producer_source_fact=$2 WHERE commit_id=$1 AND producer_source_fact IS NULL")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(fact).map_err(PersistenceError::database)?)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "Service original source was already frozen".into(),
        ));
    }
    Ok(())
}
pub(crate) async fn retain_prepared_applet_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    fact: &arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact as Fact;
    let created_subject =
        crate::realm_actor_control::creation(event)?.map(|candidate| candidate.actor_id);
    let governed_subject: Option<arkret_wire::ActorId> =
        if crate::realm_actor_governance::is_command(event) {
            Some(
                serde_json::from_value(event.payload.get("target_actor_id").cloned().ok_or_else(
                    || PersistenceError::Conflict("private governance target absent".into()),
                )?)
                .map_err(PersistenceError::database)?,
            )
        } else {
            None
        };
    let subject = match fact {
        Fact::AccountDevice(_) if governed_subject.is_some() => {
            governed_subject.as_ref().expect("checked governance")
        }
        Fact::Service(_) if created_subject.is_some() => {
            created_subject.as_ref().expect("checked creation")
        }
        Fact::Service(fact) => {
            return retain_prepared_service_in_connection(conn, event, commit, fact).await;
        }
        Fact::RealmRecoveryService(fact) => &fact.target_actor_id,
        Fact::RealmControl(fact) => &fact.actor_id,
        _ => {
            return Err(PersistenceError::Conflict(
                "private Applet signer branch differs".into(),
            ));
        }
    };
    if subject
        .as_realm_actor_id()
        .is_none_or(|subject| subject.realm_id != event.realm_id)
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::RealmControl {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(PersistenceError::Conflict(
            "private signer target or stream differs".into(),
        ));
    }
    validate_producer_fact_binding(event, commit, Some(fact))?;
    let written=sql_query("INSERT INTO realm_actor_private_signer_facts(commit_id,realm_id,event_id,actor_id,fact) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(subject).map_err(PersistenceError::database)?)
        .bind::<Jsonb,_>(serde_json::to_value(fact).map_err(PersistenceError::database)?)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "private original signer source was already frozen".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn producer_source_for_commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<
    Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
> {
    let row = if matches!(
        commit.stream_ref,
        arkret_wire::CommitStreamRef::RealmControl { .. }
    ) {
        sql_query("SELECT fact AS payload FROM realm_actor_private_signer_facts WHERE commit_id=$1 AND realm_id=$2 AND event_id=$3")
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str())
            .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
    } else {
        sql_query("SELECT producer_source_fact AS payload FROM agent_producer_signer_keys WHERE commit_id=$1 AND producer_source_fact IS NOT NULL")
        .bind::<Text,_>(commit.commit_id.as_str()).get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
    };
    let fact = row
        .map(|row| serde_json::from_value(row.payload).map_err(PersistenceError::database))
        .transpose()?;
    validate_producer_fact_binding(event, commit, fact.as_ref())?;
    Ok(fact)
}

pub(crate) async fn account_device_source_for_commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<
    Option<arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact>,
> {
    Ok(
        producer_source_for_commit_in_connection(conn, event, commit)
            .await?
            .and_then(|fact| fact.as_account_device().cloned()),
    )
}

pub(crate) async fn read(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    selector: &SignerKeyQuerySelector,
) -> PersistenceResult<Option<SignerKeyResolution>> {
    let Some(target) = selector.committed_event_ref() else {
        historical_fact_diagnostic("ordinary_read", "target_missing");
        return Ok(None);
    };
    let mut conn = pg_conn(pool).await.inspect_err(|_| {
        historical_fact_diagnostic("historical_read", "database_connection_failed");
    })?;
    #[derive(QueryableByName)]
    struct HistoricalRow {
        #[diesel(sql_type=Jsonb)]
        payload: Value,
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
        #[diesel(sql_type=Nullable<Jsonb>)]
        producer_source_fact: Option<Value>,
    }
    let row =
        sql_query("SELECT k.outcome AS payload,e.envelope,c.commit_json,k.producer_source_fact FROM agent_producer_signer_keys k JOIN realm_commits c ON c.commit_id=k.commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE k.commit_id=$1 AND c.realm_id=$2 AND e.state='committed' AND e.envelope->>'event_id'=$3 AND c.stream_ref=$4 AND c.stream_position=$5")
            .bind::<Text, _>(target.commit_id.as_str())
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(target.event_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&target.stream_ref).map_err(PersistenceError::database)?)
            .bind::<BigInt, _>(i64::try_from(target.stream_position).map_err(PersistenceError::database)?)
            .get_result::<HistoricalRow>(&mut conn)
            .await
            .optional()
            .map_err(|error| {
                historical_fact_diagnostic("ordinary_read", "database_lookup_failed");
                PersistenceError::database(error)
            })?;
    let Some(row) = row else {
        historical_fact_diagnostic("ordinary_read", "immutable_fact_not_found");
        return Ok(None);
    };
    let outcome: SignerKeyResolution = serde_json::from_value(row.payload).map_err(|error| {
        historical_fact_diagnostic("ordinary_read", "fact_decode_failed");
        PersistenceError::database(error)
    })?;
    outcome.validate(realm_id).map_err(|error| {
        historical_fact_diagnostic("ordinary_read", "fact_validation_failed");
        PersistenceError::Internal(error.to_string())
    })?;
    let event: arkret_wire::Event =
        serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    if (event.actor_id.as_realm_actor_id().is_some()
        || event
            .account_device_producer()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?
            .is_some()
        || (event.applet_id.is_some()
            && matches!(event.actual_signer(), arkret_wire::ActorId::Service { .. })))
        && !native_control_target_in_connection(&mut conn, &event.realm_id).await?
    {
        let Some(raw) = row.producer_source_fact else {
            historical_fact_diagnostic("ordinary_read", "immutable_fact_not_found");
            return Ok(None);
        };
        let fact = serde_json::from_value(raw).map_err(PersistenceError::database)?;
        validate_producer_fact_binding(&event, &commit, Some(&fact))?;
        if outcome != producer_fact_outcome(&fact, &commit)? {
            historical_fact_diagnostic("ordinary_read", "immutable_fact_outcome_mismatch");
            return Ok(None);
        }
    }
    if matches!(
        &outcome,
        SignerKeyResolution::HistoricalServiceResolved { .. }
    ) {
        let fact = producer_source_for_commit_in_connection(&mut conn, &event, &commit).await?;
        let Some(
            arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(
                fact,
            ),
        ) = fact
        else {
            return Ok(None);
        };
        if outcome != service_fact_outcome(&fact, &commit) {
            return Ok(None);
        }
    }
    let matches = outcome.selector() == selector
        && matches!(
            outcome,
            SignerKeyResolution::HistoricalResolved { .. }
                | SignerKeyResolution::HistoricalServiceResolved { .. }
                | SignerKeyResolution::HistoricalRealmDeviceResolved { .. }
        );
    historical_fact_diagnostic(
        "ordinary_read",
        if matches {
            "resolved"
        } else {
            "selector_or_result_kind_mismatch"
        },
    );
    Ok(matches.then_some(outcome))
}

/// Key-only disclosure of an original local self-admission, never PCR history.
pub(crate) async fn read_self_pcr(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    selector: &SignerKeyQuerySelector,
    recipient: &arkret_wire::AccountId,
) -> PersistenceResult<Option<SignerKeyResolution>> {
    let SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::AccountDevice { actor, .. },
    } = selector
    else {
        historical_fact_diagnostic("restricted_self_pcr_read", "wrong_selector");
        return Ok(None);
    };
    if actor.as_account_id() != Some(recipient) {
        historical_fact_diagnostic("restricted_self_pcr_read", "wrong_recipient");
        return Ok(None);
    }
    let Some(target) = selector.committed_event_ref() else {
        historical_fact_diagnostic("restricted_self_pcr_read", "target_missing");
        return Ok(None);
    };
    let mut conn = pg_conn(pool).await.inspect_err(|_| {
        historical_fact_diagnostic("historical_read", "database_connection_failed");
    })?;
    #[derive(QueryableByName)]
    struct SelfRow {
        #[diesel(sql_type = Jsonb)]
        envelope: Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
        #[diesel(sql_type = Jsonb)]
        outcome: Value,
        #[diesel(sql_type = Text)]
        self_admission_kind: String,
        #[diesel(sql_type = Jsonb)]
        self_admission_provenance: Value,
    }
    let row = sql_query("SELECT e.envelope,c.commit_json,k.outcome,k.self_admission_kind,k.self_admission_provenance FROM agent_producer_signer_keys k JOIN realm_commits c ON c.commit_id=k.commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE k.commit_id=$1 AND c.realm_id=$2 AND e.state='committed' AND e.envelope->>'event_id'=$3 AND c.stream_ref=$4 AND c.stream_position=$5 AND k.self_admission_account=$6 AND k.self_admission_kind IN ('own_pcr','agent_pcr_genesis','agent_pcr_controller')")
        .bind::<Text,_>(target.commit_id.as_str())
        .bind::<Text,_>(realm_id.as_str())
        .bind::<Text,_>(target.event_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&target.stream_ref).map_err(|error| {
            historical_fact_diagnostic("restricted_self_pcr_read", "fact_or_selector_decode_failed");
            PersistenceError::database(error)
        })?)
        .bind::<BigInt,_>(i64::try_from(target.stream_position).map_err(|error| {
            historical_fact_diagnostic("restricted_self_pcr_read", "fact_or_selector_decode_failed");
            PersistenceError::database(error)
        })?)
        .bind::<Jsonb,_>(serde_json::to_value(recipient).map_err(|error| {
            historical_fact_diagnostic("restricted_self_pcr_read", "fact_or_selector_decode_failed");
            PersistenceError::database(error)
        })?)
        .get_result::<SelfRow>(&mut conn).await.optional().map_err(|error| {
            historical_fact_diagnostic("restricted_self_pcr_read", "database_lookup_failed");
            PersistenceError::database(error)
        })?;
    let Some(row) = row else {
        historical_fact_diagnostic("restricted_self_pcr_read", "self_fact_not_found");
        return Ok(None);
    };
    let event: arkret_wire::Event = serde_json::from_value(row.envelope).map_err(|error| {
        historical_fact_diagnostic("restricted_self_pcr_read", "fact_or_selector_decode_failed");
        PersistenceError::database(error)
    })?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(|error| {
            historical_fact_diagnostic(
                "restricted_self_pcr_read",
                "fact_or_selector_decode_failed",
            );
            PersistenceError::database(error)
        })?;
    event
        .verify_event_id_matches_content_with_digest_suite(
            realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(|error| {
            historical_fact_diagnostic(
                "restricted_self_pcr_read",
                "content_proof_or_fact_validation_failed",
            );
            PersistenceError::SchemaViolation(error.to_string())
        })?;
    commit.verify_commit_id_matches_content().map_err(|error| {
        historical_fact_diagnostic(
            "restricted_self_pcr_read",
            "content_proof_or_fact_validation_failed",
        );
        PersistenceError::SchemaViolation(error.to_string())
    })?;
    let producer = event
        .verify_producer_proof_self_consistency(realm_id.digest_suite_code().digest_suite())
        .map_err(|error| {
            historical_fact_diagnostic(
                "restricted_self_pcr_read",
                "content_proof_or_fact_validation_failed",
            );
            PersistenceError::SchemaViolation(error.to_string())
        })?;
    if producer.as_ref().map(|producer| &producer.account_id) != Some(recipient)
        || event.actual_signer().as_account_id() != Some(recipient)
        || event.realm_id != *realm_id
        || commit.realm_id != *realm_id
        || commit.event_ref != event.event_id
        || commit.commit_id != target.commit_id
        || commit.stream_ref != target.stream_ref
        || commit.stream_position != target.stream_position
    {
        historical_fact_diagnostic(
            "restricted_self_pcr_read",
            "target_or_actual_producer_mismatch",
        );
        return Ok(None);
    }
    let source = &row.self_admission_provenance;
    let pcr: arkret_wire::RealmId = serde_json::from_value(source["accepted_pcr_realm_id"].clone())
        .map_err(|error| {
            historical_fact_diagnostic(
                "restricted_self_pcr_read",
                "fact_or_selector_decode_failed",
            );
            PersistenceError::database(error)
        })?;
    let outcome: SignerKeyResolution = serde_json::from_value(row.outcome).map_err(|error| {
        historical_fact_diagnostic("restricted_self_pcr_read", "fact_or_selector_decode_failed");
        PersistenceError::database(error)
    })?;
    outcome.validate(realm_id).map_err(|error| {
        historical_fact_diagnostic(
            "restricted_self_pcr_read",
            "content_proof_or_fact_validation_failed",
        );
        PersistenceError::SchemaViolation(error.to_string())
    })?;
    if outcome.selector() != selector
        || !matches!(outcome, SignerKeyResolution::HistoricalResolved { .. })
        || outcome
            .key()
            .map(|key| key.authorization_ref.stream_ref.realm_id())
            != Some(&pcr)
    {
        historical_fact_diagnostic(
            "restricted_self_pcr_read",
            "outcome_or_authorization_pcr_mismatch",
        );
        return Ok(None);
    }
    if row.self_admission_kind == "own_pcr" {
        if &pcr != realm_id {
            historical_fact_diagnostic("restricted_self_pcr_read", "own_pcr_binding_mismatch");
            return Ok(None);
        }
    } else {
        let controller: arkret_wire::AccountId =
            serde_json::from_value(source["controller_account"].clone()).map_err(|error| {
                historical_fact_diagnostic(
                    "restricted_self_pcr_read",
                    "fact_or_selector_decode_failed",
                );
                PersistenceError::database(error)
            })?;
        let delegation: arkret_wire::DidUrl = serde_json::from_value(
            source["controller_delegation_ref"].clone(),
        )
        .map_err(|error| {
            historical_fact_diagnostic(
                "restricted_self_pcr_read",
                "fact_or_selector_decode_failed",
            );
            PersistenceError::database(error)
        })?;
        let provision_ref: arkret_wire::CommittedEventRef =
            serde_json::from_value(source["provision_ref"].clone()).map_err(|error| {
                historical_fact_diagnostic(
                    "restricted_self_pcr_read",
                    "fact_or_selector_decode_failed",
                );
                PersistenceError::database(error)
            })?;
        if &controller != recipient
            || provision_ref.stream_ref.realm_id() != &pcr
            || (row.self_admission_kind == "agent_pcr_genesis"
                && (event.kind != arkret_wire::EventKind::RealmCreate
                    || event.realm_id != arkret_wire::RealmId::from_event_id(&event.event_id)))
            || event
                .executed_by
                .as_ref()
                .and_then(|actor| actor.as_account_id())
                != Some(&controller)
            || event.authorization_ref.as_deref() != Some(delegation.as_str())
        {
            historical_fact_diagnostic(
                "restricted_self_pcr_read",
                "agent_original_binding_mismatch",
            );
            return Ok(None);
        }
        let provision = sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND c.realm_id=$2 AND e.state='committed'")
            .bind::<Text,_>(provision_ref.commit_id.as_str()).bind::<Text,_>(pcr.as_str()).get_result::<SourceRow>(&mut conn).await.optional().map_err(|error| {
            historical_fact_diagnostic("restricted_self_pcr_read", "database_lookup_failed");
            PersistenceError::database(error)
        })?;
        let Some(provision) = provision else {
            historical_fact_diagnostic(
                "restricted_self_pcr_read",
                "agent_original_provision_missing",
            );
            return Ok(None);
        };
        let provision_event: arkret_wire::Event = serde_json::from_value(provision.envelope)
            .map_err(|error| {
                historical_fact_diagnostic(
                    "restricted_self_pcr_read",
                    "fact_or_selector_decode_failed",
                );
                PersistenceError::database(error)
            })?;
        let provision_commit: arkret_wire::RealmCommit =
            serde_json::from_value(provision.commit_json).map_err(|error| {
                historical_fact_diagnostic(
                    "restricted_self_pcr_read",
                    "fact_or_selector_decode_failed",
                );
                PersistenceError::database(error)
            })?;
        provision_event
            .verify_event_id_matches_content_with_digest_suite(
                pcr.digest_suite_code().digest_suite(),
            )
            .map_err(|error| {
                historical_fact_diagnostic(
                    "restricted_self_pcr_read",
                    "content_proof_or_fact_validation_failed",
                );
                PersistenceError::SchemaViolation(error.to_string())
            })?;
        provision_commit
            .verify_commit_id_matches_content()
            .map_err(|error| {
                historical_fact_diagnostic(
                    "restricted_self_pcr_read",
                    "content_proof_or_fact_validation_failed",
                );
                PersistenceError::SchemaViolation(error.to_string())
            })?;
        let payload =
            arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
                &provision_event,
            )
            .map_err(|error| {
                historical_fact_diagnostic(
                    "restricted_self_pcr_read",
                    "content_proof_or_fact_validation_failed",
                );
                PersistenceError::SchemaViolation(error.to_string())
            })?;
        let Some(agent) = event.actor_id.as_account_id() else {
            historical_fact_diagnostic("restricted_self_pcr_read", "agent_actual_account_missing");
            return Ok(None);
        };
        if provision_event.actor_id.as_account_id() != Some(recipient)
            || provision_event.event_id != provision_ref.event_id
            || provision_event.realm_id != pcr
            || provision_commit.realm_id != pcr
            || provision_commit.commit_id != provision_ref.commit_id
            || provision_commit.event_ref != provision_ref.event_id
            || provision_commit.stream_ref != provision_ref.stream_ref
            || provision_commit.stream_position != provision_ref.stream_position
            || payload.agent_id != agent.principal_id
            || agent.station_id != recipient.station_id
            || payload.principal_control_realm_id != *realm_id
            || payload.controller_principal_id != recipient.principal_id
            || payload.controller_authorization_ref != delegation
        {
            historical_fact_diagnostic(
                "restricted_self_pcr_read",
                "agent_original_provision_mismatch",
            );
            return Ok(None);
        }
    }
    historical_fact_diagnostic("restricted_self_pcr_read", "resolved");
    Ok(Some(outcome))
}

pub(crate) async fn prepare_confirmed_human_outcome_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    status: &crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut,
    account: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
) -> PersistenceResult<PreparedSelfHistoricalFact> {
    if event.realm_id != status.authority.realm_id {
        return Err(PersistenceError::Conflict(
            "self target is not the admitted PCR".into(),
        ));
    }
    let outcome =
        confirmed_human_outcome_in_connection(conn, event, commit, status, account, device).await?;
    Ok(PreparedSelfHistoricalFact {
        outcome,
        kind: "own_pcr",
        provenance: serde_json::json!({"accepted_pcr_realm_id": status.authority.realm_id}),
    })
}

pub(crate) async fn prepare_admitted_own_pcr_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<PreparedSelfHistoricalFact> {
    let producer = event
        .verify_producer_proof_self_consistency(event.realm_id.digest_suite_code().digest_suite())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        .ok_or_else(|| PersistenceError::Conflict("self PCR producer is not Human".into()))?;
    let status = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &producer.account_id,
        &producer.device_id,
        commit.committed_at,
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    .ok_or_else(|| PersistenceError::Conflict("self PCR accepted cut unavailable".into()))?;
    prepare_confirmed_human_outcome_in_connection(
        conn,
        event,
        commit,
        &status,
        &producer.account_id,
        &producer.device_id,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Agent Genesis admission binds the controller, signer, Event and preverified evidence on one connection."
)]
pub(crate) async fn prepare_agent_genesis_outcome_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    status: &crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut,
    controller: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
    provision_ref: &arkret_wire::CommittedEventRef,
    delegation: &arkret_wire::DidUrl,
) -> PersistenceResult<PreparedSelfHistoricalFact> {
    if event.kind != arkret_wire::EventKind::RealmCreate
        || event.realm_id != arkret_wire::RealmId::from_event_id(&event.event_id)
        || provision_ref.stream_ref.realm_id() != &status.authority.realm_id
        || event
            .executed_by
            .as_ref()
            .and_then(|actor| actor.as_account_id())
            != Some(controller)
        || event.authorization_ref.as_deref() != Some(delegation.as_str())
    {
        return Err(PersistenceError::Conflict(
            "Agent genesis original controller source differs".into(),
        ));
    }
    let outcome =
        confirmed_human_outcome_in_connection(conn, event, commit, status, controller, device)
            .await?;
    Ok(PreparedSelfHistoricalFact {
        outcome,
        kind: "agent_pcr_genesis",
        provenance: serde_json::json!({"accepted_pcr_realm_id":status.authority.realm_id,"provision_ref":provision_ref,"controller_account":controller,"controller_delegation_ref":delegation}),
    })
}

pub(crate) async fn prepare_agent_controller_outcome_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    status: &crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut,
    controller: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
) -> PersistenceResult<PreparedSelfHistoricalFact> {
    let (pcr, provision, provision_ref) =
        crate::agent_provisioning::declared_agent_provision_in_connection(conn, &event.realm_id)
            .await
            .map_err(PgTransactionError::into_persistence)?
            .ok_or_else(|| {
                PersistenceError::Conflict("original Agent provision unavailable".into())
            })?;
    let agent = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| PersistenceError::Conflict("Agent self target is not an Account".into()))?;
    if pcr != status.authority.realm_id
        || provision.agent_id != agent.principal_id
        || agent.station_id != controller.station_id
        || provision.controller_principal_id != controller.principal_id
        || event
            .executed_by
            .as_ref()
            .and_then(|actor| actor.as_account_id())
            != Some(controller)
        || event.authorization_ref.as_deref()
            != Some(provision.controller_authorization_ref.as_str())
    {
        return Err(PersistenceError::Conflict(
            "Agent controller original delegation differs".into(),
        ));
    }
    let outcome =
        confirmed_human_outcome_in_connection(conn, event, commit, status, controller, device)
            .await?;
    Ok(PreparedSelfHistoricalFact {
        outcome,
        kind: "agent_pcr_controller",
        provenance: serde_json::json!({"accepted_pcr_realm_id":pcr,"provision_ref":provision_ref,"controller_account":controller,"controller_delegation_ref":provision.controller_authorization_ref}),
    })
}

pub(crate) async fn retain_prepared_producer_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    fact: &arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
) -> PersistenceResult<()> {
    match fact {
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::AccountDevice(
            fact,
        ) => retain_prepared_account_device_in_connection(conn, event, commit, fact).await,
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(
            fact,
        ) if !matches!(commit.stream_ref, arkret_wire::CommitStreamRef::RealmControl { .. }) => retain_prepared_service_in_connection(conn, event, commit, fact).await,
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::RealmDevice(_) => {
            validate_producer_fact_binding(event, commit, Some(fact))?;
            retain_outcome_in_connection(conn, event, commit, producer_fact_outcome(fact, commit)?).await?;
            let written = sql_query("UPDATE agent_producer_signer_keys SET producer_source_fact=$2 WHERE commit_id=$1 AND producer_source_fact IS NULL")
                .bind::<Text,_>(commit.commit_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(fact).map_err(PersistenceError::database)?)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if written != 1 {
                return Err(PersistenceError::Conflict("Realm Device original signer source was already frozen".into()));
            }
            Ok(())
        }
        _ => retain_prepared_applet_in_connection(conn, event, commit, fact).await,
    }
}
