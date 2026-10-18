//! Ordinary Principal-signed managed Device authorization. No candidate overlay.

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizationScopes, DeviceAuthorizePayload,
};
use arkret_models_identity::{PrincipalResolutionProjection, ResolutionMethodHistoryEvidence};
use arkret_models_integration::AppletManagedActorProvisionPayload;
use arkret_wire::{CommitStreamRef, DidCoreId, Event, EventKind, ScopeRef};
use coland_storage::{
    AcceptedDeviceAuthorizationOutcome, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    ConflictCode, PersistenceError,
};
use diesel::sql_types::{Binary, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::Value;

use crate::{AsyncPgConnection, PgTransactionError};

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct ResolutionRow {
    #[diesel(sql_type=Text)]
    pcr_realm_id: String,
    #[diesel(sql_type=Jsonb)]
    projection: Value,
    #[diesel(sql_type=Jsonb)]
    genesis: Value,
    #[diesel(sql_type=Jsonb)]
    current: Value,
}
#[derive(QueryableByName)]
struct MethodRow {
    #[diesel(sql_type=Jsonb)]
    did_document: Value,
    #[diesel(sql_type=Jsonb)]
    method_evidence: Value,
    #[diesel(sql_type=Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
fn refuse(code: ConflictCode, detail: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {detail}")).into()
}
fn corrupt(detail: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::SchemaViolation(detail.to_string()).into()
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, PgTransactionError> {
    serde_json::from_value(value).map_err(corrupt)
}

pub(crate) async fn admit(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    carrier: &coland_storage::AppletControlCarrier,
) -> Result<AcceptedDeviceAuthorizationOutcome, PgTransactionError> {
    let source = &carrier.service_id;
    let carrier_did =
        arkret_identity::verification_method_did(carrier.verification_method.as_str())
            .map_err(corrupt)?;
    if arkret_wire::project_did_to_core_id(&carrier_did).map_err(corrupt)? != *source {
        return Err(refuse(
            ConflictCode::SignatureInvalid,
            "carrier method does not bind the source Service",
        ));
    }
    let event = &transaction.event;
    let commit = &transaction.commit;
    event.validate_for_submit_structural().map_err(corrupt)?;
    let suite = event
        .event_id
        .event_digest()
        .digest_suite()
        .map_err(corrupt)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|e| refuse(ConflictCode::EventIdDigestMismatch, e))?;
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| corrupt("managed authorize requires a full Account"))?;
    let payload: DeviceAuthorizePayload =
        decode(serde_json::to_value(&event.payload).map_err(corrupt)?)?;
    payload.validate_wire_constraints().map_err(corrupt)?;
    if event.kind != EventKind::DeviceAuthorize
        || payload.authorization_binding_kind
            != DeviceAuthorizationBindingKind::AppletManagedDelegation
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.applet_id.is_some()
        || event.scope_ref
            != (ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || account.station_id != transaction.expected_authority.service_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(refuse(
            ConflictCode::FailedPrecondition,
            "not an own managed PCR successor",
        ));
    }
    let applet = payload
        .applet_id
        .as_ref()
        .ok_or_else(|| corrupt("managed authorize has no Applet"))?;
    arkret_signatures::verify_device_authorize_possession(&payload, account)
        .map_err(|e| refuse(ConflictCode::SignatureInvalid, e))?;

    // The same Applet identity lock is taken by authoring; installation rows
    // additionally serialize this cut with each per-scope revoke fence.
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("applet:{applet}:{}", account.station_id))
        .execute(&mut *conn)
        .await?;
    let locked = sql_query(
        "SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<JsonRow>(&mut *conn)
    .await
    .optional()?;
    if locked.is_none() {
        return Err(refuse(
            ConflictCode::FailedPrecondition,
            "accepted PCR authority missing",
        ));
    }
    let known = sql_query("SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json) AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'")
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).get_result::<JsonRow>(&mut *conn).await.optional()?;
    if let Some(known) = known {
        let original: Event = decode(known.value["event"].clone())?;
        if original != *event {
            return Err(refuse(
                ConflictCode::DuplicateConflict,
                "Event already accepted with different bytes",
            ));
        }
        // HTTP identity still has to be the original Service on exact replay.
        require_provenance(conn, &event.actor_id, source, applet).await?;
        return Ok(AcceptedDeviceAuthorizationOutcome::Duplicate(decode(
            known.value["commit"].clone(),
        )?));
    }
    let provision = require_provenance(conn, &event.actor_id, source, applet).await?;
    if payload
        .expires_at
        .flatten()
        .is_none_or(|expiry| expiry <= payload.not_before || expiry <= commit.committed_at)
    {
        return Err(refuse(
            ConflictCode::FailedPrecondition,
            "managed device authorization has expired or has an empty window",
        ));
    }
    let identity = sql_query("SELECT record AS value FROM applet_managed_identities WHERE applet_id=$1 AND target_station_id=$2 FOR SHARE")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional()?.ok_or_else(|| corrupt("accepted Applet identity missing"))?;
    if !identity.value["globally_fenced_at"].is_null() {
        return Err(refuse(
            ConflictCode::AppletRevoked,
            "Applet identity is fenced",
        ));
    }
    let installs = sql_query("SELECT record AS value FROM applet_installations WHERE applet_id=$1 AND record->>'target_station_id'=$2 ORDER BY effective_scope_key FOR SHARE")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(account.station_id.as_str()).load::<JsonRow>(&mut *conn).await?;
    let Some(DeviceAuthorizationScopes::AppletManaged(scopes)) = &payload.scopes else {
        return Err(corrupt(
            "managed Device authorization requires paired scopes",
        ));
    };
    for entry in scopes.entries() {
        let expected = serde_json::to_value(&entry.effective_scope).map_err(corrupt)?;
        if !installs.iter().any(|row| {
            row.value["effective_scope"] == expected
                && row.value["package"]["service_id"].as_str() == Some(source.as_str())
                && row.value["revoked_at"].is_null()
                && matches!(
                    row.value["status"].as_str(),
                    Some("installed" | "partially_installed")
                )
        }) {
            return Err(refuse(
                ConflictCode::AppletRevoked,
                "managed Device scope has no exact active owning Applet installation",
            ));
        }
    }
    let record = current_resolution_in_connection(conn, account).await?;
    let projection = &record.projection;
    let genesis = &record.genesis_event;
    if record.pcr_realm_id != event.realm_id
        || genesis
            .payload
            .get("object")
            .and_then(|o| o.get("purpose"))
            .and_then(Value::as_str)
            != Some("applet_managed_control")
        || genesis.actor_id != event.actor_id
        || genesis.executed_by.as_ref() != Some(&arkret_wire::ActorId::service(source.clone()))
        || provision.actor_id != event.actor_id
        || provision.initial_resolution.did != projection.did
    {
        return Err(refuse(
            ConflictCode::FailedPrecondition,
            "accepted managed PCR provenance differs",
        ));
    }
    let cut = crate::pcr_device_revocation_proposals::confirmed_pcr_device_cut_in_connection(
        conn,
        account,
        &payload.device_id,
    )
    .await?
    .ok_or_else(|| corrupt("confirmed PCR device cut missing"))?;
    if cut.realm_id != event.realm_id
        || cut.current_generation != Some(payload.authorized_generation_ref)
    {
        return Err(refuse(
            ConflictCode::DeviceGenerationFenced,
            "generation differs from accepted writer",
        ));
    }
    if commit.previous_commit_ref.as_ref() != Some(&cut.authority_commit_id) {
        return Err(refuse(
            ConflictCode::CasConflict,
            "PCR head moved before acceptance",
        ));
    }
    if !cut.proposals.is_empty() {
        return Err(refuse(
            ConflictCode::DeviceRevoked,
            "a revoked Device id cannot be reused",
        ));
    }
    let method = sql_query(
        "SELECT did_document,method_evidence,expires_at FROM webvh_documents WHERE id=$1 FOR SHARE",
    )
    .bind::<Text, _>(projection.did.as_str())
    .get_result::<MethodRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| corrupt("accepted current method history unavailable"))?;
    let evidence: ResolutionMethodHistoryEvidence = decode(method.method_evidence)?;
    evidence.validate_shape().map_err(corrupt)?;
    let ResolutionMethodHistoryEvidence::WebvhLog {
        log_entries: logs,
        witness_records: witnesses,
        ..
    } = &evidence
    else {
        return Err(corrupt(
            "managed Principal requires authenticated native WebVH history",
        ));
    };
    let mut bytes = Vec::new();
    for log in logs {
        bytes.extend(arkret_canonical::canonical_json_bytes(log).map_err(corrupt)?);
        bytes.push(b'\n');
    }
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &projection.did,
        &bytes,
        Some(&serde_json::to_vec(witnesses).map_err(corrupt)?),
    )
    .map_err(corrupt)?;
    let head = verified
        .log
        .raw_entries
        .last()
        .ok_or_else(|| corrupt("empty current native history"))?;
    if method.expires_at <= commit.committed_at
        || verified.log.head_version_id != projection.version_id
        || arkret_canonical::canonical_sha256(head).map_err(corrupt)?
            != projection.method_history_head
        || verified.log.head_state != method.did_document
    {
        return Err(refuse(
            ConflictCode::FailedPrecondition,
            "method history is not the accepted current resolution",
        ));
    }
    let selected = arkret_signatures::webvh::validate_webvh_history_at(
        &projection.did,
        logs,
        event.created_at,
    )
    .map_err(corrupt)?;
    if selected.version_id != projection.version_id {
        return Err(refuse(
            ConflictCode::SignatureInvalid,
            "producer uses a superseded resolution",
        ));
    }
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| refuse(ConflictCode::SignatureInvalid, "Principal proof absent"))?;
    let did = arkret_identity::verification_method_did(proof.verification_method.as_str())
        .map_err(corrupt)?;
    if did != projection.did
        || proof
            .verification_method
            .as_str()
            .split_once('#')
            .is_some_and(|(_, fragment)| fragment.starts_with("ak:device:"))
    {
        return Err(refuse(
            ConflictCode::SignatureInvalid,
            "producer method does not belong to this Principal",
        ));
    }
    let document: arkret_identity::DidDocument = decode(method.did_document)?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &proof.verification_method,
        &did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|e| refuse(ConflictCode::SignatureInvalid, e))?;
    let key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &document,
        proof.verification_method.as_str(),
    )
    .map_err(corrupt)?;
    let controller_multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.to_bytes());
    let device_multibase = payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| corrupt("Device key is not a fingerprint"))?;
    let device_key =
        arkret_canonical::decode_ed25519_multibase(device_multibase).map_err(corrupt)?;
    if key.to_bytes()==carrier.public_key || device_key==carrier.public_key || controller_multibase == device_multibase || logs.iter().any(|entry| {
        entry.pointer("/parameters/updateKeys").and_then(Value::as_array).is_some_and(|keys| keys.iter().any(|root| {
            matches!(root.as_str(),Some(root) if root==controller_multibase || root==device_multibase)
        }))
    }) {
        return Err(refuse(ConflictCode::SignatureInvalid,"Service, Principal controller, Device and native history keys must be independent"));
    }
    let envelope = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(corrupt)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_bytes().to_vec(),
        },
        suite,
    )
    .map_err(|e| refuse(ConflictCode::SignatureInvalid, e))?;
    crate::authority_commit::queue_event_in_connection(conn, event, commit.committed_at).await?;
    match crate::authority_commit::commit_verified_pcr_device_transaction_in_connection(
        conn,
        transaction,
    )
    .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        _ => {
            return Err(refuse(
                ConflictCode::CasConflict,
                "managed PCR authority moved",
            ));
        }
    }
    crate::pcr_device_current_results::project_pcr_device_current_in_connection(
        conn, event, commit, None,
    )
    .await?;
    mirror(conn, account, &payload, event, commit).await?;
    Ok(AcceptedDeviceAuthorizationOutcome::Committed(
        commit.clone(),
    ))
}

/// Validate the projected resolution against its latest accepted writer at
/// the caller's snapshot. Write callers must already serialize the PCR head.
pub(crate) async fn current_resolution_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
) -> Result<coland_storage::PrincipalResolutionRecord, PgTransactionError> {
    let resolution = sql_query("SELECT p.pcr_realm_id,p.projection,g.envelope AS genesis,c.envelope AS current FROM principal_resolutions p JOIN canonical_events g ON g.envelope->>'event_id'=p.genesis_event_id JOIN realm_commits gc ON gc.event_pk=g.pk AND gc.stream_position=0 AND gc.realm_id=p.pcr_realm_id AND g.state='committed' JOIN canonical_events c ON c.envelope->>'event_id'=p.current_event_id JOIN realm_commits cc ON cc.event_pk=c.pk AND cc.realm_id=p.pcr_realm_id AND c.state='committed' WHERE p.principal_id=$1 AND p.station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<ResolutionRow>(&mut *conn).await.optional()?.ok_or_else(|| corrupt("accepted current resolution missing"))?;
    let projection: PrincipalResolutionProjection = decode(resolution.projection)?;
    let genesis: Event = decode(resolution.genesis)?;
    let current: Event = decode(resolution.current)?;
    let record = coland_storage::PrincipalResolutionRecord {
        account_id: account.clone(),
        pcr_realm_id: arkret_wire::RealmId::new(resolution.pcr_realm_id).map_err(corrupt)?,
        genesis_event: genesis.clone(),
        current_event: current,
        projection: projection.clone(),
    };
    coland_storage::validate_principal_resolution_record(&record)?;
    let latest = sql_query("SELECT e.envelope AS value FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND e.state='committed' AND e.kind IN ('ak.realm.create','ak.identity.resolution.update') ORDER BY c.stream_position DESC LIMIT 1")
        .bind::<Text,_>(record.pcr_realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await?;
    let latest: Event = decode(latest.value)?;
    let accepted_resolution: arkret_models_identity::ResolutionCommitment =
        if latest.kind == EventKind::RealmCreate {
            let create: arkret_models_collaboration::events_payloads::RealmCreatePayload =
                decode(serde_json::to_value(&latest.payload).map_err(corrupt)?)?;
            create
                .object
                .initial_resolution
                .ok_or_else(|| corrupt("managed genesis has no initial resolution"))?
        } else {
            let update: arkret_models_identity::PrincipalResolutionUpdatePayload =
                decode(serde_json::to_value(&latest.payload).map_err(corrupt)?)?;
            update.next
        };
    if latest != record.current_event
        || accepted_resolution.did != projection.did
        || accepted_resolution.method_history_head != projection.method_history_head
        || accepted_resolution.version_id != projection.version_id
    {
        return Err(corrupt(
            "current resolution differs from latest accepted writer",
        ));
    }
    Ok(record)
}

pub(crate) async fn require_provenance(
    conn: &mut AsyncPgConnection,
    actor: &arkret_wire::ActorId,
    source: &DidCoreId,
    applet: &arkret_wire::AppletId,
) -> Result<AppletManagedActorProvisionPayload, PgTransactionError> {
    let rows = sql_query("SELECT e.envelope AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.kind='ak.applet.managed_actor.provision' AND e.state='committed' AND e.envelope#>'{payload,actor_id}'=$1")
        .bind::<Jsonb,_>(serde_json::to_value(actor).map_err(corrupt)?).load::<JsonRow>(&mut *conn).await?;
    if rows.len() != 1 {
        return Err(refuse(
            ConflictCode::FailedPrecondition,
            "unique accepted managed provision missing",
        ));
    }
    let original: Event = decode(rows.into_iter().next().unwrap().value)?;
    let payload: AppletManagedActorProvisionPayload =
        decode(serde_json::to_value(&original.payload).map_err(corrupt)?)?;
    payload.validate().map_err(corrupt)?;
    if &payload.service_id != source || &payload.applet_id != applet || &payload.actor_id != actor {
        return Err(refuse(
            ConflictCode::FailedPrecondition,
            "Service differs from accepted managed provenance",
        ));
    }
    Ok(payload)
}

async fn mirror(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    payload: &DeviceAuthorizePayload,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
) -> Result<(), PgTransactionError> {
    let mut value = serde_json::to_value(payload).map_err(corrupt)?;
    value["device_authorize_event_id"] = serde_json::to_value(&event.event_id).map_err(corrupt)?;
    value["device_authorization_ref"] = serde_json::to_value(arkret_wire::CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    })
    .map_err(corrupt)?;
    let updated = sql_query("INSERT INTO devices (id,station_id,actor_id,device_id,device_key,verification_state,payload,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,'verified',$6,$7,$7) ON CONFLICT(actor_id,device_id) DO UPDATE SET device_key=EXCLUDED.device_key,verification_state='verified',payload=EXCLUDED.payload,updated_at=EXCLUDED.updated_at WHERE devices.station_id=EXCLUDED.station_id AND devices.revoked_at IS NULL")
        .bind::<diesel::sql_types::Uuid,_>(uuid::Uuid::now_v7()).bind::<Text,_>(account.station_id.as_str())
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(payload.device_id.as_str()).bind::<Text,_>(payload.device_public_key_did.as_str())
        .bind::<Jsonb,_>(value).bind::<Timestamptz,_>(commit.committed_at).execute(conn).await?;
    if updated != 1 {
        return Err(refuse(
            ConflictCode::DeviceRevoked,
            "managed device mirror is revoked or belongs to another Account",
        ));
    }
    Ok(())
}
