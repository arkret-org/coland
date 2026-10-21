//! Realm Device authority read from one accepted private control cut.
use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_integration::{
    RealmActorDeviceAuthorizationValue, RealmActorDeviceGenerationValue, RealmActorManagerValue,
    RealmActorRecoveryValue,
};
use arkret_wire::{ActorId, CommittedEventRef, DeviceId, Event, RealmCommit};
use coland_storage::{AppletManagedDeviceAuthority, PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::{Value, json};

use crate::{AsyncPgConnection, PgPool, PgTransactionError, pg_conn};

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
fn invalid(message: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::SchemaViolation(message.to_string()).into()
}
fn denied(message: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::Conflict(format!("device_unauthorized: {message}")).into()
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, PgTransactionError> {
    serde_json::from_value(value).map_err(invalid)
}

pub(crate) async fn for_event(
    pool: &PgPool,
    event: &Event,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<AppletManagedDeviceAuthority>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *conn)
            .await?;
        for_event_in_connection(conn, event, now).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// This checks identity and Device state. Business permission remains an
/// additional accepting-cut check, never inferred from a valid signature.
pub(crate) async fn for_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<AppletManagedDeviceAuthority>, PgTransactionError> {
    if event.actor_id.as_realm_actor_id().is_none() {
        return Ok(None);
    }
    if event.executed_by.is_some() {
        return Err(denied("Realm Device cannot have a proxy signer"));
    }
    event.validate_for_submit_structural().map_err(invalid)?;
    let suite = event.realm_id.digest_suite_code().digest_suite();
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(denied)?;
    event
        .verify_producer_proof_self_consistency(suite)
        .map_err(denied)?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| denied("producer proof absent"))?;
    let Some((_, fragment)) = proof.verification_method.as_str().split_once('#') else {
        return Err(denied("producer method fragment absent"));
    };
    if !fragment.starts_with("ak:device:") {
        return Ok(None);
    }
    let device = DeviceId::new(fragment.to_owned()).map_err(invalid)?;
    let authority = current_in_connection(conn, &event.actor_id, &device, now)
        .await?
        .ok_or_else(|| denied("Realm Device authorization unavailable"))?;
    if proof.verification_method.as_str() != format!("{}#{}", authority.native_did, device)
        || event.realm_id != authority.realm_id
        || event.applet_id.as_ref() != Some(&authority.applet_id)
        || event.created_at < authority.not_before
        || event.created_at >= authority.expires_at
        || proof.created_at < authority.not_before
        || proof.created_at >= authority.expires_at
    {
        return Err(denied(
            "Realm Device method, Applet, Realm or signature time differs",
        ));
    }
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(denied)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: authority.public_key.to_vec(),
        },
        suite,
    )
    .map_err(denied)?;
    Ok(Some(authority))
}

pub(crate) async fn current(
    pool: &PgPool,
    actor: &ActorId,
    device: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<AppletManagedDeviceAuthority>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *conn)
            .await?;
        current_in_connection(conn, actor, device, now).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Callers that write must already hold the parent Realm authority lock.
pub(crate) async fn current_in_connection(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    device: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<AppletManagedDeviceAuthority>, PgTransactionError> {
    let Some(subject) = actor.as_realm_actor_id() else {
        return Ok(None);
    };
    use crate::realm_actor_control::{current_source, optional_current_source};
    let Some((value, source)) = optional_current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_device_authorization","actor_id":actor,"device_id":device}),
    )
    .await?
    else {
        return Ok(None);
    };
    let authorization: RealmActorDeviceAuthorizationValue = decode(value)?;
    let creation = crate::realm_actor_control::creation_source(conn, actor).await?;
    let control = crate::realm_actor_control_source::current(conn, actor)
        .await?
        .value;
    let (value, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_manager","actor_id":actor}),
    )
    .await?;
    let manager: RealmActorManagerValue = decode(value)?;
    let (value, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_recovery","actor_id":actor}),
    )
    .await?;
    let recovery: RealmActorRecoveryValue = decode(value)?;
    let (value, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_device_generation","actor_id":actor}),
    )
    .await?;
    let generation: RealmActorDeviceGenerationValue = decode(value)?;
    for gate in ["owner", "governance"] {
        let (value, _) = current_source(
            conn,
            actor,
            json!({"kind":"realm_actor_status","actor_id":actor,"gate":gate}),
        )
        .await?;
        if value != "active" {
            return Err(denied("Realm actor status gate is not active"));
        }
    }
    if recovery.pending.is_some()
        || generation.current_device_generation_ref != authorization.authorized_generation_ref
        || now < authorization.not_before
        || now >= authorization.expires_at
        || authorization.applet_id != creation.applet_id
        || authorization.authorized_by != subject.principal_id
        || source.event_id != authorization.device_authorize_event_id
    {
        return Err(denied(
            "Realm Device is fenced, outside its window or has changed owner",
        ));
    }
    let row=sql_query("SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json) AS value FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND e.state='committed'")
  .bind::<Text,_>(source.commit_id.as_str()).get_result::<JsonRow>(&mut *conn).await?;
    let original: Event = decode(row.value["event"].clone())?;
    let commit: RealmCommit = decode(row.value["commit"].clone())?;
    arkret_wire::CommittedEventFullView {
        event: original.clone(),
        commit: commit.clone(),
    }
    .validate_shape()
    .map_err(invalid)?;
    let actual = CommittedEventRef {
        event_id: original.event_id.clone(),
        commit_id: commit.commit_id,
        stream_ref: commit.stream_ref,
        stream_position: commit.stream_position,
    };
    let payload: DeviceAuthorizePayload = decode(json!(original.payload))?;
    if actual != source
        || original.actor_id != *actor
        || payload.device_id != *device
        || RealmActorDeviceAuthorizationValue::from_event(&original).map_err(invalid)?
            != authorization
    {
        return Err(invalid(
            "Realm Device current differs from its original authorization",
        ));
    }
    arkret_signatures::verify_realm_device_authorize_possession(&payload, actor).map_err(denied)?;
    // Each proposal has an independent durable result; rejecting one never clears
    // another pending proposal. A missing ledger is unavailable, never pending.
    let proposals=sql_query("SELECT jsonb_build_object('result',r.command_result,'event',e.envelope,'commit',c.commit_json) AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk LEFT JOIN realm_actor_device_revoke_results r ON r.proposal_commit_id=c.commit_id WHERE c.realm_id=$1 AND e.state='committed' AND e.kind='ak.device.revoke' AND e.envelope->'actor_id'=$2 AND e.envelope#>>'{payload,device_id}'=$3")
  .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Text,_>(device.as_str()).load::<JsonRow>(&mut *conn).await?;
    for proposal in proposals {
        let commit: RealmCommit = decode(proposal.value["commit"].clone())?;
        let reference = CommittedEventRef {
            event_id: commit.event_ref,
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        };
        match crate::realm_actor_device_revoke::read(conn, actor, &reference).await? {
            arkret_models_integration::RealmActorOperationOutcome::DeviceRevoke {
                state, ..
            } => {
                use arkret_models_integration::RealmActorDeviceRevokeState;
                match state {
                    RealmActorDeviceRevokeState::Rejected => {}
                    RealmActorDeviceRevokeState::Accepted => {
                        return Err(denied("Realm Device permanently revoked"));
                    }
                    RealmActorDeviceRevokeState::Pending => {
                        return Err(denied("Realm Device revocation pending"));
                    }
                }
            }
            _ => return Err(invalid("invalid Realm Device command result")),
        }
    }
    crate::realm_management_archive::require_unfrozen(conn, &subject.realm_id).await?;
    let current =
        sql_query("SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1")
            .bind::<Text, _>(subject.realm_id.as_str())
            .get_result::<JsonRow>(&mut *conn)
            .await?;
    let key = authorization
        .device_public_key_did
        .strip_prefix("did:key:")
        .ok_or_else(|| invalid("Realm Device has no did:key"))?;
    let public_key = arkret_canonical::decode_ed25519_multibase(key).map_err(invalid)?;
    Ok(Some(AppletManagedDeviceAuthority {
        actor_id: actor.clone(),
        device_id: device.clone(),
        authorization_ref: source,
        applet_id: creation.applet_id,
        source_service_id: manager.service_id,
        native_did: control.resolution.did,
        realm_id: subject.realm_id.clone(),
        current_device_generation_ref: generation.current_device_generation_ref,
        public_key,
        scopes: authorization.scopes,
        not_before: authorization.not_before,
        expires_at: authorization.expires_at,
        governance_service_id: decode(current.value["service_id"].clone())?,
        governance_generation: decode(current.value["generation"].clone())?,
    }))
}

pub(crate) async fn consume_nonce(
    pool: &PgPool,
    expected: &AppletManagedDeviceAuthority,
    metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
    retain_until: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AppletManagedDeviceAuthority> {
    metadata
        .validate()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
  let locked=sql_query("SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1 FOR UPDATE")
   .bind::<Text,_>(expected.realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.optional()?;
  if locked.is_none() {return Err(denied("Realm authority unavailable"));}
  let now=chrono::Utc::now();
  if retain_until<=now || retain_until>now+chrono::Duration::seconds(arkret_signatures::http_signature::HTTP_SIGNATURE_MAX_LIFETIME_SECONDS+arkret_signatures::http_signature::HTTP_SIGNATURE_CREATED_SKEW_SECONDS) {return Err(denied("Device signature window is not current"));}
  let current=current_in_connection(conn,&expected.actor_id,&expected.device_id,now).await?.ok_or_else(||denied("Realm Device disappeared"))?;
  if &current!=expected || metadata.actor_id!=current.actor_id || metadata.device_id!=current.device_id
    || metadata.authorization_event_id!=current.authorization_ref.event_id || metadata.applet_id!=current.applet_id
    || !current.scopes.contains_scope(&metadata.effective_scope) {return Err(denied("Realm Device current differs from signed metadata"));}
  sql_query("DELETE FROM applet_managed_device_nonces WHERE actor_id=$1 AND device_id=$2 AND retain_until<=$3")
   .bind::<Jsonb,_>(json!(current.actor_id)).bind::<Text,_>(current.device_id.as_str()).bind::<Timestamptz,_>(now).execute(&mut *conn).await?;
  let inserted=sql_query("INSERT INTO applet_managed_device_nonces(actor_id,device_id,nonce,consumed_at,retain_until) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
   .bind::<Jsonb,_>(json!(current.actor_id)).bind::<Text,_>(current.device_id.as_str()).bind::<Text,_>(&metadata.nonce).bind::<Timestamptz,_>(now).bind::<Timestamptz,_>(retain_until).execute(&mut *conn).await?;
  if inserted!=1 {return Err(denied("Realm Device nonce already consumed"));}
  Ok(current)
 }).await.map_err(PgTransactionError::into_persistence)
}

/// Freeze the actual accepted Device key and generation for this original Event.
pub(crate) async fn signer_fact(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<
    arkret_models_collaboration::authority_commit::RealmDeviceHistoricalSignerFact,
    PgTransactionError,
> {
    use arkret_models_collaboration::authority_commit::{
        RealmDeviceHistoricalSignerFact, RealmDeviceHistoricalSignerFactKind,
    };
    let at = arkret_canonical::normalize_timestamp_canonical(at);
    let authority = for_event_in_connection(conn, event, at)
        .await?
        .ok_or_else(|| denied("Realm Device producer is unavailable"))?;
    let fact = RealmDeviceHistoricalSignerFact {
        kind: RealmDeviceHistoricalSignerFactKind::RealmDevice,
        event_id: event.event_id.clone(),
        actor_id: authority.actor_id,
        verification_method: event
            .producer_proof
            .as_ref()
            .ok_or_else(|| denied("producer proof absent"))?
            .verification_method
            .clone(),
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            authority.public_key,
        ))
        .map_err(invalid)?,
        accepted_at: at,
        device_id: authority.device_id,
        authorization_event_id: authority.authorization_ref.event_id,
        authorized_generation_ref: authority.current_device_generation_ref,
    };
    fact.validate_event_binding(event, event.realm_id.digest_suite_code().digest_suite())
        .map_err(invalid)?;
    Ok(fact)
}
