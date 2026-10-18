//! Accepted managed Device identity from one confirmed, repeatable-read cut.

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizationScopes,
};
use arkret_wire::{AccountId, ActorId, CommittedEventRef, DeviceId, Event, RealmCommit};
use coland_storage::{
    AppletManagedDeviceAuthority, DeviceRevocationGateSelector, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;

use crate::{AsyncPgConnection, PgPool, PgTransactionError, pg_conn};

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn invalid(message: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::SchemaViolation(message.to_string()).into()
}

fn denied(message: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("unauthenticated: {message}")).into()
}

fn invalid_signature(error: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::Conflict(format!("signature_invalid: {error}")).into()
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

/// Identity/proof verification only. Management and business consumers must
/// re-read this under their ordered PCR locks, then qualify the actual scope.
pub(crate) async fn for_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<AppletManagedDeviceAuthority>, PgTransactionError> {
    event.validate_for_submit_structural().map_err(invalid)?;
    let suite = event.realm_id.digest_suite_code().digest_suite();
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(invalid_signature)?;
    let Some(producer) = event
        .verify_producer_proof_self_consistency(suite)
        .map_err(invalid_signature)?
    else {
        return Ok(None);
    };
    let Some(authority) =
        current_in_connection(conn, &producer.account_id, &producer.device_id, now).await?
    else {
        return Ok(None);
    };
    if event.executed_by.is_some()
        || event.actor_id.as_account_id() != Some(&authority.account_id)
        || event
            .applet_id
            .as_ref()
            .is_some_and(|applet| applet != &authority.applet_id)
    {
        return Err(invalid_signature(
            "managed Device cannot sign for another actor",
        ));
    }
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| invalid_signature("Event producer proof is absent"))?;
    if proof.verification_method.as_str()
        != format!("{}#{}", authority.native_did, authority.device_id)
        || event.created_at < authority.not_before
        || event.created_at >= authority.expires_at
        || proof.created_at < authority.not_before
        || proof.created_at >= authority.expires_at
    {
        return Err(invalid_signature(
            "managed producer method or original signing window differs",
        ));
    }
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(invalid_signature)?;
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: authority.public_key.to_vec(),
    };
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(invalid_signature)?;
    Ok(Some(authority))
}

pub(crate) async fn consume_nonce(
    pool: &PgPool,
    expected: &AppletManagedDeviceAuthority,
    metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
    retain_until: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AppletManagedDeviceAuthority> {
    metadata
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        let locked = sql_query("SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1 FOR UPDATE")
            .bind::<Text,_>(expected.pcr_realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.optional()?;
        if locked.is_none() { return Err(denied("managed PCR authority is unavailable")); }
        let now = chrono::Utc::now();
        if retain_until <= now || retain_until > now + chrono::Duration::seconds(
            arkret_signatures::http_signature::HTTP_SIGNATURE_MAX_LIFETIME_SECONDS
                + arkret_signatures::http_signature::HTTP_SIGNATURE_CREATED_SKEW_SECONDS
        ) {
            return Err(denied("managed Device signature window is not current"));
        }
        let current = current_in_connection(conn, &expected.account_id, &expected.device_id, now)
            .await?.ok_or_else(|| denied("managed Device authority is absent"))?;
        if &current != expected
            || metadata.account_id != current.account_id
            || metadata.device_id != current.device_id
            || metadata.authorization_event_id != current.selector.authorization_ref.event_id
            || metadata.applet_id != current.applet_id
            || !current.scopes.contains_scope(&metadata.effective_scope)
        {
            return Err(denied("managed Device instance changed or differs from signed metadata"));
        }
        sql_query("DELETE FROM applet_managed_device_nonces WHERE principal_id=$1 AND station_id=$2 AND device_id=$3 AND retain_until<=$4")
            .bind::<Text,_>(current.account_id.principal_id.as_str()).bind::<Text,_>(current.account_id.station_id.as_str())
            .bind::<Text,_>(current.device_id.as_str()).bind::<Timestamptz,_>(now).execute(&mut *conn).await?;
        let inserted = sql_query("INSERT INTO applet_managed_device_nonces(principal_id,station_id,device_id,nonce,consumed_at,retain_until) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind::<Text,_>(current.account_id.principal_id.as_str()).bind::<Text,_>(current.account_id.station_id.as_str())
            .bind::<Text,_>(current.device_id.as_str()).bind::<Text,_>(&metadata.nonce)
            .bind::<Timestamptz,_>(now).bind::<Timestamptz,_>(retain_until).execute(&mut *conn).await?;
        if inserted != 1 {
            return Err(denied("managed Device HTTP nonce was already consumed"));
        }
        Ok(current)
    }).await.map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn current(
    pool: &PgPool,
    account: &AccountId,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<AppletManagedDeviceAuthority>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *conn)
            .await?;
        current_in_connection(conn, account, device_id, now).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Write consumers must serialize the PCR authority before re-reading this
/// identity. A previous read must never stand in for acceptance-time checks.
pub(crate) async fn current_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<AppletManagedDeviceAuthority>, PgTransactionError> {
    let Some(authority) =
        crate::pcr_device_revocation_proposals::confirmed_pcr_device_cut_in_connection(
            conn, account, device_id,
        )
        .await?
    else {
        return Ok(None);
    };
    let Some(authorization) = &authority.authorization else {
        return Ok(None);
    };
    if authorization.payload.authorization_binding_kind
        != DeviceAuthorizationBindingKind::AppletManagedDelegation
    {
        return Ok(None);
    }
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_from_authority(
        conn, account, device_id, authority, now,
    )
    .await?;
    let authorization = cut
        .authority
        .authorization
        .as_ref()
        .ok_or_else(|| invalid("managed Device lost its confirmed authorization"))?;
    let payload = &authorization.payload;
    payload.validate_wire_constraints().map_err(invalid)?;
    if let Some(code) = cut.admission().error_code() {
        return Err(PersistenceError::Conflict(format!(
            "{}: managed Device is not currently admitted",
            code.as_str()
        ))
        .into());
    }
    let Some(DeviceAuthorizationScopes::AppletManaged(scopes)) = &payload.scopes else {
        return Err(invalid("managed Device has no accepted paired scopes"));
    };
    let applet_id = payload
        .applet_id
        .as_ref()
        .ok_or_else(|| invalid("managed Device has no accepted Applet"))?;
    let actor = ActorId::account(account.clone());
    let resolution =
        crate::pcr_applet_device::current_resolution_in_connection(conn, account).await?;
    let genesis = &resolution.genesis_event;
    let Some(ActorId::Service { service_id: source }) = genesis.executed_by.as_ref() else {
        return Err(invalid("managed PCR has no accepted Service executor"));
    };
    let provision =
        crate::pcr_applet_device::require_provenance(conn, &actor, source, applet_id).await?;
    if resolution.pcr_realm_id != cut.authority.realm_id
        || genesis.actor_id != actor
        || genesis
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(Value::as_str)
            != Some("applet_managed_control")
        || provision.initial_resolution.did != resolution.projection.did
        || payload.device_id != *device_id
        || cut.authority.current_generation != Some(payload.authorized_generation_ref)
    {
        return Err(invalid(
            "managed Device differs from accepted PCR provenance",
        ));
    }
    let lifecycle = sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM account_lifecycle l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 AND l.state<>'active')) AS value")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await?;
    if lifecycle.value.as_bool() != Some(false) {
        return Err(invalid("managed Account lifecycle is not active"));
    }
    let row = sql_query("SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json,'position',c.stream_position,'stream',c.stream_ref) AS value FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND c.realm_id=$2 AND e.state='committed'")
        .bind::<Text,_>(authorization.source_commit_id.as_str()).bind::<Text,_>(cut.authority.realm_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await?;
    let event: Event = serde_json::from_value(row.value["event"].clone()).map_err(invalid)?;
    let commit: RealmCommit =
        serde_json::from_value(row.value["commit"].clone()).map_err(invalid)?;
    if event.actor_id != actor
        || event.event_id != authorization.event_id
        || event.realm_id != cut.authority.realm_id
        || event.executed_by.is_some()
        || event.kind != arkret_wire::EventKind::DeviceAuthorize
        || event.authorization_ref.is_some()
        || event.applet_id.is_some()
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: cut.authority.realm_id.clone(),
            })
        || serde_json::to_value(&event.payload).map_err(invalid)?
            != serde_json::to_value(payload).map_err(invalid)?
        || commit.commit_id != authorization.source_commit_id
        || commit.event_ref != event.event_id
        || commit.realm_id != cut.authority.realm_id
        || row.value["position"].as_u64() != Some(commit.stream_position)
        || row.value["stream"] != serde_json::to_value(&commit.stream_ref).map_err(invalid)?
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: cut.authority.realm_id.clone(),
            })
    {
        return Err(invalid(
            "managed Device source Commit differs from accepted authorization",
        ));
    }
    let key = payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| invalid("managed Device has no accepted did:key"))?;
    let public_key = arkret_canonical::multibase::decode_ed25519_multibase(key).map_err(invalid)?;
    let expires_at = payload
        .expires_at
        .flatten()
        .ok_or_else(|| invalid("managed Device has no finite expiry"))?;
    Ok(Some(AppletManagedDeviceAuthority {
        account_id: account.clone(),
        device_id: device_id.clone(),
        selector: DeviceRevocationGateSelector {
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            device_id: device_id.as_str().to_owned(),
            authorization_ref: CommittedEventRef {
                event_id: event.event_id,
                commit_id: commit.commit_id,
                stream_ref: commit.stream_ref,
                stream_position: commit.stream_position,
            },
        },
        applet_id: applet_id.clone(),
        source_service_id: source.clone(),
        native_did: resolution.projection.did,
        pcr_realm_id: resolution.pcr_realm_id,
        current_device_generation_ref: payload.authorized_generation_ref,
        public_key,
        scopes: scopes.clone(),
        not_before: payload.not_before,
        expires_at,
    }))
}
