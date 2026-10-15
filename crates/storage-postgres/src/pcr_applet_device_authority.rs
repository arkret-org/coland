//! Accepted managed Device identity from one confirmed, repeatable-read cut.

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizationScopes,
};
use arkret_wire::{AccountId, ActorId, CommittedEventRef, DeviceId, Event, RealmCommit};
use coland_storage::{
    AppletManagedDeviceAuthority, DeviceRevocationGateSelector, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
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
