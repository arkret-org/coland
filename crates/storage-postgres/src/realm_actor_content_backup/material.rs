//! Station-local verification before supplying the two public native selectors.

use arkret_models_collaboration::RealmActorKeyBackupActiveSeriesValue;
use arkret_models_collaboration::events_payloads::{
    KeyBackupActiveSeries, validate_key_backup_active_series_record,
};
use arkret_models_crypto::{
    ContentBackupNextPrepareInput, RealmActorBackupAuthBinding, RealmActorBackupAuthBindingKind,
};
use arkret_models_integration::{RealmActorManagerValue, RealmActorRecoveryValue};
use arkret_wire::{CommittedEventRef, CurrentSelector, ScopeRef};
use coland_storage::{AppletManagedDeviceAuthority, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

use super::{AsyncPgConnection, unavailable};

#[derive(QueryableByName)]
struct SeriesRow {
    #[diesel(sql_type = Jsonb)]
    record: Value,
    #[diesel(sql_type = Jsonb)]
    source: Value,
}

pub(crate) struct NativeBackupPreparation {
    pub input: ContentBackupNextPrepareInput,
    pub record: KeyBackupActiveSeries,
    pub selection_ref: CommittedEventRef,
}

/// The parent Realm lock keeps all reads at one accepted cut. The complete
/// private originals stay inside the Station; only the final typed input and
/// five-field series projection can leave through a Device response.
pub(crate) async fn prepare_input_in_connection(
    conn: &mut AsyncPgConnection,
    authority: &AppletManagedDeviceAuthority,
    scope: &ScopeRef,
) -> PersistenceResult<NativeBackupPreparation> {
    let actor = &authority.actor_id;
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| unavailable("native backup material requires a Realm actor"))?;
    arkret_models_crypto::validate_realm_actor_backup_scope(subject, scope).map_err(unavailable)?;
    if !authority.scopes.contains_scope(scope) {
        return Err(unavailable(
            "native backup scope is outside original Device authorization",
        ));
    }
    let (manager, manager_ref) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!(CurrentSelector::RealmActorManager {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let manager: RealmActorManagerValue = serde_json::from_value(manager).map_err(unavailable)?;
    if manager.binding_ref != manager_ref || manager.service_id != authority.source_service_id {
        return Err(unavailable(
            "native backup manager source differs from the current Device",
        ));
    }
    let (recovery, recovery_ref) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!(CurrentSelector::RealmActorRecovery {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let recovery: RealmActorRecoveryValue =
        serde_json::from_value(recovery).map_err(unavailable)?;
    if recovery.pending.is_some() {
        return Err(unavailable(
            "native backup preparation is fenced by recovery",
        ));
    }
    super::require_recipient_original(
        conn,
        actor,
        &recovery.content_backup_recipient_ref,
        &recovery.content_backup_recipient,
    )
    .await?;
    let selector = CurrentSelector::RealmActorKeyBackupActiveSeries {
        actor_id: actor.clone(),
        effective_scope: scope.clone(),
        backup_kind: arkret_wire::RealmActorBackupKind::SecretStorage,
    };
    let (public, selection_ref) =
        crate::realm_actor_control::current_source(conn, actor, json!(selector)).await?;
    let public: RealmActorKeyBackupActiveSeriesValue =
        serde_json::from_value(public).map_err(unavailable)?;
    if public.manager_ref != manager_ref
        || public.recipient_ref != recovery.content_backup_recipient_ref
    {
        return Err(unavailable(
            "native series must use the current manager and recipient",
        ));
    }
    let row = sql_query("SELECT record,source FROM realm_actor_backup_series WHERE realm_id=$1 AND actor_id=$2 AND effective_scope=$3 AND series_pointer_version=$4 AND active_series_id=$5 FOR SHARE")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor))
        .bind::<Jsonb,_>(json!(scope)).bind::<BigInt,_>(i64::try_from(public.series_pointer_version).map_err(unavailable)?)
        .bind::<Text,_>(public.active_series_id.as_str()).get_result::<SeriesRow>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)?.ok_or_else(||unavailable("native series original is absent"))?;
    let record: KeyBackupActiveSeries = serde_json::from_value(row.record).map_err(unavailable)?;
    validate_key_backup_active_series_record(&record).map_err(unavailable)?;
    let source = super::original_material(conn, &selection_ref).await?;
    if json!(source) != row.source
        || json!(source.event.payload) != json!(record)
        || record.actor_id != *actor
        || record.effective_scope.as_ref() != Some(scope)
        || record.manager_ref.as_ref() != Some(&public.manager_ref)
        || record.recovery_ref.as_ref() != Some(&public.recovery_ref)
        || record.recipient_ref.as_ref() != Some(&public.recipient_ref)
        || record.active_series_id != public.active_series_id
        || record.series_pointer_version != public.series_pointer_version
    {
        return Err(unavailable(
            "native series projection and immutable selection original differ",
        ));
    }
    // The current request binds today's Recovery source. The immutable series
    // keeps the accepted source at selection; an enabled-only/no-op source
    // advance with unchanged manager/recipient does not rotate this series.
    let input = ContentBackupNextPrepareInput {
        auth_binding: RealmActorBackupAuthBinding {
            kind: RealmActorBackupAuthBindingKind::Value,
            manager_ref,
            recovery_ref,
            recipient_ref: recovery.content_backup_recipient_ref,
            device_generation: authority.current_device_generation_ref,
        },
        content_backup_recipient: recovery.content_backup_recipient,
        active_series_id: record.active_series_id.clone(),
    };
    input.validate().map_err(unavailable)?;
    Ok(NativeBackupPreparation {
        input,
        record,
        selection_ref,
    })
}
