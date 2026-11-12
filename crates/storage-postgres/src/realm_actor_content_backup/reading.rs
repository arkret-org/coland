//! Native predecessor and manager inventory have disjoint disclosure bounds.

use arkret_models_crypto::{
    BackupActiveSeriesPointer, RealmActorBackupActiveSeriesState, RealmActorBackupHeadEntry,
    RealmActorBackupMetadata, RealmActorBackupSeriesHeadResponseBody,
    RealmActorBackupSeriesHeadResponseBodyPurpose,
};
use arkret_models_integration::{RealmActorManagerValue, RealmActorRecoveryValue};
use arkret_wire::ActorId;
use coland_storage::{
    PersistenceResult, RealmActorBackupManagerReader, RealmActorBackupPutContext,
};
use diesel::sql_types::{Jsonb, Text, Uuid};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

use super::{AsyncPgConnection, PersistenceError, unavailable};
use crate::{PgPool, PgTransactionError};

pub(crate) struct NativeDelivery {
    held: Box<crate::account_content_delivery::DeliveryGuard>,
    expires_at: chrono::DateTime<chrono::Utc>,
    reader: coland_storage::RealmActorBackupReader,
    action: &'static str,
    expected_head: Option<arkret_wire::BackupId>,
}

impl NativeDelivery {
    pub(crate) fn new(
        held: Box<crate::account_content_delivery::DeliveryGuard>,
        reader: coland_storage::RealmActorBackupReader,
        action: &'static str,
        expected_head: Option<arkret_wire::BackupId>,
    ) -> Box<dyn coland_storage::AccountContentDeliveryGuard> {
        let expires_at = match &reader {
            coland_storage::RealmActorBackupReader::Device(context) => context
                .credential_expires_at
                .min(context.endpoint.authority.expires_at),
            coland_storage::RealmActorBackupReader::Manager(reader) => reader.transport_expires_at,
        };
        Box::new(Self {
            held,
            expires_at,
            reader,
            action,
            expected_head,
        })
    }
}

#[async_trait::async_trait]
impl coland_storage::AccountContentDeliveryGuard for NativeDelivery {
    fn permits_handoff(&self) -> bool {
        chrono::Utc::now() < self.expires_at
    }
    async fn prepare_handoff(&mut self) -> bool {
        if chrono::Utc::now() >= self.expires_at {
            return false;
        }
        let valid = match &self.reader {
            coland_storage::RealmActorBackupReader::Device(context) => {
                match head_for_action(self.held.connection(), context, self.action).await {
                    Ok(head) => {
                        head.items.first().map(|entry| &entry.metadata.backup_id)
                            == self.expected_head.as_ref()
                    }
                    Err(_) => false,
                }
            }
            coland_storage::RealmActorBackupReader::Manager(reader) => {
                qualify_manager(self.held.connection(), reader)
                    .await
                    .is_ok()
            }
        };
        valid && self.held.probe().await.is_ok() && chrono::Utc::now() < self.expires_at
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        coland_storage::AccountContentDeliveryGuard::finish(self.held).await
    }
}

pub(crate) async fn require_authority_cut(
    conn: &mut AsyncPgConnection,
    authority: &arkret_identity::VerifiedRealmAuthority,
) -> PersistenceResult<()> {
    #[derive(QueryableByName)]
    struct Cut {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        generation: i64,
        #[diesel(sql_type=Text)]
        service_id: String,
    }
    let cut = sql_query(
        "SELECT generation,service_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(authority.realm_id().as_str())
    .get_result::<Cut>(conn)
    .await
    .map_err(PersistenceError::database)?;
    if u64::try_from(cut.generation).map_err(unavailable)? != authority.current_generation()
        || cut.service_id != authority.current_service_id().as_str()
    {
        return Err(unavailable(
            "native backup independently verified governance cut changed",
        ));
    }
    Ok(())
}

#[derive(QueryableByName)]
struct PacketRow {
    #[diesel(sql_type=Uuid)]
    id: uuid::Uuid,
    #[diesel(sql_type=Jsonb)]
    source: Value,
    #[diesel(sql_type=Jsonb)]
    metadata: Value,
}

pub(crate) async fn qualify_manager(
    conn: &mut AsyncPgConnection,
    reader: &RealmActorBackupManagerReader,
) -> PersistenceResult<(
    arkret_wire::CommittedEventRef,
    arkret_wire::CommittedEventRef,
)> {
    let actor = ActorId::realm(reader.actor.clone());
    require_authority_cut(conn, &reader.authority).await?;
    if chrono::Utc::now() >= reader.transport_expires_at
        || reader.authority.realm_id() != &reader.actor.realm_id
    {
        return Err(unavailable("native archive transport or authority expired"));
    }
    crate::realm_actor_control::require_current_governor(
        conn,
        &reader.actor.realm_id,
        reader.authority.current_service_id(),
    )
    .await?;
    crate::realm_management_archive::require_unfrozen(conn, &reader.actor.realm_id).await?;
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &reader.actor.realm_id,
        &actor,
    )
    .await?;
    cut.require_native_archive_lifecycle()?;
    let creation = crate::realm_actor_control::creation_source(conn, &actor).await?;
    let registration = crate::managed_message_actor::registration_for_scope(
        conn,
        &reader.actor.realm_id,
        &creation.applet_id,
        &reader.service_id,
    )
    .await?;
    if registration.webhook_signature_policy.key_ref != reader.verification_method {
        return Err(unavailable(
            "native archive Service method differs from current registration",
        ));
    }
    registration
        .manifest
        .registration_epoch_evidence
        .validate_against_did_document(&reader.service_did_document)
        .map_err(unavailable)?;
    arkret_identity::validate_verification_method_relationship(
        &reader.service_did_document,
        &reader.verification_method,
        &reader.service_did_document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(unavailable)?;
    let (manager, manager_ref) = crate::realm_actor_control::current_source(
        conn,
        &actor,
        json!(arkret_wire::CurrentSelector::RealmActorManager {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let manager: RealmActorManagerValue = serde_json::from_value(manager).map_err(unavailable)?;
    if manager.binding_ref != manager_ref || manager.service_id != reader.service_id {
        return Err(unavailable(
            "native archive requester is no longer the exact current manager",
        ));
    }
    for gate in [
        arkret_wire::RealmActorStatusGate::Owner,
        arkret_wire::RealmActorStatusGate::Governance,
    ] {
        let (status, _) = crate::realm_actor_control::current_source(
            conn,
            &actor,
            json!(arkret_wire::CurrentSelector::RealmActorStatus {
                actor_id: actor.clone(),
                gate
            }),
        )
        .await?;
        if status == "retired" {
            return Err(unavailable(
                "retired actor has no native archive maintenance authority",
            ));
        }
    }
    let (recovery, recovery_ref) = crate::realm_actor_control::current_source(
        conn,
        &actor,
        json!(arkret_wire::CurrentSelector::RealmActorRecovery {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let _: RealmActorRecoveryValue = serde_json::from_value(recovery).map_err(unavailable)?;
    Ok((manager_ref, recovery_ref))
}

pub(crate) async fn head_in_connection(
    conn: &mut AsyncPgConnection,
    context: &RealmActorBackupPutContext,
) -> PersistenceResult<RealmActorBackupSeriesHeadResponseBody> {
    head_for_action(
        conn,
        context,
        arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
    )
    .await
}

pub(crate) async fn head_for_action(
    conn: &mut AsyncPgConnection,
    context: &RealmActorBackupPutContext,
    operation: &str,
) -> PersistenceResult<RealmActorBackupSeriesHeadResponseBody> {
    let endpoint = &context.endpoint;
    require_authority_cut(conn, &context.authority).await?;
    let actor = &endpoint.authority.actor_id;
    let scope = &endpoint.effective_scope;
    if chrono::Utc::now() >= context.credential_expires_at {
        return Err(unavailable("native predecessor transport expired"));
    }
    let current = crate::realm_actor_device_authority::current_in_connection(
        conn,
        actor,
        &endpoint.authority.device_id,
        chrono::Utc::now(),
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    .ok_or_else(|| unavailable("native predecessor Device unavailable"))?;
    let action = arkret_wire::CapabilityActionId::from_wire(operation)
        .ok_or_else(|| unavailable("native predecessor action is not registered"))?;
    if current != endpoint.authority || !current.scopes.permits(scope, &[action]) {
        return Err(unavailable(
            "native predecessor original Device or exact scope changed",
        ));
    }
    let (registration, installation) = crate::applet_device_admission::installation_for_device(
        conn,
        &current,
        scope,
        &endpoint.service_did_document,
        &[action],
        chrono::Utc::now(),
        false,
    )
    .await?;
    crate::applet_e2ee::require_current_consent(
        conn,
        &registration,
        &installation,
        scope,
        chrono::Utc::now(),
    )
    .await?;
    for operation in [
        arkret_models_collaboration::governance::operation_wire::AppletPolicyOperation::Read,
        arkret_models_collaboration::governance::operation_wire::AppletPolicyOperation::Deliver,
    ] {
        super::publication::require_publication_policy(
            conn,
            &registration,
            actor,
            scope,
            action,
            operation,
            chrono::Utc::now(),
        )
        .await?;
    }
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, &current.realm_id, actor)
            .await?;
    cut.require_open_content_read()?;
    if let arkret_wire::ScopeRef::Circle {
        realm_id,
        circle_id,
    } = scope
    {
        if !crate::circle_current_states::joined_member_for_content_read_in_connection(
            conn, realm_id, circle_id, actor,
        )
        .await?
        {
            return Err(unavailable("native predecessor Circle membership changed"));
        }
    }
    let preparation = super::prepare_input_in_connection(conn, &current, scope).await?;
    let record = &preparation.record;
    let row=sql_query("SELECT b.id,a.source,key_backup_list_metadata(b.payload) AS metadata FROM key_backups b JOIN realm_actor_backup_admissions a ON a.backup_id=b.id WHERE a.realm_id=$1 AND a.actor_id=$2 AND a.effective_scope=$3 AND b.payload->>'series_id'=$4 ORDER BY (b.payload->>'series_sequence')::bigint DESC LIMIT 1 FOR SHARE OF b,a")
        .bind::<Text,_>(current.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(json!(scope))
        .bind::<Text,_>(record.active_series_id.as_str()).get_result::<PacketRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let mut items = Vec::new();
    if let Some(row) = row {
        let backup = crate::content_root_packages::read_retained_envelope(
            conn,
            &arkret_wire::BackupId::new(format!("ak:backup:{}", row.id)).map_err(unavailable)?,
        )
        .await?;
        let source: arkret_models_integration::RealmActorContentBackupSource =
            serde_json::from_value(row.source).map_err(unavailable)?;
        arkret_identity::realm_actor_content_backup::verify_realm_actor_content_backup_source(
            &backup,
            &source,
            &context.authority,
        )
        .map_err(unavailable)?;
        let metadata: RealmActorBackupMetadata =
            serde_json::from_value(row.metadata).map_err(unavailable)?;
        if metadata.backup_id != backup.backup_id
            || metadata.ciphertext_digest != backup.ciphertext_digest
        {
            return Err(unavailable(
                "native predecessor metadata differs from retained original",
            ));
        }
        items.push(RealmActorBackupHeadEntry {
            metadata,
            admission: source.admission,
        });
    }
    Ok(RealmActorBackupSeriesHeadResponseBody {
        purpose: RealmActorBackupSeriesHeadResponseBodyPurpose::Value,
        realm_actor_id: actor
            .as_realm_actor_id()
            .ok_or_else(|| unavailable("native predecessor actor absent"))?
            .clone(),
        effective_scope: scope.clone(),
        active_series: RealmActorBackupActiveSeriesState {
            realm_actor_id: actor
                .as_realm_actor_id()
                .ok_or_else(|| unavailable("native actor absent"))?
                .clone(),
            effective_scope: scope.clone(),
            manager_ref: preparation.input.auth_binding.manager_ref,
            recovery_ref: preparation.input.auth_binding.recovery_ref,
            recipient_ref: preparation.input.auth_binding.recipient_ref,
            authority_commit_id: preparation.selection_ref.commit_id,
            secret_storage: BackupActiveSeriesPointer::Active {
                active_series_id: record.active_series_id.clone(),
                series_pointer_version: record.series_pointer_version,
            },
        },
        items,
    })
}

pub(crate) async fn native_head(
    pool: &PgPool,
    context: &RealmActorBackupPutContext,
) -> PersistenceResult<(
    RealmActorBackupSeriesHeadResponseBody,
    Box<dyn coland_storage::AccountContentDeliveryGuard>,
)> {
    let mut held = crate::account_content_delivery::DeliveryGuard::begin(pool).await?;
    let value = {
        let conn = held.connection();
        crate::realm_authorization_cut::lock_realm_authorization_cut(
            conn,
            &context.endpoint.authority.realm_id,
        )
        .await?;
        super::lock_namespace(conn, &context.endpoint.authority.actor_id).await?;
        head_in_connection(conn, context).await?
    };
    let expected_head = value
        .items
        .first()
        .map(|entry| entry.metadata.backup_id.clone());
    Ok((
        value,
        NativeDelivery::new(
            held,
            coland_storage::RealmActorBackupReader::Device(Box::new(context.clone())),
            arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
            expected_head,
        ),
    ))
}

pub(crate) async fn native_inventory(
    pool: &PgPool,
    reader: &RealmActorBackupManagerReader,
) -> PersistenceResult<arkret_models_integration::RealmActorArchiveInventoryManifest> {
    let mut held = crate::account_content_delivery::DeliveryGuard::begin(pool).await?;
    let manifest = {
        let conn = held.connection();
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &reader.actor.realm_id)
            .await?;
        qualify_manager(conn, reader).await?;
        let manifest =
            super::inventory_in_connection(conn, &ActorId::realm(reader.actor.clone())).await?;
        arkret_identity::realm_actor_content_backup::verify_realm_actor_archive_inventory(
            &manifest,
            &reader.authority,
            &reader.authority_keys,
        )
        .map_err(unavailable)?;
        qualify_manager(conn, reader).await?;
        manifest
    };
    coland_storage::AccountContentDeliveryGuard::finish(held).await?;
    Ok(manifest)
}

/// Cursor persistence uses its own transaction before this final acquisition.
/// Holding a namespace while waiting for another pooled connection would let
/// concurrent page requests exhaust the pool behind the same row lock.
pub(crate) async fn native_inventory_delivery(
    pool: &PgPool,
    reader: &RealmActorBackupManagerReader,
    manifest: &arkret_models_integration::RealmActorArchiveInventoryManifest,
) -> PersistenceResult<Box<dyn coland_storage::AccountContentDeliveryGuard>> {
    let mut held = crate::account_content_delivery::DeliveryGuard::begin(pool).await?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(
        held.connection(),
        &reader.actor.realm_id,
    )
    .await?;
    let (manager, _) = qualify_manager(held.connection(), reader).await?;
    let revision =
        super::lock_namespace(held.connection(), &ActorId::realm(reader.actor.clone())).await?;
    if manifest.realm_actor_id != reader.actor
        || manifest.manager_ref != manager
        || manifest.archive_revision != revision
    {
        return Err(unavailable(
            "native archive cut changed before physical page delivery",
        ));
    }
    Ok(NativeDelivery::new(
        held,
        coland_storage::RealmActorBackupReader::Manager(Box::new(reader.clone())),
        arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
        None,
    ))
}
