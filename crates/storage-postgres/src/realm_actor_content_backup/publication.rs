//! Fixed native PUT outcomes are independent of later business admission.

use arkret_models_crypto::{KeyBackup, RealmActorBackupPutResponseBody};
use arkret_wire::ScopeRef;
use coland_storage::{AppletManagedDeviceAuthority, PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text, Uuid};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

use crate::{AsyncPgConnection, PgPool, PgTransactionError, pg_conn};

pub(crate) async fn put_native(
    pool: &PgPool,
    backup: &KeyBackup,
    context: &coland_storage::RealmActorBackupPutContext,
    sign: coland_storage::RealmActorBackupAdmissionSigner<'_>,
) -> PersistenceResult<RealmActorBackupPutResponseBody> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        let endpoint = &context.endpoint;
        let actor = &endpoint.authority.actor_id;
        let scope = &endpoint.effective_scope;
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &endpoint.authority.realm_id).await?;
        if let Some(reply) = recover_in_connection(conn,backup,&endpoint.authority,scope,context.credential_expires_at,&context.idempotency_key).await? {
            return Ok(reply);
        }
        let revision = super::lock_namespace(conn,actor).await?;
        super::reading::require_authority_cut(conn,&context.authority).await?;
        let accepted_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        if context.credential_expires_at <= accepted_at
            || context.authority.realm_id() != &endpoint.authority.realm_id
            || context.authority.current_service_id() != &endpoint.authority.governance_service_id
            || context.authority.current_generation() != endpoint.authority.governance_generation
            || context.origin_resolution.service_id != endpoint.authority.governance_service_id
        {return Err(super::unavailable("native publication governance or transport cut changed").into());}
        let current = crate::realm_actor_device_authority::current_in_connection(
            conn,actor,&endpoint.authority.device_id,accepted_at,
        ).await?.ok_or_else(||super::unavailable("native publisher current Device is absent"))?;
        if current != endpoint.authority {return Err(super::unavailable("native publisher authorization changed").into());}
        let action = arkret_wire::CapabilityActionId::from_wire(
            arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1,
        ).ok_or_else(||super::unavailable("native publication action is not registered"))?;
        let (registration,installation) = crate::applet_device_admission::installation_for_device(
            conn,&current,scope,&endpoint.service_did_document,&[action],accepted_at,true,
        ).await?;
        crate::applet_e2ee::require_current_consent(conn,&registration,&installation,scope,accepted_at).await?;
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(conn,&current.realm_id,actor).await?;
        cut.require_native_backup_subject()?;
        if let ScopeRef::Circle{realm_id,circle_id}=scope {
            let basis=crate::circle_current_states::locked_circle_basis(conn,realm_id,circle_id).await?;
            if basis["value"]["state"]!="active"
                || !crate::circle_current_states::effective_member_in_connection(conn,realm_id,circle_id,actor).await?
            {return Err(super::unavailable("native publisher has no active exact Circle membership").into());}
        }
        require_publication_policy(conn,&registration,actor,scope,action,arkret_models_collaboration::governance::operation_wire::AppletPolicyOperation::Execute,accepted_at).await?;
        let preparation = super::prepare_input_in_connection(conn,&current,scope).await?;
        backup.validate_native_recipient(&preparation.input.content_backup_recipient).map_err(|error|PersistenceError::SchemaViolation(error.to_string()))?;
        let binding=backup.auth_binding.as_ref().ok_or_else(||super::unavailable("native packet binding absent"))?;
        if backup.series_id!=preparation.input.active_series_id
            || binding.manager_ref!=preparation.input.auth_binding.manager_ref
            || binding.recovery_ref!=preparation.input.auth_binding.recovery_ref
            || binding.recipient_ref!=preparation.input.auth_binding.recipient_ref
            || binding.device_generation!=preparation.input.auth_binding.device_generation
            || backup.encryption.recipient_key_ref.as_ref().map(|reference|reference.as_str())
                !=Some(preparation.input.content_backup_recipient.key_agreement_ref.as_str())
        {return Err(super::unavailable("native packet does not echo the exact current prepare input").into());}
        let witness=crate::key_backup_authority::verify_realm_device_backup_signature(backup,&current,accepted_at)?;
        let root=backup.contents.first().and_then(|entry|entry.root_context.as_ref())
            .ok_or_else(||super::unavailable("native packet root context is absent"))?;
        let key=crate::mls_group_current_states::scope_key(scope)?;
        let group=crate::mls_group_current_states::locked_group(conn,&key).await?
            .ok_or_else(||super::unavailable("native publisher has no accepted MLS group"))?;
        if root.effective_scope!=*scope || root.epoch!=group.value.epoch
            || root.group_state_ref!=group.value.current_mls_commit_event_ref
            || group.value.current_key_access_revision!=group.value.covered_key_access_revision
            || crate::mls_group_current_states::circle_tree_holds_invalid_leaf(conn,scope,&group).await?
        {return Err(PersistenceError::Conflict("epoch_update_required: native root basis is not current".into()).into());}
        crate::content_endpoint_bindings::native_backup_endpoint_in_connection(conn,&current,&group.value).await?;
        let genesis=crate::committed_disclosure::accepted_full_event_in_connection(conn,&current.realm_id.event_id()).await?
            .ok_or_else(||super::unavailable("native publisher Realm Genesis original is absent"))?;
        crate::content_dependencies::validate_root_basis(conn,root,&group.value,&genesis.event).await?;
        let authority_ref = context.governance_history.authority_transitions.last()
            .map(|transition|arkret_wire::RealmCommitAuthorityRef::Handoff(transition.handoff.handoff_id.clone()))
            .unwrap_or_else(||arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(context.governance_history.genesis.event.event_id.clone()));
        let input=arkret_models_crypto::RealmActorContentBackupAdmissionSignatureInput{
            backup_id:backup.backup_id.clone(),
            envelope_digest:arkret_wire::Hash::new(arkret_canonical::canonical_sha256(backup).map_err(PersistenceError::database)?).map_err(PersistenceError::database)?,
            ciphertext_digest:backup.ciphertext_digest.clone(),
            realm_actor_id:current.actor_id.as_realm_actor_id().ok_or_else(||super::unavailable("native actor absent"))?.clone(),
            effective_scope:scope.clone(),device_id:current.device_id.clone(),device_authorize_ref:current.authorization_ref.clone(),
            device_generation:current.current_device_generation_ref,
            device_public_key_base64url:arkret_canonical::base64url_encode(current.public_key),
            manager_ref:binding.manager_ref.clone(),recovery_ref:binding.recovery_ref.clone(),recipient_ref:binding.recipient_ref.clone(),
            accepted_at,service_id:current.governance_service_id.clone(),governance_generation:current.governance_generation,authority_ref,
        };
        let admission=sign(input.clone())?;
        if arkret_canonical::canonical_json_bytes(&arkret_signatures::realm_actor_content_backup::admission_signing_input(&admission).map_err(PersistenceError::database)?).map_err(PersistenceError::database)?
            !=arkret_canonical::canonical_json_bytes(&input).map_err(PersistenceError::database)?
        {return Err(super::unavailable("native admission signer changed its original input").into());}
        let source=arkret_models_integration::RealmActorContentBackupSource{
            admission:admission.clone(),device_authorization:super::original_material(conn,&current.authorization_ref).await?,
            origin_resolution:context.origin_resolution.clone(),governance_history:context.governance_history.clone(),
        };
        arkret_identity::realm_actor_content_backup::verify_realm_actor_content_backup_source(backup,&source,&context.authority)
            .map_err(PersistenceError::database)?;
        crate::key_backup::put_key_backup_in_connection(conn,backup.backup_id.as_str(),&json!(backup),&witness).await?;
        let reply=RealmActorBackupPutResponseBody{status:arkret_models_crypto::KeyBackupPutStatus::Accepted,backup_id:backup.backup_id.clone(),ciphertext_digest:backup.ciphertext_digest.clone(),admission};
        sql_query("INSERT INTO realm_actor_backup_admissions(backup_id,realm_id,actor_id,effective_scope,envelope_digest,device_id,device_authorize_event_id,device_generation,idempotency_key,source,fixed_reply,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
            .bind::<Uuid,_>(crate::ids::typed_uuid_part_expect_internal(backup.backup_id.as_str()))
            .bind::<Text,_>(current.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(json!(scope))
            .bind::<Text,_>(reply.admission.envelope_digest.as_str()).bind::<Text,_>(current.device_id.as_str())
            .bind::<Text,_>(current.authorization_ref.event_id.as_str()).bind::<diesel::sql_types::BigInt,_>(i64::try_from(current.current_device_generation_ref).map_err(PersistenceError::database)?)
            .bind::<Text,_>(&context.idempotency_key).bind::<Jsonb,_>(json!(source)).bind::<Jsonb,_>(json!(reply)).bind::<diesel::sql_types::Timestamptz,_>(accepted_at)
            .execute(&mut *conn).await?;
        require_storage_budget(conn,actor,&current.realm_id,context.max_actor_bytes,context.max_realm_bytes).await?;
        let final_at=chrono::Utc::now();
        let (registration,installation)=crate::applet_device_admission::installation_for_device(conn,&current,scope,&endpoint.service_did_document,&[action],final_at,true).await?;
        crate::applet_e2ee::require_current_consent(conn,&registration,&installation,scope,final_at).await?;
        require_publication_policy(conn,&registration,actor,scope,action,arkret_models_collaboration::governance::operation_wire::AppletPolicyOperation::Execute,final_at).await?;
        if chrono::Utc::now()>=context.credential_expires_at || chrono::Utc::now()>=current.expires_at {
            return Err(super::unavailable("native publisher credential expired before durable admission").into());
        }
        super::advance_revision(conn,actor,revision).await?;
        Ok(reply)
    }).await.map_err(PgTransactionError::into_persistence)
}

pub(super) async fn require_publication_policy(
    conn: &mut AsyncPgConnection,
    registration: &arkret_models_integration::AppletRegistrationPayload,
    actor: &arkret_wire::ActorId,
    scope: &ScopeRef,
    action: arkret_wire::CapabilityActionId,
    operation: arkret_models_collaboration::governance::operation_wire::AppletPolicyOperation,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::operation_wire::{
        PolicyResourceKind, PolicyResourceSelector,
    };
    let policies =
        crate::policy_current_states::read_scoped_applet_management_policies_in_connection(
            conn,
            scope.realm_id(),
            scope.circle_id(),
        )
        .await?;
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(scope.realm_id().clone()),
        resource_ref: Some(scope.realm_id().to_string()),
    }];
    if let Some(circle) = scope.circle_id() {
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(scope.realm_id().clone()),
            resource_ref: Some(circle.to_string()),
        });
    }
    let service = arkret_wire::ActorId::service(registration.service_id.clone());
    let decision = arkret_policy::applet_management::select_applet_management(
        Some(&policies),
        &arkret_policy::applet_management::AppletManagementContext {
            device_control: None,
            realm_id: scope.realm_id(),
            requester_actor_id: &service,
            applet_id: &registration.applet_id,
            service_id: &registration.service_id,
            effective_scope: scope,
            managed_actor_id: Some(actor),
            operation,
            content_action: Some(action),
            resources: Some(&resources),
            at,
        },
    )
    .map_err(PersistenceError::database)?;
    if matches!(
        decision.effect,
        arkret_wire::PolicyEffect::Deny | arkret_wire::PolicyEffect::Quarantine
    ) || !decision.review_requirements.is_empty()
    {
        return Err(PersistenceError::Conflict(
            "capability_denied: current management policy has not admitted native root publication"
                .into(),
        ));
    }
    Ok(())
}

async fn require_storage_budget(
    conn: &mut AsyncPgConnection,
    actor: &arkret_wire::ActorId,
    realm: &arkret_wire::RealmId,
    max_actor_bytes: u64,
    max_realm_bytes: u64,
) -> PersistenceResult<()> {
    #[derive(QueryableByName)]
    struct Usage {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        actor_bytes: i64,
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        realm_bytes: i64,
    }
    let usage=sql_query("SELECT COALESCE(SUM(pg_column_size(b.payload)+pg_column_size(a.source)) FILTER (WHERE a.actor_id=$2),0)::bigint AS actor_bytes,COALESCE(SUM(pg_column_size(b.payload)+pg_column_size(a.source)),0)::bigint AS realm_bytes FROM realm_actor_backup_admissions a JOIN key_backups b ON b.id=a.backup_id WHERE a.realm_id=$1")
        .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!(actor)).get_result::<Usage>(conn).await.map_err(PersistenceError::database)?;
    if u64::try_from(usage.actor_bytes).map_err(PersistenceError::database)? > max_actor_bytes
        || u64::try_from(usage.realm_bytes).map_err(PersistenceError::database)? > max_realm_bytes
    {
        return Err(PersistenceError::Conflict(
            "quota_exceeded: native archive storage budget exceeded".into(),
        ));
    }
    Ok(())
}

#[derive(QueryableByName)]
struct Original {
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Text)]
    envelope_digest: String,
}

#[derive(QueryableByName)]
struct Outcome {
    #[diesel(sql_type = Jsonb)]
    effective_scope: Value,
    #[diesel(sql_type = Jsonb)]
    fixed_reply: Value,
}

fn refused(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("duplicate_conflict: {detail}"))
}

pub(crate) async fn recover_put(
    pool: &PgPool,
    backup: &KeyBackup,
    credential: &AppletManagedDeviceAuthority,
    effective_scope: &ScopeRef,
    credential_expires_at: chrono::DateTime<chrono::Utc>,
    idempotency_key: &str,
) -> PersistenceResult<Option<RealmActorBackupPutResponseBody>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &credential.realm_id)
            .await?;
        recover_in_connection(
            conn,
            backup,
            credential,
            effective_scope,
            credential_expires_at,
            idempotency_key,
        )
        .await
        .map_err(Into::into)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(super) async fn recover_in_connection(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
    credential: &AppletManagedDeviceAuthority,
    effective_scope: &ScopeRef,
    credential_expires_at: chrono::DateTime<chrono::Utc>,
    idempotency_key: &str,
) -> PersistenceResult<Option<RealmActorBackupPutResponseBody>> {
    let now = chrono::Utc::now();
    let action = arkret_wire::CapabilityActionId::from_wire(
        arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1,
    )
    .ok_or_else(|| super::unavailable("native PUT action is not registered"))?;
    if credential_expires_at <= now
        || backup.actor_id != credential.actor_id
        || effective_scope.realm_id_opt() != Some(&credential.realm_id)
        || !credential.scopes.permits(effective_scope, &[action])
    {
        return Err(PersistenceError::Conflict(
            "device_unauthorized: original native PUT credential differs".into(),
        ));
    }
    let actual = crate::realm_actor_device_authority::backup_put_credential_in_connection(
        conn,
        &credential.actor_id,
        &credential.device_id,
        now,
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    .ok_or_else(|| refused("native PUT Device credential is absent"))?;
    if &actual != credential {
        return Err(PersistenceError::Conflict(
            "device_unauthorized: original native PUT Device changed".into(),
        ));
    }
    super::lock_namespace(conn, &credential.actor_id).await?;
    if idempotency_key.is_empty() || idempotency_key.len() > 128 {
        return Err(refused("native PUT idempotency key is absent or overlong"));
    }
    #[derive(QueryableByName)]
    struct ExistingKey {
        #[diesel(sql_type=Text)]
        envelope_digest: String,
    }
    let keyed=sql_query("SELECT envelope_digest FROM realm_actor_backup_admissions WHERE actor_id=$1 AND idempotency_key=$2 FOR SHARE")
        .bind::<Jsonb,_>(json!(credential.actor_id)).bind::<Text,_>(idempotency_key)
        .get_result::<ExistingKey>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let complete_digest =
        arkret_canonical::canonical_sha256(backup).map_err(PersistenceError::database)?;
    if keyed.is_some_and(|existing| existing.envelope_digest != complete_digest) {
        return Err(refused(
            "native PUT idempotency key already binds another complete signed original",
        ));
    }
    let id = crate::ids::typed_uuid_part_expect_internal(backup.backup_id.as_str());
    let Some(original) = sql_query(
        "SELECT actor_id,envelope_digest FROM key_backup_identities WHERE id=$1 FOR SHARE",
    )
    .bind::<Uuid, _>(id)
    .get_result::<Original>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(None);
    };
    if original.actor_id != credential.actor_id.to_string()
        || original.envelope_digest
            != arkret_canonical::canonical_sha256(backup).map_err(PersistenceError::database)?
    {
        return Err(refused(
            "backup identity already binds another complete signed original",
        ));
    }
    let row = sql_query("SELECT effective_scope,fixed_reply FROM realm_actor_backup_admissions WHERE backup_id=$1 AND realm_id=$2 AND actor_id=$3 FOR SHARE")
        .bind::<Uuid,_>(id).bind::<Text,_>(credential.realm_id.as_str())
        .bind::<Jsonb,_>(json!(credential.actor_id)).get_result::<Outcome>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||refused("native identity is missing its durable admission outcome"))?;
    let reply: RealmActorBackupPutResponseBody =
        serde_json::from_value(row.fixed_reply).map_err(PersistenceError::database)?;
    if row.effective_scope != json!(effective_scope)
        || reply.admission.device_id != credential.device_id
        || reply.admission.device_authorize_ref != credential.authorization_ref
        || reply.admission.device_generation != credential.current_device_generation_ref
    {
        return Err(PersistenceError::Conflict("device_unauthorized: native fixed outcome belongs to another original requester or scope".into()));
    }
    arkret_signatures::realm_actor_content_backup::verify_realm_actor_backup_packet(
        backup,
        &reply.admission,
    )
    .map_err(PersistenceError::database)?;
    let retained =
        crate::content_root_packages::read_retained_envelope(conn, &backup.backup_id).await?;
    if arkret_canonical::canonical_json_bytes(&retained).map_err(PersistenceError::database)?
        != arkret_canonical::canonical_json_bytes(backup).map_err(PersistenceError::database)?
        || reply.backup_id != backup.backup_id
        || reply.ciphertext_digest != backup.ciphertext_digest
    {
        return Err(refused(
            "native fixed outcome differs from physical ciphertext custody",
        ));
    }
    Ok(Some(reply))
}
