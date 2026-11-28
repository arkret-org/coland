use super::*;

/// The initial root belongs to the Agent but is generated and signed by its
/// currently authorized controller Device, before a runtime needs to exist.
pub(crate) async fn put_controller(
    pool: &PgPool,
    owner: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
    backup: &KeyBackup,
    token: &str,
) -> PersistenceResult<KeysBackupsReplaceResponseBody> {
    backup
        .validate()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let now = Utc::now();
    let actor = backup.actor_id.as_account_id().ok_or_else(denied)?;
    if actor == owner
        || actor.station_id != owner.station_id
        || backup
            .custodian_actor_id
            .as_ref()
            .and_then(ActorId::as_account_id)
            != Some(owner)
        || backup
            .signature_proof
            .agent_authorization_event_ref
            .is_some()
        || backup.signature_proof.device_id.as_ref() != Some(device)
        || backup.encryption.recipient_method != KeyBackupRecipientMethod::RecoveryPublicKey
    {
        return Err(denied());
    }
    let mut held = DeliveryGuard::begin(pool).await?;
    let conn = held.connection();
    let owner_pcr = crate::morph_projection_reads::human_realm_in_connection(conn, owner).await?;
    crate::pcr_private_authority::require_active_human_account(conn, owner).await?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &owner_pcr).await?;
    if !crate::sidecar_access::is_owning_station_in_connection(conn, owner).await? {
        return Err(denied());
    }
    let first = backup
        .contents
        .first()
        .and_then(|i| i.root_context.as_ref())
        .ok_or_else(denied)?;
    let ScopeRef::Realm { realm_id: pcr } = &first.effective_scope else {
        return Err(denied());
    };
    let (controller_pcr, provision, reference) =
        crate::agent_provisioning::declared_agent_provision_in_connection(conn, pcr)
            .await
            .map_err(PgTransactionError::into_persistence)?
            .ok_or_else(denied)?;
    if controller_pcr != owner_pcr
        || provision.agent_id != actor.principal_id
        || provision.controller_principal_id != owner.principal_id
        || provision.principal_control_realm_id != *pcr
        || provision.history_custody.custodian_actor_id != ActorId::account(owner.clone())
        || backup.custody_authorization_ref.as_ref() != Some(&reference.event_id)
        || backup.recovery_policy_ref.as_ref()
            != Some(&provision.history_custody.recovery_policy_ref)
        || backup.encryption.recipient_key_ref.as_deref()
            != Some(provision.history_custody.recipient_key_ref.as_str())
        || crate::agent_interaction_current_states::owned_provenance_in_connection(
            conn, actor, owner, now, true,
        )
        .await?
        .is_none()
    {
        return Err(denied());
    }
    let pointer =
        crate::key_backup_current_states::confirmed_key_backup_pointer_in_connection(conn, actor)
            .await?
            .ok_or_else(denied)?;
    if &pointer.control_realm_id != pcr
        || pointer.secret_storage.series_id() != Some(&backup.series_id)
    {
        return Err(denied());
    }
    validate_pcr_roots(conn, backup, pcr).await?;
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn, owner, device, now,
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    .ok_or_else(denied)?;
    if cut.lifecycle != crate::pcr_device_status_fold::PcrDeviceLifecycle::Active
        || cut.authority.realm_id != owner_pcr
    {
        return Err(denied());
    }
    let admission = crate::key_backup_authority::verify_human_backup_signature(
        conn, backup, &cut, owner, device,
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    .bind_controller_subject(backup)?;
    crate::key_backup_authority::verify_current_backup_recipient(conn, backup, now)
        .await
        .map_err(PgTransactionError::into_persistence)?;
    store_verified(
        held,
        backup,
        token,
        admission,
        ActorId::account(owner.clone()),
        now,
    )
    .await
}
