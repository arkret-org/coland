//! First publication of a private Sidecar root under the Agent's own session.
use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
use arkret_models_crypto::{
    ContentRootContext, KeyBackup, KeyBackupPutStatus, KeyBackupRecipientMethod,
    KeysBackupsReplaceResponseBody, RecoveryMethod, RecoveryPolicy, SecretStorageItemKind,
    SidecarBackupPrepareResponseBody,
};
use arkret_wire::{ActorId, ScopeRef, ServiceOperationId, SidecarId};
use chrono::{DateTime, Utc};
use coland_storage::{
    AccountContentDeliveryGuard, AccountContentDeliveryInput, IdempotencyRecord, PersistenceError,
    PersistenceResult,
};
use diesel::sql_query;
use diesel::sql_types::Text;
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::account_content_delivery::DeliveryGuard;
use crate::{AsyncPgConnection, PgPool, PgTransactionError};

fn denied() -> PersistenceError {
    PersistenceError::Conflict(
        "capability_denied: private Sidecar root writer is unavailable".into(),
    )
}

struct WriterCut {
    prepare: SidecarBackupPrepareResponseBody,
    actor: ActorId,
    custodian: ActorId,
    public_key: [u8; 32],
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

async fn current(
    conn: &mut AsyncPgConnection,
    input: &AccountContentDeliveryInput,
    sidecar: &SidecarId,
) -> PersistenceResult<WriterCut> {
    let now = Utc::now();
    let endpoint = input.agent_endpoint.as_ref().ok_or_else(denied)?;
    let evidence = input
        .qualified_agent_scope_evidence
        .as_ref()
        .ok_or_else(denied)?;
    let (actions, details) = input.agent_session_scope.as_ref().ok_or_else(denied)?;
    let expires = input.credential_expires_at.ok_or_else(denied)?;
    let binding = evidence.accepted_binding();
    let owner = &binding.controller_account;
    let account = arkret_wire::AccountId::new(endpoint.agent_id.clone(), owner.station_id.clone());
    let actor = ActorId::account(account.clone());
    let custodian = ActorId::account(owner.clone());
    if expires <= now
        || owner == &account
        || details.controller_principal_id != owner.principal_id
        || details.agent_key_authorization_ref != endpoint.authorization_ref.event_id
        || !crate::sidecar_access::is_owning_station_in_connection(conn, owner).await?
    {
        return Err(denied());
    }
    let realm = crate::morph_projection_reads::human_realm_in_connection(conn, owner).await?;
    crate::pcr_private_authority::require_active_human_account(conn, owner).await?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
    if crate::sidecar_access::controller_account_in_connection(conn, &realm, sidecar)
        .await?
        .as_ref()
        != Some(owner)
        || !crate::sidecar_access::can_reply_in_connection(
            conn,
            &realm,
            sidecar,
            &account,
            &endpoint.verification_method,
            Some(&endpoint.authorization_ref.event_id),
        )
        .await?
        || crate::sidecar_authority_cut::controller_floor_in_connection(
            conn, &realm, sidecar, &custodian,
        )
        .await?
        .is_none()
    {
        return Err(denied());
    }
    crate::agent_current_states::lock_agent_producer_current(
        conn,
        &endpoint.pcr_realm_id,
        &endpoint.agent_id,
    )
    .await?;
    crate::authority_commit::check_agent_endpoint_current_in_connection(
        conn,
        &endpoint.pcr_realm_id,
        &endpoint.agent_id,
        &endpoint.authorization_ref,
        &endpoint.verification_method,
        now,
    )
    .await?;
    let original_key = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &endpoint.authorization_ref.event_id,
    )
    .await?
    .ok_or_else(denied)?;
    let key = AgentKeyAuthorizePayload::try_from(&original_key.event).map_err(|_| denied())?;
    let provision_scope = crate::account_content_delivery::provision_scope_in_connection(
        conn,
        endpoint,
        evidence,
        &owner.station_id,
    )
    .await?;
    let ceilings = [&key.agent_key_scope, &provision_scope];
    for op in [
        ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
        ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1,
    ] {
        if !actions.iter().any(|a| a == op)
            || ceilings
                .iter()
                .any(|scope| !scope.actions.iter().any(|a| a == op))
        {
            return Err(denied());
        }
    }
    require_current_reply(
        conn, &realm, sidecar, &account, owner, actions, details, ceilings, now,
    )
    .await?;
    let (controller_realm, provision, reference) =
        crate::agent_provisioning::declared_agent_provision_in_connection(
            conn,
            &endpoint.pcr_realm_id,
        )
        .await
        .map_err(PgTransactionError::into_persistence)?
        .ok_or_else(denied)?;
    let custody = provision.history_custody;
    if reference != binding.provision_ref
        || controller_realm != realm
        || provision.agent_id != account.principal_id
        || custody.custodian_actor_id != custodian
        || key.agent_id != endpoint.agent_id
        || key.verification_method != endpoint.verification_method
        || key.issued_at > now
    {
        return Err(denied());
    }
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let group =
        crate::mls_group_current_states::held_current_value_in_connection(conn, &scope, None)
            .await?
            .ok_or_else(denied)?;
    let create =
        crate::committed_disclosure::accepted_full_event_in_connection(conn, &realm.event_id())
            .await?
            .ok_or_else(denied)?;
    if group.effective_scope != scope || create.event.realm_id != realm {
        return Err(denied());
    }
    let root_context = ContentRootContext {
        effective_scope: scope,
        genesis_event_ref: group.genesis_event_ref,
        epoch: group.epoch,
        group_state_ref: group.current_mls_commit_event_ref,
        cipher_suite: group.cipher_suite.as_str().into(),
        encryption_backup_strategy: create
            .event
            .as_realm_create()
            .map_err(|_| denied())?
            .object
            .initial_encryption_backup_strategy,
        backup_strategy_ref: create.event.event_id,
    };
    let pointer = crate::key_backup_current_states::confirmed_key_backup_pointer_in_connection(
        conn, &account,
    )
    .await?
    .ok_or_else(denied)?;
    if pointer.control_realm_id != endpoint.pcr_realm_id {
        return Err(denied());
    }
    let series_id = pointer
        .secret_storage
        .series_id()
        .cloned()
        .ok_or_else(denied)?;
    let row = crate::pcr_recovery_policy_unit::current_policy(conn, owner)
        .await
        .map_err(PgTransactionError::into_persistence)?
        .ok_or_else(denied)?;
    let policy: RecoveryPolicy =
        serde_json::from_value(row.raw_payload).map_err(PersistenceError::database)?;
    arkret_models_crypto::key_backup::BackupRecoveryRecipient {
        subject: &custodian,
        policy_ref: &custody.recovery_policy_ref,
        key_agreement_ref: custody.recipient_key_ref.as_str(),
        hpke_suite: None,
    }
    .validate(&policy, now)
    .map_err(|_| denied())?;
    let recipient = policy
        .methods
        .iter()
        .filter_map(|method| match method {
            RecoveryMethod::RecoveryUnlock { keys } => Some(keys),
            _ => None,
        })
        .flatten()
        .find(|key| {
            key.backup_hpke.key_agreement_ref == custody.recipient_key_ref
                && key.not_before <= now
                && key.expires_at > now
                && key.revoked_at.is_none_or(|at| now < at)
        })
        .ok_or_else(denied)?;
    let mut valid_until = expires
        .min(recipient.expires_at)
        .min(recipient.backup_hpke.expires_at);
    for bound in [
        key.expires_at,
        policy.expires_at,
        recipient.revoked_at,
        recipient.backup_hpke.revoked_at,
    ]
    .into_iter()
    .flatten()
    {
        valid_until = valid_until.min(bound);
    }
    if now >= valid_until {
        return Err(denied());
    }
    let public_key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &key.public_key,
        &endpoint.verification_method,
    )
    .map_err(|_| denied())?
    .raw_public_key;
    crate::key_backup::lock_backup_series_in_connection(conn, &actor).await?;
    let predecessor = sql_query("SELECT jsonb_build_array('ak:backup:' || id::text, signing_payload_digest, series_sequence, deleted_at IS NULL) AS payload
        FROM key_backup_identities WHERE actor_id=$1 AND series_id=$2 ORDER BY series_sequence DESC LIMIT 1 FOR SHARE")
        .bind::<Text,_>(actor.to_string()).bind::<Text,_>(series_id.as_str())
        .get_result::<crate::JsonPayloadRow>(conn).await.optional().map_err(PersistenceError::database)?;
    let (series_sequence, supersedes_id, supersedes_digest) = match predecessor {
        None => (0, None, None),
        Some(row) => {
            let (id, digest, sequence, live): (
                arkret_wire::BackupId,
                arkret_wire::Hash,
                u64,
                bool,
            ) = serde_json::from_value(row.payload).map_err(PersistenceError::database)?;
            if !live {
                return Err(denied());
            }
            (
                sequence.checked_add(1).ok_or_else(denied)?,
                Some(id),
                Some(digest),
            )
        }
    };
    let prepare = SidecarBackupPrepareResponseBody {
        sidecar_id: sidecar.clone(),
        root_context,
        series_id,
        series_sequence,
        supersedes_id,
        supersedes_digest,
        custody_authorization_ref: reference.event_id.clone(),
        recovery_policy_ref: custody.recovery_policy_ref,
        backup_hpke: recipient.backup_hpke.clone(),
    };
    prepare.validate().map_err(PersistenceError::database)?;
    Ok(WriterCut {
        prepare,
        actor,
        custodian,
        public_key,
        valid_from: key.issued_at,
        valid_until,
    })
}

/// The prepare request names only the Sidecar. Any narrower target must be
/// backed by both the issuer's authenticated ceiling and an accepted attach.
#[allow(clippy::too_many_arguments)]
async fn require_current_reply(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    sidecar: &SidecarId,
    agent: &arkret_wire::AccountId,
    controller: &arkret_wire::AccountId,
    actions: &[String],
    details: &arkret_models_identity::SessionGrantScope,
    ceilings: [&arkret_models_collaboration::events_payloads::agent::AgentKeyScope; 2],
    now: DateTime<Utc>,
) -> PersistenceResult<()> {
    let actor = ActorId::account(agent.clone());
    let mut gates = Vec::new();
    for principal in [&actor, &ActorId::account(controller.clone())] {
        let cut =
            crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, realm, principal)
                .await?;
        gates.push(
            cut.enforcing_actor_authorization_in_connection(conn, now)
                .await?,
        );
    }
    let policies =
        crate::policy_current_states::read_scoped_agent_management_policies_in_connection(
            conn, realm,
        )
        .await?;
    let mut targets = Vec::new();
    if details.strand_ids.is_empty() {
        targets.push(arkret_wire::WireResourceSelector::realm(realm.clone()));
    } else {
        for strand in &details.strand_ids {
            let attached = sql_query("SELECT EXISTS(SELECT 1 FROM sidecar_context_current_states s
                JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id AND c.stream_position=s.current_stream_position
                JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.kind='ak.sidecar.context.attach'
                WHERE s.realm_id=$1 AND s.sidecar_id=$2 AND c.stream_ref=s.source_stream_ref AND e.envelope->'scope_ref'=s.source_stream_ref
                AND e.envelope->'actor_id'=$4 AND e.envelope->'payload'=s.value
                AND s.value->'source_context_ref'=jsonb_build_object('kind','strand','strand_id',$3::text)) AS present")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(sidecar.as_str()).bind::<Text,_>(strand.as_str())
                .bind::<diesel::sql_types::Jsonb,_>(serde_json::json!(ActorId::account(controller.clone())))
                .get_result::<crate::query_rows::ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
            if attached {
                targets.push(arkret_wire::WireResourceSelector::strand(
                    realm.clone(),
                    strand.clone(),
                ));
            }
        }
    }
    let tracks: Vec<_> = if details.constraints.allowed_tracks.is_empty() {
        vec![None]
    } else {
        details
            .constraints
            .allowed_tracks
            .iter()
            .map(|v| Some(v.clone()))
            .collect()
    };
    for target in targets {
        if crate::agent_management_admission::require_native_message_reply_policy(
            &policies, realm, controller, agent, &target, now,
        )
        .is_err()
        {
            continue;
        }
        for track in &tracks {
            let facts = coland_storage::OperationFacts {
                strand_id: target.strand_id.as_ref().map(ToString::to_string),
                track: track.clone(),
                object_kind: Some("message".into()),
                ..Default::default()
            };
            let operation = coland_storage::AuthorizationOperation {
                actor: &actor,
                target: &target,
                facts: &facts,
                at: now,
                actions: &["ak.message.create"],
            };
            if ceilings.iter().any(|scope| {
                crate::agent_management_admission::require_key_scope_content_ceiling(
                    scope, &operation,
                )
                .is_err()
            }) || crate::agent_management_admission::require_session_content_ceiling(
                actions, details, &operation,
            )
            .is_err()
            {
                continue;
            }
            let mut allowed = true;
            for gate in &gates {
                if gate
                    .evaluate_with_approvals_checked(operation.actions, &target, &facts, &[])?
                    .is_refusal()
                {
                    allowed = false;
                    break;
                }
            }
            if allowed {
                return Ok(());
            }
        }
    }
    Err(denied())
}

struct PreparedDelivery {
    held: Box<DeliveryGuard>,
    input: AccountContentDeliveryInput,
    expected: SidecarBackupPrepareResponseBody,
    expires: DateTime<Utc>,
}

#[async_trait::async_trait]
impl AccountContentDeliveryGuard for PreparedDelivery {
    fn permits_handoff(&self) -> bool {
        Utc::now() < self.expires
    }
    async fn prepare_handoff(&mut self) -> bool {
        self.permits_handoff()
            && current(
                self.held.connection(),
                &self.input,
                &self.expected.sidecar_id,
            )
            .await
            .is_ok_and(|cut| cut.prepare == self.expected)
            && self.held.probe().await.is_ok()
            && self.permits_handoff()
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }
}

pub(crate) async fn prepare(
    pool: &PgPool,
    input: &AccountContentDeliveryInput,
    id: &SidecarId,
) -> PersistenceResult<(
    SidecarBackupPrepareResponseBody,
    Box<dyn AccountContentDeliveryGuard>,
)> {
    let mut held = DeliveryGuard::begin(pool).await?;
    let cut = current(held.connection(), input, id).await?;
    let delivery = PreparedDelivery {
        held,
        input: input.clone(),
        expected: cut.prepare.clone(),
        expires: cut.valid_until,
    };
    Ok((cut.prepare, Box::new(delivery)))
}

pub(crate) async fn put(
    pool: &PgPool,
    input: &AccountContentDeliveryInput,
    id: &SidecarId,
    backup: &KeyBackup,
    token: &str,
) -> PersistenceResult<KeysBackupsReplaceResponseBody> {
    let mut held = DeliveryGuard::begin(pool).await?;
    let cut = current(held.connection(), input, id).await?;
    let now = Utc::now();
    backup
        .validate()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let [item] = backup.contents.as_slice() else {
        return Err(denied());
    };
    if token.is_empty()
        || token.len() > 128
        || item.item_kind != SecretStorageItemKind::ContentEpochRoot
        || item.root_context.as_ref() != Some(&cut.prepare.root_context)
        || item.root_ref.is_none()
        || backup.created_at < cut.valid_from
        || backup.created_at > now
        || now >= cut.valid_until
        || backup.expires_at.flatten().is_some_and(|at| at <= now)
        || backup.actor_id != cut.actor
        || backup.custodian_actor_id.as_ref() != Some(&cut.custodian)
        || backup.custody_authorization_ref.as_ref() != Some(&cut.prepare.custody_authorization_ref)
        || backup.series_id != cut.prepare.series_id
        || backup.recovery_policy_ref.as_ref() != Some(&cut.prepare.recovery_policy_ref)
        || backup.encryption.recipient_method != KeyBackupRecipientMethod::RecoveryPublicKey
        || backup.encryption.recipient_key_ref.as_deref()
            != Some(cut.prepare.backup_hpke.key_agreement_ref.as_str())
    {
        return Err(denied());
    }
    let admission = crate::key_backup_authority::BackupWriterAdmission::verify_agent(
        backup,
        &cut.actor,
        input.agent_endpoint.as_ref().ok_or_else(denied)?,
        &cut.public_key,
        now,
    )?;
    crate::key_backup_authority::verify_current_backup_recipient(held.connection(), backup, now)
        .await
        .map_err(PgTransactionError::into_persistence)?;
    let response = KeysBackupsReplaceResponseBody {
        status: KeyBackupPutStatus::Accepted,
        backup_id: backup.backup_id.clone(),
        ciphertext_digest: backup.ciphertext_digest.clone(),
    };
    let replay = IdempotencyRecord {
        authenticated_actor: cut.actor,
        operation_id: "ak.self.keys.backups.resource.replace".into(),
        idempotency_key: token.to_owned(),
        request_hash: arkret_canonical::canonical_sha256(backup)
            .map_err(PersistenceError::database)?,
        response_body: serde_json::to_value(&response).map_err(PersistenceError::database)?,
        response_status: 200,
        created_at: now,
        expires_at: now + chrono::Duration::hours(24),
    };
    crate::key_backup::put_key_backup_in_connection(
        held.connection(),
        backup.backup_id.as_str(),
        &serde_json::json!(backup),
        &admission,
    )
    .await?;
    crate::idempotency::record_idempotency_in_connection(held.connection(), &replay).await?;
    let stored = crate::idempotency::preparation_record(held.connection(), &replay)
        .await?
        .ok_or_else(denied)?;
    if stored.request_hash != replay.request_hash || stored.response_body != replay.response_body {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: Agent backup retry changed its signed packet".into(),
        ));
    }
    held.commit().await?;
    Ok(response)
}
