//! History-only PCR root delivery, independent of old MLS private state and
//! completed identity-recovery sessions. No decrypted root enters this module.

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_crypto::{
    ContentCoverageEntry, ContentHistoryBackupAccess, EncryptedEnvelopeEncryptionContext,
    KeyBackup, KeyBackupUnlockAuthority, KeyBackupUnlockProof, KeysBackupsUnlockChallenge,
    KeysBackupsUnlockRequestBody, RecoveryMethod, RecoveryPolicy, RecoveryPolicyRef,
};
use arkret_wire::{ActorId, CommitStreamRef, ScopeRef};
use coland_storage::{
    AccountContentDeliveryGuard, HumanPcrHistoryReader, PersistenceError, PersistenceResult,
};
use diesel::sql_query;
use diesel::sql_types::Text;
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::account_content_delivery::DeliveryGuard;
use crate::{AsyncPgConnection, JsonPayloadRow};

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: PCR history root {detail}"))
}

async fn current_reader(
    conn: &mut AsyncPgConnection,
    reader: &HumanPcrHistoryReader,
) -> PersistenceResult<(arkret_wire::RealmId, chrono::DateTime<chrono::Utc>)> {
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &reader.account_id,
        &reader.device_id,
        chrono::Utc::now(),
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| denied("current Device has no accepted PCR"))?;
    let realm = cut.authority.realm_id;
    let expires =
        crate::pcr_history_read::qualify(conn, reader, &realm, &reader.account_id.station_id)
            .await?;
    Ok((realm, expires))
}

/// The current policy may advance while retaining the same backup agreement.
/// Verify the old accepted policy independently, then bind the original public
/// key to an active agreement in the current accepted policy.
pub(crate) async fn recipient(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    let account = backup
        .custodian_actor_id
        .as_ref()
        .unwrap_or(&backup.actor_id)
        .as_account_id()
        .ok_or_else(|| denied("subject"))?;
    let current = crate::pcr_recovery_policy_unit::current_policy(conn, account)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
        .ok_or_else(|| denied("current policy unavailable"))?;
    let current: RecoveryPolicy =
        serde_json::from_value(current.raw_payload).map_err(PersistenceError::database)?;
    recipient_for_policy(conn, backup, &current).await
}

pub(crate) async fn recipient_for_policy(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
    current: &RecoveryPolicy,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    let subject = backup
        .custodian_actor_id
        .as_ref()
        .unwrap_or(&backup.actor_id);
    let account = subject
        .as_account_id()
        .ok_or_else(|| denied("recipient subject"))?;
    let reference = backup
        .recovery_policy_ref
        .as_ref()
        .ok_or_else(|| denied("policy reference"))?;
    let old = sql_query("SELECT p.raw_payload AS payload FROM recovery_policies p JOIN policy_current_states c ON c.policy_id=('ak:policy:' || p.id::text) AND c.current_commit_id=(p.acceptance_basis #>> '{}') AND c.value=p.raw_payload WHERE p.raw_payload->>'policy_id'=$1 AND p.version=$2 AND p.principal_id=$3 AND p.station_id=$4 FOR SHARE OF p")
        .bind::<Text,_>(reference.policy_id.as_str())
        .bind::<crate::Integer,_>(i32::try_from(reference.policy_version).map_err(PersistenceError::database)?)
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("original accepted policy unavailable"))?;
    let old: RecoveryPolicy =
        serde_json::from_value(old.payload).map_err(PersistenceError::database)?;
    backup
        .validate_recovery_recipient(&old, backup.created_at)
        .map_err(denied)?;
    let key_ref = backup
        .encryption
        .recipient_key_ref
        .as_deref()
        .ok_or_else(|| denied("HPKE recipient"))?;
    let current_ref = RecoveryPolicyRef {
        policy_id: current.policy_id.clone(),
        policy_version: current.version,
    };
    arkret_models_crypto::key_backup::BackupRecoveryRecipient {
        subject,
        policy_ref: &current_ref,
        key_agreement_ref: key_ref,
        hpke_suite: backup.encryption.hpke_suite.as_deref(),
    }
    .validate(current, chrono::Utc::now())
    .map_err(denied)?;
    let key = |policy: &RecoveryPolicy| {
        policy
            .methods
            .iter()
            .filter_map(|method| match method {
                RecoveryMethod::RecoveryUnlock { keys } => Some(keys),
                _ => None,
            })
            .flatten()
            .find(|key| key.backup_hpke.key_agreement_ref.as_str() == key_ref)
            .map(|key| {
                (
                    key.backup_hpke.public_key_multibase.clone(),
                    key.backup_hpke.expires_at,
                )
            })
    };
    let old_key = key(&old).ok_or_else(|| denied("original recipient key"))?;
    let current_key = key(current).ok_or_else(|| denied("current recipient key"))?;
    if old_key.0 != current_key.0 {
        return Err(denied("recipient key changed"));
    }
    Ok(current
        .expires_at
        .map_or(current_key.1, |expiry| expiry.min(current_key.1)))
}

pub(crate) async fn qualify(
    conn: &mut AsyncPgConnection,
    reader: &HumanPcrHistoryReader,
    history: &ContentHistoryBackupAccess,
    backup_id: &arkret_wire::BackupId,
) -> PersistenceResult<(KeyBackup, chrono::DateTime<chrono::Utc>)> {
    let realm = history.source.stream_ref.realm_id();
    if history.source.stream_ref
        != (CommitStreamRef::Realm {
            realm_id: realm.clone(),
        })
        || history.root_refs.is_empty()
    {
        return Err(denied("source or selection"));
    }
    let (owned_realm, expires) = current_reader(conn, reader).await?;
    if realm != &owned_realm {
        return Err(denied("source is outside the original Account PCR"));
    }
    let original = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &history.source.event_id,
    )
    .await?
    .ok_or_else(|| denied("original unavailable"))?;
    if original.commit.commit_id != history.source.commit_id
        || original.commit.stream_ref != history.source.stream_ref
        || original.commit.stream_position != history.source.stream_position
        || original.event.scope_ref
            != (ScopeRef::Realm {
                realm_id: realm.clone(),
            })
        || original.event.actor_id != ActorId::account(reader.account_id.clone())
    {
        return Err(denied("original coordinates or subject"));
    }
    let coverage = sql_query("SELECT coverage AS payload FROM content_originals WHERE event_id=$1 AND commit_id=$2 AND retain_full_history=true FOR SHARE")
        .bind::<Text,_>(history.source.event_id.as_str()).bind::<Text,_>(history.source.commit_id.as_str())
        .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("retained coverage unavailable"))?;
    let coverage: ContentCoverageEntry =
        serde_json::from_value(coverage.payload).map_err(PersistenceError::database)?;
    let carriers = original.event.event_content_envelopes().map_err(denied)?;
    if coverage.source != history.source
        || history.root_refs.iter().any(|root| {
            !coverage.root_refs.contains(root)
                || !carriers.iter().any(|carrier| {
                    let EncryptedEnvelopeEncryptionContext::EpochContent { protection, .. } =
                        &carrier.envelope.encryption_context;
                    protection.root_refs.contains(root)
                })
        })
    {
        return Err(denied("selection is outside original signed protection"));
    }
    // Mapping is derived from both immutable signed indices and the original
    // Event protection. The caller's alternate backup ID alone grants nothing.
    let actor = ActorId::account(reader.account_id.clone());
    crate::pcr_recovery_policy_unit::current_policy(conn, &reader.account_id)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
    crate::key_backup::lock_backup_series_in_connection(conn, &actor).await?;
    let wanted = history
        .root_refs
        .iter()
        .map(|root| root.as_str().to_owned())
        .collect::<Vec<_>>();
    let packet = crate::content_root_packages::read_in_connection(conn, backup_id, &wanted)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
    if packet.actor != actor
        || packet.recipient_subject != actor
        || history.root_refs.iter().any(|root| {
            !packet.roots.iter().any(|(r, context)| {
                r == root && context.effective_scope == original.event.scope_ref
            })
        })
    {
        return Err(denied("package does not cover the original roots"));
    }
    for (root, context) in &packet.roots {
        let accepted = sql_query("SELECT root_context AS payload FROM content_original_roots WHERE event_id=$1 AND root_ref=$2 AND backup_actor_id=$3 FOR SHARE")
            .bind::<Text,_>(history.source.event_id.as_str()).bind::<Text,_>(root.as_str())
            .bind::<Text,_>(actor.to_string()).get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| denied("original root context unavailable"))?;
        if accepted.payload != serde_json::to_value(context).map_err(PersistenceError::database)? {
            return Err(denied("original root context changed"));
        }
        let original_ids = carriers
            .iter()
            .filter_map(|carrier| {
                let EncryptedEnvelopeEncryptionContext::EpochContent { protection, .. } =
                    &carrier.envelope.encryption_context;
                protection
                    .root_refs
                    .contains(root)
                    .then_some(protection.backup_refs.iter().cloned())
            })
            .flatten()
            .collect::<Vec<_>>();
        crate::content_root_packages::require_original_binding(
            conn,
            &original_ids,
            &actor,
            root,
            context,
        )
        .await?;
    }
    let backup = crate::content_root_packages::read_retained_envelope(conn, backup_id).await?;
    if backup.backup_id != *backup_id
        || backup.custodian_actor_id.is_some()
        || backup.custody_authorization_ref.is_some()
    {
        return Err(denied("subject differs"));
    }
    let recipient_expiry = recipient(conn, &backup).await?;
    Ok((backup, expires.min(recipient_expiry)))
}

pub(crate) async fn verify_proof(
    conn: &mut AsyncPgConnection,
    reader: &HumanPcrHistoryReader,
    proof: &KeyBackupUnlockProof,
    backup: &KeyBackup,
) -> PersistenceResult<()> {
    proof.validate().map_err(denied)?;
    let KeyBackupUnlockAuthority::CurrentDevice {
        challenge_id,
        nonce,
    } = &proof.authority
    else {
        return Err(denied("requires current Device PoP"));
    };
    let stored = sql_query("SELECT challenge AS payload FROM key_backup_unlock_authorities WHERE authority_id=$1 AND kind='current_device'")
        .bind::<Text,_>(challenge_id.as_str()).get_result::<JsonPayloadRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?.ok_or_else(|| denied("challenge unavailable"))?;
    let challenge: KeysBackupsUnlockChallenge =
        serde_json::from_value(stored.payload).map_err(PersistenceError::database)?;
    challenge
        .validate_for_request(&challenge.request_body(), &backup.backup_id)
        .map_err(denied)?;
    if proof.account_id != reader.account_id
        || proof.requesting_device_id != reader.device_id
        || challenge.account_id != proof.account_id
        || challenge.requesting_device_id != proof.requesting_device_id
        || challenge.backup_id != proof.backup_id
        || backup.backup_id != proof.backup_id
        || challenge.series_id != proof.series_id
        || backup.series_id != proof.series_id
        || backup.backup_kind != proof.backup_kind
        || challenge.ciphertext_digest != proof.ciphertext_digest
        || backup.ciphertext_digest != proof.ciphertext_digest
        || challenge.nonce != *nonce
        || challenge.challenge != proof.challenge
        || challenge.audience != proof.audience
        || challenge.service_id != proof.service_id
        || proof.service_id != reader.account_id.station_id
        || challenge.subject_actor_id != proof.subject_actor_id
        || challenge.custody_authorization_ref != proof.custody_authorization_ref
        || challenge.content_history != proof.content_history
        || proof.content_history.is_none()
        || proof.subject_actor_id.is_some()
        || proof.custody_authorization_ref.is_some()
        || proof.issued_at < challenge.issued_at
        || proof.issued_at >= challenge.expires_at
        || proof.issued_at > chrono::Utc::now()
        || proof.expires_at != challenge.expires_at
    {
        return Err(denied("proof differs from exact server challenge"));
    }
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &reader.account_id,
        &reader.device_id,
        chrono::Utc::now(),
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| denied("current Device unavailable"))?;
    let authorization = cut
        .authority
        .authorization
        .ok_or_else(|| denied("authorization unavailable"))?;
    let did_key = authorization.payload.device_public_key_did.as_str();
    let fragment = did_key
        .strip_prefix("did:key:")
        .ok_or_else(|| denied("Device key"))?;
    let method = &proof.signature_proof.verification_method;
    if crate::key_backup_current_states::verification_method_device(method, &reader.account_id)
        .as_ref()
        != Some(&reader.device_id)
        && method.as_str() != format!("{did_key}#{fragment}")
        && method.as_str() != format!("{did_key}#device")
    {
        return Err(denied("signer method"));
    }
    let key = arkret_canonical::multibase::decode_ed25519_multibase(fragment).map_err(denied)?;
    if !arkret_signatures::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_vec(),
        },
        &proof.signing_payload_bytes().map_err(denied)?,
        proof.signature_proof.signature.as_str(),
    ) {
        return Err(denied("signature invalid"));
    }
    Ok(())
}

pub(crate) fn proof_digest(proof: &KeyBackupUnlockProof) -> PersistenceResult<String> {
    arkret_canonical::canonical_sha256(&KeysBackupsUnlockRequestBody {
        proof: proof.clone(),
    })
    .map_err(PersistenceError::database)
}

struct HistoryDelivery {
    held: Box<DeliveryGuard>,
    checked_at: chrono::DateTime<chrono::Utc>,
    expires: chrono::DateTime<chrono::Utc>,
}
#[async_trait::async_trait]
impl AccountContentDeliveryGuard for HistoryDelivery {
    fn permits_handoff(&self) -> bool {
        let now = chrono::Utc::now();
        self.checked_at <= now && now < self.expires
    }
    async fn prepare_handoff(&mut self) -> bool {
        self.held.probe().await.is_ok() && self.permits_handoff()
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }
}

pub(crate) async fn issue(
    pool: &crate::PgPool,
    reader: &HumanPcrHistoryReader,
    challenge: &KeysBackupsUnlockChallenge,
) -> PersistenceResult<KeysBackupsUnlockChallenge> {
    challenge
        .validate_for_request(&challenge.request_body(), &challenge.backup_id)
        .map_err(denied)?;
    if challenge.account_id != reader.account_id
        || challenge.requesting_device_id != reader.device_id
        || challenge.service_id != reader.account_id.station_id
        || challenge.subject_actor_id.is_some()
        || challenge.custody_authorization_ref.is_some()
    {
        return Err(denied("challenge caller"));
    }
    let history = challenge
        .content_history
        .as_ref()
        .ok_or_else(|| denied("selection missing"))?;
    let mut held = DeliveryGuard::begin(pool).await?;
    current_reader(held.connection(), reader).await?;
    // Check a durable request identity before interpreting a changed selection.
    // The writer repeats this check under its account lock for concurrent first
    // issuance; this immutable read introduces no reverse row-lock ordering.
    let known = sql_query("SELECT challenge AS payload FROM key_backup_unlock_authorities WHERE account_id=$1 AND device_id=$2 AND kind='current_device' AND challenge->>'backup_id'=$3 AND challenge->>'request_id'=$4 ORDER BY verified_at DESC,authority_id DESC LIMIT 1")
        .bind::<Text,_>(arkret_canonical::canonical_json_string(&reader.account_id).map_err(PersistenceError::database)?)
        .bind::<Text,_>(reader.device_id.as_str()).bind::<Text,_>(challenge.backup_id.as_str()).bind::<Text,_>(challenge.request_id.as_str())
        .get_result::<JsonPayloadRow>(held.connection()).await.optional().map_err(PersistenceError::database)?;
    if let Some(known) = known {
        let known: KeysBackupsUnlockChallenge =
            serde_json::from_value(known.payload).map_err(PersistenceError::database)?;
        if known.request_body() != challenge.request_body() {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: unlock issuance request changed".into(),
            ));
        }
    }
    let (backup, _) = qualify(held.connection(), reader, history, &challenge.backup_id).await?;
    if challenge.series_id != backup.series_id
        || challenge.ciphertext_digest != backup.ciphertext_digest
    {
        return Err(denied("challenge immutable object"));
    }
    let stored = crate::key_backup_unlock::issue_unlock_in_connection(
        held.connection(),
        serde_json::to_value(challenge).map_err(PersistenceError::database)?,
        chrono::Utc::now(),
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?;
    held.commit().await?;
    serde_json::from_value(stored).map_err(PersistenceError::database)
}

pub(crate) async fn delivery(
    pool: &crate::PgPool,
    reader: &HumanPcrHistoryReader,
    proof: &KeyBackupUnlockProof,
    holder: &str,
) -> PersistenceResult<(KeyBackup, Box<dyn AccountContentDeliveryGuard>)> {
    let mut held = DeliveryGuard::begin(pool).await?;
    let history = proof
        .content_history
        .as_ref()
        .ok_or_else(|| denied("selection missing"))?;
    let (backup, expires) = qualify(held.connection(), reader, history, &proof.backup_id).await?;
    verify_proof(held.connection(), reader, proof, &backup).await?;
    let KeyBackupUnlockAuthority::CurrentDevice { challenge_id, .. } = &proof.authority else {
        return Err(denied("Device PoP"));
    };
    let delivered = sql_query("SELECT to_jsonb(e) AS payload FROM key_backup_unlock_entries e WHERE authority_id=$1 AND backup_id=$2 AND request_digest=$3 AND holder=$4 AND consumed_at IS NOT NULL FOR SHARE")
        .bind::<Text,_>(challenge_id.as_str()).bind::<Text,_>(proof.backup_id.as_str())
        .bind::<Text,_>(proof_digest(proof)?).bind::<Text,_>(holder)
        .get_result::<JsonPayloadRow>(held.connection()).await.optional().map_err(PersistenceError::database)?;
    if delivered.is_none() {
        return Err(denied("has no durable exact consumption"));
    }
    held.probe().await?;
    Ok((
        backup,
        Box::new(HistoryDelivery {
            held,
            checked_at: chrono::Utc::now(),
            expires,
        }),
    ))
}
