//! Real accepted PCR revoke proposal and local worker terminal for MLS tests.
//! The prepared backup material is a signed future plan only; this helper
//! does not claim backup upload, pointer switching, erasure or worker HTTP.

use arkret_models_collaboration::events_payloads::{
    ControllerBackupTrustAnchor, UnsignedKeyBackupActiveSeries,
};
use arkret_models_crypto::{
    AcceptedSecurityTransactionStep, BackupObjectRef, BackupRotationBinding, BackupRotationKind,
    BackupRotationPlan, KeyBackup, PreparedEventUnit, SecurityRotationRevokeCommandDecision,
    SecurityRotationRevokeCommandOutcome, SecurityRotationRevokeProposal,
    SecurityRotationTransactionCreateRequestBody, SecurityTransaction, SecurityTransactionAcceptor,
    SecurityTransactionCreateRequestBody, SecurityTransactionStep,
};
use arkret_wire::{
    BackupId, BackupSeriesId, Base64UrlString, DetachedSignatureContext, DidUrl, EventKind, Hash,
    RealmCommitId, ScopeRef, TransactionId,
};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, DeviceRevocationGateSelector,
    DeviceRevocationStore, RevokeCommandTerminalWrite, RevokeProposalCommitWrite,
    SecurityTransactionRecord, SecurityTransactionStepOutcomeRecord, SecurityTransactionStore,
};
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgDeviceRevocationStore, PgPool, PgSecurityTransactionStore,
};
use ed25519_dalek::{Signer as _, SigningKey};

pub async fn accept_revoke(
    pool: &PgPool,
    source: &super::pcr_genesis::PcrGenesisFixture,
    target: &DeviceRevocationGateSelector,
    authorizer: &super::pcr_genesis::AcceptedDevice,
) {
    let account = &source.history.account;
    assert_eq!(&target.principal_id, &account.principal_id);
    assert_eq!(
        &authorizer.authorization.principal_id,
        &account.principal_id
    );
    assert_ne!(target.device_id, authorizer.authorization.device_id);
    let previous = source.history.commits.last().unwrap();
    let prior = PgAuthorityCommitStore { pool: pool.clone() }
        .committed_event(&previous.event_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(prior.commit, *previous);
    let at = previous.committed_at + chrono::TimeDelta::seconds(1);
    let device = arkret_wire::DeviceId::new(authorizer.authorization.device_id.clone()).unwrap();
    let mut event=arkret_wire::test_support::raw_event(EventKind::DeviceRevoke.as_str(),ScopeRef::Realm {realm_id:previous.realm_id.clone()},account.principal_id.clone(),account.station_id.clone(),
        serde_json::json!({"device_id":target.device_id,"revoked_by":device,"revoked_at":arkret_canonical::format_timestamp_canonical(at),"reason":"security_rotation"})).unwrap();
    event.created_at = at;
    let revoke = super::device_authorization_history::sign_event(
        event,
        authorizer.verification_method.clone(),
        authorizer.signing_seed,
    );
    let mut covering = previous.clone();
    covering.stream_position += 1;
    covering.previous_commit_ref = Some(previous.commit_id.clone());
    covering.event_ref = revoke.event_id.clone();
    covering.committed_at = at;
    let identity =
        arkret_canonical::canonical::unsigned_value(&covering, &["commit_id", "signature"])
            .unwrap();
    covering.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&covering, &["signature"]).unwrap();
    covering.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{}#authority", source.history.station_did)).unwrap(),
        at,
        &SigningKey::from_bytes(&super::device_authorization_history::STATION_AUTHORITY_SEED),
    )
    .unwrap();
    let series = BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let old_series =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let digest = |bytes: &[u8]| Hash::new(arkret_canonical::sha256_digest(bytes)).unwrap();
    let mut backup:KeyBackup=serde_json::from_value(serde_json::json!({
        "backup_id":format!("ak:backup:{}",uuid::Uuid::now_v7()),"actor_id":arkret_wire::ActorId::account(account.clone()),"backup_kind":"secret_storage","backup_version":"kb_1",
        "created_at":arkret_canonical::format_timestamp_canonical(at),"series_id":series,"series_sequence":0,
        "encryption":{"recipient_method":"secret_storage_key","recipient_key_ref":"backup-key","aead":{"name":"xchacha20_poly1305","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "domain_separation":{"subdomain":"secret_storage"},"contents":[{"item_kind":"recovery_key_share","secret_id":"share"}],
        "ciphertext":"AAAA","ciphertext_digest":digest(&[0,0,0]),
        "signature_proof":{"device_id":device,"verification_method":authorizer.verification_method,"signature_algorithm":"Ed25519","signature":"AA","device_authorize_event_id":authorizer.authorization.authorization_ref.event_id}
    })).unwrap();
    backup.signature_proof.signature = Base64UrlString::new(arkret_canonical::base64url_encode(
        SigningKey::from_bytes(&authorizer.signing_seed)
            .sign(&backup.signing_payload_bytes().unwrap())
            .to_bytes(),
    ))
    .unwrap();
    backup.validate().unwrap();
    let unsigned = UnsignedKeyBackupActiveSeries::new(
        arkret_wire::ActorId::account(account.clone()),
        arkret_models_crypto::BackupKind::SecretStorage,
        series.clone(),
        1,
        vec![old_series.clone()],
        covering.commit_id.clone(),
        at,
        authorizer.verification_method.clone(),
        ControllerBackupTrustAnchor {
            authorize_event_id: authorizer.authorization.authorization_ref.event_id.clone(),
            generation_ref: 1,
        },
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&authorizer.signing_seed)
        .sign(&unsigned.signing_payload_bytes().unwrap())
        .to_bytes();
    let pointer_payload = unsigned
        .attach_signature(
            Base64UrlString::new(arkret_canonical::base64url_encode(signature)).unwrap(),
        )
        .unwrap();
    let mut pointer = arkret_wire::test_support::raw_event(
        EventKind::KeyBackupActiveSeries.as_str(),
        revoke.scope_ref.clone(),
        account.principal_id.clone(),
        account.station_id.clone(),
        serde_json::to_value(pointer_payload).unwrap(),
    )
    .unwrap();
    pointer.created_at = at;
    let pointer = super::device_authorization_history::sign_event(
        pointer,
        authorizer.verification_method.clone(),
        authorizer.signing_seed,
    );
    let unit = |event| {
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::EventsSubmitBatchRequestBody {
                events: vec![arkret_wire::EventAdmissionSubmission::new(event)],
            },
        )
        .unwrap()
    };
    let request = SecurityRotationTransactionCreateRequestBody::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        device,
        at + chrono::TimeDelta::hours(1),
        unit(revoke.clone()),
        digest(b"future-rotated-secret"),
        vec![BackupRotationPlan {
            binding: BackupRotationBinding {
                backup_kind: BackupRotationKind::SecretStorage,
                previous_series_id: old_series,
                new_series_id: series,
                new_backups: vec![BackupObjectRef {
                    backup_id: backup.backup_id.clone(),
                    ciphertext_digest: backup.ciphertext_digest.clone(),
                }],
                active_series_event_id: pointer.event_id.clone(),
                old_backups: vec![BackupObjectRef {
                    backup_id: BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7()))
                        .unwrap(),
                    ciphertext_digest: digest(b"old-backup"),
                }],
            },
            new_backup_envelopes: vec![backup],
            active_series_unit: unit(pointer),
        }],
    )
    .unwrap();
    let (initial, canonical_request) =
        SecurityTransactionCreateRequestBody::SecurityRotation(request)
            .into_rotation_resource(at)
            .unwrap();
    let transactions = PgSecurityTransactionStore { pool: pool.clone() };
    let mut proposed = transactions
        .create(SecurityTransactionRecord {
            resource: initial,
            canonical_request,
        })
        .await
        .unwrap();
    proposed.rotation_mut().unwrap().revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
    });
    transactions
        .commit_revoke_proposal(RevokeProposalCommitWrite {
            transaction: proposed.clone(),
            commit: AuthorityCommitTransaction {
                expected_authority: source.unit.transactions[1].expected_authority.clone(),
                event: revoke.clone(),
                commit: covering.clone(),
                producer_signer_fact: None,
                content_backup_source: None,
                mls_state: None,
                welcomes: vec![],
                recipient_queue_capacity: 0,
            },
            queued_at: at,
        })
        .await
        .unwrap();
    let decided_at = at + chrono::TimeDelta::seconds(1);
    proposed
        .rotation_mut()
        .unwrap()
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: account.station_id.clone(),
            },
            accepted_at: decided_at,
        });
    proposed.rotation_mut().unwrap().revoke_command_outcome =
        Some(SecurityRotationRevokeCommandOutcome {
            proposal_event_id: revoke.event_id.clone(),
            covering_commit_id: covering.commit_id.clone(),
            outcome: SecurityRotationRevokeCommandDecision::Accepted,
            decided_at,
        });
    assert!(matches!(
        proposed.resource,
        SecurityTransaction::SecurityRotation(_)
    ));
    let terminal = transactions
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            step_outcome: Some(SecurityTransactionStepOutcomeRecord {
                transaction_id: proposed.resource.transaction_id().to_string(),
                step: SecurityTransactionStep::Revoke,
                canonical_request: proposed.canonical_request.clone(),
                response: serde_json::to_value(&proposed.resource).unwrap(),
                participant_outcome: None,
            }),
            transaction: proposed,
        })
        .await
        .unwrap();
    assert_eq!(
        terminal
            .rotation()
            .unwrap()
            .revoke_command_outcome
            .as_ref()
            .unwrap()
            .outcome,
        SecurityRotationRevokeCommandDecision::Accepted
    );
    let accepted = PgAuthorityCommitStore { pool: pool.clone() }
        .committed_event(&revoke.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, revoke);
    assert_eq!(accepted.commit, covering);
    // Freeze the artifact gate from the actual canonical source, as the
    // accepted revocation effect does; no synthetic Event or Commit is used.
    PgDeviceRevocationStore { pool: pool.clone() }
        .commit_revocation(&coland_storage::DeviceRevocationTransition {
            selector: target.clone(),
            revoke_ref: arkret_wire::CommittedEventRef {
                event_id: accepted.event.event_id,
                commit_id: accepted.commit.commit_id,
                stream_ref: accepted.commit.stream_ref,
                stream_position: accepted.commit.stream_position,
            },
            committed_at: accepted.commit.committed_at,
        })
        .await
        .unwrap();
}
