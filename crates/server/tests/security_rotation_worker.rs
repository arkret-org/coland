use arkret_models_collaboration::events_payloads::{
    ControllerBackupTrustAnchor, UnsignedKeyBackupActiveSeries,
};
use arkret_models_crypto::{
    AcceptedSecurityTransactionStep as AcceptedStep, BackupObjectRef, BackupRotationBinding,
    BackupRotationKind, BackupRotationPlan, PreparedEventBatchRequest, PreparedEventUnit,
    SecurityRotationRevokeCommandDecision, SecurityRotationRevokeCommandOutcome,
    SecurityRotationRevokeProposal, SecurityRotationTransactionCreateRequest,
    SecurityTransactionAcceptor, SecurityTransactionCreateRequest, SecurityTransactionPreparedPlan,
    SecurityTransactionStep,
};
use arkret_wire::{ActorId, BackupSeriesId, CommittedEventRef, EventKind, Hash, TransactionId};
use coland_storage::{
    AuthorityCommitTransaction, KeyBackupActiveSeriesCommitOutcome,
    KeyBackupActiveSeriesCommitWrite, RevokeCommandTerminalWrite, RevokeProposalCommitWrite,
    SecurityTransactionRecord, SecurityTransactionStepOutcomeRecord,
};
use coland_test_support::AppStateTestExt as _;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use ed25519_dalek::Signer as _;
use serde_json::json;

struct EraseFixture {
    state: coland_http::state::AppState,
    pcr: PcrGenesisFixture,
    record: SecurityTransactionRecord,
    request: coland_storage::BackupSeriesEraseWorkerRequest,
    old_backup_id: arkret_wire::BackupId,
    authorizer: coland_storage::DeviceRevocationGateSelector,
    revoker_id: arkret_wire::DeviceId,
    revoker_authorization_ref: CommittedEventRef,
    revoker_verification_method: arkret_wire::DidUrl,
    revoker_signing_seed: [u8; 32],
    active_series_id: BackupSeriesId,
    pointer_ref: CommittedEventRef,
}

fn test_hash(label: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(label.as_bytes())).unwrap()
}

fn backup_value(
    fixture: &PcrGenesisFixture,
    series_id: &BackupSeriesId,
    authorize_event_id: &arkret_wire::EventId,
    label: &str,
) -> arkret_models_crypto::KeyBackup {
    let backup_id =
        arkret_wire::BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7())).unwrap();
    let mut backup: arkret_models_crypto::KeyBackup = serde_json::from_value(json!({
        "backup_id": backup_id,
        "actor_id": ActorId::account(fixture.history.account.clone()),
        "backup_kind": "secret_storage",
        "backup_version": "kb_1",
        "created_at": "2026-09-09T00:00:00.000Z",
        "series_id": series_id,
        "series_seq": 0,
        "encryption": {
            "recipient_method": "secret_storage_key",
            "recipient_key_ref": "backup-key",
            "aead": {"name": "xchacha20_poly1305", "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        },
        "domain_separation": {"subdomain": "secret_storage"},
        "contents": [{"item_kind": "recovery_key_share", "secret_id": label}],
        "ciphertext": "AAAA",
        "ciphertext_digest": test_hash(label),
        "auth_data": {
            "device_id": fixture.history.founding_device_id,
            "verification_method": fixture.history.device_verification_method,
            "signature_algorithm": "Ed25519",
            "signature": "AA",
            "device_authorize_event_id": authorize_event_id
        }
    }))
    .unwrap();
    let signature =
        ed25519_dalek::SigningKey::from_bytes(&fixture.history.founding_device_signing_seed)
            .sign(&backup.signing_payload_bytes().unwrap())
            .to_bytes();
    backup.auth_data.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(signature)).unwrap();
    backup
}

async fn erase_fixture() -> EraseFixture {
    let (state, pool) = coland_test_support::app_state_with_pool(coland_test_support::app_config());
    let persistence = state.test_persistence();
    let mut fixture = PcrGenesisFixture::new(state.service_did());
    let authorizer = fixture
        .admit_founding_device(persistence.as_ref())
        .await
        .unwrap();
    let revoker = fixture
        .admit_accepted_device(persistence.as_ref(), [92; 32])
        .await
        .unwrap();
    let revoker_id = arkret_wire::DeviceId::new(revoker.authorization.device_id.clone()).unwrap();
    let account = fixture.history.account.clone();
    let authorize_event_id = fixture.history.events[1].event_id.clone();
    let previous_series =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let new_series =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let old_backup = backup_value(
        &fixture,
        &previous_series,
        &authorize_event_id,
        "old-backup",
    );
    let new_backup = backup_value(&fixture, &new_series, &authorize_event_id, "new-backup");

    let unsigned = UnsignedKeyBackupActiveSeries::new(
        ActorId::account(account.clone()),
        arkret_models_crypto::BackupKind::SecretStorage,
        new_series.clone(),
        1,
        vec![previous_series.clone()],
        fixture.history.commits.last().unwrap().commit_id.clone(),
        chrono::Utc::now(),
        fixture.history.device_verification_method.clone(),
        ControllerBackupTrustAnchor {
            authorize_event_id: authorize_event_id.clone(),
            generation_ref: 1,
        },
    )
    .unwrap();
    let signature =
        ed25519_dalek::SigningKey::from_bytes(&fixture.history.founding_device_signing_seed)
            .sign(&unsigned.signing_payload_bytes().unwrap())
            .to_bytes();
    let pointer_payload = unsigned
        .attach_signature(
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(signature))
                .unwrap(),
        )
        .unwrap();
    let pointer_event = fixture.history.event(
        EventKind::KeyBackupActiveSeries,
        serde_json::to_value(pointer_payload).unwrap(),
    );
    fixture.history.append(vec![pointer_event.clone()]);
    let pointer_commit = fixture.history.commits.last().unwrap().clone();
    let pointer_ref = CommittedEventRef {
        event_id: pointer_event.event_id.clone(),
        commit_id: pointer_commit.commit_id.clone(),
        stream_ref: pointer_commit.stream_ref.clone(),
        stream_position: pointer_commit.stream_position,
    };
    let outcome = persistence
        .key_backups()
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            commit: AuthorityCommitTransaction {
                expected_authority: fixture.unit.transactions[1].expected_authority.clone(),
                event: pointer_event.clone(),
                commit: pointer_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: pointer_commit.committed_at,
        })
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        KeyBackupActiveSeriesCommitOutcome::Committed(_)
            | KeyBackupActiveSeriesCommitOutcome::Duplicate(_)
    ));
    persistence
        .key_backups()
        .put(
            old_backup.backup_id.to_string(),
            serde_json::to_value(&old_backup).unwrap(),
        )
        .await
        .unwrap();
    persistence
        .key_backups()
        .put(
            new_backup.backup_id.to_string(),
            serde_json::to_value(&new_backup).unwrap(),
        )
        .await
        .unwrap();

    let target = arkret_wire::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let revoke = fixture.history.event(
        EventKind::DeviceRevoke,
        json!({
            "device_id": target,
            "revoked_by": fixture.history.founding_device_id,
            "revoked_at": chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "reason": "security_rotation"
        }),
    );
    let binding = BackupRotationBinding {
        backup_kind: BackupRotationKind::SecretStorage,
        previous_series_id: previous_series,
        new_series_id: new_series.clone(),
        new_backups: vec![BackupObjectRef {
            backup_id: new_backup.backup_id.clone(),
            ciphertext_digest: new_backup.ciphertext_digest.clone(),
        }],
        active_series_event_id: pointer_event.event_id.clone(),
        old_backups: vec![BackupObjectRef {
            backup_id: old_backup.backup_id.clone(),
            ciphertext_digest: old_backup.ciphertext_digest.clone(),
        }],
    };
    let create = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account,
        fixture.history.founding_device_id.clone(),
        chrono::Utc::now() + chrono::TimeDelta::hours(1),
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            PreparedEventBatchRequest {
                events: vec![revoke.clone()],
            },
        )
        .unwrap(),
        test_hash("new-secret"),
        vec![BackupRotationPlan {
            binding: binding.clone(),
            new_backup_envelopes: vec![new_backup],
            active_series_unit: PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                PreparedEventBatchRequest {
                    events: vec![pointer_event],
                },
            )
            .unwrap(),
        }],
    )
    .unwrap();
    let prepared_plan =
        SecurityTransactionPreparedPlan::SecurityRotation(create.prepared_plan.clone());
    let (mut resource, canonical_request) =
        SecurityTransactionCreateRequest::SecurityRotation(create)
            .into_initial_resource(prepared_plan, chrono::Utc::now())
            .unwrap();
    let now = chrono::Utc::now();
    resource.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: pointer_commit.commit_id.clone(),
    });
    resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: revoke.event_id,
        covering_commit_id: pointer_commit.commit_id.clone(),
        result: SecurityRotationRevokeCommandDecision::Accepted,
        decided_at: now,
    });
    resource.accepted_steps = (0..3)
        .map(|offset| AcceptedStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: state.service_core_id(),
            },
            accepted_at: now + chrono::TimeDelta::milliseconds(offset),
        })
        .collect();
    resource.validate_structural().unwrap();
    let record = SecurityTransactionRecord {
        resource,
        canonical_request,
    };
    coland_storage_postgres::PgSecurityTransactionStore { pool }
        .seed_worker_checkpoint_for_test(&record)
        .await
        .unwrap();
    let request = coland_storage::BackupSeriesEraseWorkerRequest {
        transaction_id: record.resource.transaction_id.clone(),
        transaction_request_digest: record.resource.request_digest.clone(),
        prepared_plan_digest: record.resource.prepared_plan_digest.clone(),
        erase_confirmation_digest: record
            .resource
            .security_rotation_plan()
            .unwrap()
            .erase_confirmation_digest
            .clone(),
        series: vec![binding],
        authority_commit_id: pointer_commit.commit_id,
    };
    EraseFixture {
        state,
        pcr: fixture,
        record,
        request,
        old_backup_id: old_backup.backup_id,
        authorizer,
        revoker_id,
        revoker_authorization_ref: revoker.authorization.authorization_ref,
        revoker_verification_method: revoker.verification_method,
        revoker_signing_seed: revoker.signing_seed,
        active_series_id: new_series,
        pointer_ref,
    }
}

async fn propose_authorizer_revocation(fixture: &mut EraseFixture) -> SecurityTransactionRecord {
    let persistence = fixture.state.test_persistence();
    let account = fixture.pcr.history.account.clone();
    let authorizer = fixture.pcr.history.founding_device_id.clone();
    let authorize_event_id = fixture.revoker_authorization_ref.event_id.clone();
    let revoke = coland_test_support::device_authorization_history::sign_event(
        fixture.pcr.history.raw_event(
            EventKind::DeviceRevoke,
            json!({
                "device_id": authorizer,
                "revoked_by": fixture.revoker_id,
                "revoked_at": chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "reason": "security_rotation"
            }),
            &fixture.pcr.history.events[0].realm_id,
        ),
        fixture.revoker_verification_method.clone(),
        fixture.revoker_signing_seed,
    );
    fixture.pcr.history.append(vec![revoke.clone()]);
    let covering = fixture.pcr.history.commits.last().unwrap().clone();

    let replacement_series =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let mut replacement = backup_value(
        &fixture.pcr,
        &replacement_series,
        &authorize_event_id,
        "revocation-replacement",
    );
    replacement.auth_data.device_id = fixture.revoker_id.clone();
    replacement.auth_data.verification_method = fixture.revoker_verification_method.clone();
    replacement.auth_data.device_authorize_event_id = authorize_event_id.clone();
    replacement.auth_data.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&fixture.revoker_signing_seed)
                .sign(&replacement.signing_payload_bytes().unwrap())
                .to_bytes(),
        ))
        .unwrap();
    let unsigned = UnsignedKeyBackupActiveSeries::new(
        ActorId::account(account.clone()),
        arkret_models_crypto::BackupKind::SecretStorage,
        replacement_series.clone(),
        2,
        vec![fixture.active_series_id.clone()],
        covering.commit_id.clone(),
        covering.committed_at,
        fixture.revoker_verification_method.clone(),
        ControllerBackupTrustAnchor {
            authorize_event_id,
            generation_ref: 1,
        },
    )
    .unwrap();
    let pointer_signature = ed25519_dalek::SigningKey::from_bytes(&fixture.revoker_signing_seed)
        .sign(&unsigned.signing_payload_bytes().unwrap())
        .to_bytes();
    let replacement_pointer = unsigned
        .attach_signature(
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                pointer_signature,
            ))
            .unwrap(),
        )
        .unwrap();
    let replacement_pointer_event = coland_test_support::device_authorization_history::sign_event(
        fixture.pcr.history.raw_event(
            EventKind::KeyBackupActiveSeries,
            serde_json::to_value(replacement_pointer).unwrap(),
            &fixture.pcr.history.events[0].realm_id,
        ),
        fixture.revoker_verification_method.clone(),
        fixture.revoker_signing_seed,
    );
    let request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account,
        fixture.revoker_id.clone(),
        covering.committed_at + chrono::TimeDelta::hours(1),
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            PreparedEventBatchRequest {
                events: vec![revoke.clone()],
            },
        )
        .unwrap(),
        test_hash("revoked-authorizer-secret"),
        vec![BackupRotationPlan {
            binding: BackupRotationBinding {
                backup_kind: BackupRotationKind::SecretStorage,
                previous_series_id: fixture.active_series_id.clone(),
                new_series_id: replacement_series,
                new_backups: vec![BackupObjectRef {
                    backup_id: replacement.backup_id.clone(),
                    ciphertext_digest: replacement.ciphertext_digest.clone(),
                }],
                active_series_event_id: replacement_pointer_event.event_id.clone(),
                old_backups: fixture.request.series[0].old_backups.clone(),
            },
            new_backup_envelopes: vec![replacement],
            active_series_unit: PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                PreparedEventBatchRequest {
                    events: vec![replacement_pointer_event],
                },
            )
            .unwrap(),
        }],
    )
    .unwrap();
    let plan = SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan.clone());
    let (initial, canonical_request) = SecurityTransactionCreateRequest::SecurityRotation(request)
        .into_initial_resource(plan, covering.committed_at)
        .unwrap();
    let transaction_id = initial.transaction_id.clone();
    let transactions = persistence.security_transactions();
    transactions
        .create(SecurityTransactionRecord {
            resource: initial.clone(),
            canonical_request: canonical_request.clone(),
        })
        .await
        .unwrap();
    let mut proposed = initial;
    proposed.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
    });
    transactions
        .commit_revoke_proposal(RevokeProposalCommitWrite {
            transaction: SecurityTransactionRecord {
                resource: proposed,
                canonical_request,
            },
            commit: AuthorityCommitTransaction {
                expected_authority: fixture.pcr.unit.transactions[1].expected_authority.clone(),
                event: revoke.clone(),
                commit: covering.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: covering.committed_at,
        })
        .await
        .unwrap();

    transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap()
}

async fn accept_authorizer_revocation(
    fixture: &EraseFixture,
    mut accepted: SecurityTransactionRecord,
) {
    let persistence = fixture.state.test_persistence();
    let proposal = accepted.resource.revoke_proposal.as_ref().unwrap().clone();
    let decided_at = chrono::Utc::now();
    let transaction_id = accepted.resource.transaction_id.clone();
    accepted.resource.accepted_steps.push(AcceptedStep {
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: fixture.state.service_core_id(),
        },
        accepted_at: decided_at,
    });
    accepted.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: proposal.proposal_event_id,
        covering_commit_id: proposal.covering_commit_id,
        result: SecurityRotationRevokeCommandDecision::Accepted,
        decided_at,
    });
    persistence
        .security_transactions()
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            step_outcome: Some(SecurityTransactionStepOutcomeRecord {
                transaction_id: transaction_id.to_string(),
                step: SecurityTransactionStep::Revoke,
                canonical_request: b"revoked-authorizer-terminal".to_vec(),
                response: serde_json::to_value(&accepted.resource).unwrap(),
                participant_outcome: None,
            }),
            transaction: accepted,
        })
        .await
        .unwrap();
}

async fn assert_old_backup_was_not_touched(fixture: &EraseFixture) {
    let persistence = fixture.state.test_persistence();
    assert!(
        persistence
            .key_backups()
            .get(fixture.old_backup_id.as_str())
            .await
            .unwrap()
            .is_some(),
        "the refusal must happen before deletion"
    );
    assert!(
        persistence
            .security_transactions()
            .backup_erase_progress(fixture.record.resource.transaction_id.as_str())
            .await
            .unwrap()
            .is_none(),
        "the refusal must not freeze partial erase progress"
    );
}

#[tokio::test]
async fn erase_worker_refuses_a_revoked_authorizer_without_deleting_old_backups() {
    let mut fixture = erase_fixture().await;
    let proposal = propose_authorizer_revocation(&mut fixture).await;
    accept_authorizer_revocation(&fixture, proposal).await;
    let error = coland_http::security_rotation_worker::execute_erase_for_test(
        &fixture.state,
        fixture.record.clone(),
        &fixture.request,
    )
    .await
    .unwrap_err();
    assert_eq!(error.wire_code(), "failed_precondition", "{error}");
    assert_old_backup_was_not_touched(&fixture).await;
}

async fn assert_forward_refused_before_effects(fixture: &EraseFixture, expected: &str) {
    let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    let event = coland_test_support::device_authorization_history::sign_event(
        fixture.pcr.history.raw_event(
            EventKind::RealmProfile,
            arkret_models_collaboration::events_payloads::RealmProfile::new(
                "refused forwarding attempt",
            )
            .unwrap()
            .to_value()
            .unwrap(),
            &realm_id,
        ),
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let store = fixture.state.test_persistence();
    let pcr_stream = fixture.pcr.history.commits[0].stream_ref.clone();
    let before = store
        .authority_commits()
        .stream_head(&pcr_stream)
        .await
        .unwrap();
    // No remote service is needed: reaching service resolution, HTTP or the
    // queue would return a different error or leave an observable Event.
    let error = coland_http::test_forward_self_event(
        &fixture.state,
        &arkret_wire::DidCoreId::new("ak:did_core:web:governance.example").unwrap(),
        arkret_wire::EventAdmissionSubmission::new(event.clone()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .conflict_code()
            .map(coland_storage::ConflictCode::as_str),
        Some(expected),
        "{error}"
    );
    assert!(
        store
            .authority_commits()
            .queued_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .authority_commits()
            .stream_head(&arkret_wire::CommitStreamRef::Realm { realm_id })
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .authority_commits()
            .stream_head(&pcr_stream)
            .await
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn authority_forward_pending_device_is_refused_before_queueing() {
    let mut fixture = erase_fixture().await;
    propose_authorizer_revocation(&mut fixture).await;
    assert_forward_refused_before_effects(&fixture, "device_revocation_pending").await;
}

#[tokio::test]
async fn authority_forward_revoked_device_is_refused_before_queueing() {
    let mut fixture = erase_fixture().await;
    let proposal = propose_authorizer_revocation(&mut fixture).await;
    accept_authorizer_revocation(&fixture, proposal).await;
    assert_forward_refused_before_effects(&fixture, "device_revoked").await;
}

#[tokio::test]
async fn erase_worker_refuses_a_wrong_authority_commit_without_deleting_old_backups() {
    let mut fixture = erase_fixture().await;
    fixture.request.authority_commit_id = fixture.authorizer.authorization_ref.commit_id.clone();
    assert_ne!(
        fixture.request.authority_commit_id,
        fixture.pointer_ref.commit_id
    );
    let error = coland_http::security_rotation_worker::execute_erase_for_test(
        &fixture.state,
        fixture.record.clone(),
        &fixture.request,
    )
    .await
    .unwrap_err();
    assert_eq!(error.wire_code(), "failed_precondition", "{error}");
    assert_old_backup_was_not_touched(&fixture).await;
}
