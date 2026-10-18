//! Recovery storage boundary: an accepted policy and a verified session feed
//! the real terminal unit. Factor/session HTTP verification is outside this
//! fixture; no SQL manufactures a generation, device authorization or Commit.

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, DeviceReanchorPayload, SignatureMaterial,
    device_authorize_payload_digest,
};
use arkret_models_crypto::*;
use arkret_wire::*;
use coland_storage::{
    RecoveryAuthorityContext, RecoveryPolicyPublicationWrite, RecoverySessionLifecycle,
    RecoverySessionRecord, RecoveryUnitCommitWrite, SecurityTransactionRecord,
    SecurityTransactionStepOutcomeRecord,
};
use coland_test_support::AppStateTestExt as _;
use coland_test_support::device_authorization_history::{
    DeviceAuthorizationSpec, possession_with, sign_event,
};
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use diesel::sql_types::Jsonb;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

struct Fixture {
    state: coland_http::state::AppState,
    pool: coland_storage_postgres::PgPool,
    pcr: PcrGenesisFixture,
    initial: SecurityTransactionRecord,
    write: RecoveryUnitCommitWrite,
}

fn hash(value: impl serde::Serialize) -> Hash {
    Hash::new(arkret_canonical::canonical_sha256(&value).unwrap()).unwrap()
}

fn signature(seed: [u8; 32], bytes: &[u8]) -> Base64UrlString {
    Base64UrlString::new(arkret_canonical::base64url_encode(
        SigningKey::from_bytes(&seed).sign(bytes).to_bytes(),
    ))
    .unwrap()
}

async fn fixture() -> Fixture {
    let (state, pool) = coland_test_support::app_state_with_pool(coland_test_support::app_config());
    // A killed test can leave its DDL in a reused, exclusively leased database.
    let mut conn = pool.get().await.unwrap();
    conn.batch_execute("DROP FUNCTION IF EXISTS fail_policy_boundary() CASCADE; DROP FUNCTION IF EXISTS fail_recovery_boundary() CASCADE;").await.unwrap();
    drop(conn);
    let store = state.test_persistence();
    let mut pcr = PcrGenesisFixture::new(state.service_did());
    pcr.admit_founding_device(store.as_ref()).await.unwrap();
    let account = pcr.history.account.clone();
    let realm = pcr.history.events[0].realm_id.clone();
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let expires = now + chrono::TimeDelta::minutes(15);
    let policy_id = PolicyId::new(format!("ak:policy:{}", uuid::Uuid::now_v7())).unwrap();
    let mut policy: RecoveryPolicy = serde_json::from_value(json!({
        "schema": "ak.schema.recovery_policy.v1", "policy_id": policy_id,
        "account_id": account, "version": 1, "supersedes_id": null,
        "trust_domain": "ak:trust_domain:fixture.example",
        "issued_at": arkret_canonical::format_timestamp_canonical(now),
        "auth_data": {"verification_method": pcr.history.device_verification_method,
                      "signature_algorithm": "Ed25519", "signature": "AA"},
        "methods": [{"kind": "did_root"}]
    }))
    .unwrap();
    policy.auth_data.signature = signature(
        pcr.history.founding_device_signing_seed,
        &recovery_policy_signature_transcript_bytes(&policy).unwrap(),
    );
    let policy_event = pcr.history.event(
        EventKind::PolicySet,
        json!({"policy_id": policy_id, "value": policy}),
    );
    pcr.history.append(vec![policy_event.clone()]);
    let policy_commit = pcr.history.commits.last().unwrap().clone();
    store
        .recovery_policies()
        .commit_publication(RecoveryPolicyPublicationWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: pcr.unit.transactions[1].expected_authority.clone(),
                event: policy_event,
                commit: policy_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: now,
        })
        .await
        .unwrap();
    let predecessor = store
        .authority_commits()
        .stream_head(&policy_commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    let device_id = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let session_id =
        RecoverySessionId::new(format!("ak:recovery_session:{}", uuid::Uuid::now_v7())).unwrap();
    let replacement_seed = [96; 32];
    let replacement_method = DidUrl::new(format!("{}#{device_id}", pcr.history.did)).unwrap();
    let mut authorize_payload = possession_with(
        &account,
        DeviceAuthorizationSpec {
            device_id: device_id.clone(),
            signing_seed: replacement_seed,
            hpke_seed: [97; 32],
            authorized_by: DeviceOrPrincipalRef::Principal(account.principal_id.clone()),
            not_before: now,
            expires_at: None,
            binding: DeviceAuthorizationBindingKind::PcrRecovery,
            authorized_generation_ref: 2,
            applet_id: None,
        },
    );
    // Re-sign the possession transcript after binding this unique session.
    authorize_payload.recovery_session_id = Some(session_id.clone());
    authorize_payload.device_signature = SignatureMaterial::NonEmptyString(
        NonEmptyString::new(
            signature(
                replacement_seed,
                &authorize_payload
                    .device_possession_signature_input(&account)
                    .unwrap(),
            )
            .to_string(),
        )
        .unwrap(),
    );
    let authorize_value = serde_json::to_value(&authorize_payload).unwrap();
    let root_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[70; 32]).verifying_key().to_bytes(),
    );
    let root_method = DidUrl::new(format!("did:key:{root_key}#{root_key}")).unwrap();
    let context: PublicationAuthorityContext = serde_json::from_value(json!({
        "authority_commit_id": policy_commit.commit_id, "scope_ref": policy_commit.stream_ref,
        "authority_set_policy": {
            "schema": "ak.schema.authority_set_policy.v1", "authority_set_id": AuthoritySetId::RECOVERY_IDENTITY_REANCHOR_V1,
            "policy_kind": "principal_control", "scope_ref": policy_commit.stream_ref,
            "source_commit_id": policy_commit.commit_id,
            "authorization_rules": [{"rule_id": "did_root", "issuer_role": "identity_recovery",
                "allowed_actions": ["ak.device.reanchor"], "issuers": [{"verification_method": root_method}], "threshold": 1}]
        }, "allowed_actions": ["ak.device.reanchor"]
    })).unwrap();
    context.validate_shape().unwrap();
    let context_digest = hash(&context);
    let request_id = RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7())).unwrap();
    let grant_id = SessionGrantId::from_issuance_digest(arkret_canonical::sha256_bytes(
        session_id.as_str().as_bytes(),
    ));
    let challenge = Base64UrlString::new("Y2hhbGxlbmdl").unwrap();
    let transcript = DidRootRecoveryTranscript {
        schema: RECOVERY_PROOF_TRANSCRIPT_SCHEMA.to_owned(),
        kind: RecoveryProofKind::DidRoot,
        request_id: request_id.clone(),
        session_grant_id: grant_id.clone(),
        session_grant_cnf_jkt: Base64UrlString::new("A".repeat(43)).unwrap(),
        account_id: account.clone(),
        requesting_device_id: device_id.clone(),
        requesting_device_public_key_did: DidKey::new(
            authorize_payload.device_public_key_did.to_string(),
        )
        .unwrap(),
        trust_domain: policy.trust_domain.clone(),
        policy_id: policy_id.clone(),
        policy_version: 1,
        recovery_session_id: session_id.clone(),
        identity_model: RecoveryIdentityModel::PcrPolicy,
        model_generation_ref: 1,
        publication_authority_context_digest: context_digest.clone(),
        challenge: challenge.clone(),
        expires_at: expires,
        created_at: now,
    };
    let proof = RecoverySessionProof::DidRoot(DidRootProofBody {
        kind: DidRootProofKind::DidRoot,
        challenge: challenge.clone(),
        verification_method: root_method,
        signature_algorithm: RecoverySignatureAlgorithm::Ed25519,
        signature: signature(
            [70; 32],
            &arkret_canonical::canonical_json_bytes(&transcript).unwrap(),
        ),
    });
    // This is the verified-session storage input boundary, not a claim that
    // the session HTTP factor verifier was exercised by this fixture.
    store
        .recovery_sessions()
        .insert(RecoverySessionRecord {
            request_id: request_id.to_string(),
            create_intent_digest: hash(&transcript).to_string(),
            recovery_session_id: session_id.to_string(),
            session_grant_id: grant_id.to_string(),
            session_grant_cnf_jkt: "A".repeat(43),
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            requesting_device_id: device_id.to_string(),
            requesting_device_public_key_did: authorize_payload.device_public_key_did.to_string(),
            trust_domain: policy.trust_domain.to_string(),
            policy_id: policy_id.to_string(),
            policy_version: 1,
            identity_model: RecoveryIdentityModel::PcrPolicy,
            current_device_generation_ref: 1,
            accepted_stream_head: predecessor.clone(),
            policy_payload: serde_json::to_value(&policy).unwrap(),
            authority_context: RecoveryAuthorityContext {
                realm_id: realm.clone(),
                authority_generation: 0,
                authority_ref: policy_commit.authority_ref.clone(),
                realm_stream_head: predecessor.clone(),
            },
            publication_authority_context: context,
            publication_authority_context_digest: context_digest,
            challenge: challenge.to_string(),
            state: RecoverySessionLifecycle::Verified,
            proof_payload: Some(json!({"proof": proof})),
            transaction_id: None,
            created_at: now,
            updated_at: now,
            expires_at: expires,
        })
        .await
        .unwrap();
    let reanchor_payload = DeviceReanchorPayload {
        account_id: account.clone(),
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        recovery_policy_id: policy_id.clone(),
        recovery_policy_version: 1,
        recovery_session_id: session_id.clone(),
        previous_device_generation: 1,
        new_device_generation: 2,
        did_root_evidence_digest: None,
        replacement_authorize_payload_digest: device_authorize_payload_digest(
            &authorize_value,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
    };
    let reanchor = sign_event(
        pcr.history.raw_event(
            EventKind::DeviceReanchor,
            serde_json::to_value(reanchor_payload).unwrap(),
            &realm,
        ),
        replacement_method.clone(),
        replacement_seed,
    );
    let authorize = sign_event(
        pcr.history
            .raw_event(EventKind::DeviceAuthorize, authorize_value, &realm),
        replacement_method.clone(),
        replacement_seed,
    );
    let unit = PreparedEventUnit::new(
        arkret_canonical::DigestSuite::Sha256,
        arkret_wire::EventsSubmitBatchRequestBody {
            events: (vec![reanchor.clone(), authorize.clone()])
                .into_iter()
                .map(arkret_wire::EventAdmissionSubmission::new)
                .collect(),
        },
    )
    .unwrap();
    let intent = RecoveryCommitIntent {
        realm_id: realm,
        predecessor_ref: predecessor.commit_id.clone(),
        unit_event_digests: [
            Hash::new(
                reanchor
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap(),
            Hash::new(
                authorize
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap(),
        ],
    };
    let receipt_id = ReceiptId::new(format!("ak:receipt:{}", uuid::Uuid::now_v7())).unwrap();
    let plan = PcrPolicyRecoveryPlan {
        binding: PcrPolicyRecoveryBinding {
            identity_model: RecoveryIdentityModel::PcrPolicy,
            recovery_session_id: session_id.clone(),
            replacement_device_id: device_id.clone(),
            reanchor_event_id: reanchor.event_id.clone(),
            authorize_event_id: authorize.event_id.clone(),
            terminal_receipt_id: receipt_id.clone(),
        },
        recovery_session_snapshot_digest: hash(&transcript),
        proof_digest: hash(&proof),
        previous_model_generation_ref: 1,
        result_model_generation_ref: 2,
        reanchor_unit: unit.clone(),
        reanchor_commit_intent: intent.clone(),
    };
    let request = RecoveryTransactionCreateRequest::new(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        expires,
        PcrPolicyRecoveryIntent {
            recovery_session_id: session_id.clone(),
            replacement_device_id: device_id.clone(),
            previous_model_generation_ref: 1,
            result_model_generation_ref: 2,
            terminal_receipt_id: receipt_id.clone(),
            reanchor_unit: unit,
            reanchor_commit_intent: intent,
        },
    )
    .unwrap();
    let (resource, canonical_request) = SecurityTransactionCreateRequest::Recovery(request)
        .into_initial_resource(SecurityTransactionPreparedPlan::Recovery(plan), now)
        .unwrap();
    let initial = SecurityTransactionRecord {
        resource,
        canonical_request,
    };
    store
        .security_transactions()
        .create(initial.clone())
        .await
        .unwrap();
    let authority = store
        .authority_commits()
        .current_authority(&pcr.history.events[0].realm_id)
        .await
        .unwrap()
        .unwrap();
    let commits = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(store.clone()),
        0,
    )
    .prepare_recovery_unit_commits(
        &[reanchor, authorize],
        &authority,
        &predecessor,
        pcr.history.authority_method(),
        &SigningKey::from_bytes(
            &coland_test_support::device_authorization_history::STATION_AUTHORITY_SEED,
        ),
        now,
    )
    .unwrap();
    let committed_ref = |index: usize| CommittedEventRef {
        event_id: commits[index].event.event_id.clone(),
        commit_id: commits[index].commit.commit_id.clone(),
        stream_ref: commits[index].commit.stream_ref.clone(),
        stream_position: commits[index].commit.stream_position,
    };
    let mut receipt = RecoveryReceipt {
        schema: SchemaId::RECOVERY_RECEIPT_V1.to_owned(),
        receipt_id: receipt_id.clone(),
        transaction_id: initial.resource.transaction_id.clone(),
        transaction_request_digest: initial.resource.request_digest.clone(),
        prepared_plan_digest: initial.resource.prepared_plan_digest.clone(),
        account_id: account.clone(),
        recovery_session_id: session_id.clone(),
        policy_id,
        policy_version: 1,
        trust_domain: policy.trust_domain.clone(),
        new_device_id: device_id.clone(),
        identity_model: RecoveryIdentityModel::PcrPolicy,
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        previous_model_generation_ref: 1,
        result_model_generation_ref: 2,
        authorization_event_id: commits[1].event.event_id.clone(),
        reanchor_event_id: commits[0].event.event_id.clone(),
        proof_summary: RecoveryProofSummary {
            kind: RecoveryProofKind::DidRoot,
            proof_digest: hash(&proof),
            quorum_participant_count: None,
        },
        unlocked_backups: Vec::new(),
        welcome_count: 0,
        welcome_realm_summaries: None,
        outcome: RecoveryReceiptOutcome::Completed,
        outcome_reason_code: None,
        started_at: now,
        completed_at: now,
        auth_data: RecoveryReceiptAuthData {
            verification_method: replacement_method.clone(),
            signature_algorithm: "Ed25519".to_owned(),
            signature: Base64UrlString::new("AA").unwrap(),
        },
        extra: Default::default(),
    };
    receipt.auth_data.signature = signature(
        replacement_seed,
        &receipt.signature_transcript_bytes().unwrap(),
    );
    let terminal = RecoveryTerminalCommit {
        recovery_receipt: receipt.clone(),
    };
    let mut client_attestation = ClientStepAttestation {
        step: SecurityTransactionStep::CommitRecoveryUnit,
        output_ref: receipt_id.to_string(),
        transaction_id: initial.resource.transaction_id.clone(),
        transaction_request_digest: initial.resource.request_digest.clone(),
        prepared_plan_digest: initial.resource.prepared_plan_digest.clone(),
        artifact: ClientStepAttestationArtifact::Recovery(terminal.clone()),
        auth_data: ClientStepAttestationAuthData {
            verification_method: replacement_method,
            signature_algorithm: "Ed25519".to_owned(),
            signature: Base64UrlString::new("AA").unwrap(),
        },
    };
    client_attestation.auth_data.signature = signature(
        replacement_seed,
        &client_attestation.signing_bytes().unwrap(),
    );
    let terminal_request = SecurityTransactionContinueRequest {
        request_digest: initial.resource.request_digest.clone(),
        prepared_plan_digest: initial.resource.prepared_plan_digest.clone(),
        expected_accepted_step_count: 0,
        client_attestation,
    };
    terminal_request
        .validate_for_transaction(&initial.resource)
        .unwrap();
    let unsigned = UnsignedRecoveryCompletionAttestation::new(
        UnsignedRecoveryCompletionAttestationBody {
            transaction_id: initial.resource.transaction_id.clone(),
            transaction_request_digest: initial.resource.request_digest.clone(),
            prepared_plan_digest: initial.resource.prepared_plan_digest.clone(),
            account_id: account,
            recovery_session_id: session_id,
            terminal_receipt_id: receipt_id.clone(),
            terminal_receipt_digest: hash(&receipt),
            replacement_device_id: device_id,
            result_model_generation_ref: 2,
            completed_at: now,
            reanchor_event_ref: committed_ref(0),
            device_authorization_event_ref: committed_ref(1),
        },
        pcr.history.authority_method(),
    )
    .unwrap();
    let completion_signature = signature(
        coland_test_support::device_authorization_history::STATION_AUTHORITY_SEED,
        &unsigned.signing_bytes().unwrap(),
    );
    let completion = unsigned.attach_signature(completion_signature).unwrap();
    let mut completed = initial.clone();
    completed
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: state.service_core_id(),
            },
            accepted_at: now,
        });
    completed.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Completed {
        completed_at: now,
        receipt_id: Some(receipt_id),
        completion_attestation: Some(completion),
    });
    let write = RecoveryUnitCommitWrite {
        step_outcome: SecurityTransactionStepOutcomeRecord {
            transaction_id: completed.resource.transaction_id.to_string(),
            step: SecurityTransactionStep::CommitRecoveryUnit,
            canonical_request: arkret_canonical::canonical_json_bytes(&terminal_request).unwrap(),
            response: serde_json::to_value(&completed.resource).unwrap(),
            participant_outcome: Some(serde_json::to_value(terminal).unwrap()),
        },
        transaction: completed,
        predecessor,
        commits,
        queued_at: now,
    };
    write.validate().unwrap();
    Fixture {
        state,
        pool,
        pcr,
        initial,
        write,
    }
}

#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn footprint(fixture: &Fixture) -> Value {
    let mut conn = fixture.pool.get().await.unwrap();
    let mut result = serde_json::Map::new();
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_commit_event_kinds",
        "realm_authorities",
        "recovery_policies",
        "policy_current_results",
        "devices",
        "pcr_device_generation_current_results",
        "pcr_device_authorization_current_results",
        "account_global_versions",
        "account_global_clock",
        "account_global_channel_clocks",
        "security_transactions",
        "security_transaction_step_attempts",
        "security_transaction_step_outcomes",
        "recovery_sessions",
        "device_messages",
    ] {
        let row = diesel::sql_query(format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS value FROM {table} t"))
            .get_result::<JsonRow>(&mut conn).await.unwrap();
        result.insert(table.to_owned(), row.value);
    }
    Value::Object(result)
}

async fn assert_old_device_fenced(fixture: &Fixture) {
    let realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    let event = sign_event(
        fixture.pcr.history.raw_event(
            EventKind::RealmProfile,
            arkret_models_collaboration::events_payloads::RealmProfile::new("fenced attempt")
                .unwrap()
                .to_value()
                .unwrap(),
            &realm_id,
        ),
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let before = footprint(fixture).await;
    let error = coland_http::test_forward_self_event(
        &fixture.state,
        &DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
        EventAdmissionSubmission::new(event.clone()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .conflict_code()
            .map(coland_storage::ConflictCode::as_str),
        Some("device_generation_fenced"),
        "{error}"
    );
    let store = fixture.state.test_persistence();
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
            .stream_head(&CommitStreamRef::Realm { realm_id })
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(footprint(fixture).await, before);
}

#[tokio::test]
async fn recovery_terminal_unit_fences_old_device_and_replays_after_response_loss() {
    let fixture = fixture().await;
    let store = fixture.state.test_persistence();
    // Discard the first result, then retry through a freshly constructed PG adapter.
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let before = footprint(&fixture).await;
    let restarted = coland_storage_postgres::PgSecurityTransactionStore {
        pool: fixture.pool.clone(),
    };
    use coland_storage::SecurityTransactionStore as _;
    let replay = restarted
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    assert_eq!(replay.response, fixture.write.step_outcome.response);
    assert_eq!(footprint(&fixture).await, before);
    let head = store
        .authority_commits()
        .stream_head(&fixture.write.predecessor.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.commit_id, fixture.write.commits[1].commit.commit_id);
    let session = store
        .recovery_sessions()
        .get(
            fixture
                .initial
                .resource
                .recovery_plan()
                .unwrap()
                .binding
                .recovery_session_id
                .as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.state, RecoverySessionLifecycle::Completed);
    assert_old_device_fenced(&fixture).await;
    let mut changed = fixture.write.clone();
    // Different canonical input cannot reuse the first outcome, even when
    // its outer request remains structurally well formed.
    let mut request: SecurityTransactionContinueRequest =
        serde_json::from_slice(&fixture.write.step_outcome.canonical_request).unwrap();
    request.client_attestation.auth_data.signature = Base64UrlString::new("AQ").unwrap();
    changed.step_outcome.canonical_request =
        arkret_canonical::canonical_json_bytes(&request).unwrap();
    assert!(matches!(
        restarted.commit_recovery_unit(changed).await,
        Err(coland_storage::PersistenceError::Conflict(_))
    ));
    assert_eq!(footprint(&fixture).await, before);
}

#[tokio::test]
async fn completed_recovery_device_is_admitted_without_inventory_projection() {
    let fixture = fixture().await;
    let store = fixture.state.test_persistence();
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(
            serde_json::to_value(&fixture.write.commits[1].event.payload).unwrap(),
        )
        .unwrap();
    let account = &fixture.pcr.history.account;
    let missing = store
        .devices()
        .get(account.principal_id.as_str(), payload.device_id.as_str())
        .await
        .unwrap();
    assert!(
        missing.is_none(),
        "the fixture must not supply an authorization mirror"
    );
    let selector = coland_http::test_active_device_revocation_gate_selector(
        &fixture.state,
        account.principal_id.as_str(),
        payload.device_id.as_str(),
    )
    .await
    .unwrap();
    let committed = &fixture.write.commits[1];
    assert_eq!(
        selector.authorization_ref,
        CommittedEventRef {
            event_id: committed.event.event_id.clone(),
            commit_id: committed.commit.commit_id.clone(),
            stream_ref: committed.commit.stream_ref.clone(),
            stream_position: committed.commit.stream_position,
        }
    );
    let gates = coland_storage_postgres::PgDeviceRevocationStore {
        pool: fixture.pool.clone(),
    };
    assert_eq!(
        gates
            .test_gate_status_in_transaction(&selector)
            .await
            .unwrap(),
        coland_storage::DeviceRevocationGateStatus::Active
    );
    let mut wrong = selector;
    wrong.authorization_ref = CommittedEventRef {
        event_id: fixture.write.commits[0].event.event_id.clone(),
        commit_id: fixture.write.commits[0].commit.commit_id.clone(),
        stream_ref: fixture.write.commits[0].commit.stream_ref.clone(),
        stream_position: fixture.write.commits[0].commit.stream_position,
    };
    assert_eq!(
        gates.test_gate_status_in_transaction(&wrong).await.unwrap(),
        coland_storage::DeviceRevocationGateStatus::GenerationMismatch
    );
    assert_old_device_fenced(&fixture).await;
}

#[tokio::test]
async fn recovery_terminal_metadata_must_bind_the_exact_receipt_and_response() {
    let fixture = fixture().await;
    let before = footprint(&fixture).await;
    for case in 0..6 {
        let mut write = fixture.write.clone();
        match case {
            0 => write.step_outcome.response = json!({"unrelated":"response"}),
            1 => write.step_outcome.participant_outcome = None,
            2 => {
                write.step_outcome.participant_outcome.as_mut().unwrap()["recovery_receipt"]["auth_data"]
                    ["signature"] = json!("AQ")
            }
            3 => {
                let Some(SecurityTransactionTerminalOutcome::Completed {
                    completion_attestation: Some(completion),
                    ..
                }) = &mut write.transaction.resource.terminal_outcome
                else {
                    unreachable!()
                };
                completion.terminal_receipt_digest = hash("different receipt");
                write.step_outcome.response =
                    serde_json::to_value(&write.transaction.resource).unwrap();
            }
            4 => {
                let mut request: SecurityTransactionContinueRequest =
                    serde_json::from_slice(&write.step_outcome.canonical_request).unwrap();
                request.expected_accepted_step_count = 1;
                write.step_outcome.canonical_request =
                    arkret_canonical::canonical_json_bytes(&request).unwrap();
            }
            5 => {
                let mut request: SecurityTransactionContinueRequest =
                    serde_json::from_slice(&write.step_outcome.canonical_request).unwrap();
                request.client_attestation.auth_data.verification_method =
                    DidUrl::new("did:web:another.example#device").unwrap();
                write.step_outcome.canonical_request =
                    arkret_canonical::canonical_json_bytes(&request).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                fixture
                    .state
                    .test_persistence()
                    .security_transactions()
                    .commit_recovery_unit(write)
                    .await,
                Err(coland_storage::PersistenceError::SchemaViolation(_))
            ),
            "case {case}"
        );
        assert_eq!(
            footprint(&fixture).await,
            before,
            "case {case} wrote durable state"
        );
    }
    fixture
        .state
        .test_persistence()
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    assert_old_device_fenced(&fixture).await;
}

async fn policy_revocation_write(fixture: &mut Fixture) -> RecoveryPolicyPublicationWrite {
    let store = fixture.state.test_persistence();
    let active = store
        .recovery_policies()
        .get_active_for_account(&fixture.pcr.history.account)
        .await
        .unwrap()
        .unwrap();
    let mut revoke: RecoveryPolicy = serde_json::from_value(active.raw_payload).unwrap();
    revoke.supersedes_id = Some(revoke.policy_id.clone());
    revoke.policy_id = PolicyId::new(format!("ak:policy:{}", uuid::Uuid::now_v7())).unwrap();
    revoke.version = 2;
    revoke.methods.clear();
    revoke.auth_data.signature = signature(
        fixture.pcr.history.founding_device_signing_seed,
        &recovery_policy_signature_transcript_bytes(&revoke).unwrap(),
    );
    let event = fixture.pcr.history.event(
        EventKind::PolicySet,
        json!({"policy_id":revoke.policy_id,"value":revoke}),
    );
    fixture.pcr.history.append(vec![event.clone()]);
    let commit = fixture.pcr.history.commits.last().unwrap().clone();
    RecoveryPolicyPublicationWrite {
        commit: coland_storage::AuthorityCommitTransaction {
            expected_authority: fixture.pcr.unit.transactions[1].expected_authority.clone(),
            event,
            commit: commit.clone(),
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
        queued_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn accepted_policy_revocation_refuses_a_prepared_recovery_without_fencing() {
    let mut fixture = fixture().await;
    let write = policy_revocation_write(&mut fixture).await;
    let store = fixture.state.test_persistence();
    store
        .recovery_policies()
        .commit_publication(write)
        .await
        .unwrap();
    let before = footprint(&fixture).await;
    assert!(
        store
            .security_transactions()
            .commit_recovery_unit(fixture.write.clone())
            .await
            .is_err()
    );
    assert_eq!(footprint(&fixture).await, before);
    assert_eq!(
        store
            .security_transactions()
            .get(fixture.initial.resource.transaction_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .resource,
        fixture.initial.resource
    );
}

#[tokio::test]
async fn policy_revocation_boundaries_roll_back_and_response_loss_replays_without_writes() {
    let mut fixture = fixture().await;
    let history_len = fixture.pcr.history.events.len();
    let write = policy_revocation_write(&mut fixture).await;
    fixture.pcr.history.events.truncate(history_len);
    fixture.pcr.history.commits.truncate(history_len);
    // A second valid publication is prepared at the same original PCR cut.
    let conflicting = policy_revocation_write(&mut fixture).await;
    let before = footprint(&fixture).await;
    for (table, condition) in [
        ("canonical_events", "NEW.kind='ak.policy.set'"),
        ("realm_commits", "TRUE"),
        ("realm_commit_event_kinds", "TRUE"),
        ("policy_current_results", "TRUE"),
        ("recovery_policies", "TRUE"),
        ("recovery_sessions", "NEW.state='rejected'"),
    ] {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute(&format!("CREATE FUNCTION fail_policy_boundary() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition} THEN RAISE EXCEPTION 'injected policy durable boundary'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_policy_boundary BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION fail_policy_boundary();")).await.unwrap();
        drop(conn);
        let result = fixture
            .state
            .test_persistence()
            .recovery_policies()
            .commit_publication(write.clone())
            .await;
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute(&format!(
            "DROP TRIGGER fail_policy_boundary ON {table}; DROP FUNCTION fail_policy_boundary();"
        ))
        .await
        .unwrap();
        drop(conn);
        let error = result.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected policy durable boundary"),
            "{table}: {error}"
        );
        assert_eq!(footprint(&fixture).await, before, "rollback at {table}");
    }
    fixture
        .state
        .test_persistence()
        .recovery_policies()
        .commit_publication(write.clone())
        .await
        .unwrap();
    let accepted = footprint(&fixture).await;
    use coland_storage::RecoveryPolicyStore as _;
    let restarted = coland_storage_postgres::PgRecoveryPolicyStore {
        pool: fixture.pool.clone(),
    };
    let replay = restarted.commit_publication(write.clone()).await.unwrap();
    let coland_storage::RecoveryPolicyPublicationOutcome::Duplicate(policy) = replay else {
        panic!("policy replay created a second acceptance")
    };
    assert_eq!(policy.acceptance_basis, write.commit.commit.commit_id);
    assert_eq!(footprint(&fixture).await, accepted);
    assert!(matches!(
        restarted.commit_publication(conflicting).await,
        Err(coland_storage::PersistenceError::Conflict(_))
    ));
    assert_eq!(footprint(&fixture).await, accepted);
    let session = fixture
        .state
        .test_persistence()
        .recovery_sessions()
        .get(
            fixture
                .initial
                .resource
                .recovery_plan()
                .unwrap()
                .binding
                .recovery_session_id
                .as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.state, RecoverySessionLifecycle::Rejected);
    let current = restarted
        .get_active_for_account(&fixture.pcr.history.account)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.version, 2);
    assert_eq!(current.acceptance_basis, write.commit.commit.commit_id);
}

#[tokio::test]
async fn every_recovery_durable_boundary_rolls_back_both_commits_and_terminal_ledger() {
    let fixture = fixture().await;
    let before = footprint(&fixture).await;
    let first = fixture.write.commits[0].commit.stream_position;
    let second = fixture.write.commits[1].commit.stream_position;
    for (table, condition) in [
        (
            "canonical_events",
            "NEW.kind='ak.device.reanchor'".to_owned(),
        ),
        ("realm_commits", format!("NEW.stream_position={first}")),
        (
            "realm_commit_event_kinds",
            "NEW.kind='ak.device.reanchor'".to_owned(),
        ),
        ("pcr_device_generation_current_results", "TRUE".to_owned()),
        (
            "canonical_events",
            "NEW.kind='ak.device.authorize'".to_owned(),
        ),
        ("realm_commits", format!("NEW.stream_position={second}")),
        (
            "realm_commit_event_kinds",
            "NEW.kind='ak.device.authorize'".to_owned(),
        ),
        (
            "pcr_device_authorization_current_results",
            "TRUE".to_owned(),
        ),
        ("account_global_versions", "TRUE".to_owned()),
        ("account_global_clock", "TRUE".to_owned()),
        ("account_global_channel_clocks", "TRUE".to_owned()),
        ("security_transaction_step_attempts", "TRUE".to_owned()),
        ("security_transaction_step_outcomes", "TRUE".to_owned()),
        (
            "security_transactions",
            "NEW.terminal_outcome IS NOT NULL".to_owned(),
        ),
        ("recovery_sessions", "NEW.state='completed'".to_owned()),
    ] {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute(&format!("CREATE FUNCTION fail_recovery_boundary() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition} THEN RAISE EXCEPTION 'injected recovery durable boundary'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_recovery_boundary BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION fail_recovery_boundary();")).await.unwrap();
        drop(conn);
        let result = fixture
            .state
            .test_persistence()
            .security_transactions()
            .commit_recovery_unit(fixture.write.clone())
            .await;
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute(&format!("DROP TRIGGER fail_recovery_boundary ON {table}; DROP FUNCTION fail_recovery_boundary();")).await.unwrap();
        drop(conn);
        let error = result.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected recovery durable boundary"),
            "{table}: {error}"
        );
        assert_eq!(footprint(&fixture).await, before, "rollback at {table}");
    }
    // A failed attempt must not freeze bytes or consume the session; the same
    // corrected terminal input can still become the first accepted outcome.
    fixture
        .state
        .test_persistence()
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    assert_old_device_fenced(&fixture).await;
}
