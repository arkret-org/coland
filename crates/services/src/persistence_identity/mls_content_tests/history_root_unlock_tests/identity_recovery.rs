//! Native identity-recovery unit using a real same-24-word policy factor.
//! The factor signature is verified before the verified-session storage port;
//! no HTTP grant issuance or factor endpoint is claimed by this adapter fixture.

use std::sync::Arc;

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, DeviceReanchorPayload, SignatureMaterial,
    device_authorize_payload_digest,
};
use arkret_models_crypto::*;
use arkret_wire::*;
use coland_storage::{
    PersistenceStore, RecoveryAuthorityContext, RecoverySessionLifecycle, RecoverySessionRecord,
    RecoveryUnitCommitWrite, SecurityTransactionRecord, SecurityTransactionStepOutcomeRecord,
};
use coland_storage_postgres::{PgPersistenceStore, PgPool};
use device_authorization_history::{DeviceAuthorizationSpec, possession_with, sign_event};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

use crate::persistence_identity::key_backup_tests::{RootFixture, device_authorization_history};

fn hash(value: impl serde::Serialize) -> Hash {
    Hash::new(arkret_canonical::canonical_sha256(&value).unwrap()).unwrap()
}
fn signature(seed: [u8; 32], bytes: &[u8]) -> Base64UrlString {
    Base64UrlString::new(arkret_canonical::base64url_encode(
        SigningKey::from_bytes(&seed).sign(bytes).to_bytes(),
    ))
    .unwrap()
}

pub(super) async fn recover(
    pool: &PgPool,
    fixture: &mut RootFixture,
) -> (DeviceId, EventId, DidUrl, [u8; 32], RecoverySessionId) {
    let material = arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
        fixture.recovery_words.as_deref().unwrap(),
        "",
        1,
    )
    .unwrap();
    let policy = fixture.policy.clone();
    let RecoveryMethod::RecoveryUnlock { keys } = &policy.methods[0] else {
        panic!("24-word policy expected")
    };
    assert!(keys.iter().any(|key| key.public_key_multibase
        == material.recovery_proof_public_key_multikey
        && key.backup_hpke.public_key_multibase == material.backup_hpke_public_key_multikey));
    let store: Arc<dyn PersistenceStore> = Arc::new(PgPersistenceStore::new(pool.clone()));
    let pcr = &mut fixture.pcr;
    let account = pcr.history.account.clone();
    let station = account.station_id.clone();
    let realm = pcr.history.events[0].realm_id.clone();
    let policy_id = policy.policy_id.clone();
    let policy_commit = pcr
        .history
        .commits
        .iter()
        .find(|commit| {
            pcr.history.events.iter().any(|event| {
                event.event_id == commit.event_ref
                    && event.kind == EventKind::PolicySet
                    && event
                        .payload
                        .get("policy_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(policy_id.as_str())
            })
        })
        .unwrap()
        .clone();
    let predecessor = store
        .authority_commits()
        .stream_head(&policy_commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let expires = now + chrono::Duration::seconds(900);
    let device_id = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let session_id =
        RecoverySessionId::new(format!("ak:recovery_session:{}", uuid::Uuid::now_v7())).unwrap();
    let replacement_seed = [122; 32];
    let replacement_method = DidUrl::new(format!("{}#{device_id}", pcr.history.did)).unwrap();
    let mut authorize_payload = possession_with(
        &account,
        DeviceAuthorizationSpec {
            device_id: device_id.clone(),
            signing_seed: replacement_seed,
            hpke_seed: [123; 32],
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
    let factor_key = material.recovery_proof_public_key_multikey.clone();
    let factor_method = DidUrl::new(format!("did:key:{factor_key}#{factor_key}")).unwrap();
    let context: PublicationAuthorityContext = serde_json::from_value(json!({
        "authority_commit_id": policy_commit.commit_id, "scope_ref": policy_commit.stream_ref,
        "authority_set_policy": {
            "schema": "ak.schema.authority_set_policy.v1", "authority_set_id": AuthoritySetId::RECOVERY_IDENTITY_REANCHOR_V1,
            "policy_kind": "principal_control", "scope_ref": policy_commit.stream_ref,
            "source_commit_id": policy_commit.commit_id,
            "authorization_rules": [{"rule_id": "recovery_unlock", "issuer_role": "identity_recovery",
                "allowed_actions": ["ak.device.reanchor"], "issuers": [{"verification_method": factor_method}], "threshold": 1}]
        }, "allowed_actions": ["ak.device.reanchor"]
    })).unwrap();
    context.validate_shape().unwrap();
    let context_digest = hash(&context);
    let request_id = RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7())).unwrap();
    let grant_id = SessionGrantId::from_issuance_digest(arkret_canonical::sha256_bytes(
        session_id.as_str().as_bytes(),
    ));
    let challenge =
        Base64UrlString::new(arkret_crypto::content_history::fresh_content_key_salt().unwrap())
            .unwrap();
    let transcript = GenericRecoveryTranscript {
        schema: RECOVERY_PROOF_TRANSCRIPT_SCHEMA.to_owned(),
        kind: RecoveryProofKind::RecoveryUnlock,
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
        policy_version: policy.version,
        recovery_session_id: session_id.clone(),
        identity_model: RecoveryIdentityModel::PcrPolicy,
        model_generation_ref: 1,
        publication_authority_context_digest: context_digest.clone(),
        challenge: challenge.clone(),
        expires_at: expires,
        created_at: now,
        proof_body: RecoveryTranscriptProofBody::RecoveryUnlock(RecoveryUnlockProofBody {
            kind: RecoveryUnlockProofKind::RecoveryUnlock,
            challenge: challenge.clone(),
            verification_method: factor_method.clone(),
            signature_algorithm: RecoverySignatureAlgorithm::Ed25519,
        }),
    };
    transcript.validate_shape().unwrap();
    let factor_bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    let factor_signature = signature(material.recovery_proof_seed, &factor_bytes);
    assert!(arkret_signatures::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: material.recovery_proof_public_key.to_vec()
        },
        &factor_bytes,
        factor_signature.as_str(),
    ));
    let proof = RecoverySessionProof::RecoveryUnlock(RecoveryUnlockProofBodyWithSignature {
        kind: RecoveryUnlockProofKind::RecoveryUnlock,
        challenge: challenge.clone(),
        verification_method: factor_method,
        signature_algorithm: RecoverySignatureAlgorithm::Ed25519,
        signature: factor_signature,
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
            policy_version: u32::try_from(policy.version).unwrap(),
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
        recovery_policy_version: policy.version,
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
        new_model_generation_ref: 2,
        reanchor_unit: unit.clone(),
        reanchor_commit_intent: intent.clone(),
    };
    let request = RecoveryTransactionCreateRequestBody::new(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        expires,
        PcrPolicyRecoveryIntent {
            recovery_session_id: session_id.clone(),
            replacement_device_id: device_id.clone(),
            previous_model_generation_ref: 1,
            new_model_generation_ref: 2,
            terminal_receipt_id: receipt_id.clone(),
            reanchor_unit: unit,
            reanchor_commit_intent: intent,
        },
    )
    .unwrap();
    let (resource, canonical_request) = SecurityTransactionCreateRequestBody::Recovery(request)
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
    let commits = crate::authority_commit::AuthorityCommitApplication::new(
        crate::persistence::PersistenceHandle::from_shared(store.clone()),
        0,
    )
    .prepare_recovery_unit_commits(
        &[reanchor, authorize],
        &authority,
        &predecessor,
        pcr.history.authority_method(),
        &SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED),
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
        policy_version: policy.version,
        trust_domain: policy.trust_domain.clone(),
        new_device_id: device_id.clone(),
        identity_model: RecoveryIdentityModel::PcrPolicy,
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        previous_model_generation_ref: 1,
        new_model_generation_ref: 2,
        authorization_event_id: commits[1].event.event_id.clone(),
        reanchor_event_id: commits[0].event.event_id.clone(),
        proof_summary: RecoveryProofSummary {
            kind: RecoveryProofKind::RecoveryUnlock,
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
        signature_proof: RecoveryReceiptSignatureProof {
            verification_method: replacement_method.clone(),
            signature_algorithm: "Ed25519".to_owned(),
            signature: Base64UrlString::new("AA").unwrap(),
        },
        extra: Default::default(),
    };
    receipt.signature_proof.signature = signature(
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
        signature_proof: ClientStepAttestationSignatureProof {
            verification_method: replacement_method,
            signature_algorithm: "Ed25519".to_owned(),
            signature: Base64UrlString::new("AA").unwrap(),
        },
    };
    client_attestation.signature_proof.signature = signature(
        replacement_seed,
        &client_attestation.signing_bytes().unwrap(),
    );
    let terminal_request = SecurityTransactionContinueRequestBody {
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
            account_id: account.clone(),
            recovery_session_id: session_id,
            terminal_receipt_id: receipt_id.clone(),
            terminal_receipt_digest: hash(&receipt),
            replacement_device_id: device_id,
            new_model_generation_ref: 2,
            completed_at: now,
            reanchor_event_ref: committed_ref(0),
            device_authorization_event_ref: committed_ref(1),
        },
        pcr.history.authority_method(),
    )
    .unwrap();
    let completion_signature = signature(
        device_authorization_history::STATION_AUTHORITY_SEED,
        &unsigned.signing_bytes().unwrap(),
    );
    let completion = unsigned.attach_signature(completion_signature).unwrap();
    let mut completed = initial.clone();
    completed
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
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
    let new_device = write.commits[1]
        .event
        .as_device_authorize()
        .unwrap()
        .device_id
        .clone();
    let new_authorization = write.commits[1].event.event_id.clone();
    let method = DidUrl::new(format!("{}#{new_device}", pcr.history.did)).unwrap();
    let session_id = plan_session_id(&write);
    let first = store
        .security_transactions()
        .commit_recovery_unit(write.clone())
        .await
        .unwrap();
    let replay = store
        .security_transactions()
        .commit_recovery_unit(write.clone())
        .await
        .unwrap();
    assert_eq!(first.canonical_request, replay.canonical_request);
    let session = store
        .recovery_sessions()
        .get(session_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.state, RecoverySessionLifecycle::Completed);
    for transaction in write.commits {
        pcr.history.events.push(transaction.event);
        pcr.history.commits.push(transaction.commit);
    }
    (
        new_device,
        new_authorization,
        method,
        replacement_seed,
        session_id,
    )
}

fn plan_session_id(write: &RecoveryUnitCommitWrite) -> RecoverySessionId {
    write
        .transaction
        .resource
        .recovery_plan()
        .unwrap()
        .binding
        .recovery_session_id
        .clone()
}
