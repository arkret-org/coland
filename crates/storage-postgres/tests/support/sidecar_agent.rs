//! Accepted Agent fixture material shared by the Sidecar authority matrix.
use arkret_wire::{AccountId, ActorId, DidCoreId, DidUrl, EventKind, RealmId};

use super::device_authorization_history;

/// Publish the controller's actual native recipient policy before provisioning.
pub(super) async fn history_custody(
    pool: &coland_storage_postgres::PgPool,
    principal: &super::pcr_genesis::PcrGenesisFixture,
) -> (
    arkret_wire::RealmCommit,
    arkret_models_crypto::AgentHistoryCustody,
) {
    use coland_storage::{AuthorityCommitStore, RecoveryPolicyStore};
    use ed25519_dalek::Signer as _;
    let account = &principal.history.account;
    let realm = &principal.unit.transactions[0].event.realm_id;
    let commits = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
    let policies = coland_storage_postgres::PgRecoveryPolicyStore { pool: pool.clone() };
    let mut head = commits
        .held_stream_head_commit(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    let policy = if let Some(accepted) = policies.get_active_for_account(account).await.unwrap() {
        serde_json::from_value::<arkret_models_crypto::RecoveryPolicy>(accepted.raw_payload)
            .unwrap()
    } else {
        let at = arkret_canonical::normalize_timestamp_canonical(
            head.committed_at + chrono::TimeDelta::seconds(1),
        );
        let timestamp = arkret_canonical::format_timestamp_canonical(at);
        let expires =
            arkret_canonical::format_timestamp_canonical(at + chrono::TimeDelta::days(3650));
        let material =
            arkret_crypto::identity_root::derive_identity_recovery_key_material(&[149; 32], 0)
                .unwrap();
        let did = &principal.history.did;
        let method = &principal.history.device_verification_method;
        let seed = principal.history.founding_device_signing_seed;
        let mut policy: arkret_models_crypto::RecoveryPolicy = serde_json::from_value(serde_json::json!({
            "schema":"ak.schema.recovery_policy.v1",
            "policy_id":format!("ak:policy:{}",uuid::Uuid::now_v7()),
            "account_id":account,"version":1,"supersedes_id":null,
            "trust_domain":"ak:trust_domain:station.example","issued_at":timestamp,
            "signature_proof":{"verification_method":method,"signature_algorithm":"Ed25519","signature":"AA"},
            "methods":[{"kind":"recovery_unlock","keys":[{
                "verification_method":format!("{did}#recovery-proof-0"),
                "public_key_multibase":material.recovery_proof_public_key_multikey,
                "signature_algorithm":"Ed25519","not_before":timestamp,"expires_at":expires,
                "backup_hpke":{"key_agreement_ref":format!("{did}#backup-hpke-0"),
                    "key_agreement_algorithm":"X25519","public_key_multibase":material.backup_hpke_public_key_multikey,
                    "hpke_suites":["ak.hpke_x25519_aead_chacha20poly1305.v1"],"use":"backup_hpke",
                    "not_before":timestamp,"expires_at":expires}
            }]}]
        })).unwrap();
        policy.signature_proof.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&seed)
                    .sign(
                        &arkret_models_crypto::recovery_policy_signature_transcript_bytes(&policy)
                            .unwrap(),
                    )
                    .to_bytes(),
            ))
            .unwrap();
        let event = device_authorization_history::sign_event(
            arkret_wire::test_support::raw_event_at(
                "ak.policy.set",
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                account.principal_id.clone(),
                account.station_id.clone(),
                serde_json::json!({"policy_id":policy.policy_id,"value":policy}),
                at,
            )
            .unwrap(),
            method.clone(),
            seed,
        );
        let commit = station_successor(&head, &event, &principal.history.station_did, 1);
        policies
            .commit_publication(coland_storage::RecoveryPolicyPublicationWrite {
                commit: coland_storage::AuthorityCommitTransaction {
                    expected_authority: principal.unit.transactions[1].expected_authority.clone(),
                    event,
                    commit: commit.clone(),
                    producer_signer_fact: None,
                    content_backup_source: None,
                    mls_state: None,
                    welcomes: vec![],
                    recipient_queue_capacity: 0,
                },
                queued_at: commit.committed_at,
            })
            .await
            .unwrap();
        head = commit;
        policy
    };
    let recipient = policy
        .methods
        .iter()
        .find_map(|method| match method {
            arkret_models_crypto::RecoveryMethod::RecoveryUnlock { keys } => keys.first(),
            _ => None,
        })
        .unwrap();
    let custody = arkret_models_crypto::AgentHistoryCustody {
        custodian_actor_id: ActorId::account(account.clone()),
        recovery_policy_ref: arkret_models_crypto::RecoveryPolicyRef {
            policy_id: policy.policy_id,
            policy_version: policy.version,
        },
        recipient_key_ref: recipient.backup_hpke.key_agreement_ref.clone(),
    };
    (head, custody)
}

pub(super) fn station_successor(
    previous: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    offset_seconds: i64,
) -> arkret_wire::RealmCommit {
    let mut commit = previous.clone();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{}:successor", event.event_id, previous.commit_id).as_bytes(),
    ));
    commit.stream_position = previous.stream_position + 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = previous.committed_at + chrono::TimeDelta::seconds(offset_seconds);
    commit.producer_signer_fact_digest = None;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

pub(super) fn station_genesis_commit(
    template: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::RealmCommit {
    let realm_id = RealmId::from_event_id(&event.event_id);
    let mut commit = template.clone();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:genesis", event.event_id).as_bytes(),
    ));
    commit.realm_id = realm_id.clone();
    commit.stream_ref = arkret_wire::CommitStreamRef::Realm { realm_id };
    commit.stream_position = 0;
    commit.previous_commit_ref = None;
    commit.event_ref = event.event_id.clone();
    commit.governance_generation = 0;
    commit.authority_ref =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    commit.committed_at = committed_at;
    commit.producer_signer_fact_digest = None;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

#[allow(clippy::too_many_arguments)]
pub(super) fn agent_provision_event(
    controller: &AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    agent_id: &DidCoreId,
    agent_pcr_id: &RealmId,
    controller_authorization_ref: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::AgentProvision.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        controller.principal_id.clone(),
        controller.station_id.clone(),
        serde_json::json!({
            "schema": "ak.schema.agent_provision.v1",
            "agent_id": agent_id,
            "controller_principal_id": controller.principal_id,
            "principal_control_realm_id": agent_pcr_id,
            "controller_authorization_ref": controller_authorization_ref,
            "agent_slug": format!("sidecar-{}",uuid::Uuid::now_v7().simple()),
            "accountability_scope": "agent_operator",
            "requested_scope_digest": format!("sha256:{}", "b".repeat(64)),
            "selector_visibility": "private",
            "created_at": arkret_canonical::format_timestamp_canonical(created_at)
        }),
        created_at,
    )
    .unwrap();
    device_authorization_history::sign_event(event, method.clone(), seed)
}

pub(super) fn agent_control_event(
    controller_method: &DidUrl,
    signing_seed: [u8; 32],
    controller: &AccountId,
    agent: &AccountId,
    agent_pcr: &RealmId,
    authorization_ref: &str,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::AgentKeyAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr.clone(),
        },
        ActorId::account(agent.clone()),
        payload,
        at,
    )
    .unwrap();
    event.executed_by = Some(ActorId::account(controller.clone()));
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.to_owned()).unwrap());
    device_authorization_history::sign_event(event, controller_method.clone(), signing_seed)
}

pub(super) fn agent_key_authorization(
    agent_did: &arkret_wire::Did,
    controller: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let method = format!("{agent_did}#runtime-1");
    let submit = arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1;
    serde_json::json!({
        "agent_id": arkret_wire::project_did_to_core_id(agent_did).unwrap(),
        "key_id": method,
        "verification_method": method,
        "public_key": {
            "kty": "OKP",
            "kid": method,
            "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]).verifying_key().as_bytes()
            )
        },
        "accountable_principal_id": controller,
        "agent_key_scope": {
            "actions": [submit],
            "resources": [{"kind": "operation", "operation": submit}]
        },
        "audience": ["ak:did_core:web:direct-conversation.example"],
        "issued_at": arkret_canonical::format_timestamp_canonical(at),
        "approval_evidence": {
            "kind": "pairing_request",
            "request_canonical_digest": format!("sha256:{}", "d".repeat(64)),
            "pairing_request_id": format!("agent_pairing_request:{}", uuid::Uuid::now_v7()),
            "approved_by": controller
        }
    })
}
