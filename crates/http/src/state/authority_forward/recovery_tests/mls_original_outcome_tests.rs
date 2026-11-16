//! Real PG tests of the origin journal port and authenticated recovery reader.
//! Outcomes passed directly to the trusted retention port model its already
//! verified G-response precondition. They do not claim a G admission, HTTP
//! signature, native Device acceptance, or H replica-readiness execution.

use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_wire::{AuthorityCommitStatus, AuthorityRejectionStatus, BlobRef, EventId, RealmCommit};
use diesel_async::RunQueryDsl as _;

use super::*;

fn complete_submission(human: &historical_human::HumanFixture) -> arkret_wire::MlsCommitSubmission {
    complete_with_material(human).0
}

fn complete_with_material(
    human: &historical_human::HumanFixture,
) -> (arkret_wire::MlsCommitSubmission, MlsGroupStateMaterial) {
    let previous = human.unit.transactions.last().unwrap();
    let realm = previous.event.realm_id.clone();
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let key =
        ed25519_dalek::SigningKey::from_bytes(&human.pcr.history.founding_device_signing_seed);
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(human.pcr.history.account.clone()),
        human.pcr.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key),
    )
    .unwrap();
    let inception = MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
    let mut group = identity
        .create_group_with_governance_binding(&scope, &inception)
        .unwrap();
    let base = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [179; 32]);
    let binding = MlsGovernanceBindingPayload::realm(realm, Some(base.clone()), 0, 1, 0).unwrap();
    let commit = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let (info, tree) = group
        .pending_public_group_state_bytes(&commit, &binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        base,
        0,
        &commit,
        binding,
        BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::sha256_digest(&info)
        ))
        .unwrap(),
        BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::sha256_digest(&tree)
        ))
        .unwrap(),
    )
    .unwrap();
    let event = historical_human::signed_ordinary_event(
        human,
        previous,
        EventKind::MlsCommit,
        serde_json::to_value(payload).unwrap(),
        previous.commit.committed_at + Duration::seconds(1),
    );
    let submission = arkret_wire::MlsCommitSubmission {
        commit_event: event,
        welcomes: Vec::new(),
        idempotency_key: serde_json::from_value(serde_json::json!(uuid::Uuid::now_v7())).unwrap(),
        recovery_source: None,
    };
    submission.validate().unwrap();
    (submission, MlsGroupStateMaterial::from_bytes(&info, &tree))
}

fn port_commit(
    state: &AppState,
    human: &historical_human::HumanFixture,
    event: &Event,
) -> RealmCommit {
    let mut commit = human.unit.transactions.last().unwrap().commit.clone();
    commit.previous_commit_ref = Some(commit.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.stream_position += 1;
    commit.committed_at = event.created_at;
    commit.producer_signer_fact_digest = None;
    seal_service_commit(&mut commit, state);
    commit
}

#[tokio::test]
async fn terminal_mls_origin_journal_reopens_original_status_and_refusal_without_material_or_replica()
 {
    scenario_future(|| async {
        let (state, pool, _lease) = station("https://mls-origin-journal.invalid/".into());
        let human = scenario_future(|| historical_human::HumanFixture::new(&pool, state.service_did())).await;
        human.admit(&pool).await;
        let session = authenticated_context(&pool, &human).await;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        for accepted in [true, false] {
            let submission = complete_submission(&human);
            let request = SelfAuthoritySubmitRequestBody::MlsCommit(submission.clone());
            let event = &submission.commit_event;
            let outcome = if accepted {
                AuthoritySubmitResponseBody::Accepted {
                    status: AuthorityCommitStatus::Committed,
                    commit: port_commit(&state, &human, event),
                }
            } else {
                AuthoritySubmitResponseBody::Rejected {
                    status: AuthorityRejectionStatus::Rejected,
                    reason_code: "governance_binding_mismatch".into(),
                }
            };
            store.retain_forwarded_submission(event, &request, event.created_at).await.unwrap();
            store.retain_forwarded_outcome(event, &outcome, event.created_at).await.unwrap();
            let retry = crate::state::authority_managed_device::mls::MlsRequest::from_request(&request).unwrap().unwrap();
            let mirror = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(outcome.clone());
            assert_eq!(retry.retain_outcome(&state, mirror.clone()).await.unwrap(), mirror);
            assert!(retry.replay(&state).await.unwrap().is_some());
            assert!(state.jobs().prune_expired_idempotency(Utc::now() + Duration::days(31)).await.unwrap() >= 1);
            assert!(retry.replay(&state).await.unwrap().is_none());
            let first = store.queued_event(&event.event_id).await.unwrap().unwrap().forward_attempt.unwrap();
            assert_eq!(first.terminal_outcome, Some(outcome.clone()));
            assert!(first.peer_request.is_none());
            store.record_forward_attempt(&event.event_id,
                coland_storage::ForwardAttemptStatus::TemporarilyUnavailable, None,
                event.created_at + Duration::days(90)).await.unwrap();
            assert_eq!(store.queued_event(&event.event_id).await.unwrap().unwrap().forward_attempt.unwrap(), first);
            let reopened = PgAuthorityCommitStore { pool: pool.clone() };
            assert!(reopened.committed_event(&event.event_id).await.unwrap().is_none());
            assert!(state.authority_commits().current_authority(&event.realm_id).await.unwrap().is_some());
            let original_bytes = arkret_canonical::canonical_json_bytes(&outcome).unwrap();
            let recovered = recover_forwarded_original(&state, &session, &request).await.unwrap().unwrap();
            assert_eq!(arkret_canonical::canonical_json_bytes(&recovered).unwrap(), original_bytes);
            let mut changed = submission.clone();
            changed.idempotency_key = serde_json::from_value(serde_json::json!(uuid::Uuid::now_v7())).unwrap();
            assert_eq!(recover_forwarded_original(&state, &session,
                &SelfAuthoritySubmitRequestBody::MlsCommit(changed)).await.unwrap_err().conflict_code(),
                Some(coland_storage::ConflictCode::DuplicateConflict));
            if let AuthoritySubmitResponseBody::Accepted { commit, .. } = &outcome {
                let changed_status = AuthoritySubmitResponseBody::Accepted {
                    status: AuthorityCommitStatus::Duplicate, commit: commit.clone(),
                };
                assert_eq!(store.retain_forwarded_outcome(event, &changed_status, event.created_at)
                    .await.unwrap_err().conflict_code(), Some(coland_storage::ConflictCode::DuplicateConflict));
            }
            assert_eq!(reopened.queued_event(&event.event_id).await.unwrap().unwrap().forward_attempt.unwrap(), first);
        }
    }).await;
}

#[tokio::test]
async fn accepted_mls_result_survives_terminal_optional_cache_refusal_but_preserves_database_errors()
 {
    scenario_future(|| async {
        let (state, pool, _lease) = station("https://mls-origin-cache.invalid/".into());
        let human = scenario_future(|| historical_human::HumanFixture::new(&pool, state.service_did())).await;
        human.admit(&pool).await;
        let _session = authenticated_context(&pool, &human).await;
        let submission = complete_submission(&human);
        let request = SelfAuthoritySubmitRequestBody::MlsCommit(submission);
        let context = crate::state::authority_managed_device::mls::MlsRequest::from_request(&request).unwrap().unwrap();
        let SelfAuthoritySubmitRequestBody::MlsCommit(submission) = &request else { unreachable!() };
        let outcomes = [
            AuthoritySubmitResponseBody::Accepted {
                status: AuthorityCommitStatus::Committed,
                commit: port_commit(&state, &human, &submission.commit_event),
            },
            AuthoritySubmitResponseBody::Rejected {
                status: AuthorityRejectionStatus::Rejected, reason_code: "governance_binding_mismatch".into(),
            },
        ].map(arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary);
        let account = &human.pcr.history.account;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        store.retain_forwarded_submission(&submission.commit_event, &request, submission.commit_event.created_at).await.unwrap();
        let journal_before = store.queued_event(&submission.commit_event.event_id).await.unwrap().unwrap().forward_attempt.unwrap();
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO account_lifecycle(account_pk,state,changed_at) SELECT pk,'erasure_pending',now() FROM accounts WHERE principal_id=$1 AND station_id=$2 ON CONFLICT(account_pk) DO UPDATE SET state='erasure_pending'")
            .bind::<diesel::sql_types::Text,_>(account.principal_id.as_str())
            .bind::<diesel::sql_types::Text,_>(account.station_id.as_str()).execute(&mut *conn).await.unwrap();
        drop(conn);
        for outcome in &outcomes {
            assert_eq!(context.retain_outcome(&state, outcome.clone()).await.unwrap(), *outcome);
            assert!(context.replay(&state).await.unwrap().is_none());
            let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(ordinary) = outcome else { unreachable!() };
            store.retain_forwarded_outcome(&submission.commit_event, ordinary, Utc::now()).await.unwrap();
        }
        store.record_forward_attempt(&submission.commit_event.event_id,
            coland_storage::ForwardAttemptStatus::Rejected, Some("not_authorized"), Utc::now()).await.unwrap();
        assert_eq!(store.queued_event(&submission.commit_event.event_id).await.unwrap().unwrap().forward_attempt.unwrap(), journal_before);
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("ALTER TABLE idempotency_keys RENAME TO unavailable_mls_cache")
            .execute(&mut *conn).await.unwrap();
        drop(conn);
        assert!(context.retain_outcome(&state, outcomes[0].clone()).await.is_err());
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("ALTER TABLE unavailable_mls_cache RENAME TO idempotency_keys")
            .execute(&mut *conn).await.unwrap();
    }).await;
}

/// No accepted outcome is invented here: real RFC public material reaches
/// the actual G port with an authenticated-state-port source and an unknown
/// complete unit. The result-only branch must return NotFound before writes.
#[tokio::test]
async fn missing_mls_original_probe_never_admits_an_event_and_preserves_source_binding() {
    scenario_future(|| async {
        let (origin, origin_pool, _origin_lease) = station("https://probe-origin.invalid/".into());
        let human = scenario_future(|| historical_human::HumanFixture::new(&origin_pool, origin.service_did())).await;
        human.admit(&origin_pool).await;
        let _session = authenticated_context(&origin_pool, &human).await;
        let (submission, material) = complete_with_material(&human);
        material.decode_for_event(&submission.commit_event).unwrap();
        let request = PeerAuthorityForwardMlsRequestBody {
            branch: arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
            mls_submission: submission.clone().for_origin_forward(None),
            mls_group_state_material: material,
            content_backup_sources: None,
            producer_device_evidence: None,
            producer_agent_evidence: None,
        };
        request.validate_replay_shape().unwrap();
        assert!(request.validate().is_err());
        let (governor, pool, _lease) = station("https://probe-governor.invalid/".into());
        let before = probe_write_footprint(&pool).await;
        let peer = coland_services::authority_commit::AuthenticatedPeerContext {
            source_service_id: human.pcr.history.account.station_id.clone(), replay_receipt: None,
        };
        assert!(matches!(admit_forwarded_mls(&governor, &peer, request.clone(), Utc::now()).await,
            Err(ServiceError::NotFound(_))));
        assert_eq!(probe_write_footprint(&pool).await, before);
        let foreign = coland_services::authority_commit::AuthenticatedPeerContext {
            source_service_id: governor.service_core_id(), replay_receipt: None,
        };
        assert!(matches!(admit_forwarded_mls(&governor, &foreign, request, Utc::now()).await,
            Err(ServiceError::Conflict(_))));
        assert_eq!(probe_write_footprint(&pool).await, before);
        // A local transport refusal is not a canonical terminal Event and
        // cannot preempt the normal current-producer path after a G miss.
        let store = PgAuthorityCommitStore { pool: origin_pool.clone() };
        let original = SelfAuthoritySubmitRequestBody::MlsCommit(submission.clone());
        store.retain_forwarded_submission(&submission.commit_event, &original, submission.commit_event.created_at).await.unwrap();
        store.record_forward_attempt(&submission.commit_event.event_id,
            coland_storage::ForwardAttemptStatus::Rejected, Some("device_unauthorized"), Utc::now()).await.unwrap();
        assert!(crate::state::authority_self_event_unit::exact_replay(&origin, &submission.commit_event).await.unwrap().is_none());
    }).await;
}

async fn probe_write_footprint(pool: &PgPool) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Counts {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events),'commits',(SELECT count(*) FROM realm_commits),'results',(SELECT count(*) FROM idempotency_keys),'groups',(SELECT count(*) FROM mls_group_current_states),'blobs',(SELECT count(*) FROM blobs),'welcomes',(SELECT count(*) FROM mls_welcome_deliveries),'claims',(SELECT count(*) FROM peer_keypackage_claims),'proposals',(SELECT count(*) FROM mls_consumed_proposal_provenance),'journal',(SELECT count(*) FROM authority_forward_attempts),'outbox',(SELECT count(*) FROM federation_outbox)) AS value")
        .get_result::<Counts>(&mut *conn).await.unwrap().value
}

/// A real G refusal transaction supplies the known complete-unit result.
/// Wrong/mixed proof families must fail closed before that result is read.
/// The compact Agent object below is intentionally unauthentic negative input;
/// it is never used to establish an Agent or an accepted Event.
#[tokio::test]
async fn known_mls_result_does_not_hide_opposite_or_mixed_producer_evidence() {
    scenario_future(|| async {
        let (state, pool, _lease) = station("https://probe-closed-shape.invalid/".into());
        let human = scenario_future(|| historical_human::HumanFixture::new(&pool, state.service_did())).await;
        human.admit(&pool).await;
        let (submission, material) = complete_with_material(&human);
        let original = SelfAuthoritySubmitRequestBody::MlsCommit(submission.clone());
        let context = crate::state::authority_managed_device::mls::MlsRequest::from_request(&original).unwrap().unwrap();
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let authority = store.current_authority(&submission.commit_event.realm_id).await.unwrap().unwrap();
        let reason = "governance_binding_mismatch";
        let record = context.refusal_record(reason).unwrap();
        let outcome = store.finalize_mls_rejection(&submission.commit_event, &authority, reason, None, Some(&record)).await.unwrap();
        assert!(matches!(outcome, AuthoritySubmitResponseBody::Rejected {..}));
        assert!(context.replay(&state).await.unwrap().is_some());
        let PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(ordinary) =
            crate::state::authority_forward::tests::forwarded_request(0x7b) else { unreachable!() };
        let device = ordinary.producer_device_evidence.unwrap();
        let core = &device.device_projection_attestation.attestation;
        let digest = format!("sha256:{}", "0".repeat(64));
        let agent: arkret_models_identity::AgentProducerEvidence = serde_json::from_value(serde_json::json!({
            "authenticated_signer_evidence":{
                "signer_kind":"agent", "subject_id":core.account_id.principal_id,
                "verification_method":device.device_projection_attestation.proof.verification_method,
                "public_key_jwk":{"kty":"OKP","crv":"Ed25519","x":arkret_canonical::base64url_encode([1u8;32])},
                "authority_commit_id":core.event_authorization.authorization_ref.commit_id,
                "resolved_at":core.attested_at
            },
            "agent_authority_state_evidence":{
                "schema":arkret_wire::SchemaId::AGENT_AUTHORITY_STATE_EVIDENCE_V1,
                "state_digest":digest,
                "attestation":{
                    "authority_id":core.account_id.station_id,
                    "verification_method":device.device_projection_attestation.proof.verification_method,
                    "state_digest":digest,"issued_at":core.attested_at,"expires_at":core.expires_at,
                    "proof":{"kind":"detached_jws","jws":"invalid-negative-fixture"}
                }
            },
            "controller_account_gate_attestation":{
                "schema":arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation::SCHEMA_ID,
                "principal_id":core.account_id.principal_id,"eligibility":"active","status":"active",
                "basis":{"kind":"account_binding_default","binding_version":1,"binding_receipt_digest":digest},
                "basis_digest":digest,"authority_id":core.account_id.station_id,
                "verification_method":device.device_projection_attestation.proof.verification_method,
                "issued_at":core.attested_at,"expires_at":core.expires_at,
                "proof":{"kind":"detached_jws","jws":"invalid-negative-fixture"}
            },
            "authority_resolution":device.service_resolution
        })).unwrap();
        let peer = coland_services::authority_commit::AuthenticatedPeerContext {
            source_service_id: human.pcr.history.account.station_id.clone(), replay_receipt:None,
        };
        let before = probe_write_footprint(&pool).await;
        for include_device in [false,true] {
            let request = PeerAuthorityForwardMlsRequestBody {
                branch:arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
                mls_submission:submission.clone().for_origin_forward(None),
                mls_group_state_material:material.clone(),content_backup_sources:None,
                producer_device_evidence:include_device.then(||device.clone()),
                producer_agent_evidence:Some(agent.clone()),
            };
            assert!(!request.is_original_result_probe());
            request.validate_replay_shape().unwrap();
            assert!(request.validate().is_err());
            assert!(matches!(admit_forwarded_mls(&state,&peer,request,Utc::now()).await,
                Err(ServiceError::SchemaViolation(_))));
            assert_eq!(probe_write_footprint(&pool).await,before);
            assert!(context.replay(&state).await.unwrap().is_some());
        }
    }).await;
}
