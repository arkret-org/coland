//! Real signed inputs only; callers must run the actual native acceptance port.
#![allow(dead_code)]
use arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody;
use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions};
use arkret_wire::*;
use chrono::{DateTime, Duration, Utc};
use coland_storage::{ActorProfileStore as _, OrganizationPcrGovernanceChangeAdmissionWrite};
use coland_storage_postgres::{PgActorProfileStore, PgPersistenceStore, PgPool};
use serde_json::json;

use super::organization_origin::OrganizationFixture;
pub(crate) fn application(
    pool: PgPool,
) -> coland_services::authority_commit::AuthorityCommitApplication {
    coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::new(std::sync::Arc::new(
            PgPersistenceStore::new(pool),
        )),
        1024,
    )
}

pub(crate) fn author_change(
    fixture: &OrganizationFixture,
    root: EventId,
    expected_head: RealmCommitId,
    methods: &[(u8, DidUrl, DateTime<Utc>)],
    at: DateTime<Utc>,
) -> EventAdmissionSubmission {
    let mut event = fixture.write.request.event_submission.event.clone();
    event.kind = EventKind::RealmGovernanceStationChange;
    event.scope_ref = ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    event.created_at = at - Duration::seconds(2);
    event.authorization_ref = Some(serde_json::from_value(json!(root)).unwrap());
    event.payload = serde_json::from_value(json!({
        "expected_governance_generation":"0",
        "expected_realm_stream_commit_id":expected_head,
        "new_governance_station_id":"ak:did_core:web:next-governor.example",
    }))
    .unwrap();
    event.producer_proof = None;
    let mut authored =
        AuthoredEvent::finalize_with_digest_suite(event, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(
            fixture.producer.did_key_seed,
            &fixture.producer.did_key_id,
        ),
        SignEventOptions::new().with_created_at(at - Duration::seconds(2)),
    )
    .unwrap();
    let event = authored.into_event();
    approve_event(fixture, event, methods)
}

pub(crate) fn approve_event(
    fixture: &OrganizationFixture,
    event: Event,
    methods: &[(u8, DidUrl, DateTime<Utc>)],
) -> EventAdmissionSubmission {
    let mut votes = methods
        .iter()
        .map(|(seed, method, approved_at)| {
            let mut vote = ApprovalSignature {
                input: ApprovalSignatureInput {
                    approval_context: ApprovalContext::RealmGovernance {},
                    approval_target: ApprovalTarget::Event {
                        event_id: event.event_id.clone(),
                    },
                    request_canonical_digest: Hash::new(
                        arkret_canonical::canonical_sha256(&event).unwrap(),
                    )
                    .unwrap(),
                    operation: ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1.into(),
                    action: CapabilityActionId::RealmGovernanceStationChange,
                    realm_id: event.realm_id.clone(),
                    initiating_actor_id: event.actor_id.clone(),
                    approver_did: fixture.organization_did.clone(),
                    approved_at: *approved_at,
                    nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
                },
                proof: ApprovalSignatureProof {
                    kind: ApprovalSignatureProofKind::DetachedJws,
                    verification_method: method.clone(),
                    jws: String::new(),
                },
            };
            vote.proof.jws = Ed25519DetachedJwsSigner::from_seed([*seed; 32], method.as_str())
                .sign_detached_jws(
                    &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)
                        .unwrap(),
                );
            vote
        })
        .collect::<Vec<_>>();
    votes.sort_by_key(|vote| arkret_canonical::canonical_json_string(&vote.input).unwrap());
    EventAdmissionSubmission {
        event,
        approval_signatures: (!votes.is_empty()).then_some(votes),
    }
}

pub(crate) async fn prepare(
    pool: &PgPool,
    fixture: &OrganizationFixture,
    submission: EventAdmissionSubmission,
    at: DateTime<Utc>,
) -> OrganizationPcrGovernanceChangeAdmissionWrite {
    let request = PeerAuthorityForwardEventRequestBody::new(submission, None, None, None).unwrap();
    let (method, seed) = fixture.governor_signer();
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let transaction = application(pool.clone())
        .prepare_organization_pcr_governance_change_transaction(
            &request.event_submission.event,
            &fixture.write.source_service_id,
            method,
            &key,
            at,
        )
        .await
        .unwrap();
    OrganizationPcrGovernanceChangeAdmissionWrite {
        transaction,
        request,
        source_service_id: project_did_to_core_id(&Did::new(&fixture.producer.did).unwrap())
            .unwrap(),
        organization_log_entries: fixture.write.organization_log_entries.clone(),
        organization_witness_records: fixture.write.organization_witness_records.clone(),
        producer_service_resolution: fixture.write.producer_service_resolution.clone(),
    }
}

pub(crate) fn votes(
    fixture: &OrganizationFixture,
    at: DateTime<Utc>,
) -> Vec<(u8, DidUrl, DateTime<Utc>)> {
    fixture
        .control_seeds
        .iter()
        .map(|seed| {
            (
                *seed,
                DidUrl::new(format!(
                    "{}#{}",
                    fixture.organization_did,
                    if *seed == 33 {
                        "organization-control"
                    } else {
                        "governance-second"
                    }
                ))
                .unwrap(),
                at - Duration::seconds(1),
            )
        })
        .collect()
}

pub(crate) async fn native_create(pool: &PgPool, fixture: &OrganizationFixture) {
    fixture.retain_current_histories(pool).await;
    PgActorProfileStore { pool: pool.clone() }
        .admit_organization_pcr_genesis(fixture.write.clone())
        .await
        .unwrap();
}

pub(crate) async fn prepare_planned_change(
    pool: &PgPool,
    fixture: &OrganizationFixture,
) -> OrganizationPcrGovernanceChangeAdmissionWrite {
    let at = fixture.write.queued_at + Duration::seconds(5);
    let submission = author_change(
        fixture,
        fixture.write.transaction.event.event_id.clone(),
        fixture.write.transaction.commit.commit_id.clone(),
        &votes(fixture, at),
        at,
    );
    prepare(pool, fixture, submission, at).await
}
