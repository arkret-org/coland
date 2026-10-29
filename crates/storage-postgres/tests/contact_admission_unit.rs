//! Contact admission at the governing Station's transaction cut
//! (`contact-and-direct-conversation.md` sections 2 and 3.1).
//!
//! A Contact Event, its covering `RealmCommit`, the holder-private Contact row
//! and the frozen completion intent commit in one transaction. The request-slot
//! CAS the intent signs -- a request's slot version and predecessor, a normal
//! response's exact lifetime version and original predecessor -- is
//! recomputed from the row that transaction locks, so a stale, foreign or
//! rewritten observation refuses the whole unit with zero writes.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_models_collaboration::contact_operations::{
    ContactPeer, ContactProducerSigner, ContactRound, OutgoingRequestState,
    OutgoingSlotAbsenceTranscript, RequestAcceptanceReceipt,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_wire::{DidUrl, EventId, EventKind, Hash};
use chrono::{DateTime, Duration, Utc};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, ContactCompletionAction,
    ContactCompletionBinding, ContactCompletionDraft, ContactCompletionIntent,
    ContactDeliveryTarget, ContactProjectionCommit, ContactRecord, ContactRequestSlotState,
    ContactStore, EventCommitRequest, EventCommitUnitOfWork,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgContactStore, PgEventCommitUnitOfWork, PgPersistenceStore, PgPool,
};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn alice() -> ContactPeer {
    ContactPeer::Human {
        account_id: ordinary_realm::human_profile::account(
            &ordinary_realm::station(),
            "contact-alice",
        ),
    }
}

fn bob() -> ContactPeer {
    ContactPeer::Human {
        account_id: ordinary_realm::human_profile::account(
            &ordinary_realm::station(),
            "contact-bob",
        ),
    }
}

fn producer(holder: &ContactPeer) -> ContactProducerSigner {
    let label = if holder == &alice() {
        "contact-alice"
    } else {
        "contact-bob"
    };
    let fixture = ordinary_realm::human_profile::fixture(&ordinary_realm::station(), label);
    assert_eq!(
        holder.contact_actor_id(),
        arkret_wire::ActorId::account(fixture.history.account)
    );
    ContactProducerSigner::direct(
        fixture.history.device_verification_method,
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&fixture.history.founding_device_signing_seed)
                .verifying_key()
                .to_bytes(),
        ))
        .unwrap(),
    )
    .unwrap()
}

/// The next Contact Event on the fixture stream, authored by `holder`.
async fn contact_request(
    pool: &PgPool,
    guard: &coland_storage::DeviceRevocationGateSelector,
    previous: &AuthorityCommitTransaction,
    kind: EventKind,
    holder: &ContactPeer,
    payload: serde_json::Value,
    at: DateTime<Utc>,
) -> EventCommitRequest {
    let mut request = ordinary_realm::next_human_request_for_actor(
        previous,
        kind,
        holder.contact_actor_id(),
        payload,
        at,
    );
    let fact = PgAuthorityCommitStore { pool: pool.clone() }
        .prepare_account_device_signer_fact(&request.authority_commit.event, at)
        .await
        .unwrap();
    assert!(
        fact.is_none(),
        "native PCR forbids the ordinary Human signer fact"
    );
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        guard.clone(),
    ));
    ordinary_realm::seal_final_commit(&mut request.authority_commit.commit);
    request
}

/// The completion intent the serving layer freezes for `event`.
fn intent(
    event: &arkret_wire::Event,
    holder: &ContactPeer,
    peer: &ContactPeer,
    action: ContactCompletionAction,
    accepted_at: DateTime<Utc>,
) -> ContactCompletionIntent {
    let request = matches!(action, ContactCompletionAction::Request { .. });
    let mut intent = ContactCompletionDraft {
        event: event.clone(),
        operation_id: arkret_wire::ProtocolOperationId::new(format!(
            "ak:operation:contact-{}",
            event
                .event_id
                .event_digest()
                .as_str()
                .trim_start_matches("sha256:")
        ))
        .unwrap(),
        holder: holder.clone(),
        action,
        response_binding: ContactCompletionBinding {
            authenticated_actor: holder.contact_actor_id(),
            idempotency_key: format!("contact-commit:{}", event.event_id),
            request_hash: format!("sha256:{}", "a".repeat(64)),
        },
        target: ContactDeliveryTarget {
            contact_address: PeerContactAddress::for_recipient(
                peer.clone(),
                ServiceResolutionCarrier::ResolutionUrl {
                    resolution_url: "https://ordinary-station.example/.well-known/resolution"
                        .to_owned(),
                },
            ),
            introduction_evidence: request.then_some(ContactIntroductionEvidence::SameStation),
            idempotency_key: arkret_wire::IdempotencyKey::new(format!(
                "peer-contact:{}",
                event.event_id
            ))
            .unwrap(),
        },
        local_mirror_target: None,
    }
    .bind_producer(producer(holder))
    .unwrap();
    intent.freeze_acceptance_time(accepted_at).unwrap();
    intent
}

fn slot(
    owner: &ContactPeer,
    peer: &ContactPeer,
    sequence: u64,
    _head: Hash,
    refs: &[&EventId],
) -> ContactRequestSlotState {
    ContactRequestSlotState {
        owner_id: owner.contact_actor_id(),
        peer_id: peer.contact_actor_id(),
        version: sequence,
        head_event_ref: (*refs.last().unwrap()).clone(),
        operation_digest: None,
        request_choice: None,
    }
}

/// Alice's committed request to Bob and the Contact row it wrote.
struct Requested {
    pool: PgPool,
    request: EventCommitRequest,
    request_intent: ContactCompletionIntent,
    row: ContactRecord,
    responder_head: AuthorityCommitTransaction,
    responder_guard: coland_storage::DeviceRevocationGateSelector,
}

async fn requested(database: &TestDatabase) -> Requested {
    let pool = database.pool();
    database.bind_device_inventory_station(ordinary_realm::STATION);
    let requester =
        ordinary_realm::human_profile::fixture(&ordinary_realm::station(), "contact-alice");
    let responder =
        ordinary_realm::human_profile::fixture(&ordinary_realm::station(), "contact-bob");
    let persistence = PgPersistenceStore::new(pool.clone());
    let requester_guard = Box::pin(requester.admit_founding_device(&persistence))
        .await
        .expect("accept the requester PCR and Device");
    let responder_guard = Box::pin(responder.admit_founding_device(&persistence))
        .await
        .expect("accept the responder PCR and Device");
    for fixture in [&requester, &responder] {
        ordinary_realm::human_profile::register_fixture_signer(
            &fixture.history.account,
            fixture.history.device_verification_method.clone(),
            fixture.history.founding_device_signing_seed,
        );
    }
    let requester_head = requester.unit.transactions.last().unwrap();
    let at = responder
        .unit
        .transactions
        .last()
        .unwrap()
        .commit
        .committed_at
        .max(requester_head.commit.committed_at)
        + Duration::seconds(1);
    let accepted_at = arkret_canonical::normalize_timestamp_canonical(at);
    let mut request = contact_request(
        &pool,
        &requester_guard,
        requester_head,
        EventKind::ContactRequested,
        &alice(),
        serde_json::json!({
            "trust_domain_id":"ak:trust_domain:contact.test","version":1,
            "peer": bob(),
            "granted_to_peer_scopes": ["direct_message"],
            "introduction_evidence_digest": format!("sha256:{}", "e".repeat(64)),
        }),
        at,
    )
    .await;
    let event = request.authority_commit.event.clone();
    let request_intent = intent(
        &event,
        &alice(),
        &bob(),
        ContactCompletionAction::Request {
            version: 1,
            predecessor_event_ref: None,
        },
        accepted_at,
    );
    let row = ContactRecord {
        requester_id: alice().contact_actor_id(),
        target_id: bob().contact_actor_id(),
        contact_round_id: None,
        granted_to_target_scopes: vec!["direct_message".to_owned()],
        granted_to_requester_scopes: Vec::new(),
        status: "pending".to_owned(),
        pending_incoming_admitted: true,
        request_event_ref: Some(event.event_id.clone()),
        request_slot_states: vec![slot(
            &alice(),
            &bob(),
            1,
            request_intent.request_core_digest().unwrap(),
            &[&event.event_id],
        )],
        request_receipts: Vec::new(),
        request_mirror_receipts: Vec::new(),
        contact_round_evidence: None,
        current_state: Default::default(),

        response_event_ref: None,
        tombstone_event_ref: None,
        message: None,
        peer_host_id: None,
        peer_service_resolution: None,
        created_at: accepted_at,
        updated_at: accepted_at,
    };
    request.contact_projection = Some(ContactProjectionCommit {
        completion_intent: Some(request_intent.clone()),
        record: Box::new(row.clone()),
        expected_updated_at: None,
        conflict_code: "contact_round_conflict".to_owned(),
        verified_mirror: None,
        invite_policy: None,
    });
    request.projections.clear();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request.clone())
        .await
        .expect("the request unit commits");
    Requested {
        pool,
        request,
        request_intent,
        row,
        responder_head: responder.unit.transactions.last().unwrap().clone(),
        responder_guard,
    }
}

/// Bob's normal response to `requested`, planned against its current row.
/// `edit` rewrites the frozen absence observation before the unit is built.
async fn response(
    requested: &Requested,
    edit: impl FnOnce(&mut OutgoingSlotAbsenceTranscript),
) -> EventCommitRequest {
    let request_event = &requested.request.authority_commit.event;
    let accepted_at = requested.row.updated_at + Duration::seconds(1);
    let key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
    let receipt = RequestAcceptanceReceipt::sign_with(
        requested.request_intent.request_receipt_core().unwrap(),
        |bytes| {
            Ok(arkret_wire::ProtocolSignature {
                verification_method: DidUrl::new("did:web:ordinary-station.example#receipt")
                    .unwrap(),
                created_at: accepted_at,
                jws: arkret_signatures::sign_ed25519_detached_jws(&key, bytes).unwrap(),
            })
        },
    )
    .unwrap();
    let mut pair = [alice().contact_actor_id(), bob().contact_actor_id()];
    if arkret_canonical::canonical_json_bytes(&pair[0]).unwrap()
        > arkret_canonical::canonical_json_bytes(&pair[1]).unwrap()
    {
        pair.swap(0, 1);
    }
    let receipt_digest = receipt.computed_receipt_digest().unwrap();
    let round = ContactRound::Normal {
        sorted_pair_member_ids: pair.clone(),
        request_event_ref: request_event.event_id.clone(),
        request_acceptance_receipt_digest: receipt_digest.clone(),
    };
    let contact_round_id = Hash::new(
        arkret_canonical::domain_prefixed_canonical_sha256("ak.contact.round.v1", &round).unwrap(),
    )
    .unwrap();
    let mut absence = OutgoingSlotAbsenceTranscript {
        trust_domain_id: arkret_wire::TrustDomainId::new("ak:trust_domain:contact.test").unwrap(),
        request_event_ref: request_event.event_id.clone(),
        sorted_pair_member_ids: pair,
        request_slot_owner: bob().contact_actor_id(),
        contact_round_id: contact_round_id.clone(),
        predecessor_event_ref: None,
        version: 1,
        observed_at: arkret_canonical::normalize_timestamp_canonical(accepted_at),
        outgoing_request_state: OutgoingRequestState::Absent,
    };
    edit(&mut absence);
    let mut unit = contact_request(
        &requested.pool,
        &requested.responder_guard,
        &requested.responder_head,
        EventKind::ContactAccepted,
        &bob(),
        serde_json::json!({
            "trust_domain_id":"ak:trust_domain:contact.test",
            "peer": alice(),
            "contact_round_id": contact_round_id,
            "version": 1,
            "request_event_ref": request_event.event_id,
            "request_acceptance_receipt_digest": receipt_digest,
            "granted_to_peer_scopes": ["direct_message"],
        }),
        accepted_at,
    )
    .await;
    let event = unit.authority_commit.event.clone();
    let response_intent = intent(
        &event,
        &bob(),
        &alice(),
        ContactCompletionAction::Response {
            request_receipt: Box::new(receipt),
            absence: Box::new(absence.clone()),
        },
        absence.observed_at,
    );
    let mut row = requested.row.clone();
    row.status = "accepted".to_owned();
    row.contact_round_id = Some(contact_round_id);
    row.granted_to_requester_scopes = vec!["direct_message".to_owned()];
    row.response_event_ref = Some(event.event_id.clone());
    row.updated_at = accepted_at;
    row.request_slot_states.push(ContactRequestSlotState {
        owner_id: bob().contact_actor_id(),
        peer_id: alice().contact_actor_id(),
        version: 1,
        head_event_ref: event.event_id.clone(),
        operation_digest: None,
        request_choice: Some(coland_domain::identity::ContactRequestChoice::Normal {
            request_event_ref: request_event.event_id.clone(),
        }),
    });
    unit.contact_projection = Some(ContactProjectionCommit {
        completion_intent: Some(response_intent),
        record: Box::new(row),
        expected_updated_at: Some(requested.row.updated_at),
        conflict_code: "contact_lineage_conflict".to_owned(),
        verified_mirror: None,
        invite_policy: None,
    });
    unit.projections.clear();
    unit
}

async fn count(pool: &PgPool, query: &str, value: &str) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(query)
        .bind::<Text, _>(value)
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// Nothing of a refused unit is durable: no Event, no Commit, no completion
/// intent, and the Contact row still at its planned pre-state.
async fn assert_zero_writes(requested: &Requested, refused: &EventCommitRequest) {
    let event_id = refused.authority_commit.event.event_id.clone();
    assert!(
        PgAuthorityCommitStore {
            pool: requested.pool.clone(),
        }
        .committed_event(&event_id)
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
        count(
            &requested.pool,
            "SELECT count(*) AS count FROM contact_completion_intents WHERE event_id = $1",
            event_id.as_str(),
        )
        .await,
        0
    );
    let row = PgContactStore {
        pool: requested.pool.clone(),
    }
    .get(&requested.row.requester_id, &requested.row.target_id)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(row.updated_at, requested.row.updated_at);
    assert_eq!(row.status, "pending");
    assert_eq!(row.request_slot_states, requested.row.request_slot_states);
}

#[tokio::test]
async fn request_and_normal_response_commit_with_the_slot_cas_they_sign() {
    let database = TestDatabase::lease().await;
    let requested = requested(&database).await;
    let request_id = requested.request.authority_commit.event.event_id.clone();
    let committed = PgAuthorityCommitStore {
        pool: requested.pool.clone(),
    }
    .committed_event(&request_id)
    .await
    .unwrap()
    .expect("the request Event is committed with its Commit");
    assert_eq!(committed.commit.event_ref, request_id);
    let contacts = PgContactStore {
        pool: requested.pool.clone(),
    };
    assert_eq!(
        contacts
            .get(&requested.row.requester_id, &requested.row.target_id)
            .await
            .unwrap()
            .unwrap()
            .request_slot_states,
        requested.row.request_slot_states
    );
    let staged = contacts
        .committed_completion_intents(8, None)
        .await
        .unwrap();
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].committed_ref.event_id, request_id);
    assert_eq!(
        staged[0].committed_ref.commit_id,
        committed.commit.commit_id
    );

    let response = response(&requested, |_| {}).await;
    assert_eq!(
        response.authority_commit.event.realm_id,
        requested.responder_head.event.realm_id
    );
    assert_ne!(
        response.authority_commit.event.realm_id,
        requested.request.authority_commit.event.realm_id
    );
    PgEventCommitUnitOfWork::new(requested.pool.clone())
        .commit_event(response.clone())
        .await
        .expect("the normal response unit commits");
    let row = contacts
        .get(&requested.row.requester_id, &requested.row.target_id)
        .await
        .unwrap()
        .unwrap();
    let response_id = response.authority_commit.event.event_id.clone();
    assert_eq!(row.status, "accepted");
    assert_eq!(row.response_event_ref, Some(response_id.clone()));
    let responder_slot = row
        .request_slot_states
        .iter()
        .find(|state| state.owner_id == bob().contact_actor_id())
        .unwrap();
    assert_eq!(responder_slot.version, 1);
    assert_eq!(responder_slot.head_event_ref, response_id);
    assert_eq!(
        contacts
            .committed_completion_intents(8, None)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn wrong_revision_foreign_slot_and_lost_row_cas_refuse_with_zero_writes() {
    let database = TestDatabase::lease().await;
    let requested = requested(&database).await;
    let uow = PgEventCommitUnitOfWork::new(requested.pool.clone());

    // A revision naming anything but the slot prefix plus the consumed request.
    let stale = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3_u8; 32]);
    let wrong_revision = response(&requested, |absence| {
        absence.request_event_ref = stale.clone();
    })
    .await;
    assert!(uow.commit_event(wrong_revision.clone()).await.is_err());
    assert_zero_writes(&requested, &wrong_revision).await;

    // The requester's slot is not the responder's CAS observation.
    let foreign_slot = response(&requested, |absence| {
        absence.request_slot_owner = alice().contact_actor_id();
    })
    .await;
    assert!(uow.commit_event(foreign_slot.clone()).await.is_err());
    assert_zero_writes(&requested, &foreign_slot).await;

    // A predecessor or sequence the slot never accepted.
    let skipped = response(&requested, |absence| {
        absence.version = 2;
    })
    .await;
    assert!(uow.commit_event(skipped.clone()).await.is_err());
    assert_zero_writes(&requested, &skipped).await;

    // The row moved after the plan read it: the planned revision is gone.
    let mut concurrent = response(&requested, |_| {}).await;
    let projection = concurrent.contact_projection.as_mut().unwrap();
    projection.expected_updated_at = Some(requested.row.updated_at - Duration::seconds(1));
    assert!(uow.commit_event(concurrent.clone()).await.is_err());
    assert_zero_writes(&requested, &concurrent).await;

    // The exact planned unit still commits afterwards.
    uow.commit_event(response(&requested, |_| {}).await)
        .await
        .expect("the untouched response commits");
}

#[tokio::test]
async fn moved_contact_row_retries_the_frozen_event_but_consumed_slot_still_conflicts() {
    let database = TestDatabase::lease().await;
    let requested = requested(&database).await;
    let uow = PgEventCommitUnitOfWork::new(requested.pool.clone());
    let mut planned = response(&requested, |_| {}).await;
    let original_event =
        arkret_canonical::canonical_json_bytes(&planned.authority_commit.event).unwrap();
    // The private projection timestamp is stale, while the holder's signed
    // version and predecessor still name the exact durable operation slot.
    planned
        .contact_projection
        .as_mut()
        .unwrap()
        .expected_updated_at = Some(requested.row.updated_at - Duration::microseconds(1));
    let error = uow.commit_event(planned.clone()).await.unwrap_err();
    assert!(
        error.to_string().contains("temporarily_unavailable"),
        "{error}"
    );
    assert_zero_writes(&requested, &planned).await;

    // A future private revision is not a confirmed concurrent advance.
    planned
        .contact_projection
        .as_mut()
        .unwrap()
        .expected_updated_at = Some(requested.row.updated_at + Duration::microseconds(1));
    let error = uow.commit_event(planned.clone()).await.unwrap_err();
    assert!(
        error.to_string().contains("contact_lineage_conflict"),
        "{error}"
    );
    assert_zero_writes(&requested, &planned).await;

    planned
        .contact_projection
        .as_mut()
        .unwrap()
        .expected_updated_at = Some(requested.row.updated_at);
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&planned.authority_commit.event).unwrap(),
        original_event,
    );
    uow.commit_event(planned.clone()).await.unwrap();
    let current = PgContactStore {
        pool: requested.pool.clone(),
    }
    .get(&requested.row.requester_id, &requested.row.target_id)
    .await
    .unwrap()
    .unwrap();
    let projection = planned.contact_projection.as_ref().unwrap();
    // Accepted replay deduplication is checked separately. A new admission
    // cannot treat this consumed slot as a retryable private-row refresh.
    let error = projection
        .completion_intent
        .as_ref()
        .unwrap()
        .validate_slot_cas(Some(&current), &projection.record)
        .unwrap_err();
    assert!(
        error.to_string().contains("contact_lineage_conflict"),
        "{error}"
    );
}

#[tokio::test]
async fn exact_replay_of_the_accepting_unit_installs_nothing_twice() {
    let database = TestDatabase::lease().await;
    let requested = requested(&database).await;
    let outcome = PgEventCommitUnitOfWork::new(requested.pool.clone())
        .commit_event(requested.request.clone())
        .await
        .expect("an exact replay observes the committed unit");
    assert!(!outcome.event_inserted);
    let contacts = PgContactStore {
        pool: requested.pool.clone(),
    };
    assert_eq!(
        contacts
            .committed_completion_intents(8, None)
            .await
            .unwrap()
            .len(),
        1
    );
    let row = contacts
        .get(&requested.row.requester_id, &requested.row.target_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.updated_at, requested.row.updated_at);
    assert_eq!(row.request_slot_states, requested.row.request_slot_states);
}

#[tokio::test]
async fn current_contact_cas_and_frozen_response_rollback_together_on_conflicting_result() {
    use coland_storage::IdempotencyStore;
    let database = TestDatabase::lease().await;
    let requested = requested(&database).await;
    let contacts = PgContactStore {
        pool: requested.pool.clone(),
    };
    let keys = coland_storage_postgres::PgIdempotencyStore {
        pool: requested.pool.clone(),
    };
    let original = contacts
        .get(&requested.row.requester_id, &requested.row.target_id)
        .await
        .unwrap()
        .unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let result = coland_storage::IdempotencyRecord {
        authenticated_actor: original.requester_id.clone(),
        operation_id: "ak.peer.contacts.command.submit.v1".into(),
        idempotency_key: "current-state-atomicity".into(),
        request_hash: format!("sha256:{}", "a".repeat(64)),
        response_status: 200,
        response_body: serde_json::json!({"frozen":"accepted-response"}),
        created_at: at,
        expires_at: at + chrono::Duration::days(1),
    };
    keys.record(&result).await.unwrap();
    let mut candidate = original.clone();
    candidate.updated_at += chrono::Duration::milliseconds(1);
    candidate.message = Some("result transaction".into());
    for wrong_body in [false, true] {
        let mut conflicting = result.clone();
        if wrong_body {
            conflicting.response_body = serde_json::json!({"replacement":true});
        } else {
            conflicting.request_hash = format!("sha256:{}", "b".repeat(64));
        }
        assert!(
            contacts
                .put_if_updated_at_with_result(original.updated_at, &candidate, &conflicting)
                .await
                .is_err()
        );
        let reopened = PgContactStore {
            pool: requested.pool.clone(),
        };
        let observed = reopened
            .get(&original.requester_id, &original.target_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.updated_at, original.updated_at);
        assert_eq!(observed.message, original.message);
        assert_eq!(
            keys.get(
                &result.authenticated_actor,
                &result.operation_id,
                &result.idempotency_key
            )
            .await
            .unwrap()
            .unwrap(),
            result
        );
    }
    assert!(
        contacts
            .put_if_updated_at_with_result(original.updated_at, &candidate, &result)
            .await
            .unwrap()
    );
    assert!(
        !contacts
            .put_if_updated_at_with_result(original.updated_at, &candidate, &result)
            .await
            .unwrap()
    );
    assert_eq!(
        contacts
            .get(&original.requester_id, &original.target_id)
            .await
            .unwrap()
            .unwrap()
            .message,
        candidate.message
    );
}
