//! Real PostgreSQL proof that Contact completion finalization is exactly-once
//! under concurrent workers, idempotent on exact replay after the staged plan
//! has been replaced by its terminal result, and still fails closed on any
//! different plan, commit reference, result, or delivery.

use arkret_models_collaboration::contact_operations::{
    ContactAcceptedOutcome, ContactPeer, ContactProducerSigner, RequestAcceptanceReceipt,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_wire::{
    AccountId, CommitStreamRef, CommittedEventRef, DidCoreId, DidUrl, Event, EventId,
    ProtocolSignature, RealmCommitId, RealmId, ScopeRef,
};
use chrono::{DateTime, Duration, Utc};
use coland_storage::{
    ContactCompletionAction, ContactCompletionDraft, ContactDeliveryTarget, FederationOutboxRecord,
};
use ed25519_dalek::SigningKey;
use serde_json::json;

use super::*;
use crate::test_database::TestDatabase;

const STATION: &str = "ak:did_core:web:contact-station.example";
const PEER_STATION: &str = "ak:did_core:web:contact-peer-station.example";
const RECEIPT_METHOD: &str = "did:web:contact-station.example#receipt";

#[derive(Clone)]
struct Fixture {
    ready: CommittedContactCompletionIntent,
    result: ContactCompletionResult,
    delivery: Option<FederationOutboxRecord>,
}

fn core(value: &str) -> DidCoreId {
    DidCoreId::new(value).unwrap()
}

fn human(local: &str, station: &str) -> ContactPeer {
    ContactPeer::Human {
        account_id: AccountId::new(
            core(&format!("ak:did_core:web:{local}.example")),
            core(station),
        ),
    }
}

fn hash(fill: char) -> arkret_wire::Hash {
    arkret_wire::Hash::new(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
}

fn base() -> DateTime<Utc> {
    "2026-09-20T00:00:00Z".parse().unwrap()
}

/// One structurally bound request Event carrying its producer proof.
fn request_event(holder: &ContactPeer, peer: &ContactPeer, realm_id: &RealmId) -> Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::ContactRequested.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        holder.contact_actor_id(),
        json!({
            "trust_domain_id":"ak:trust_domain:contact.test","version":1,
            "peer": peer,
            "granted_to_peer_scopes": ["direct_message"],
            "introduction_evidence_digest": hash('e'),
        }),
        base(),
    )
    .unwrap();
    let digest = event.event_id.event_digest();
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: DidUrl::new("did:web:contact-holder.example#key").unwrap(),
        event_digest: digest.clone(),
        created_at: base(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

/// Sign the request receipt the way the completion worker does: the
/// signature records its own signing instant, so two signings differ.
fn request_result(
    intent: &ContactCompletionIntent,
    signed_at: DateTime<Utc>,
) -> ContactCompletionResult {
    let key = SigningKey::from_bytes(&[41_u8; 32]);
    let receipt =
        RequestAcceptanceReceipt::sign_with(intent.request_receipt_core().unwrap(), |bytes| {
            Ok(ProtocolSignature {
                verification_method: DidUrl::new(RECEIPT_METHOD).unwrap(),
                created_at: signed_at,
                jws: arkret_signatures::sign_ed25519_detached_jws(&key, bytes).unwrap(),
            })
        })
        .unwrap();
    ContactCompletionResult::Accepted {
        outcome: Box::new(ContactAcceptedOutcome::Request {
            operation_id: intent.plan.operation_id.clone(),
            request_acceptance_receipt: receipt,
        }),
    }
}

#[test]
fn contact_completion_indirection_preserves_closed_json() {
    let fixture = fixture(false);
    let ContactCompletionResult::Accepted { outcome } = &fixture.result else {
        panic!("fixture must contain an accepted result");
    };
    let expected = json!({ "result": "accepted", "outcome": outcome.as_ref() });
    assert_eq!(serde_json::to_value(&fixture.result).unwrap(), expected);
    let restored: ContactCompletionResult = serde_json::from_value(expected.clone()).unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), expected);
    let mut unknown = expected;
    unknown["unknown"] = json!(true);
    assert!(serde_json::from_value::<ContactCompletionResult>(unknown).is_err());

    let ContactAcceptedOutcome::Request {
        request_acceptance_receipt,
        ..
    } = outcome.as_ref()
    else {
        panic!("fixture must contain a request receipt");
    };
    let action = ContactCompletionAction::Reject {
        request_receipt: Box::new(request_acceptance_receipt.clone()),
    };
    let expected = json!({ "action": "reject", "request_receipt": request_acceptance_receipt });
    assert_eq!(serde_json::to_value(&action).unwrap(), expected);
    let restored: ContactCompletionAction = serde_json::from_value(expected.clone()).unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), expected);
    let mut unknown = expected;
    unknown["unknown"] = json!(true);
    assert!(serde_json::from_value::<ContactCompletionAction>(unknown).is_err());
}

/// A confirmed Contact request whose peer is served by this Station
/// (`remote == false`, no delivery) or by another Station (`remote == true`,
/// one federation delivery).
fn fixture(remote: bool) -> Fixture {
    let holder = human("contact-holder", STATION);
    let peer = human("contact-peer", if remote { PEER_STATION } else { STATION });
    let realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [5_u8; 32],
    ));
    let event = request_event(&holder, &peer, &realm_id);
    let target = ContactDeliveryTarget {
        contact_address: PeerContactAddress::for_recipient(
            peer.clone(),
            ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: "https://contact-peer-station.example/.well-known/resolution"
                    .to_owned(),
            },
        ),
        introduction_evidence: Some(ContactIntroductionEvidence::SharedRealm {
            realm_id: realm_id.clone(),
            requester_member_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [6_u8; 32],
            ),
            target_member_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [7_u8; 32],
            ),
        }),
        idempotency_key: arkret_wire::IdempotencyKey::new("contact-delivery-1").unwrap(),
    };
    let producer = ContactProducerSigner::direct(
        DidUrl::new("did:web:contact-holder.example#key").unwrap(),
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            SigningKey::from_bytes(&[23_u8; 32])
                .verifying_key()
                .to_bytes(),
        ))
        .unwrap(),
    )
    .unwrap();
    let mut intent = ContactCompletionDraft {
        event: event.clone(),
        operation_id: arkret_wire::ProtocolOperationId::new(
            "ak:operation:org.arkret.coland.contact.commit.v1",
        )
        .unwrap(),
        holder: holder.clone(),
        action: ContactCompletionAction::Request {
            version: 1,
            predecessor_event_ref: None,
        },
        response_binding: ContactCompletionBinding {
            authenticated_actor: holder.contact_actor_id(),
            idempotency_key: "contact-commit-1".to_owned(),
            request_hash: hash('a').as_str().to_owned(),
        },
        target,
        local_mirror_target: None,
    }
    .bind_producer(producer)
    .unwrap();
    intent
        .freeze_acceptance_time(base() + Duration::seconds(1))
        .unwrap();
    assert_eq!(intent.requires_delivery(), remote);
    let committed_ref = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: RealmCommitId::from_digest(arkret_canonical::sha256_bytes(b"contact-commit")),
        stream_ref: CommitStreamRef::Realm { realm_id },
        stream_position: 7,
    };
    let ready = CommittedContactCompletionIntent {
        event_digest: event.event_id.event_digest(),
        committed_ref,
        intent,
    };
    worker(&ready, base() + Duration::seconds(2))
}

/// One completion worker's own finalization of `ready`: it signs the outcome
/// at `signed_at` and, for a remote peer, builds the delivery carrier from
/// that outcome exactly as the HTTP worker does.
fn worker(ready: &CommittedContactCompletionIntent, signed_at: DateTime<Utc>) -> Fixture {
    let intent = &ready.intent;
    let result = request_result(intent, signed_at);
    let delivery = intent.requires_delivery().then(|| {
        let ContactCompletionResult::Accepted { outcome } = &result else {
            unreachable!()
        };
        FederationOutboxRecord::pending(
            format!("contact-outbox-{}", signed_at.timestamp_millis()),
            core(PEER_STATION),
            "https://contact-peer-station.example".to_owned(),
            "/_arkret/peer/contacts".to_owned(),
            intent.plan.target.idempotency_key.as_str().to_owned(),
            String::from_utf8(
                arkret_canonical::canonical_json_bytes(&intent.finalized_carrier(outcome).unwrap())
                    .unwrap(),
            )
            .unwrap(),
            base().timestamp_millis(),
        )
    });
    Fixture {
        ready: ready.clone(),
        result,
        delivery,
    }
}

/// The pending Contact row the accepting unit wrote with the intent.
fn pending_row(intent: &ContactCompletionIntent) -> coland_storage::ContactRecord {
    let peer: ContactPeer =
        serde_json::from_value(intent.plan.event.payload.get("peer").cloned().unwrap()).unwrap();
    let accepted_at = intent.accepted_at().unwrap();
    coland_storage::ContactRecord {
        requester_id: intent.plan.event.actor_id.clone(),
        target_id: peer.contact_actor_id(),
        contact_round_id: None,
        granted_to_target_scopes: vec!["direct_message".to_owned()],
        granted_to_requester_scopes: Vec::new(),
        status: "pending".to_owned(),
        pending_incoming_admitted: false,
        request_event_ref: Some(intent.plan.event.event_id.clone()),
        request_slot_states: vec![coland_storage::ContactRequestSlotState {
            owner_id: intent.plan.holder.contact_actor_id(),
            peer_id: peer.contact_actor_id(),
            version: 1,
            head_event_ref: intent.plan.event.event_id.clone(),
            operation_digest: None,
            request_choice: Some(coland_domain::identity::ContactRequestChoice::Open {
                request_event_ref: intent.plan.event.event_id.clone(),
            }),
        }],
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
    }
}

async fn stage(pool: &PgPool, fixture: &Fixture) {
    let mut conn = pg_conn(pool).await.unwrap();
    crate::unit_of_work::commit_contact_projection(
        &mut conn,
        None,
        coland_storage::ContactProjectionCommit {
            completion_intent: None,
            record: Box::new(pending_row(&fixture.ready.intent)),
            expected_updated_at: None,
            conflict_code: "contact_round_conflict".to_owned(),
            verified_mirror: None,
            invite_policy: None,
        },
    )
    .await
    .unwrap();
    stage_in_transaction(
        &mut conn,
        &fixture.ready.committed_ref,
        &fixture.ready.intent,
    )
    .await
    .unwrap();
    // Exactly what the worker queue reads back.
    let queued = confirmed(pool, 16, None).await.unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].event_digest, fixture.ready.event_digest);
}

async fn run(pool: &PgPool, fixture: &Fixture) -> PersistenceResult<bool> {
    finalize(
        pool,
        &fixture.ready,
        &fixture.result,
        fixture.delivery.as_ref(),
        None,
    )
    .await
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn count(pool: &PgPool, query: &str) -> i64 {
    let mut conn = pg_conn(pool).await.unwrap();
    sql_query(query)
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

#[derive(QueryableByName)]
struct Payload {
    #[diesel(sql_type = Text)]
    payload_json: String,
}

/// The single terminal state every accepted path must leave behind: the first
/// durable result and delivery, which is also what the request lookup returns.
async fn assert_terminal_once(pool: &PgPool, first: &Fixture) {
    let mut conn = pg_conn(pool).await.unwrap();
    let row = sql_query(format!(
        "SELECT {COLUMNS} FROM contact_completion_intents WHERE event_digest=$1"
    ))
    .bind::<Text, _>(first.ready.event_digest.as_str())
    .get_result::<CompletionRow>(&mut *conn)
    .await
    .unwrap();
    let outbox = sql_query("SELECT payload_json FROM federation_outbox")
        .load::<Payload>(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let first_result = serde_json::to_value(&first.result).unwrap();
    assert!(row.intent.is_none());
    assert_eq!(row.result.as_ref(), Some(&first_result));
    assert_eq!(
        row.delivery_outbox_id,
        first.delivery.as_ref().map(|delivery| delivery.id.clone())
    );
    assert_eq!(
        outbox
            .into_iter()
            .map(|row| row.payload_json)
            .collect::<Vec<_>>(),
        first
            .delivery
            .iter()
            .map(|delivery| delivery.payload_json.clone())
            .collect::<Vec<_>>(),
    );
    // The HTTP caller answers from this lookup, never from its own signing.
    let binding = &first.ready.intent.plan.response_binding;
    let returned = lookup(
        pool,
        &binding.authenticated_actor,
        &binding.idempotency_key,
        &binding.request_hash,
    )
    .await
    .unwrap()
    .and_then(|state| state.result)
    .expect("the terminal result is readable");
    assert_eq!(serde_json::to_value(returned).unwrap(), first_result);
    assert!(confirmed(pool, 16, None).await.unwrap().is_empty());
    assert_eq!(
        count(
            pool,
            "SELECT count(*) AS count FROM idempotency_keys \
             WHERE operation_id='org.arkret.coland.contact.commit.v1'"
        )
        .await,
        1
    );
}

/// Two production-like workers sign the same staged plan at different
/// instants. Hold the staged row's lock until both are queued on it, then
/// release it so the two finalizations genuinely contend for the same row.
async fn race(remote: bool) {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let staged = fixture(remote);
    stage(&pool, &staged).await;
    let workers = [
        worker(&staged.ready, base() + Duration::seconds(3)),
        worker(&staged.ready, base() + Duration::seconds(4)),
    ];
    assert_ne!(
        serde_json::to_value(&workers[0].result).unwrap(),
        serde_json::to_value(&workers[1].result).unwrap(),
        "each worker signs its own bytes"
    );

    let mut holder = pg_conn(&pool).await.unwrap();
    sql_query("BEGIN").execute(&mut *holder).await.unwrap();
    sql_query(
        "SELECT event_digest FROM contact_completion_intents WHERE event_digest=$1 FOR UPDATE",
    )
    .bind::<Text, _>(staged.ready.event_digest.as_str())
    .execute(&mut *holder)
    .await
    .unwrap();
    let release = async {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(20);
        loop {
            let waiting = count(
                &pool,
                "SELECT count(*) AS count FROM pg_stat_activity \
                 WHERE datname=current_database() AND wait_event_type='Lock'",
            )
            .await;
            if waiting >= 2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "both Contact workers must block on the staged row"
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }
        sql_query("COMMIT").execute(&mut *holder).await.unwrap();
    };
    let (first, second, ()) =
        tokio::join!(run(&pool, &workers[0]), run(&pool, &workers[1]), release);
    let applied = [
        first.expect("first concurrent worker"),
        second.expect("second concurrent worker"),
    ];
    assert_eq!(
        applied.iter().filter(|applied| **applied).count(),
        1,
        "exactly one worker applies its result: {applied:?}"
    );
    let winner = if applied[0] { &workers[0] } else { &workers[1] };
    assert_terminal_once(&pool, winner).await;
}

#[tokio::test]
async fn concurrent_workers_finalize_local_completion_exactly_once() {
    race(false).await;
}

#[tokio::test]
async fn concurrent_workers_finalize_delivered_completion_exactly_once() {
    race(true).await;
}

#[tokio::test]
async fn sequential_replay_after_terminal_is_idempotent() {
    for remote in [false, true] {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let first = fixture(remote);
        stage(&pool, &first).await;
        assert!(run(&pool, &first).await.unwrap());
        // An exact replay, and a later worker that signed the same plan again.
        let later = worker(&first.ready, base() + Duration::seconds(5));
        for replay in [&first, &first, &later] {
            assert!(
                !run(&pool, replay)
                    .await
                    .expect("replay of the same completion after terminal"),
                "a replay never re-applies the terminal result"
            );
        }
        assert_terminal_once(&pool, &first).await;
    }
}

#[tokio::test]
async fn different_completion_after_terminal_still_conflicts() {
    for remote in [false, true] {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let fixture = fixture(remote);
        stage(&pool, &fixture).await;
        assert!(run(&pool, &fixture).await.unwrap());

        // A result that is not a valid terminal for this plan.
        let mut invalid_result = fixture.clone();
        if let ContactCompletionResult::Accepted { outcome } = &mut invalid_result.result
            && let ContactAcceptedOutcome::Request { operation_id, .. } = outcome.as_mut()
        {
            *operation_id =
                arkret_wire::ProtocolOperationId::new("ak:operation:ak.self.contact.other")
                    .unwrap();
        }
        // A different staged plan for the same Event, alone and with its own signing.
        let mut replanned = fixture.clone();
        replanned.ready.intent.plan.local_mirror_target = Some("mirror-elsewhere".to_owned());
        let replanned_resigned = worker(&replanned.ready, base() + Duration::seconds(6));
        // A different authority commit for the same Event.
        let mut recommitted = worker(&fixture.ready, base() + Duration::seconds(7));
        recommitted.ready.committed_ref.stream_position += 1;
        let mut cases = vec![
            (
                "invalid result",
                invalid_result,
                "changed its confirmed business inputs",
            ),
            (
                "different plan",
                replanned,
                "does not bind the exact committed Event",
            ),
            (
                "different plan, own signing",
                replanned_resigned,
                "does not bind the exact committed Event",
            ),
            (
                "different commit",
                recommitted,
                "does not bind the exact committed Event",
            ),
        ];
        if remote {
            // A delivery whose bytes are not the carrier of its own result.
            let mut redelivered = fixture.clone();
            redelivered.delivery.as_mut().unwrap().payload_json = "{}".to_owned();
            let mut unbound = worker(&fixture.ready, base() + Duration::seconds(8));
            unbound.delivery = fixture.delivery.clone();
            cases.push((
                "different delivery",
                redelivered,
                "delivery does not carry its finalized result",
            ));
            cases.push((
                "delivery of another result",
                unbound,
                "delivery does not carry its finalized result",
            ));
        }
        for (name, case, expected) in cases {
            let error = run(&pool, &case)
                .await
                .expect_err("a different completion after terminal must fail closed");
            assert!(
                error.to_string().contains(expected),
                "{name} (remote={remote}) failed for the wrong reason: {error}"
            );
        }
        assert_terminal_once(&pool, &fixture).await;
    }
}

/// The HTTP replay lookup reads the durable terminal result back into the
/// typed outcome. A detached-JWS receipt reads back and still verifies; the
/// retired bare base64url signature of the same bytes is not a readable
/// result, so the lookup fails closed instead of reinterpreting it.
#[tokio::test]
async fn request_lookup_reads_detached_jws_receipts_and_rejects_bare_signatures() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = fixture(false);
    stage(&pool, &fixture).await;
    assert!(run(&pool, &fixture).await.unwrap());
    let binding = &fixture.ready.intent.plan.response_binding;
    let read = || {
        lookup(
            &pool,
            &binding.authenticated_actor,
            &binding.idempotency_key,
            &binding.request_hash,
        )
    };
    let Some(ContactCompletionResult::Accepted { outcome }) =
        read().await.unwrap().and_then(|state| state.result)
    else {
        panic!("the terminal request result is readable");
    };
    let ContactAcceptedOutcome::Request {
        request_acceptance_receipt,
        ..
    } = *outcome
    else {
        panic!("the terminal result retains its request outcome");
    };
    arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
        &request_acceptance_receipt,
        &request_acceptance_receipt.core.request_event_ref,
        &SigningKey::from_bytes(&[41_u8; 32]).verifying_key(),
    )
    .unwrap();

    let jws = &request_acceptance_receipt.signature.jws;
    let bare = jws.rsplit('.').next().unwrap();
    assert!(!bare.is_empty() && bare != jws);
    let mut conn = pg_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE contact_completion_intents SET result = jsonb_set(result, \
         '{outcome,request_acceptance_receipt,signature,jws}', to_jsonb($1::text)) \
         WHERE event_digest=$2",
    )
    .bind::<Text, _>(bare)
    .bind::<Text, _>(fixture.ready.event_digest.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(read().await.is_err());
}

#[tokio::test]
async fn request_current_and_exact_delivery_freeze_in_the_same_completion() {
    use arkret_models_collaboration::contact_operations::{
        ContactCurrentProof, PeerContactSubmitRequestBody,
    };
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut f = fixture(true);
    stage(&pool, &f).await;
    let ContactCompletionResult::Accepted { outcome } = &f.result else {
        unreachable!()
    };
    let ContactAcceptedOutcome::Request {
        request_acceptance_receipt,
        ..
    } = outcome.as_ref()
    else {
        unreachable!()
    };
    let core = &request_acceptance_receipt.core;
    let key = SigningKey::from_bytes(&[41; 32]);
    let proof = ContactCurrentProof::sign_with(
        core.trust_domain_id.clone(),
        core.holder.clone(),
        core.peer.clone(),
        None,
        None,
        core.issuer_id.clone(),
        core.request_event_ref.clone(),
        core.version,
        vec![],
        None,
        core.accepted_at,
        core.accepted_at + Duration::minutes(10),
        |bytes| {
            Ok(ProtocolSignature {
                verification_method: DidUrl::new(RECEIPT_METHOD).unwrap(),
                created_at: core.accepted_at,
                jws: arkret_signatures::sign_ed25519_detached_jws(&key, bytes).unwrap(),
            })
        },
    )
    .unwrap();
    let mut carrier = f.ready.intent.finalized_carrier(outcome).unwrap();
    let PeerContactSubmitRequestBody::Request { current_proof, .. } = &mut carrier else {
        unreachable!()
    };
    *current_proof = Some(proof.clone());
    f.delivery.as_mut().unwrap().payload_json =
        String::from_utf8(arkret_canonical::canonical_json_bytes(&carrier).unwrap()).unwrap();
    assert!(
        finalize(
            &pool,
            &f.ready,
            &f.result,
            f.delivery.as_ref(),
            Some(&proof)
        )
        .await
        .unwrap()
    );
    assert_terminal_once(&pool, &f).await;
    assert!(
        !finalize(
            &pool,
            &f.ready,
            &f.result,
            f.delivery.as_ref(),
            Some(&proof)
        )
        .await
        .unwrap()
    );
    assert!(
        finalize(&pool, &f.ready, &f.result, f.delivery.as_ref(), None)
            .await
            .is_err()
    );
}
