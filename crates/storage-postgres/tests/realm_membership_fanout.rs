//! Second-member admission and committed-replication fanout on real
//! PostgreSQL.
//!
//! * The governance Station admits `ak.member.state` only at its same-cut FSM, writer and join-rule
//!   decision, and plans the committed-replication fanout of every Realm-stream Event from the
//!   joined set that Event produced (`federation.md` §4.1.1), in the Event's own transaction.
//! * A member Station stores exact source replicas: the hosted member's own verified `join` opens
//!   its held Realm stream, later Commits must directly follow it, and gaps, forks and unheld
//!   streams are refused with zero writes.

#[path = "support/accepted_pcr_account.rs"]
mod accepted_pcr_account;
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/historical_human.rs"]
mod historical_human;
#[path = "support/hydration.rs"]
mod hydration;
#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
#[path = "support/realm_fanout_authority_cases.rs"]
mod realm_fanout_authority_cases;
#[path = "support/realm_terminal_replica_cases.rs"]
mod realm_terminal_replica_cases;
#[path = "support/space_parent_replica_cases.rs"]
mod space_parent_replica_cases;

use arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest;
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CommittedChainNode, CommittedReplica,
    CommittedReplicaOutcome, CommittedReplicaRole, ConflictCode, CurrentRealmAuthority,
    EventCommitRequest, EventCommitUnitOfWork, OrdinaryRealmBootstrapCommitUnit,
    RealmFanoutAuthorityWitness, ReplicaAnchorInstall,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{STATION, message_payload, next_request, next_request_for_actor};

// Construct large native fixture futures in a separate synchronous frame.
// Returning the pinned allocation before polling avoids stacking construction
// temporaries on the parent poll frame in unoptimized Windows test builds.
#[inline(never)]
fn heap_future<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

fn bootstrap_snapshot(
    realm: &arkret_wire::RealmId,
    generation: u64,
    heads: &[arkret_wire::CommitStreamHead],
    entries: &[arkret_wire::TypedCurrentRow],
) -> arkret_wire::RealmStateSnapshot {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut snapshot = arkret_wire::RealmStateSnapshot {
        snapshot_id: arkret_wire::RealmSnapshotId::from_digest([0; 32]),
        realm_id: realm.clone(),
        governance_generation: generation,
        visible_stream_heads: heads.to_vec(),
        current_state_entries: entries.to_vec(),
        retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
            history_access: arkret_wire::HistoryAccess::SinceJoin,
            stream_floors: heads
                .iter()
                .map(|h| arkret_wire::StreamHistoryFloor {
                    stream_ref: h.stream_ref.clone(),
                    oldest_position: h.stream_position,
                })
                .collect(),
        },
        created_at: at,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmSnapshot,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new("did:web:station.example#authority")
                .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: at,
            sig: arkret_wire::Base64UrlString::new("c2ln").unwrap(),
        },
    };
    let mut identity = serde_json::to_value(&snapshot).unwrap();
    identity.as_object_mut().unwrap().remove("snapshot_id");
    identity.as_object_mut().unwrap().remove("signature");
    snapshot.snapshot_id = arkret_wire::RealmSnapshotId::from_digest(
        arkret_canonical::sha256_bytes(&arkret_canonical::canonical_json_bytes(&identity).unwrap()),
    );
    snapshot
}

const MEMBER_STATION: &str = "ak:did_core:web:member-station.example";

fn member_station() -> arkret_wire::DidCoreId {
    arkret_wire::DidCoreId::new(MEMBER_STATION).unwrap()
}

fn remote_member(label: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
        member_station(),
    ))
}

fn founder_actor() -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        founder(),
        arkret_wire::DidCoreId::new(STATION).unwrap(),
    ))
}

fn founder() -> arkret_wire::DidCoreId {
    ordinary_realm::human_profile::account(&ordinary_realm::station(), "fanout-founder")
        .principal_id
}

fn bootstrap_unit_with_join_rule(seed: &str, join_rule: &str) -> OrdinaryRealmBootstrapCommitUnit {
    ordinary_realm::bootstrap_unit_with_history_for_account(
        seed,
        join_rule,
        "since_join",
        &ordinary_realm::human_profile::account(&ordinary_realm::station(), "fanout-founder"),
        &ordinary_realm::human_profile::station_did(&ordinary_realm::station()),
    )
}

/// A membership payload. Every call carries its own audit reason, so two
/// requests for the same transition are distinct Events.
fn membership(
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
    state: &str,
) -> serde_json::Value {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    serde_json::json!({
        "realm_id": realm_id,
        "member_id": member,
        "membership": state,
        "reason": format!("fixture transition {sequence}"),
    })
}

/// The request as the guarded unit sends it: carrying its exact source
/// submission so a remote joined member can be owed the Event.
fn sourced(mut request: EventCommitRequest) -> EventCommitRequest {
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

fn membership_request(
    previous: &AuthorityCommitTransaction,
    writer: arkret_wire::ActorId,
    member: &arkret_wire::ActorId,
    state: &str,
) -> EventCommitRequest {
    sourced(next_request_for_actor(
        previous,
        arkret_wire::EventKind::MemberState,
        writer,
        membership(&previous.event.realm_id, member, state),
        previous.commit.committed_at,
    ))
}

async fn admit(pool: &PgPool, seed: &str, join_rule: &str) -> OrdinaryRealmBootstrapCommitUnit {
    ordinary_realm::human_profile::admit(pool, &ordinary_realm::station(), "fanout-founder").await;
    let unit = bootstrap_unit_with_join_rule(seed, join_rule);
    let unit = ordinary_realm::source_bootstrap(pool, unit).await;
    unit.validate().unwrap();
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .expect("admit ordinary Realm bootstrap");
    unit
}

#[derive(diesel::QueryableByName)]
struct OutboxRow {
    #[diesel(sql_type = Text)]
    peer_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    payload_json: String,
    #[diesel(sql_type = Jsonb)]
    realm_fanout: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    linked: i64,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct MembershipRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

async fn fanout_rows(pool: &PgPool, request: &EventCommitRequest) -> Vec<OutboxRow> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT o.peer_id, o.state, o.endpoint, o.payload_json, o.realm_fanout, \
         (SELECT count(*) FROM event_federation_outbox l WHERE l.outbox_id = o.id) AS linked \
         FROM federation_outbox o WHERE o.idempotency_key = $1 ORDER BY o.peer_id",
    )
    .bind::<Text, _>(format!(
        "realm-fanout:{}",
        request.authority_commit.commit.commit_id
    ))
    .load::<OutboxRow>(&mut *conn)
    .await
    .unwrap()
}

async fn outbox_count(pool: &PgPool) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT count(*) AS count FROM federation_outbox")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn member_state(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> Option<String> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT membership FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .load::<MembershipRow>(&mut *conn)
    .await
    .unwrap()
    .pop()
    .map(|row| row.membership)
}

/// The one intent the Event owes the member Station, with exactly the
/// expected frozen bases and an exact source-submission body.
fn assert_owed(
    rows: &[OutboxRow],
    request: &EventCommitRequest,
    witnesses: &[(&arkret_wire::ActorId, &arkret_wire::EventId)],
) {
    assert_eq!(rows.len(), 1, "one intent per distinct remote Station");
    let row = &rows[0];
    assert_eq!(row.peer_id, MEMBER_STATION);
    assert_eq!(row.state, "pending_route");
    assert_eq!(row.endpoint, "/_arkret/peer/events");
    assert_eq!(row.linked, 1);
    let body: PeerAuthoritySubmitRequest = serde_json::from_str(&row.payload_json).unwrap();
    body.validate().unwrap();
    let PeerAuthoritySubmitRequest::CommittedReplication(body) = body else {
        panic!("Realm fanout must use the committed_replication branch");
    };
    assert_eq!(body.replications.len(), 1);
    assert_eq!(
        body.replications[0].event_submission,
        arkret_wire::EventAdmissionSubmission::new(request.authority_commit.event.clone())
    );
    assert!(
        !row.payload_json.contains("approval_signatures"),
        "approval votes belong only to first admission, never committed replication"
    );
    assert_eq!(
        body.replications[0].source_commit,
        request.authority_commit.commit
    );
    assert!(
        !row.payload_json.contains("fanout_authorization_basis")
            && !row.payload_json.contains("authority_witnesses"),
        "the frozen basis stays in sender metadata"
    );
    let mut frozen: Vec<RealmFanoutAuthorityWitness> =
        serde_json::from_value(row.realm_fanout["authority_witnesses"].clone()).unwrap();
    let mut expected: Vec<_> = witnesses
        .iter()
        .map(|(member, event_id)| RealmFanoutAuthorityWitness {
            member_id: (*member).clone(),
            circle_membership_event_ref: None,
            membership_event_ref: event_id.to_string(),
        })
        .collect();
    // Compare the exact authority basis independently of database text collation.
    frozen.sort_by_key(|witness| witness.member_id.to_string());
    expected.sort_by_key(|witness| witness.member_id.to_string());
    assert_eq!(frozen, expected);
}

/// A remote account enters a public Realm by its own `join`; every later
/// Realm Event is owed to its Station with the membership that authorizes it,
/// a plaintext Message only when the Station may read plaintext, and a
/// member who leaves stops authorizing the intent.
#[tokio::test]
async fn remote_joined_target_set_and_fanout_basis_commit_with_the_event() {
    heap_future(remote_joined_target_set_and_fanout_basis_commit_with_the_event_case).await;
}

async fn remote_joined_target_set_and_fanout_basis_commit_with_the_event_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = heap_future(|| admit(&pool, "fanout-public", "public")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let alice = remote_member("fanout-alice");
    let bob = remote_member("fanout-bob");

    let alice_join = membership_request(last, alice.clone(), &alice, "join");
    let alice_join = heap_future(|| ordinary_realm::source_request(&pool, alice_join)).await;
    let outcome = uow.commit_event(alice_join.clone()).await.unwrap();
    assert_eq!(outcome.outbox_inserted, 1);
    assert_eq!(
        member_state(&pool, &realm_id, &alice).await.as_deref(),
        Some("join")
    );
    let alice_ref = alice_join.authority_commit.event.event_id.clone();
    assert_owed(
        &fanout_rows(&pool, &alice_join).await,
        &alice_join,
        &[(&alice, &alice_ref)],
    );

    let at = last.commit.committed_at;
    let strand = sourced(next_request(
        &alice_join.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Fanout discussion"},
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    let strand = heap_future(|| ordinary_realm::source_request(&pool, strand)).await;
    uow.commit_event(strand.clone()).await.unwrap();
    assert_owed(
        &fanout_rows(&pool, &strand).await,
        &strand,
        &[(&alice, &alice_ref)],
    );
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = sourced(next_request(
        &strand.authority_commit,
        arkret_wire::EventKind::RealmSetDefaultStrand,
        &founder(),
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": null,
        }),
        at,
    ));
    let default = heap_future(|| ordinary_realm::source_request(&pool, default)).await;
    uow.commit_event(default.clone()).await.unwrap();

    // The member Station is not a private plaintext service of this Realm:
    // it may not hold the plaintext body, so no intent is planned.
    let message = sourced(next_request(
        &default.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&strand_id, "plaintext stays on the governance Station"),
        at,
    ));
    let message = heap_future(|| ordinary_realm::source_request(&pool, message)).await;
    let outcome = uow.commit_event(message.clone()).await.unwrap();
    assert_eq!(outcome.outbox_inserted, 0);
    assert!(fanout_rows(&pool, &message).await.is_empty());

    // A second member on the same Station adds a basis to one intent.
    let bob_join = membership_request(&message.authority_commit, bob.clone(), &bob, "join");
    let bob_join = heap_future(|| ordinary_realm::source_request(&pool, bob_join)).await;
    uow.commit_event(bob_join.clone()).await.unwrap();
    let bob_ref = bob_join.authority_commit.event.event_id.clone();
    let mut expected = vec![(&alice, &alice_ref), (&bob, &bob_ref)];
    expected.sort_by_key(|(member, _)| member.to_string());
    assert_owed(&fanout_rows(&pool, &bob_join).await, &bob_join, &expected);

    // After Alice leaves by her own Control Event, Bob still authorizes it
    // and the leave itself is owed to Alice's Station, frozen with the leave
    // as her basis (`federation.md` section 4.1.1).
    let alice_leave =
        membership_request(&bob_join.authority_commit, alice.clone(), &alice, "leave");
    let alice_leave = heap_future(|| ordinary_realm::source_request(&pool, alice_leave)).await;
    uow.commit_event(alice_leave.clone()).await.unwrap();
    assert_eq!(
        member_state(&pool, &realm_id, &alice).await.as_deref(),
        Some("leave")
    );
    let alice_leave_ref = alice_leave.authority_commit.event.event_id.clone();
    assert_owed(
        &fanout_rows(&pool, &alice_leave).await,
        &alice_leave,
        &[(&bob, &bob_ref), (&alice, &alice_leave_ref)],
    );

    // Bob leaves: nobody on the member Station stays joined, but Bob's own
    // leave is still owed to it as the last Commit it holds for Bob.
    let bob_leave = membership_request(&alice_leave.authority_commit, bob.clone(), &bob, "leave");
    let bob_leave = heap_future(|| ordinary_realm::source_request(&pool, bob_leave)).await;
    let outcome = uow.commit_event(bob_leave.clone()).await.unwrap();
    assert_eq!(outcome.outbox_inserted, 1);
    let bob_leave_ref = bob_leave.authority_commit.event.event_id.clone();
    assert_owed(
        &fanout_rows(&pool, &bob_leave).await,
        &bob_leave,
        &[(&bob, &bob_leave_ref)],
    );
}

fn assert_code(error: &coland_storage::PersistenceError, code: ConflictCode) {
    assert_eq!(error.conflict_code(), Some(code), "{error}");
}

async fn assert_refused(
    pool: &PgPool,
    uow: &PgEventCommitUnitOfWork,
    request: EventCommitRequest,
    code: ConflictCode,
) {
    let request = ordinary_realm::source_request(pool, request).await;
    let outbox = outbox_count(pool).await;
    let error = uow.commit_event(request.clone()).await.unwrap_err();
    assert_code(&error, code);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(
        store
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none(),
        "a refused membership Event is not committed"
    );
    assert_eq!(
        outbox_count(pool).await,
        outbox,
        "a refusal plans no fanout"
    );
}

/// Real PostgreSQL: only the listed FSM edges by their listed writers are
/// admitted -- self entry under an open join rule, self leave, and a kick or
/// ban by a joined member the same-cut evaluator admits for `ak.member.state`
/// (the root controller, or a holder of an active `ak.realm.admin` grant) --
/// and every refusal writes nothing.
#[tokio::test]
async fn member_state_join_leave_and_kick_follow_join_rule_and_capability() {
    heap_future(member_state_join_leave_and_kick_follow_join_rule_and_capability_case).await;
}

async fn member_state_join_leave_and_kick_follow_join_rule_and_capability_case() {
    // Accepted PCRs and devices belong to this database's one hosted Station;
    // the FSM and capability guards depend on exact Accounts, not remote routing.
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = heap_future(|| {
        accepted_pcr_account::accepted_pcr_account(
            &pool,
            device_authorization_history::did_web_station(&ordinary_realm::station()),
        )
    })
    .await;
    let bob = heap_future(|| {
        accepted_pcr_account::accepted_pcr_account(
            &pool,
            device_authorization_history::did_web_station(&ordinary_realm::station()),
        )
    })
    .await;

    // An invite-only Realm has no self entry.
    let invite = heap_future(|| admit(&pool, "fsm-invite", "invite")).await;
    let last = invite.transactions.last().unwrap();
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(last, alice.clone(), &alice, "join"),
            ConflictCode::GateCheckFailed,
        )
    })
    .await;
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(last, alice.clone(), &alice, "knock"),
            ConflictCode::GateCheckFailed,
        )
    })
    .await;

    let public = heap_future(|| admit(&pool, "fsm-public", "public")).await;
    let last = public.transactions.last().unwrap();
    // Even the Realm root controller cannot enter someone else.
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(last, founder_actor(), &alice, "join"),
            ConflictCode::CapabilityDenied,
        )
    })
    .await;
    let alice_join = membership_request(last, alice.clone(), &alice, "join");
    let alice_join = heap_future(|| ordinary_realm::source_request(&pool, alice_join)).await;
    uow.commit_event(alice_join.clone()).await.unwrap();
    // `join -> join` is not an edge.
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(&alice_join.authority_commit, alice.clone(), &alice, "join"),
            ConflictCode::InvalidMembershipTransition,
        )
    })
    .await;
    let bob_join = membership_request(&alice_join.authority_commit, bob.clone(), &bob, "join");
    let bob_join = heap_future(|| ordinary_realm::source_request(&pool, bob_join)).await;
    uow.commit_event(bob_join.clone()).await.unwrap();
    // A member without `ak.realm.admin` cannot ban or remove another.
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(&bob_join.authority_commit, alice.clone(), &bob, "ban"),
            ConflictCode::CapabilityDenied,
        )
    })
    .await;
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(&bob_join.authority_commit, alice.clone(), &bob, "leave"),
            ConflictCode::CapabilityDenied,
        )
    })
    .await;
    // The root controller holds every action and bans Bob.
    let ban = membership_request(&bob_join.authority_commit, founder_actor(), &bob, "ban");
    let ban = heap_future(|| ordinary_realm::source_request(&pool, ban)).await;
    uow.commit_event(ban.clone()).await.unwrap();
    let realm_id = public.transactions[0].event.realm_id.clone();
    assert_eq!(
        member_state(&pool, &realm_id, &bob).await.as_deref(),
        Some("ban")
    );
    // Bob cannot lift his own ban, and a banned member cannot rejoin.
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(&ban.authority_commit, bob.clone(), &bob, "leave"),
            ConflictCode::CapabilityDenied,
        )
    })
    .await;
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(&ban.authority_commit, bob.clone(), &bob, "join"),
            ConflictCode::InvalidMembershipTransition,
        )
    })
    .await;

    // A grant of `ak.realm.admin` from the root lets Alice remove Carol; once
    // the root revokes it, the same Alice is refused at the next cut.
    let carol = heap_future(|| {
        accepted_pcr_account::accepted_pcr_account(
            &pool,
            device_authorization_history::did_web_station(&ordinary_realm::station()),
        )
    })
    .await;
    let carol_join = membership_request(&ban.authority_commit, carol.clone(), &carol, "join");
    let carol_join = heap_future(|| ordinary_realm::source_request(&pool, carol_join)).await;
    uow.commit_event(carol_join.clone()).await.unwrap();
    let root_event_ref = realm_root_event_ref(&pool, &realm_id).await;
    let admin_grant = grant_request(
        &carol_join.authority_commit,
        &alice,
        &["ak.realm.admin"],
        &root_event_ref,
    );
    let admin_grant = heap_future(|| ordinary_realm::source_request(&pool, admin_grant)).await;
    uow.commit_event(admin_grant.clone()).await.unwrap();
    let kick = membership_request(
        &admin_grant.authority_commit,
        alice.clone(),
        &carol,
        "leave",
    );
    let kick = heap_future(|| ordinary_realm::source_request(&pool, kick)).await;
    uow.commit_event(kick.clone()).await.unwrap();
    assert_eq!(
        member_state(&pool, &realm_id, &carol).await.as_deref(),
        Some("leave")
    );
    let revoke = sourced(next_request_for_actor(
        &kick.authority_commit,
        arkret_wire::EventKind::CapabilityRevoke,
        founder_actor(),
        serde_json::json!({
            "grant_id": arkret_wire::GrantId::from_event_id(
                &admin_grant.authority_commit.event.event_id
            ),
            "expected_revision": {
                "commit_id": admin_grant.authority_commit.commit.commit_id,
                "stream_position": admin_grant.authority_commit.commit.stream_position,
            },
        }),
        kick.authority_commit.commit.committed_at,
    ));
    let revoke = heap_future(|| ordinary_realm::source_request(&pool, revoke)).await;
    uow.commit_event(revoke.clone()).await.unwrap();
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(&revoke.authority_commit, alice.clone(), &carol, "ban"),
            ConflictCode::CapabilityDenied,
        )
    })
    .await;
    // Alice leaves by her own Event, and a member who left holds no
    // administration even with the Realm's grants restored.
    let alice_leave = membership_request(&revoke.authority_commit, alice.clone(), &alice, "leave");
    let alice_leave = heap_future(|| ordinary_realm::source_request(&pool, alice_leave)).await;
    uow.commit_event(alice_leave.clone()).await.unwrap();
    assert_eq!(
        member_state(&pool, &realm_id, &alice).await.as_deref(),
        Some("leave")
    );
    // A distinct grant body: the first grant's exact Event is already committed.
    let regrant = grant_request(
        &alice_leave.authority_commit,
        &alice,
        &["ak.realm.admin", "ak.message.create"],
        &root_event_ref,
    );
    let regrant = heap_future(|| ordinary_realm::source_request(&pool, regrant)).await;
    uow.commit_event(regrant.clone()).await.unwrap();
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            membership_request(&regrant.authority_commit, alice.clone(), &carol, "ban"),
            ConflictCode::CapabilityDenied,
        )
    })
    .await;
}

async fn realm_root_event_ref(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> String {
    #[derive(diesel::QueryableByName)]
    struct RootRow {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .unwrap()
    .authority_event_ref
}

/// The root controller's grant of `actions` over the whole Realm to
/// `subject`, sequenced after `previous`.
fn grant_request(
    previous: &AuthorityCommitTransaction,
    subject: &arkret_wire::ActorId,
    actions: &[&str],
    root_event_ref: &str,
) -> EventCommitRequest {
    let realm_id = previous.event.realm_id.clone();
    let at = previous.commit.committed_at;
    sourced(next_request_for_actor(
        previous,
        arkret_wire::EventKind::CapabilityGrant,
        founder_actor(),
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer_id": founder_actor(),
                "subject": subject,
                "actions": actions,
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "authority_event_ref": root_event_ref,
                    "authority_generation": 0
                }],
                "issued_at": arkret_canonical::format_timestamp_canonical(at),
            }
        }),
        at,
    ))
}

#[derive(Debug, PartialEq, Eq)]
struct AcceptState {
    events: i64,
    lifecycle: Vec<(String, serde_json::Value, String)>,
    live_target: Vec<(String, serde_json::Value, String)>,
    members: Vec<(String, serde_json::Value, String)>,
}

/// Every row an `ak.invite.accept` may write, with its covering Commit.
async fn accept_state(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> AcceptState {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        subject: String,
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
        #[diesel(sql_type = Text)]
        current_commit_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    let events =
        diesel::sql_query("SELECT count(*) AS count FROM canonical_events WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap()
            .count;
    let mut families = Vec::new();
    for sql in [
        "SELECT invite_id AS subject, value, current_commit_id \
         FROM invite_lifecycle_current_results WHERE realm_id=$1 ORDER BY invite_id",
        "SELECT invitee_account_id AS subject, value, current_commit_id \
         FROM invite_live_target_current_results WHERE realm_id=$1 ORDER BY invitee_account_id",
        "SELECT member_id AS subject, value, current_commit_id \
         FROM member_state_current_results WHERE realm_id=$1 ORDER BY member_id",
    ] {
        families.push(
            diesel::sql_query(sql)
                .bind::<Text, _>(realm_id.as_str())
                .load::<Row>(&mut *conn)
                .await
                .unwrap()
                .into_iter()
                .map(|row| (row.subject, row.value, row.current_commit_id))
                .collect::<Vec<_>>(),
        );
    }
    let members = families.pop().unwrap();
    let live_target = families.pop().unwrap();
    let lifecycle = families.pop().unwrap();
    AcceptState {
        events,
        lifecycle,
        live_target,
        members,
    }
}

/// `(membership, available)` of the member's current Account summary row.
async fn account_summary(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> Option<(Option<String>, bool)> {
    #[derive(diesel::QueryableByName)]
    struct SummaryRow {
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        membership: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        available: bool,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT membership, available FROM account_summary_current \
         WHERE realm_id=$1 AND actor_key=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .load::<SummaryRow>(&mut *conn)
    .await
    .unwrap()
    .pop()
    .map(|row| (row.membership, row.available))
}

fn invite_create_request(
    previous: &AuthorityCommitTransaction,
    invitee: &arkret_wire::AccountId,
) -> EventCommitRequest {
    let at = previous.commit.committed_at;
    sourced(next_request_for_actor(
        previous,
        arkret_wire::EventKind::InviteCreate,
        founder_actor(),
        serde_json::json!({
            "invitee_account_id": invitee,
            "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
            "expires_at": arkret_canonical::format_timestamp_canonical(
                at + chrono::TimeDelta::days(7)
            ),
        }),
        at,
    ))
}

/// An `ak.invite.accept` by `actor` of the Invite `create` opened, created
/// `offset_ms` after the head it extends so that retries are distinct Events.
fn accept_request(
    previous: &AuthorityCommitTransaction,
    actor: &arkret_wire::ActorId,
    create: &EventCommitRequest,
    previous_state: &str,
    invitee: Option<&arkret_wire::AccountId>,
    offset_ms: i64,
) -> EventCommitRequest {
    let mut payload = serde_json::json!({
        "invite_id": arkret_wire::InviteId::from_event_id(&create.authority_commit.event.event_id),
        "previous_state": previous_state,
    });
    if let Some(invitee) = invitee {
        payload["invitee_account_id"] = serde_json::to_value(invitee).unwrap();
    }
    sourced(next_request_for_actor(
        previous,
        arkret_wire::EventKind::InviteAccept,
        actor.clone(),
        payload,
        previous.commit.committed_at + chrono::TimeDelta::milliseconds(offset_ms),
    ))
}

async fn assert_accept_refused(
    pool: &PgPool,
    uow: &PgEventCommitUnitOfWork,
    request: EventCommitRequest,
    code: ConflictCode,
) {
    let realm_id = request.authority_commit.event.realm_id.clone();
    let before = accept_state(pool, &realm_id).await;
    assert_refused(pool, uow, request, code).await;
    assert_eq!(accept_state(pool, &realm_id).await, before);
}

/// Real PostgreSQL: the directed invitee's `ak.invite.accept` moves the Invite
/// `pending -> accepted`, releases its live-target slot and moves its own
/// member row `leave -> join`, all on the accepting Commit. Another actor, a
/// payload invitee other than the stored one, a stale `previous_state` and a
/// second accept of the terminal Invite are refused with zero writes; after
/// leaving, the same account joins again through a fresh Invite.
#[tokio::test]
async fn invite_accept_joins_member_atomically_and_second_accept_is_rejected() {
    heap_future(invite_accept_joins_member_atomically_and_second_accept_is_rejected_case).await;
}

async fn invite_accept_joins_member_atomically_and_second_accept_is_rejected_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = heap_future(|| admit(&pool, "accept-invite", "invite")).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let bob = remote_member("accept-bob");
    let bob_account = bob.as_account_id().unwrap().clone();
    let carol = remote_member("accept-carol");
    let carol_account = carol.as_account_id().unwrap().clone();

    let create = invite_create_request(unit.transactions.last().unwrap(), &bob_account);
    let create = heap_future(|| ordinary_realm::source_request(&pool, create)).await;
    uow.commit_event(create.clone()).await.unwrap();
    let head = &create.authority_commit;
    for (request, code) in [
        // Only the invitee accepts, even with the invitee's exact payload.
        (
            accept_request(head, &carol, &create, "pending", Some(&bob_account), 1),
            ConflictCode::FailedPrecondition,
        ),
        // The payload invitee must match the stored one in both directions.
        (
            accept_request(head, &carol, &create, "pending", Some(&carol_account), 2),
            ConflictCode::InviteDirectedInviteeMismatch,
        ),
        (
            accept_request(head, &bob, &create, "pending", None, 3),
            ConflictCode::InviteDirectedInviteeMismatch,
        ),
        // The declared pre-state is compared with the frozen register.
        (
            accept_request(head, &bob, &create, "claimed", Some(&bob_account), 4),
            ConflictCode::FailedPrecondition,
        ),
    ] {
        heap_future(|| assert_accept_refused(&pool, &uow, request, code)).await;
    }
    assert_eq!(member_state(&pool, &realm_id, &bob).await, None);

    let accept = accept_request(head, &bob, &create, "pending", Some(&bob_account), 5);
    let accept = heap_future(|| ordinary_realm::source_request(&pool, accept)).await;
    uow.commit_event(accept.clone()).await.unwrap();
    let accept_commit = accept.authority_commit.commit.commit_id.to_string();
    let invite_id = arkret_wire::InviteId::from_event_id(&create.authority_commit.event.event_id);
    let state = accept_state(&pool, &realm_id).await;
    assert_eq!(
        state.lifecycle,
        vec![(
            invite_id.to_string(),
            serde_json::json!("accepted"),
            accept_commit.clone()
        )]
    );
    assert_eq!(
        state.live_target,
        vec![(
            String::from_utf8(arkret_canonical::canonical_json_bytes(&bob_account).unwrap())
                .unwrap(),
            serde_json::Value::Null,
            accept_commit.clone()
        )]
    );
    assert!(state.members.contains(&(
        bob.to_string(),
        serde_json::json!({"membership": "join"}),
        accept_commit.clone()
    )));
    // The Account summary follows the accepting Commit.
    assert_eq!(
        account_summary(&pool, &realm_id, &bob).await,
        Some((Some("join".to_owned()), true))
    );

    // `accepted` is terminal: a second accept is refused before any write.
    heap_future(|| {
        assert_accept_refused(
            &pool,
            &uow,
            accept_request(
                &accept.authority_commit,
                &bob,
                &create,
                "pending",
                Some(&bob_account),
                6,
            ),
            ConflictCode::InviteAlreadyTerminal,
        )
    })
    .await;

    // After leaving, Bob returns only through a fresh Invite.
    let leave = membership_request(&accept.authority_commit, bob.clone(), &bob, "leave");
    let leave = heap_future(|| ordinary_realm::source_request(&pool, leave)).await;
    uow.commit_event(leave.clone()).await.unwrap();
    assert_eq!(
        account_summary(&pool, &realm_id, &bob)
            .await
            .map(|(membership, _)| membership),
        Some(None),
        "leaving withdraws Bob's Realm from his Account summary"
    );
    let reinvite = invite_create_request(&leave.authority_commit, &bob_account);
    let reinvite = heap_future(|| ordinary_realm::source_request(&pool, reinvite)).await;
    uow.commit_event(reinvite.clone()).await.unwrap();
    let rejoin = accept_request(
        &reinvite.authority_commit,
        &bob,
        &reinvite,
        "pending",
        Some(&bob_account),
        7,
    );
    let rejoin = heap_future(|| ordinary_realm::source_request(&pool, rejoin)).await;
    uow.commit_event(rejoin.clone()).await.unwrap();
    assert_eq!(
        member_state(&pool, &realm_id, &bob).await.as_deref(),
        Some("join")
    );
}

/// An Event owed to a remote Station cannot commit without the exact source
/// submission its fanout carries.
#[tokio::test]
async fn an_event_owed_to_a_remote_station_needs_its_source_submission() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = admit(&pool, "fanout-unsourced", "public").await;
    let alice = remote_member("unsourced-alice");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        alice.clone(),
        &alice,
        "join",
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    let mut unsourced = join.clone();
    unsourced.realm_fanout_source = None;
    let outbox = outbox_count(&pool).await;
    uow.commit_event(unsourced).await.unwrap_err();
    assert_eq!(outbox_count(&pool).await, outbox);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&join.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    uow.commit_event(join).await.unwrap();
}

fn governance_authority(unit: &OrdinaryRealmBootstrapCommitUnit) -> CurrentRealmAuthority {
    unit.transactions[0].expected_authority.clone()
}

fn successor_authority(mut authority: CurrentRealmAuthority) -> CurrentRealmAuthority {
    let handoff = arkret_wire::RealmAuthorityHandoffId::from_digest([0x72; 32]);
    authority.generation += 1;
    authority.service_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:next-governor.example").unwrap();
    authority.authority_ref = arkret_wire::RealmCommitAuthorityRef::Handoff(handoff.clone());
    authority.last_handoff_ref = Some(handoff);
    authority
}

/// A replica as the member Station receives it: `opens_stream` marks the
/// hosted member's own join on a stream this Station does not hold yet.
fn replica(
    unit: &OrdinaryRealmBootstrapCommitUnit,
    request: &EventCommitRequest,
    opens_stream: bool,
) -> CommittedReplica {
    let event = &request.authority_commit.event;
    let role = if opens_stream {
        let member = match event.kind {
            arkret_wire::EventKind::InviteAccept => event.actor_id.clone(),
            _ => serde_json::from_value(event.payload["member_id"].clone()).unwrap(),
        };
        CommittedReplicaRole::OpeningJoin {
            member_account_id: member.as_account_id().unwrap().clone(),
        }
    } else {
        CommittedReplicaRole::HeldStream
    };
    CommittedReplica {
        producer_signer_fact: request.authority_commit.producer_signer_fact.clone(),
        local_service_id: member_station(),
        authority: governance_authority(unit),
        event: event.clone(),
        commit: request.authority_commit.commit.clone(),
        genesis_event_ref: None,
        role,
        received_at: request.authority_commit.commit.committed_at,
        welcomes: Vec::new(),
    }
}

/// Anchor the member Station's pending stream at the join itself with the
/// given typed current, as a verified bootstrap snapshot whose head is the
/// join would.
async fn anchor_at_join(
    store: &PgAuthorityCommitStore,
    join: &EventCommitRequest,
    entries: Vec<arkret_wire::TypedCurrentRow>,
) {
    let commit = &join.authority_commit.commit;
    store
        .install_replica_anchor(&{
            let mut install = ReplicaAnchorInstall {
                realm_id: commit.realm_id.clone(),
                join_commit_id: commit.commit_id.clone(),
                governance_generation: commit.governance_generation,
                snapshot_head: arkret_wire::CommitStreamHead {
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                    commit_id: commit.commit_id.clone(),
                },
                visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                    commit_id: commit.commit_id.clone(),
                }],
                current_state_entries: entries,

                verified_snapshot: bootstrap_snapshot(&(commit.realm_id.clone()), 0, &[], &[]),
            };
            install.verified_snapshot = bootstrap_snapshot(
                &install.realm_id,
                install.governance_generation,
                &install.visible_stream_heads,
                &install.current_state_entries,
            );
            install
        })
        .await
        .unwrap();
}

/// The member-state row a bootstrap snapshot carries for `member`'s join.
fn joined_row(
    join: &EventCommitRequest,
    member: &arkret_wire::ActorId,
) -> arkret_wire::TypedCurrentRow {
    let commit = &join.authority_commit.commit;
    arkret_wire::TypedCurrentRow::Value {
        selector: arkret_wire::CurrentSelector::MemberState {
            actor_id: member.clone(),
        },
        source_stream_ref: commit.stream_ref.clone(),
        revision: arkret_wire::CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        value: serde_json::json!({"membership":"join"}),
    }
}

/// An epoch-zero member roster derives its immutable Genesis only from an
/// exact held source Full, before any later MLS Commit carrier exists.
#[tokio::test]
async fn held_genesis_replica_freezes_only_its_exact_scope_provenance() {
    #[derive(diesel::QueryableByName)]
    struct GenesisProvenanceRow {
        #[diesel(sql_type = Text)]
        realm_id: String,
        #[diesel(sql_type = Text)]
        mls_group_id: String,
        #[diesel(sql_type = Text)]
        genesis_event_ref: String,
        #[diesel(sql_type = Text)]
        first_carried_commit_event_ref: String,
    }
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("replica-genesis-provenance", "public");
    let last = unit.transactions.last().unwrap();
    let member = remote_member("genesis-reader");
    let join = membership_request(last, member.clone(), &member, "join");
    let realm = join.authority_commit.event.realm_id.clone();
    let at = join.authority_commit.event.created_at;
    let payload = serde_json::json!({
        "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref":format!("ak:blob:sha256:{}", "3".repeat(64)),
        "ratchet_tree_ref":format!("ak:blob:sha256:{}", "4".repeat(64)),
        "creator_leaf_authority":{
            "leaf_signature_key_b64u":arkret_canonical::base64url_encode([7_u8;32]),
            "endpoint":{"kind":"device","device_id":format!("ak:device:{}",uuid::Uuid::now_v7())},
            "authorization_event_ref":last.event.event_id,
        },
        "governance_binding":arkret_models_crypto::MlsGovernanceBindingPayload::realm(
            realm.clone(),None,0,0,0).unwrap(),
        "created_at":arkret_canonical::format_timestamp_canonical(at),
    });
    let genesis = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::MlsGenesis,
        &founder(),
        payload.clone(),
        at,
    ));
    // No hosted opening/held prefix means no durable selector or Event.
    assert!(
        store
            .install_committed_replica(&replica(&unit, &genesis, false))
            .await
            .is_err()
    );
    store
        .install_committed_replica(&replica(&unit, &join, true))
        .await
        .unwrap();
    anchor_at_join(&store, &join, vec![joined_row(&join, &member)]).await;
    let source = replica(&unit, &genesis, false);
    let scope_key =
        String::from_utf8(arkret_canonical::canonical_json_bytes(&source.event.scope_ref).unwrap())
            .unwrap();
    let mut conn = pool.get().await.unwrap();
    for wrong in [
        {
            let mut extra = source.clone();
            extra.genesis_event_ref = Some(last.event.event_id.clone());
            extra
        },
        {
            let mut wrong_payload = payload.clone();
            wrong_payload["governance_binding"] = serde_json::to_value(
                arkret_models_crypto::MlsGovernanceBindingPayload::realm(
                    arkret_wire::RealmId::from_event_id(&last.event.event_id),
                    None,
                    0,
                    0,
                    0,
                )
                .unwrap(),
            )
            .unwrap();
            replica(
                &unit,
                &sourced(next_request(
                    &join.authority_commit,
                    arkret_wire::EventKind::MlsGenesis,
                    &founder(),
                    wrong_payload,
                    at,
                )),
                false,
            )
        },
    ] {
        assert!(store.install_committed_replica(&wrong).await.is_err());
        assert!(
            store
                .committed_event(&wrong.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        let frozen: Vec<GenesisProvenanceRow> = diesel::sql_query(
            "SELECT realm_id,mls_group_id,genesis_event_ref,first_carried_commit_event_ref \
             FROM mls_replica_genesis_provenance WHERE scope_key=$1",
        )
        .bind::<Text, _>(&scope_key)
        .load(&mut conn)
        .await
        .unwrap();
        assert!(frozen.is_empty(), "a refused Full wrote Genesis provenance");
    }
    assert_eq!(
        store.install_committed_replica(&source).await.unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        store.install_committed_replica(&source).await.unwrap(),
        CommittedReplicaOutcome::Duplicate
    );
    // The held exact replay may restore its own provenance, without another
    // Event, a caller-selected locator, or an MLS Commit/Welcome.
    diesel::sql_query("DELETE FROM mls_replica_genesis_provenance WHERE scope_key=$1")
        .bind::<Text, _>(&scope_key)
        .execute(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        store
            .queue_replicated_welcomes(&source.event, &source.commit, None, &[], at)
            .await
            .unwrap(),
        CommittedReplicaOutcome::Duplicate
    );
    let conflicting_at = at + chrono::Duration::milliseconds(1);
    let mut conflicting_payload = payload;
    conflicting_payload["created_at"] =
        serde_json::json!(arkret_canonical::format_timestamp_canonical(conflicting_at));
    let conflicting = sourced(next_request(
        &genesis.authority_commit,
        arkret_wire::EventKind::MlsGenesis,
        &founder(),
        conflicting_payload,
        conflicting_at,
    ));
    assert_ne!(
        conflicting.authority_commit.event.event_id,
        source.event.event_id
    );
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &conflicting, false))
            .await
            .unwrap_err(),
        ConflictCode::DuplicateConflict,
    );
    assert!(
        store
            .committed_event(&conflicting.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let frozen: Vec<GenesisProvenanceRow> = diesel::sql_query(
        "SELECT realm_id,mls_group_id,genesis_event_ref,first_carried_commit_event_ref \
         FROM mls_replica_genesis_provenance WHERE scope_key=$1",
    )
    .bind::<Text, _>(&scope_key)
    .load(&mut conn)
    .await
    .unwrap();
    assert_eq!(frozen.len(), 1);
    assert_eq!(frozen[0].realm_id, source.event.realm_id.as_str());
    assert_eq!(
        frozen[0].mls_group_id,
        source
            .event
            .scope_ref
            .canonical_mls_group_id()
            .unwrap()
            .as_str()
    );
    assert_eq!(
        frozen[0].first_carried_commit_event_ref,
        source.event.event_id.as_str()
    );
    assert_eq!(frozen[0].genesis_event_ref, source.event.event_id.as_str());
    assert_eq!(
        store
            .stream_head(&source.commit.stream_ref)
            .await
            .unwrap()
            .unwrap()
            .commit_id,
        source.commit.commit_id
    );
}

/// The member Station opens its held Realm stream with its member's own join
/// and then stores only direct successors while that member is joined.
#[tokio::test]
async fn committed_replication_persists_exact_source_bytes_and_remote_authority() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    // The governance Station's cut is built but never admitted here: this
    // database is the member Station.
    let unit = bootstrap_unit_with_join_rule("replica-public", "public");
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let alice = remote_member("replica-alice");
    let join = membership_request(last, alice.clone(), &alice, "join");

    // A non-join Event cannot open the stream.
    let early = sourced(next_request(
        last,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Renamed"}),
        last.commit.committed_at,
    ));
    let error = store
        .install_committed_replica(&replica(&unit, &early, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::DependencyMissing);

    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &join, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &join, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Duplicate
    );
    let held = store
        .committed_event(&join.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.commit, join.authority_commit.commit);
    assert_eq!(held.event, join.authority_commit.event);
    assert_eq!(
        member_state(&pool, &realm_id, &alice).await.as_deref(),
        Some("join")
    );
    let authority = store.current_authority(&realm_id).await.unwrap().unwrap();
    assert_eq!(authority, governance_authority(&unit));

    let next = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Replicated"}),
        last.commit.committed_at,
    ));
    // The join left the stream pending its bootstrap anchor: nothing after it
    // is stored until the snapshot is installed.
    let pending = store
        .replica_stream_anchor(&realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.join_commit, join.authority_commit.commit);
    assert_eq!(pending.anchored_head, None);
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &next, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    anchor_at_join(&store, &join, vec![joined_row(&join, &alice)]).await;
    // A different Commit at the held position is a fork, not a successor.
    let mut fork = next.clone();
    fork.authority_commit.commit.stream_position = join.authority_commit.commit.stream_position;
    fork.authority_commit.commit.previous_commit_ref = last.commit.previous_commit_ref.clone();
    let error = store
        .install_committed_replica(&replica(&unit, &fork, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::ForkQuarantine);
    // A Commit after an unheld one is a missing dependency.
    let after_next = sourced(next_request(
        &next.authority_commit,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Too early"}),
        last.commit.committed_at,
    ));
    let error = store
        .install_committed_replica(&replica(&unit, &after_next, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::DependencyMissing);
    assert!(
        store
            .committed_event(&after_next.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    // An own join is not a license to skip an unheld predecessor while
    // another hosted member is still joined. The locked OpeningJoin gate
    // must retain Alice's existing anchor and write none of Bob's join.
    let bob = remote_member("replica-bob-gap");
    let bob_join = membership_request(&next.authority_commit, bob.clone(), &bob, "join");
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &bob_join, true))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    assert!(
        store
            .committed_event(&bob_join.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .replica_stream_anchor(&realm_id)
            .await
            .unwrap()
            .unwrap()
            .join_commit,
        join.authority_commit.commit
    );

    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &next, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &after_next, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );

    // Once Alice has left, the member Station hosts nobody who may hold
    // further Events.
    let leave = membership_request(&after_next.authority_commit, alice.clone(), &alice, "leave");
    store
        .install_committed_replica(&replica(&unit, &leave, false))
        .await
        .unwrap();
    let later = sourced(next_request(
        &leave.authority_commit,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Unowed"}),
        last.commit.committed_at,
    ));
    let error = store
        .install_committed_replica(&replica(&unit, &later, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::CapabilityDenied);

    // Alice joins again after a position this Station has no right to: her
    // own join re-opens the held stream at the join, pending a new anchor,
    // and the gap is never pulled (decision 0122).
    let rejoin = membership_request(&later.authority_commit, alice.clone(), &alice, "join");
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &rejoin, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let reopened = store
        .replica_stream_anchor(&realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reopened.join_commit, rejoin.authority_commit.commit);
    assert_eq!(reopened.anchored_head, None);
    let after_rejoin = sourced(next_request(
        &rejoin.authority_commit,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"After the rejoin"}),
        last.commit.committed_at,
    ));
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &after_rejoin, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    anchor_at_join(&store, &rejoin, vec![joined_row(&rejoin, &alice)]).await;
    // The position in the gap is behind the re-opened head.
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &later, false))
            .await
            .unwrap_err(),
        ConflictCode::ForkQuarantine,
    );
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &after_rejoin, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert!(
        store
            .committed_event(&later.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

/// A hosted invitee's `ak.invite.accept` is its join: the replica opens the
/// held Realm stream, derives the invitee's joined membership and publishes
/// its Account summary in the same transaction; a later replicated leave
/// withdraws that summary.
#[tokio::test]
async fn committed_replication_opens_the_stream_with_a_hosted_invite_accept() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("replica-invite", "invite");
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let bob = remote_member("replica-bob");
    let arkret_wire::ActorId::Account {
        account_id: bob_account,
    } = &bob
    else {
        unreachable!("remote_member is an Account");
    };
    let create = invite_create_request(last, bob_account);
    let accept = accept_request(
        &create.authority_commit,
        &bob,
        &create,
        "pending",
        Some(bob_account),
        1,
    );
    assert_eq!(account_summary(&pool, &realm_id, &bob).await, None);

    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &accept, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let held = store
        .committed_event(&accept.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.commit, accept.authority_commit.commit);
    assert_eq!(held.event, accept.authority_commit.event);
    assert_eq!(
        member_state(&pool, &realm_id, &bob).await.as_deref(),
        Some("join")
    );
    assert_eq!(
        account_summary(&pool, &realm_id, &bob).await,
        Some((Some("join".to_owned()), true))
    );

    anchor_at_join(&store, &accept, vec![joined_row(&accept, &bob)]).await;
    let leave = membership_request(&accept.authority_commit, bob.clone(), &bob, "leave");
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &leave, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        member_state(&pool, &realm_id, &bob).await.as_deref(),
        Some("leave")
    );
    assert_eq!(
        account_summary(&pool, &realm_id, &bob).await,
        Some((None, true))
    );
}

/// A remote authority record never names this Station, never goes back a
/// generation and never forks one.
#[tokio::test]
async fn remote_authority_records_only_move_forward() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("remote-authority", "public");
    let authority = governance_authority(&unit);
    store
        .record_remote_authority(&authority, &member_station())
        .await
        .unwrap();
    store
        .record_remote_authority(&authority, &member_station())
        .await
        .unwrap();
    assert!(
        store
            .record_remote_authority(&authority, &authority.service_id)
            .await
            .is_err()
    );
    let mut forked = authority.clone();
    forked.service_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    let error = store
        .record_remote_authority(&forked, &member_station())
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::ForkQuarantine);
    assert_eq!(
        store
            .current_authority(&authority.realm_id)
            .await
            .unwrap()
            .unwrap(),
        authority
    );
}

#[tokio::test]
async fn old_governance_replica_replay_is_idempotent_but_successor_writes_nothing() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("old-replica-tenure", "public");
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let actor = remote_member("old-replica-tenure-member");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        actor.clone(),
        &actor,
        "join",
    );
    let opening = replica(&unit, &join, true);
    assert_eq!(
        store.install_committed_replica(&opening).await.unwrap(),
        CommittedReplicaOutcome::Stored
    );
    anchor_at_join(&store, &join, vec![joined_row(&join, &actor)]).await;
    store
        .record_remote_authority(
            &successor_authority(governance_authority(&unit)),
            &member_station(),
        )
        .await
        .unwrap();

    assert_eq!(
        store.install_committed_replica(&opening).await.unwrap(),
        CommittedReplicaOutcome::Duplicate
    );
    let leave = membership_request(&join.authority_commit, actor.clone(), &actor, "leave");
    let error = store
        .install_committed_replica(&replica(&unit, &leave, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::ForkQuarantine);
    let error = store
        .install_committed_chain_node(&CommittedChainNode {
            local_service_id: member_station(),
            authority: governance_authority(&unit),
            commit: leave.authority_commit.commit.clone(),
        })
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::ForkQuarantine);
    assert!(
        store
            .committed_event(&leave.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        member_state(&pool, &realm_id, &actor).await.as_deref(),
        Some("join")
    );
    assert_eq!(
        store
            .current_authority(&realm_id)
            .await
            .unwrap()
            .unwrap()
            .generation,
        1
    );
}

#[tokio::test]
async fn old_governance_snapshot_cannot_anchor_or_publish_current() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("old-snapshot-tenure", "public");
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let actor = remote_member("old-snapshot-tenure-member");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        actor.clone(),
        &actor,
        "join",
    );
    store
        .install_committed_replica(&replica(&unit, &join, true))
        .await
        .unwrap();
    store
        .record_remote_authority(
            &successor_authority(governance_authority(&unit)),
            &member_station(),
        )
        .await
        .unwrap();
    let commit = &join.authority_commit.commit;
    let head = arkret_wire::CommitStreamHead {
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
        commit_id: commit.commit_id.clone(),
    };
    let error = store
        .install_replica_anchor(&{
            let mut install = ReplicaAnchorInstall {
                realm_id: realm_id.clone(),
                join_commit_id: commit.commit_id.clone(),
                governance_generation: 0,
                snapshot_head: head.clone(),
                visible_stream_heads: vec![head],
                current_state_entries: vec![joined_row(&join, &actor)],

                verified_snapshot: bootstrap_snapshot(&(realm_id.clone()), 0, &[], &[]),
            };
            install.verified_snapshot = bootstrap_snapshot(
                &install.realm_id,
                install.governance_generation,
                &install.visible_stream_heads,
                &install.current_state_entries,
            );
            install
        })
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::ForkQuarantine);
    assert!(
        store
            .replica_stream_anchor(&realm_id)
            .await
            .unwrap()
            .unwrap()
            .anchored_head
            .is_none()
    );
    assert_eq!(
        member_state(&pool, &realm_id, &actor).await.as_deref(),
        Some("join")
    );
}

/// Before every send the frozen basis is rechecked at the current accepted
/// cut: the intent stays owed while one frozen member is still joined by the
/// same membership Event, and is no longer owed once that member left.
#[tokio::test]
async fn fanout_basis_revalidation_cancels_after_member_leave() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = admit(&pool, "fanout-revalidation", "public").await;
    let local = arkret_wire::DidCoreId::new(STATION).unwrap();
    let alice = remote_member("revalidation-alice");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        alice.clone(),
        &alice,
        "join",
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    let event = &join.authority_commit.event;
    let basis = vec![RealmFanoutAuthorityWitness {
        member_id: alice.clone(),
        circle_membership_event_ref: None,
        membership_event_ref: event.event_id.to_string(),
    }];
    let now = chrono::Utc::now();
    assert!(
        store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, now)
            .await
            .unwrap()
    );
    // Another Station is never owed an intent frozen for this one, and a
    // basis naming another membership Event does not authorize it.
    let elsewhere = arkret_wire::DidCoreId::new("ak:did_core:web:elsewhere.example").unwrap();
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &elsewhere, &basis, now)
            .await
            .unwrap()
    );
    let stale = vec![RealmFanoutAuthorityWitness {
        member_id: alice.clone(),
        circle_membership_event_ref: None,
        membership_event_ref: unit.transactions.last().unwrap().event.event_id.to_string(),
    }];
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &member_station(), &stale, now)
            .await
            .unwrap()
    );

    let leave = membership_request(&join.authority_commit, alice.clone(), &alice, "leave");
    let leave = ordinary_realm::source_request(&pool, leave).await;
    uow.commit_event(leave.clone()).await.unwrap();
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, now)
            .await
            .unwrap(),
        "every frozen basis is gone once the member left"
    );
    // The leave itself stays owed to Alice's Station while it is her
    // effective membership, and stops being owed once she joins again.
    let leave_event = &leave.authority_commit.event;
    let leave_basis = vec![RealmFanoutAuthorityWitness {
        member_id: alice.clone(),
        circle_membership_event_ref: None,
        membership_event_ref: leave_event.event_id.to_string(),
    }];
    assert!(
        store
            .realm_fanout_still_owed(leave_event, &local, &member_station(), &leave_basis, now)
            .await
            .unwrap()
    );
    let rejoin = membership_request(&leave.authority_commit, alice.clone(), &alice, "join");
    let rejoin = ordinary_realm::source_request(&pool, rejoin).await;
    uow.commit_event(rejoin).await.unwrap();
    assert!(
        !store
            .realm_fanout_still_owed(leave_event, &local, &member_station(), &leave_basis, now)
            .await
            .unwrap(),
        "a later membership Event supersedes the departing basis"
    );
}

/// A member Station refuses a replica whose predecessor it does not hold, a
/// Commit forking its held head, and any replica once no member it hosts is
/// joined, each with zero writes.
#[tokio::test]
async fn committed_replication_rejects_broken_predecessor_and_no_local_member() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("replica-negative", "public");
    let last = unit.transactions.last().unwrap();
    let alice = remote_member("replica-negative-alice");
    let join = membership_request(last, alice.clone(), &alice, "join");
    let at = last.commit.committed_at;
    let profile = |previous: &AuthorityCommitTransaction, name: &str| {
        sourced(next_request(
            previous,
            arkret_wire::EventKind::RealmProfile,
            &founder(),
            serde_json::json!({ "schema":"ak.schema.realm_profile.v1", "title": name }),
            at,
        ))
    };
    // Nothing is held yet: only the hosted member's own join opens the stream.
    let first = profile(last, "Before join");
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &first, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    store
        .install_committed_replica(&replica(&unit, &join, true))
        .await
        .unwrap();
    anchor_at_join(&store, &join, vec![joined_row(&join, &alice)]).await;
    let next = profile(&join.authority_commit, "Next");
    let after = profile(&next.authority_commit, "After");
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &after, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    let mut broken = next.clone();
    broken.authority_commit.commit.previous_commit_ref = last.commit.previous_commit_ref.clone();
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &broken, false))
            .await
            .unwrap_err(),
        ConflictCode::ForkQuarantine,
    );
    for refused in [&first, &after, &broken] {
        assert!(
            store
                .committed_event(&refused.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    store
        .install_committed_replica(&replica(&unit, &next, false))
        .await
        .unwrap();
    let leave = membership_request(&next.authority_commit, alice.clone(), &alice, "leave");
    store
        .install_committed_replica(&replica(&unit, &leave, false))
        .await
        .unwrap();
    let unowed = profile(&leave.authority_commit, "Unowed");
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &unowed, false))
            .await
            .unwrap_err(),
        ConflictCode::CapabilityDenied,
    );
}

fn scan_request(
    realm_id: &arkret_wire::RealmId,
    direction: arkret_wire::StreamScanDirection,
    limit: u16,
) -> arkret_wire::StreamScanRequest {
    arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction,
        limit,
    }
}

async fn scanned(
    store: &PgAuthorityCommitStore,
    request: arkret_wire::StreamScanRequest,
    account: &arkret_wire::ActorId,
) -> coland_storage::AccountStreamScan {
    store
        .scan_stream_for_account(
            &request,
            account.as_account_id().unwrap(),
            &arkret_wire::DidCoreId::new(STATION).unwrap(),
        )
        .await
        .unwrap()
}

fn page(scan: coland_storage::AccountStreamScan) -> arkret_wire::StreamScanOutcome {
    match scan {
        coland_storage::AccountStreamScan::Page(page) => page,
        other => panic!("expected a proved page, got {other:?}"),
    }
}

/// Each row's position and whether its Event is disclosed in full.
fn rows(page: &arkret_wire::StreamScanOutcome) -> Vec<(u64, bool)> {
    page.committed_events
        .iter()
        .map(|item| {
            (
                item.commit().stream_position,
                matches!(item, arkret_wire::CommittedEventView::Full(_)),
            )
        })
        .collect()
}

/// The Realm-stream Circle create shell remains a verifiable Commit for a
/// remote joined Realm member, while its private object never enters a full
/// Event fanout or peer scan. Circle-specific replication is still closed.
#[tokio::test]
async fn circle_create_withholds_private_object_from_remote_realm_member() {
    use arkret_wire::StreamScanDirection::After;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = admit(&pool, "circle-private-fanout", "public").await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let joined_actor = remote_member("circle-private-peer");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        joined_actor.clone(),
        &joined_actor,
        "join",
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    let at = join.authority_commit.commit.committed_at;
    let create = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::CircleCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.circle.v1",
            "realm_id":realm_id,
            "title":"Private acquisition",
            "summary":"Hidden Circle summary",
            "display":{"short_name":"Private","color_token":"slate","symbol":{"glyph":"lock"}},
            "directory_visibility":"members",
            "join_rule":"public",
            "history_access":"since_join",
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    let create = ordinary_realm::source_request(&pool, create).await;
    let committed = uow.commit_event(create.clone()).await.unwrap();
    assert_eq!(committed.outbox_inserted, 0);
    assert!(fanout_rows(&pool, &create).await.is_empty());
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &create.authority_commit.event.event_id,
                &joined_actor,
                &arkret_wire::DidCoreId::new(STATION).unwrap(),
            )
            .await
        ),
        Some(false),
    );

    let scan = scan_request(&realm_id, After(None), 10);
    for result in [
        peer_page(&store, scan.clone(), &member_station()).await,
        scanned(&store, scan, &joined_actor).await,
    ] {
        let page = page(result);
        assert_eq!(
            rows(&page),
            vec![
                (join.authority_commit.commit.stream_position, true),
                (create.authority_commit.commit.stream_position, false),
            ]
        );
        let withheld = &page.committed_events[1];
        assert_eq!(
            withheld.commit().previous_commit_ref.as_ref(),
            Some(&join.authority_commit.commit.commit_id)
        );
        let body = serde_json::to_value(withheld).unwrap();
        assert_eq!(body["event_disclosure"]["status"], "withheld");
        assert!(body.get("event").is_none());
        assert!(!body.to_string().contains("Private acquisition"));
    }
}

/// A CircleCreate that cannot be pushed in full is recovered through the
/// existing peer-scan withheld branch. Its Commit-only node keeps the held
/// Realm chain contiguous so the next disclosed Event can replicate.
#[tokio::test]
async fn circle_create_withheld_gap_allows_next_realm_replica() {
    use arkret_wire::StreamScanDirection::After;
    use coland_storage::AccountStreamScan;

    let governance_database = TestDatabase::lease().await;
    let member_database = TestDatabase::lease().await;
    let governance_pool = governance_database.pool();
    let member_pool = member_database.pool();
    let governance = PgAuthorityCommitStore {
        pool: governance_pool.clone(),
    };
    let member = PgAuthorityCommitStore {
        pool: member_pool.clone(),
    };
    let uow = PgEventCommitUnitOfWork::new(governance_pool.clone());
    let unit = admit(&governance_pool, "circle-withheld-gap", "public").await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let alice = remote_member("circle-gap-alice");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        alice.clone(),
        &alice,
        "join",
    );
    let join = ordinary_realm::source_request(&governance_pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &join, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let material = governance
        .member_station_bootstrap_material(
            &realm_id,
            alice.as_account_id().unwrap(),
            &join.authority_commit.commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    member
        .install_replica_anchor(&{
            let mut install = ReplicaAnchorInstall {
                realm_id: realm_id.clone(),
                join_commit_id: join.authority_commit.commit.commit_id.clone(),
                governance_generation: join.authority_commit.commit.governance_generation,
                snapshot_head: material.visible_stream_heads[0].clone(),
                visible_stream_heads: material.visible_stream_heads.clone(),
                current_state_entries: material.current_state_entries,

                verified_snapshot: bootstrap_snapshot(&(realm_id.clone()), 0, &[], &[]),
            };
            install.verified_snapshot = bootstrap_snapshot(
                &install.realm_id,
                install.governance_generation,
                &install.visible_stream_heads,
                &install.current_state_entries,
            );
            install
        })
        .await
        .unwrap();

    let at = join.authority_commit.commit.committed_at;
    let create = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::CircleCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.circle.v1",
            "realm_id":realm_id,
            "title":"Hidden Circle title",
            "summary":"Hidden Circle summary",
            "display":{"short_name":"Hidden","color_token":"slate","symbol":{"glyph":"lock"}},
            "directory_visibility":"members",
            "join_rule":"public",
            "history_access":"since_join",
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    let create = ordinary_realm::source_request(&governance_pool, create).await;
    let accepted = uow.commit_event(create.clone()).await.unwrap();
    assert_eq!(accepted.outbox_inserted, 0);
    let next = sourced(next_request(
        &create.authority_commit,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"After Circle gap"}),
        at,
    ));
    let next = ordinary_realm::source_request(&governance_pool, next).await;
    uow.commit_event(next.clone()).await.unwrap();

    // The normal full replica cannot jump over CircleCreate. A failed receive
    // leaves no next Event on the member Station.
    assert_code(
        &member
            .install_committed_replica(&replica(&unit, &next, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    assert!(
        member
            .committed_event(&next.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let AccountStreamScan::Page(page) = peer_page(
        &governance,
        scan_request(
            &realm_id,
            After(Some(join.authority_commit.commit.stream_position)),
            10,
        ),
        &member_station(),
    )
    .await
    else {
        panic!("the joined member Station must be served its Realm interval");
    };
    assert_eq!(
        rows(&page),
        vec![
            (create.authority_commit.commit.stream_position, false),
            (next.authority_commit.commit.stream_position, true),
        ]
    );
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("Hidden Circle title")
    );

    let arkret_wire::CommittedEventView::Withheld(withheld) = &page.committed_events[0] else {
        panic!("CircleCreate must be Commit-only for the nonmember Station");
    };
    assert_eq!(withheld.commit, create.authority_commit.commit);
    assert_eq!(
        member
            .install_committed_chain_node(&CommittedChainNode {
                local_service_id: member_station(),
                authority: governance_authority(&unit),
                commit: withheld.commit.clone(),
            })
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert!(
        member
            .committed_event(&create.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &next, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        member
            .committed_event(&next.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        next.authority_commit.event
    );
    assert_eq!(
        read_shape(
            member_read(
                &member,
                &create.authority_commit.event.event_id,
                &alice,
                &member_station(),
            )
            .await
        ),
        Some(false)
    );
}

/// `ak.self.committed_event.resource.get.v1` for `caller` on `store`'s
/// Station `issuer`.
async fn member_read(
    store: &PgAuthorityCommitStore,
    event_id: &arkret_wire::EventId,
    caller: &arkret_wire::ActorId,
    issuer: &arkret_wire::DidCoreId,
) -> coland_storage::MemberCommittedEventRead {
    store
        .committed_event_for_member(event_id, caller, issuer)
        .await
        .unwrap()
}

/// Whether a single read is disclosed in full (`Some(true)`), withheld
/// (`Some(false)`) or not visible (`None`).
fn read_shape(read: coland_storage::MemberCommittedEventRead) -> Option<bool> {
    match read {
        coland_storage::MemberCommittedEventRead::Read(view) => {
            Some(matches!(*view, arkret_wire::CommittedEventView::Full(_)))
        }
        coland_storage::MemberCommittedEventRead::NotVisible => None,
        other => panic!("expected a decided read, got {other:?}"),
    }
}

/// Real PostgreSQL: under `since_join` a second member's readable interval
/// starts at its own join Commit (`membership_join`, decision 0108 §1045),
/// with the founder still reading from genesis (`stream_start`); pages stop
/// at the floor without truncation, another member's grant Event is disclosed
/// in full like every Realm-shared Event of a disclosed kind, the stream list
/// names the same floor, a member who left reads nothing and a rejoin moves
/// the floor to the new join.
#[tokio::test]
async fn account_stream_scan_serves_joined_member_from_its_join_commit() {
    heap_future(account_stream_scan_serves_joined_member_from_its_join_commit_case).await;
}

async fn account_stream_scan_serves_joined_member_from_its_join_commit_case() {
    use arkret_wire::StreamScanDirection::{After, Before};

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = heap_future(|| admit(&pool, "scan-joined-member", "public")).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let at = last.commit.committed_at;
    let bob = arkret_wire::ActorId::account(
        ordinary_realm::human_profile::admit(&pool, &ordinary_realm::station(), "scan-bob").await,
    );

    let strand = sourced(next_request(
        last,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Scan discussion"},
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    let strand = heap_future(|| ordinary_realm::source_request(&pool, strand)).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = sourced(next_request(
        &strand.authority_commit,
        arkret_wire::EventKind::RealmSetDefaultStrand,
        &founder(),
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": null,
        }),
        at,
    ));
    let default = heap_future(|| ordinary_realm::source_request(&pool, default)).await;
    uow.commit_event(default.clone()).await.unwrap();
    let join = membership_request(&default.authority_commit, bob.clone(), &bob, "join");
    let join = heap_future(|| ordinary_realm::source_request(&pool, join)).await;
    uow.commit_event(join.clone()).await.unwrap();
    // A joined member without a grant cannot write a Message.
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            sourced(ordinary_realm::next_human_request_for_actor(
                &join.authority_commit,
                arkret_wire::EventKind::MessageCreate,
                bob.clone(),
                message_payload(&strand_id, "not yet"),
                at,
            )),
            ConflictCode::CapabilityDenied,
        )
    })
    .await;
    let root_event_ref = realm_root_event_ref(&pool, &realm_id).await;
    let grant = grant_request(
        &join.authority_commit,
        &bob,
        &["ak.message.create"],
        &root_event_ref,
    );
    let grant = heap_future(|| ordinary_realm::source_request(&pool, grant)).await;
    uow.commit_event(grant.clone()).await.unwrap();
    let bob_message = sourced(ordinary_realm::next_human_request_for_actor(
        &grant.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        bob.clone(),
        message_payload(&strand_id, "hello from the second member"),
        at,
    ));
    let bob_message = heap_future(|| ordinary_realm::source_request(&pool, bob_message)).await;
    uow.commit_event(bob_message.clone()).await.unwrap();
    let founder_message = sourced(next_request(
        &bob_message.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&strand_id, "welcome"),
        at,
    ));
    let founder_message =
        heap_future(|| ordinary_realm::source_request(&pool, founder_message)).await;
    uow.commit_event(founder_message.clone()).await.unwrap();

    let join_position = join.authority_commit.commit.stream_position;
    let floor = arkret_wire::ReadableFloor {
        oldest_position: join_position,
        floor_commit_id: join.authority_commit.commit.commit_id.clone(),
        floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
    };
    let forward =
        page(heap_future(|| scanned(&store, scan_request(&realm_id, After(None), 10), &bob)).await);
    assert_eq!(forward.readable_floor.as_ref(), Some(&floor));
    assert!(!forward.truncated);
    assert_eq!(
        rows(&forward),
        vec![
            (join_position, true),
            (join_position + 1, true),
            (join_position + 2, true),
            (join_position + 3, true),
        ],
        "own join, the founder's grant and both Messages in full"
    );
    // A cursor below the floor still starts at the floor.
    let below = page(
        heap_future(|| scanned(&store, scan_request(&realm_id, After(Some(2)), 1), &bob)).await,
    );
    assert_eq!(rows(&below), vec![(join_position, true)]);
    assert!(below.truncated);
    // Backfill stops at the floor without reporting truncation.
    let backfill = page(
        heap_future(|| {
            scanned(
                &store,
                scan_request(&realm_id, Before(Some(join_position + 1)), 5),
                &bob,
            )
        })
        .await,
    );
    assert_eq!(rows(&backfill), vec![(join_position, true)]);
    assert!(!backfill.truncated);
    assert_eq!(backfill.readable_floor.as_ref(), Some(&floor));
    let newest =
        page(heap_future(|| scanned(&store, scan_request(&realm_id, Before(None), 2), &bob)).await);
    assert_eq!(
        rows(&newest),
        vec![(join_position + 3, true), (join_position + 2, true)]
    );
    assert!(newest.truncated);

    // The founder's interval still starts at the genesis Commit.
    let founder = founder_actor();
    let founder_page = page(
        heap_future(|| scanned(&store, scan_request(&realm_id, After(None), 50), &founder)).await,
    );
    assert_eq!(
        founder_page
            .readable_floor
            .as_ref()
            .map(|floor| (floor.oldest_position, floor.floor_reason)),
        Some((0, arkret_wire::ReadableFloorReason::StreamStart))
    );
    assert_eq!(
        founder_page.committed_events.len() as u64,
        join_position + 4
    );
    assert!(rows(&founder_page).iter().all(|(_, full)| *full));

    // The stream list names the same floor.
    let listed = store
        .list_realm_streams_for_account(
            &realm_id,
            bob.as_account_id().unwrap(),
            &arkret_wire::DidCoreId::new(STATION).unwrap(),
        )
        .await
        .unwrap();
    let coland_storage::AccountRealmStreamList::Listed(streams) = listed else {
        panic!("a joined member's stream list is proved, got {listed:?}");
    };
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].readable_floor.as_ref(), Some(&floor));

    // A single committed-event read applies the same floor and disclosure:
    // another actor's Event from the join on, the genesis for every current
    // member, nothing before the join and nothing for an outsider.
    let station = arkret_wire::DidCoreId::new(STATION).unwrap();
    let outsider = remote_member("scan-outsider");
    let genesis_id = unit.transactions[0].event.event_id.clone();
    assert_eq!(
        read_shape(member_read(&store, &genesis_id, &bob, &station).await),
        Some(true)
    );
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &strand.authority_commit.event.event_id,
                &bob,
                &station
            )
            .await
        ),
        None
    );
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &bob_message.authority_commit.event.event_id,
                &founder_actor(),
                &station
            )
            .await
        ),
        Some(true)
    );
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &grant.authority_commit.event.event_id,
                &bob,
                &station
            )
            .await
        ),
        Some(true)
    );
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &founder_message.authority_commit.event.event_id,
                &bob,
                &station
            )
            .await
        ),
        Some(true)
    );
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &bob_message.authority_commit.event.event_id,
                &bob,
                &station
            )
            .await
        ),
        Some(true)
    );
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &founder_message.authority_commit.event.event_id,
                &outsider,
                &station
            )
            .await
        ),
        None
    );
    assert_eq!(
        read_shape(member_read(&store, &genesis_id, &outsider, &station).await),
        None
    );
    assert!(store.accepted_realm_reader(&realm_id, &bob).await.unwrap());
    assert!(
        !store
            .accepted_realm_reader(&realm_id, &outsider)
            .await
            .unwrap()
    );
    // The owner Account reads its principal-control Realm; the same principal
    // at another Station does not.
    let pcr_realm =
        arkret_wire::RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1").unwrap();
    let owner = outsider.as_account_id().unwrap().clone();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO principal_resolutions \
         (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) \
         VALUES($1,$2,$3,$4,$4,'{}'::jsonb,now())",
    )
    .bind::<Text, _>(owner.principal_id.as_str())
    .bind::<Text, _>(owner.station_id.as_str())
    .bind::<Text, _>(pcr_realm.as_str())
    .bind::<Text, _>(genesis_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        store
            .accepted_realm_reader(&pcr_realm, &outsider)
            .await
            .unwrap()
    );
    let elsewhere = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        owner.principal_id.clone(),
        station.clone(),
    ));
    assert!(
        !store
            .accepted_realm_reader(&pcr_realm, &elsewhere)
            .await
            .unwrap()
    );

    // A member who left has no readable interval; a rejoin reads only from
    // the new join.
    let leave = membership_request(
        &founder_message.authority_commit,
        bob.clone(),
        &bob,
        "leave",
    );
    let leave = heap_future(|| ordinary_realm::source_request(&pool, leave)).await;
    uow.commit_event(leave.clone()).await.unwrap();
    assert_eq!(
        heap_future(|| scanned(&store, scan_request(&realm_id, After(None), 10), &bob)).await,
        coland_storage::AccountStreamScan::NotAuthorized
    );
    // After the leave only Bob's own Events stay readable to him.
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &founder_message.authority_commit.event.event_id,
                &bob,
                &station
            )
            .await
        ),
        None
    );
    assert_eq!(
        read_shape(
            member_read(
                &store,
                &bob_message.authority_commit.event.event_id,
                &bob,
                &station
            )
            .await
        ),
        Some(true)
    );
    assert!(!store.accepted_realm_reader(&realm_id, &bob).await.unwrap());
    let rejoin = membership_request(&leave.authority_commit, bob.clone(), &bob, "join");
    let rejoin = heap_future(|| ordinary_realm::source_request(&pool, rejoin)).await;
    uow.commit_event(rejoin.clone()).await.unwrap();
    let rejoined =
        page(heap_future(|| scanned(&store, scan_request(&realm_id, After(None), 10), &bob)).await);
    assert_eq!(
        rejoined.readable_floor,
        Some(arkret_wire::ReadableFloor {
            oldest_position: rejoin.authority_commit.commit.stream_position,
            floor_commit_id: rejoin.authority_commit.commit.commit_id.clone(),
            floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
        })
    );
    assert_eq!(
        rows(&rejoined),
        vec![(rejoin.authority_commit.commit.stream_position, true)]
    );
}

/// A revoke or relinquish of the grant `grant` created, expecting `revision`.
fn close_grant_request(
    previous: &AuthorityCommitTransaction,
    kind: arkret_wire::EventKind,
    actor: &arkret_wire::ActorId,
    grant: &EventCommitRequest,
    revision: &arkret_wire::RealmCommit,
) -> EventCommitRequest {
    sourced(next_request_for_actor(
        previous,
        kind,
        actor.clone(),
        serde_json::json!({
            "grant_id": arkret_wire::GrantId::from_event_id(&grant.authority_commit.event.event_id),
            "expected_revision": {
                "commit_id": revision.commit_id,
                "stream_position": revision.stream_position,
            },
        }),
        previous.commit.committed_at,
    ))
}

async fn grant_status(pool: &PgPool, grant: &EventCommitRequest) -> String {
    #[derive(diesel::QueryableByName)]
    struct StatusRow {
        #[diesel(sql_type = Text)]
        status: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT status FROM capability_grant_current_results WHERE grant_id=$1")
        .bind::<Text, _>(
            arkret_wire::GrantId::from_event_id(&grant.authority_commit.event.event_id).to_string(),
        )
        .get_result::<StatusRow>(&mut *conn)
        .await
        .unwrap()
        .status
}

/// Real PostgreSQL: `ak.capability.revoke` needs an authorizing action at the
/// same cut and then targets only the grant's issuer or the Realm root
/// controller; `ak.capability.relinquish` needs no action but only the
/// grant's own subject may release it, by exact revision. Every refusal is
/// zero-write.
#[tokio::test]
async fn capability_revoke_and_relinquish_follow_their_target_guards() {
    heap_future(capability_revoke_and_relinquish_follow_their_target_guards_case).await;
}

async fn capability_revoke_and_relinquish_follow_their_target_guards_case() {
    // A local Device inventory cannot host another Station's PCR devices.
    // Keep these no-Profile Accounts on the fixture's actual hosted Station.
    // Retain the exact requests for CAS/replay assertions without embedding
    // each nested source/admission future in this matrix's stack frame.
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = heap_future(|| admit(&pool, "grant-guards", "public")).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let alice = heap_future(|| {
        accepted_pcr_account::accepted_pcr_account(
            &pool,
            device_authorization_history::did_web_station(&ordinary_realm::station()),
        )
    })
    .await;
    let bob = heap_future(|| {
        accepted_pcr_account::accepted_pcr_account(
            &pool,
            device_authorization_history::did_web_station(&ordinary_realm::station()),
        )
    })
    .await;
    let alice_join = membership_request(
        unit.transactions.last().unwrap(),
        alice.clone(),
        &alice,
        "join",
    );
    let alice_join = heap_future(|| ordinary_realm::source_request(&pool, alice_join)).await;
    uow.commit_event(alice_join.clone()).await.unwrap();
    let bob_join = membership_request(&alice_join.authority_commit, bob.clone(), &bob, "join");
    let bob_join = heap_future(|| ordinary_realm::source_request(&pool, bob_join)).await;
    uow.commit_event(bob_join.clone()).await.unwrap();
    let root_event_ref = realm_root_event_ref(&pool, &realm_id).await;

    // A joined member without any grant cannot issue one.
    let unauthorized_issue = sourced(next_request_for_actor(
        &bob_join.authority_commit,
        arkret_wire::EventKind::CapabilityGrant,
        alice.clone(),
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer_id": alice,
                "subject": bob,
                "actions": ["ak.message.create"],
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "authority_event_ref": root_event_ref,
                    "authority_generation": 0
                }],
                "issued_at": arkret_canonical::format_timestamp_canonical(
                    bob_join.authority_commit.commit.committed_at
                ),
            }
        }),
        bob_join.authority_commit.commit.committed_at,
    ));
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            unauthorized_issue,
            ConflictCode::CapabilityDenied,
        )
    })
    .await;

    let bob_grant = grant_request(
        &bob_join.authority_commit,
        &bob,
        &["ak.message.create"],
        &root_event_ref,
    );
    let bob_grant = heap_future(|| ordinary_realm::source_request(&pool, bob_grant)).await;
    uow.commit_event(bob_grant.clone()).await.unwrap();
    let revision = bob_grant.authority_commit.commit.clone();
    let head = &bob_grant.authority_commit;
    for (kind, actor, code) in [
        // No authorizing action for revoke.
        (
            arkret_wire::EventKind::CapabilityRevoke,
            &alice,
            ConflictCode::CapabilityDenied,
        ),
        // Relinquish is the subject's own.
        (
            arkret_wire::EventKind::CapabilityRelinquish,
            &alice,
            ConflictCode::GrantRelinquishNotSubject,
        ),
    ] {
        heap_future(|| {
            assert_refused(
                &pool,
                &uow,
                close_grant_request(head, kind, actor, &bob_grant, &revision),
                code,
            )
        })
        .await;
    }
    // Holding ak.capability.revoke is not enough to revoke another issuer's
    // grant.
    let alice_revoker = grant_request(head, &alice, &["ak.capability.revoke"], &root_event_ref);
    let alice_revoker = heap_future(|| ordinary_realm::source_request(&pool, alice_revoker)).await;
    uow.commit_event(alice_revoker.clone()).await.unwrap();
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            close_grant_request(
                &alice_revoker.authority_commit,
                arkret_wire::EventKind::CapabilityRevoke,
                &alice,
                &bob_grant,
                &revision,
            ),
            ConflictCode::CapabilityDenied,
        )
    })
    .await;
    // The subject releases by exact revision only, once.
    let mut stale = revision.clone();
    stale.stream_position += 100;
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            close_grant_request(
                &alice_revoker.authority_commit,
                arkret_wire::EventKind::CapabilityRelinquish,
                &bob,
                &bob_grant,
                &stale,
            ),
            ConflictCode::CasConflict,
        )
    })
    .await;
    let relinquish = close_grant_request(
        &alice_revoker.authority_commit,
        arkret_wire::EventKind::CapabilityRelinquish,
        &bob,
        &bob_grant,
        &revision,
    );
    let relinquish = heap_future(|| ordinary_realm::source_request(&pool, relinquish)).await;
    uow.commit_event(relinquish.clone()).await.unwrap();
    assert_eq!(grant_status(&pool, &bob_grant).await, "relinquished");
    heap_future(|| {
        assert_refused(
            &pool,
            &uow,
            close_grant_request(
                &relinquish.authority_commit,
                arkret_wire::EventKind::CapabilityRevoke,
                &founder_actor(),
                &bob_grant,
                &revision,
            ),
            ConflictCode::CasConflict,
        )
    })
    .await;
    // The root controller revokes the grant it issued.
    let revoke = close_grant_request(
        &relinquish.authority_commit,
        arkret_wire::EventKind::CapabilityRevoke,
        &founder_actor(),
        &alice_revoker,
        &alice_revoker.authority_commit.commit,
    );
    let revoke = heap_future(|| ordinary_realm::source_request(&pool, revoke)).await;
    uow.commit_event(revoke).await.unwrap();
    assert_eq!(grant_status(&pool, &alice_revoker).await, "revoked");
}

/// A Realm where Alice posts before inviting Bob, Bob accepts, Alice grants
/// him `ak.message.create` and Bob posts, with its requests in stream order.
struct JoinedRealm {
    realm_id: arkret_wire::RealmId,
    strand_id: arkret_wire::StrandId,
    bob: arkret_wire::ActorId,
    founder_message: EventCommitRequest,
    create: EventCommitRequest,
    accept: EventCommitRequest,
    grant: EventCommitRequest,
    bob_message: EventCommitRequest,
}

async fn joined_realm(pool: &PgPool, seed: &str) -> Box<JoinedRealm> {
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = heap_future(|| admit(pool, seed, "invite")).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let at = last.commit.committed_at;
    let station = ordinary_realm::station();
    let bob_label = format!("{seed}-bob");
    let bob = arkret_wire::ActorId::account(
        heap_future(|| ordinary_realm::human_profile::admit(pool, &station, &bob_label)).await,
    );
    let bob_account = bob.as_account_id().unwrap().clone();
    let strand = sourced(next_request(
        last,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Joined discussion"},
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    let strand = heap_future(|| ordinary_realm::source_request(pool, strand)).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let founder_message = sourced(next_request(
        &strand.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&strand_id, "before Bob joins"),
        at,
    ));
    let founder_message =
        heap_future(|| ordinary_realm::source_request(pool, founder_message)).await;
    uow.commit_event(founder_message.clone()).await.unwrap();
    let create = invite_create_request(&founder_message.authority_commit, &bob_account);
    let create = heap_future(|| ordinary_realm::source_request(pool, create)).await;
    uow.commit_event(create.clone()).await.unwrap();
    let accept = accept_request(
        &create.authority_commit,
        &bob,
        &create,
        "pending",
        Some(&bob_account),
        1,
    );
    let accept = heap_future(|| ordinary_realm::source_request(pool, accept)).await;
    uow.commit_event(accept.clone()).await.unwrap();
    let root_event_ref = realm_root_event_ref(pool, &realm_id).await;
    let grant = grant_request(
        &accept.authority_commit,
        &bob,
        &["ak.message.create"],
        &root_event_ref,
    );
    let grant = heap_future(|| ordinary_realm::source_request(pool, grant)).await;
    uow.commit_event(grant.clone()).await.unwrap();
    let bob_message = sourced(ordinary_realm::next_human_request_for_actor(
        &grant.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        bob.clone(),
        message_payload(&strand_id, "hello after joining"),
        at,
    ));
    let bob_message = heap_future(|| ordinary_realm::source_request(pool, bob_message)).await;
    uow.commit_event(bob_message.clone()).await.unwrap();
    // The snapshot/window callers retain these exact requests across awaits.
    // Keep their shared fixture state out of both test future frames.
    Box::new(JoinedRealm {
        realm_id,
        strand_id,
        bob,
        founder_message,
        create,
        accept,
        grant,
        bob_message,
    })
}

fn snapshot_signer() -> impl Fn(
    &coland_storage::RealmStateSnapshotMaterial,
) -> coland_storage::PersistenceResult<arkret_wire::RealmStateSnapshot> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = arkret_wire::DidUrl::new("did:web:ordinary-station.example#notary-key").unwrap();
    move |material| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    }
}

/// Two real Stations preserve the original governance signature while the
/// member serves an exact hosted Account cut and its reserved window basis.
#[tokio::test]
async fn member_account_snapshot_preserves_governance_and_exact_replica_cut() {
    let governor_db = TestDatabase::lease().await;
    let member_db = TestDatabase::lease().await;
    let pool = governor_db.pool();
    let member_pool = member_db.pool();
    let governor = PgAuthorityCommitStore { pool: pool.clone() };
    let member = PgAuthorityCommitStore {
        pool: member_pool.clone(),
    };
    let unit = admit(&pool, "member-account-snapshot", "public").await;
    let realm = unit.transactions[0].event.realm_id.clone();
    let actor = remote_member("snapshot-reader");
    let account = actor.as_account_id().unwrap();
    let join = membership_request(
        unit.transactions.last().unwrap(),
        actor.clone(),
        &actor,
        "join",
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(join.clone()).await.unwrap();
    member
        .install_committed_replica(&replica(&unit, &join, true))
        .await
        .unwrap();
    let material = governor
        .member_station_bootstrap_material(&realm, account, &join.authority_commit.commit.commit_id)
        .await
        .unwrap()
        .unwrap();
    let sign = snapshot_signer();
    let snapshot = sign(&material).unwrap();
    let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
    )
    .unwrap();
    member
        .install_replica_anchor(&ReplicaAnchorInstall {
            realm_id: realm.clone(),
            join_commit_id: join.authority_commit.commit.commit_id.clone(),
            governance_generation: snapshot.governance_generation,
            snapshot_head: snapshot.visible_stream_heads[0].clone(),
            visible_stream_heads: snapshot.visible_stream_heads.clone(),
            current_state_entries: snapshot.current_state_entries.clone(),
            verified_snapshot: snapshot.clone(),
        })
        .await
        .unwrap();
    let never_sign = |_: &coland_storage::RealmStateSnapshotMaterial| -> coland_storage::PersistenceResult<arkret_wire::RealmStateSnapshot> {
        panic!("a member Station must never sign a Realm Snapshot")
    };
    let issuer = member_station();
    let issued = member
        .issue_realm_state_snapshot_for_account(&realm, account, &issuer, &never_sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&issued).unwrap(),
        arkret_canonical::canonical_json_bytes(&snapshot).unwrap()
    );
    assert_eq!(
        member
            .issued_realm_state_snapshot(&realm, account, &snapshot.snapshot_id, &issuer)
            .await
            .unwrap(),
        Some(snapshot.clone())
    );
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window = member
        .freeze_account_realm_window(
            &coland_storage::AccountRealmWindowRequest {
                realm_id: realm.clone(),
                account: account.clone(),
                issuer: issuer.clone(),
                window_limit: 20,
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7()),
                expires_at_ms: now_ms + 300_000,
                now_ms,
                byte_budget: 7 * 1024 * 1024,
                delivered_heads: snapshot.visible_stream_heads.clone(),
                selected_stream_refs: None,
            },
            &never_sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(window.committed_events.is_empty());
    assert_ne!(window.window.preview_only, Some(true));
    assert!(window.window.window_start_basis.is_some());
    let foreign = remote_member("another-snapshot-reader");
    assert!(
        member
            .issued_realm_state_snapshot(
                &realm,
                foreign.as_account_id().unwrap(),
                &snapshot.snapshot_id,
                &issuer
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        member
            .issue_realm_state_snapshot_for_account(
                &realm,
                account,
                &arkret_wire::DidCoreId::new("ak:did_core:web:wrong.example").unwrap(),
                &never_sign
            )
            .await
            .is_err()
    );

    // The accepted successor makes the old head insufficient for a fresh
    // Snapshot. Installing the original new object closes exactly that cut.
    let message = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1", "realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Next snapshot cut"}, "state":"active",
            "created_by":founder_actor(), "created_at":join.authority_commit.commit.committed_at,
        }}),
        join.authority_commit.commit.committed_at,
    ));
    let message = ordinary_realm::source_request(&pool, message).await;
    uow.commit_event(message.clone()).await.unwrap();
    member
        .install_committed_replica(&replica(&unit, &message, false))
        .await
        .unwrap();
    assert!(
        member
            .issue_realm_state_snapshot_for_account(&realm, account, &issuer, &never_sign)
            .await
            .is_err()
    );
    let next_material = governor
        .member_station_bootstrap_material(&realm, account, &join.authority_commit.commit.commit_id)
        .await
        .unwrap()
        .unwrap();
    let next_snapshot = sign(&next_material).unwrap();
    async fn archive_count(pool: &PgPool) -> i64 {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("SELECT COUNT(*)::bigint AS count FROM realm_state_snapshot_issuances")
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap()
            .count
    }
    let before = archive_count(&member_pool).await;
    let mut incomplete = next_material.clone();
    incomplete.current_state_entries.pop().unwrap();
    assert!(
        member
            .install_verified_account_snapshot(account, &issuer, &sign(&incomplete).unwrap())
            .await
            .is_err()
    );
    assert!(
        member
            .install_verified_account_snapshot(
                foreign.as_account_id().unwrap(),
                &issuer,
                &next_snapshot
            )
            .await
            .is_err()
    );
    let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0x43; 32]);
    let wrong_signer = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &next_material,
        arkret_wire::DidUrl::new("did:web:member-station.example#notary-key").unwrap(),
        &wrong_key,
        chrono::Utc::now(),
    )
    .unwrap();
    assert!(
        member
            .install_verified_account_snapshot(account, &issuer, &wrong_signer)
            .await
            .is_err()
    );
    assert_eq!(
        archive_count(&member_pool).await,
        before,
        "rejected objects issue nothing"
    );
    member
        .install_verified_account_snapshot(account, &issuer, &next_snapshot)
        .await
        .unwrap();
    assert_eq!(
        member
            .issue_realm_state_snapshot_for_account(&realm, account, &issuer, &never_sign)
            .await
            .unwrap(),
        Some(next_snapshot.clone())
    );
    let leave = membership_request(&message.authority_commit, actor.clone(), &actor, "leave");
    let leave = ordinary_realm::source_request(&pool, leave).await;
    uow.commit_event(leave.clone()).await.unwrap();
    member
        .install_committed_replica(&replica(&unit, &leave, false))
        .await
        .unwrap();
    assert!(!matches!(
        member
            .issued_realm_state_snapshot(&realm, account, &next_snapshot.snapshot_id, &issuer)
            .await,
        Ok(Some(_))
    ));
}

fn row_selectors(entries: &[arkret_wire::TypedCurrentRow]) -> Vec<arkret_wire::CurrentSelector> {
    entries
        .iter()
        .map(|entry| match entry {
            arkret_wire::TypedCurrentRow::Value { selector, .. } => selector.clone(),
        })
        .collect()
}

/// Real PostgreSQL: a `since_join` member's Snapshot carries every Realm-stream
/// state row, including the Invite families and the grant that name it, the
/// founder's roster row, and the rows below its floor; its only Message row is
/// its own, since the founder's earlier Message is history below the floor.
/// Its floor is its accepting Commit, the same value the stream scan names;
/// the founder still reads everything from genesis. A by-ref read rechecks
/// the member's floor and fails once it has left.
#[tokio::test]
async fn account_snapshot_serves_joined_member_floor() {
    use arkret_wire::CurrentSelector;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = Box::pin(joined_realm(&pool, "snapshot-joined")).await;
    let bob_account = realm.bob.as_account_id().unwrap().clone();
    let founder_account = founder_actor().as_account_id().unwrap().clone();
    let issuer = arkret_wire::DidCoreId::new(STATION).unwrap();
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm.realm_id.clone(),
    };
    let join_position = realm.accept.authority_commit.commit.stream_position;
    let invite_id =
        arkret_wire::InviteId::from_event_id(&realm.create.authority_commit.event.event_id);
    let grant_id =
        arkret_wire::GrantId::from_event_id(&realm.grant.authority_commit.event.event_id);
    let founder_message_id = arkret_wire::MessageId::from_event_id(
        &realm.founder_message.authority_commit.event.event_id,
    );
    let bob_message_id =
        arkret_wire::MessageId::from_event_id(&realm.bob_message.authority_commit.event.event_id);

    let full = coland_storage_postgres::account_snapshot_material(
        &pool,
        &realm.realm_id,
        &founder_account,
    )
    .await
    .unwrap()
    .unwrap();
    let bob_cut =
        coland_storage_postgres::account_snapshot_material(&pool, &realm.realm_id, &bob_account)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(bob_cut.visible_stream_heads, full.visible_stream_heads);
    assert_eq!(
        bob_cut.retention_and_history_floor.stream_floors,
        vec![arkret_wire::StreamHistoryFloor {
            stream_ref: realm_stream.clone(),
            oldest_position: join_position,
        }]
    );
    assert_eq!(
        full.retention_and_history_floor.stream_floors[0].oldest_position,
        0
    );
    let bob_rows = row_selectors(&bob_cut.current_state_entries);
    let founder_rows = row_selectors(&full.current_state_entries);
    for selector in [
        CurrentSelector::InviteLifecycle {
            invite_id: invite_id.clone(),
        },
        CurrentSelector::InviteLiveTarget {
            invitee_account_id: bob_account.clone(),
        },
        CurrentSelector::InviteDirectedInvitee {
            invite_id: invite_id.clone(),
        },
        CurrentSelector::CapabilityGrant {
            grant_id: grant_id.clone(),
        },
        CurrentSelector::MemberState {
            actor_id: realm.bob.clone(),
        },
        CurrentSelector::MemberState {
            actor_id: founder_actor(),
        },
        CurrentSelector::MessageRevision {
            message_id: bob_message_id.clone(),
        },
    ] {
        assert!(bob_rows.contains(&selector), "Bob's cut lacks {selector:?}");
        assert!(
            founder_rows.contains(&selector),
            "founder's cut lacks {selector:?}"
        );
    }
    let founder_message = CurrentSelector::MessageRevision {
        message_id: founder_message_id,
    };
    assert!(!bob_rows.contains(&founder_message));
    assert!(founder_rows.contains(&founder_message));
    let mut expected = full.current_state_entries.clone();
    expected.retain(|entry| {
        !matches!(entry, arkret_wire::TypedCurrentRow::Value { selector, .. } if selector == &founder_message)
    });
    assert_eq!(
        bob_cut.current_state_entries, expected,
        "only the Message below the floor is omitted"
    );

    // The same floor as Bob's stream scan names.
    let scan = page(
        scanned(
            &store,
            scan_request(
                &realm.realm_id,
                arkret_wire::StreamScanDirection::After(None),
                1,
            ),
            &realm.bob,
        )
        .await,
    );
    assert_eq!(
        scan.readable_floor.map(|floor| floor.oldest_position),
        Some(join_position)
    );

    // Issued, read back by reference while Bob's floor holds, then refused
    // once he left.
    let sign = snapshot_signer();
    let issued = store
        .issue_realm_state_snapshot_for_account(&realm.realm_id, &bob_account, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        issued.retention_and_history_floor,
        bob_cut.retention_and_history_floor
    );
    assert_eq!(
        store
            .issued_realm_state_snapshot(
                &realm.realm_id,
                &bob_account,
                &issued.snapshot_id,
                &issuer
            )
            .await
            .unwrap(),
        Some(issued.clone())
    );
    let leave = membership_request(
        &realm.bob_message.authority_commit,
        realm.bob.clone(),
        &realm.bob,
        "leave",
    );
    uow.commit_event(leave).await.unwrap();
    assert!(
        coland_storage_postgres::account_snapshot_material(&pool, &realm.realm_id, &bob_account)
            .await
            .is_err()
    );
    assert!(
        !matches!(
            store
                .issued_realm_state_snapshot(
                    &realm.realm_id,
                    &bob_account,
                    &issued.snapshot_id,
                    &issuer
                )
                .await,
            Ok(Some(_))
        ),
        "a member who left cannot read its issued object back"
    );
}

/// Real PostgreSQL: a `since_join` member's window never starts below its
/// join Commit and `limited` is read against that floor. A window over its
/// whole readable interval starts exactly at the floor, above genesis: no
/// prefix state inside the member's readable range can back it, so the
/// window is `preview_only` without a basis, which is the formal rule
/// (`sync/client-sync.md` §5.2, decision 0113). A window above the floor
/// names the committed prefix through its anchor, backed by a snapshot
/// already issued to the member at that anchor, whose floor is the scan
/// floor.
#[tokio::test]
async fn account_window_starts_joined_member_at_its_join_commit() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let realm = Box::pin(joined_realm(&pool, "window-joined")).await;
    let bob_account = realm.bob.as_account_id().unwrap().clone();
    let issuer = arkret_wire::DidCoreId::new(STATION).unwrap();
    let join_position = realm.accept.authority_commit.commit.stream_position;
    let head_position = realm.bob_message.authority_commit.commit.stream_position;
    let sign = snapshot_signer();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let request = |limit: u32| coland_storage::AccountRealmWindowRequest {
        realm_id: realm.realm_id.clone(),
        account: bob_account.clone(),
        issuer: issuer.clone(),
        window_limit: limit,
        window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
        expires_at_ms: now_ms + 300_000,
        now_ms,
        byte_budget: 7 * 1024 * 1024,
        delivered_heads: Vec::new(),
        selected_stream_refs: None,
    };
    let positions = |window: &coland_storage::AccountRealmWindow| {
        window
            .committed_events
            .iter()
            .map(|view| {
                (
                    view.commit().stream_position,
                    matches!(view, arkret_wire::CommittedEventView::Full(_)),
                )
            })
            .collect::<Vec<_>>()
    };

    // The whole readable interval: from the join Commit, not limited, and
    // preview only without a pre-floor basis.
    let whole = store
        .freeze_account_realm_window(&request(20), &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        positions(&whole),
        (join_position..=head_position)
            .map(|position| (position, true))
            .collect::<Vec<_>>()
    );
    assert!(!whole.window.limited && whole.window.complete);
    assert_eq!(whole.window.preview_only, Some(true));
    assert!(whole.window.window_start_basis.is_none());
    assert_eq!(whole.window.next_position, head_position + 1);

    // `/head` at the current head, then one more Commit: a one-row window
    // names that snapshot as its exact anchor.
    let at_head = store
        .issue_realm_state_snapshot_for_account(&realm.realm_id, &bob_account, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    let bootstrapped = store
        .freeze_account_realm_window(&request(1), &sign)
        .await
        .unwrap()
        .unwrap();
    assert!(bootstrapped.committed_events.is_empty());
    assert_eq!(bootstrapped.window.preview_only, None);
    assert_eq!(bootstrapped.window.next_position, head_position + 1);
    let bootstrap_basis = bootstrapped.window.window_start_basis.unwrap();
    assert_eq!(bootstrap_basis.anchor_position, head_position);
    assert_eq!(bootstrap_basis.snapshot_ref, at_head.snapshot_id);

    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let founder_reply = sourced(next_request(
        &realm.bob_message.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&realm.strand_id, "welcome"),
        realm.bob_message.authority_commit.commit.committed_at,
    ));
    let founder_reply = heap_future(|| ordinary_realm::source_request(&pool, founder_reply)).await;
    uow.commit_event(founder_reply.clone()).await.unwrap();
    let backed = store
        .freeze_account_realm_window(&request(1), &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(positions(&backed), vec![(head_position + 1, true)]);
    assert!(backed.window.limited);
    assert_eq!(backed.window.preview_only, None);
    let basis = backed.window.window_start_basis.clone().unwrap();
    assert_eq!(basis.anchor_position, head_position);
    assert_eq!(
        basis.anchor_commit_ref,
        realm.bob_message.authority_commit.commit.commit_id
    );
    assert_eq!(basis.snapshot_ref, at_head.snapshot_id);
    assert_eq!(
        at_head.retention_and_history_floor.stream_floors[0].oldest_position,
        join_position
    );
}

fn local_member(label: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
        arkret_wire::DidCoreId::new(STATION).unwrap(),
    ))
}

async fn peer_page(
    store: &PgAuthorityCommitStore,
    request: arkret_wire::StreamScanRequest,
    peer: &arkret_wire::DidCoreId,
) -> coland_storage::AccountStreamScan {
    peer_interval_decision(
        store
            .scan_stream_for_peer(
                &request,
                peer,
                &arkret_wire::DidCoreId::new(STATION).unwrap(),
            )
            .await
            .unwrap(),
    )
}

async fn summary_title(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> Option<String> {
    #[derive(diesel::QueryableByName)]
    struct TitleRow {
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        title: Option<String>,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT title FROM account_summary_current WHERE realm_id=$1 AND actor_key=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .load::<TitleRow>(&mut *conn)
    .await
    .unwrap()
    .pop()
    .and_then(|row| row.title)
}

/// A governing Station's peer scan serves a member Station its replication
/// right: from its hosted member's join floor while that member is joined,
/// and through the member's own leave once it left -- never past it -- with a
/// restricted plaintext Message kept to its Commit (`federation.md` §4.1.1).
#[tokio::test]
async fn peer_scan_serves_joined_and_departed_member_intervals() {
    heap_future(peer_scan_serves_joined_and_departed_member_intervals_case).await;
}

async fn peer_scan_serves_joined_and_departed_member_intervals_case() {
    use arkret_wire::StreamScanDirection::{After, Before};
    use coland_storage::AccountStreamScan;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = heap_future(|| admit(&pool, "peer-scan-intervals", "public")).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let alice = remote_member("peer-scan-alice");
    let carol = local_member("peer-scan-carol");
    let elsewhere = arkret_wire::DidCoreId::new("ak:did_core:web:elsewhere.example").unwrap();
    let at = last.commit.committed_at;

    assert_eq!(
        peer_page(
            &store,
            scan_request(&realm_id, After(None), 10),
            &member_station()
        )
        .await,
        AccountStreamScan::NotAuthorized
    );
    let join = membership_request(last, alice.clone(), &alice, "join");
    let join = heap_future(|| ordinary_realm::source_request(&pool, join)).await;
    uow.commit_event(join.clone()).await.unwrap();
    let strand = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Peer scan discussion"},
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    let strand = heap_future(|| ordinary_realm::source_request(&pool, strand)).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = sourced(next_request(
        &strand.authority_commit,
        arkret_wire::EventKind::RealmSetDefaultStrand,
        &founder(),
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": null,
        }),
        at,
    ));
    let default = heap_future(|| ordinary_realm::source_request(&pool, default)).await;
    uow.commit_event(default.clone()).await.unwrap();
    let message = sourced(next_request(
        &default.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&strand_id, "plaintext kept on the governing Station"),
        at,
    ));
    let message = heap_future(|| ordinary_realm::source_request(&pool, message)).await;
    uow.commit_event(message.clone()).await.unwrap();
    let join_position = join.authority_commit.commit.stream_position;

    // Under `since_join` the right starts at Alice's join; the restricted
    // plaintext Message is served as its Commit alone.
    let AccountStreamScan::Page(joined) = peer_page(
        &store,
        scan_request(&realm_id, After(None), 10),
        &member_station(),
    )
    .await
    else {
        panic!("a hosting peer is served its interval");
    };
    let floor = joined.readable_floor.clone().unwrap();
    assert_eq!(floor.oldest_position, join_position);
    assert_eq!(
        floor.floor_commit_id,
        join.authority_commit.commit.commit_id
    );
    assert_eq!(
        rows(&joined),
        vec![
            (join_position, true),
            (join_position + 1, true),
            (join_position + 2, true),
            (join_position + 3, false),
        ]
    );
    assert!(!joined.truncated);
    assert_eq!(
        peer_page(&store, scan_request(&realm_id, After(None), 10), &elsewhere).await,
        AccountStreamScan::NotAuthorized
    );

    // Alice leaves; Carol, a member of this Station, joins after her. The
    // member Station's right now ends at Alice's own leave.
    let leave = membership_request(&message.authority_commit, alice.clone(), &alice, "leave");
    let leave = heap_future(|| ordinary_realm::source_request(&pool, leave)).await;
    uow.commit_event(leave.clone()).await.unwrap();
    let carol_join = membership_request(&leave.authority_commit, carol.clone(), &carol, "join");
    let carol_join = heap_future(|| ordinary_realm::source_request(&pool, carol_join)).await;
    uow.commit_event(carol_join.clone()).await.unwrap();
    let leave_position = leave.authority_commit.commit.stream_position;
    let AccountStreamScan::Page(departed) = peer_page(
        &store,
        scan_request(&realm_id, After(Some(join_position + 2)), 10),
        &member_station(),
    )
    .await
    else {
        panic!("a departed member's Station keeps its right through the leave");
    };
    assert_eq!(
        rows(&departed),
        vec![(join_position + 3, false), (leave_position, true)]
    );
    assert!(!departed.truncated);
    let AccountStreamScan::Page(newest) = peer_page(
        &store,
        scan_request(&realm_id, Before(None), 2),
        &member_station(),
    )
    .await
    else {
        panic!("a newest-first page stops at the leave");
    };
    assert_eq!(
        rows(&newest),
        vec![(leave_position, true), (join_position + 3, false)]
    );
    assert!(
        newest.truncated,
        "older authorized rows remain above the join floor"
    );
    let before = newest
        .committed_events
        .last()
        .unwrap()
        .commit()
        .stream_position;
    let AccountStreamScan::Page(older) = peer_page(
        &store,
        scan_request(&realm_id, Before(Some(before)), 10),
        &member_station(),
    )
    .await
    else {
        panic!("backfill continues to the departed member's join floor");
    };
    assert_eq!(
        rows(&older),
        vec![
            (join_position + 2, true),
            (join_position + 1, true),
            (join_position, true),
        ]
    );
    assert!(!older.truncated);
    assert_eq!(older.readable_floor.as_ref(), Some(&floor));
    assert_eq!(
        older.committed_events.last().unwrap().commit().commit_id,
        floor.floor_commit_id
    );
    let backfill_positions: Vec<_> = newest
        .committed_events
        .iter()
        .chain(&older.committed_events)
        .map(|item| item.commit().stream_position)
        .collect();
    assert_eq!(
        backfill_positions,
        (join_position..=leave_position).rev().collect::<Vec<_>>()
    );
    let AccountStreamScan::Page(after_leave) = peer_page(
        &store,
        scan_request(&realm_id, After(Some(leave_position)), 10),
        &member_station(),
    )
    .await
    else {
        panic!("a page after the leave is empty, not refused");
    };
    assert!(after_leave.committed_events.is_empty());

    // Bob, another member of that Station, joins after Carol: the Station has
    // a right again from Bob's join, but never to Carol's join between the
    // two intervals -- not even as a Commit.
    let bob = remote_member("peer-scan-bob");
    let bob_join = membership_request(&carol_join.authority_commit, bob.clone(), &bob, "join");
    let bob_join = heap_future(|| ordinary_realm::source_request(&pool, bob_join)).await;
    uow.commit_event(bob_join.clone()).await.unwrap();
    let bob_position = bob_join.authority_commit.commit.stream_position;
    let AccountStreamScan::Page(gap) = peer_page(
        &store,
        scan_request(&realm_id, After(Some(leave_position)), 10),
        &member_station(),
    )
    .await
    else {
        panic!("a page into the gap is empty, not refused");
    };
    assert!(gap.committed_events.is_empty() && !gap.truncated);
    let AccountStreamScan::Page(rejoined) = peer_page(
        &store,
        scan_request(&realm_id, After(Some(bob_position - 1)), 10),
        &member_station(),
    )
    .await
    else {
        panic!("the Station reads again from Bob's join");
    };
    assert_eq!(rows(&rejoined), vec![(bob_position, true)]);
}

/// A member Station's held stream: the hosted member's join opens it pending
/// anchor; the governing Station's bootstrap material anchors it at the
/// member's join floor and installs its typed current; the peer scan fills
/// the prefix, keeping a restricted plaintext Message as a chain node; later
/// replicas advance local current and are re-verified against it, and the
/// member's own scan is served from its join (`federation.md` §4.1.1).
#[tokio::test]
async fn member_station_anchors_on_the_bootstrap_snapshot_and_keeps_chain_nodes() {
    use arkret_wire::StreamScanDirection::After;
    use coland_storage::AccountStreamScan;

    let governance_database = TestDatabase::lease().await;
    let member_database = TestDatabase::lease().await;
    let governance_pool = governance_database.pool();
    let member_pool = member_database.pool();
    let governance = PgAuthorityCommitStore {
        pool: governance_pool.clone(),
    };
    let member = PgAuthorityCommitStore {
        pool: member_pool.clone(),
    };
    let uow = PgEventCommitUnitOfWork::new(governance_pool.clone());
    let fixture = historical_human::HumanFixture::new(
        &governance_pool,
        arkret_wire::Did::new("did:web:ordinary-station.example").unwrap(),
    )
    .await;
    fixture.admit(&governance_pool).await;
    ordinary_realm::human_profile::register_fixture_signer(
        &fixture.pcr.history.account,
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let unit = fixture.unit.clone();
    let founder = || fixture.pcr.history.account.principal_id.clone();
    let founder_actor = || arkret_wire::ActorId::account(fixture.pcr.history.account.clone());
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let at = last.commit.committed_at;
    let alice = remote_member("member-anchor-alice");
    let bob = remote_member("member-anchor-bob");
    let alice_account = alice.as_account_id().unwrap().clone();

    let join = membership_request(last, alice.clone(), &alice, "join");
    uow.commit_event(join.clone()).await.unwrap();
    let mut founder_previous = join.authority_commit.clone();
    founder_previous.producer_signer_fact = unit
        .transactions
        .last()
        .unwrap()
        .producer_signer_fact
        .clone();
    let strand = sourced(next_request(
        &founder_previous,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Anchored discussion"},
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    let strand = ordinary_realm::source_request(&governance_pool, strand).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = sourced(next_request(
        &strand.authority_commit,
        arkret_wire::EventKind::RealmSetDefaultStrand,
        &founder(),
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": null,
        }),
        at,
    ));
    let default = ordinary_realm::source_request(&governance_pool, default).await;
    uow.commit_event(default.clone()).await.unwrap();
    let message = sourced(next_request(
        &default.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&strand_id, "plaintext kept on the governing Station"),
        at,
    ));
    let message = ordinary_realm::source_request(&governance_pool, message).await;
    uow.commit_event(message.clone()).await.unwrap();

    // The join opens the held stream pending anchor.
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &join, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_code(
        &member
            .install_committed_replica(&replica(&unit, &strand, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    let pending_scan = member
        .scan_stream_for_account(
            &scan_request(&realm_id, After(None), 10),
            &alice_account,
            &member_station(),
        )
        .await
        .unwrap();
    assert!(
        matches!(pending_scan, AccountStreamScan::Unproved(_)),
        "{pending_scan:?}"
    );
    assert_eq!(
        member_read(
            &member,
            &join.authority_commit.event.event_id,
            &alice,
            &member_station(),
        )
        .await,
        coland_storage::MemberCommittedEventRead::PendingAnchor
    );
    assert_eq!(summary_title(&member_pool, &realm_id, &alice).await, None);

    // The bootstrap material floors the Realm stream at Alice's join, and
    // only for her current joined membership.
    assert!(
        governance
            .member_station_bootstrap_material(
                &realm_id,
                &alice_account,
                &strand.authority_commit.commit.commit_id,
            )
            .await
            .unwrap()
            .is_none()
    );
    let material = governance
        .member_station_bootstrap_material(
            &realm_id,
            &alice_account,
            &join.authority_commit.commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        material.retention_and_history_floor.stream_floors[0].oldest_position,
        join.authority_commit.commit.stream_position
    );
    let head = material.visible_stream_heads[0].clone();
    assert_eq!(head.commit_id, message.authority_commit.commit.commit_id);
    member
        .install_replica_anchor(&{
            let mut install = ReplicaAnchorInstall {
                realm_id: realm_id.clone(),
                join_commit_id: join.authority_commit.commit.commit_id.clone(),
                governance_generation: join.authority_commit.commit.governance_generation,
                snapshot_head: head.clone(),
                visible_stream_heads: material.visible_stream_heads.clone(),
                current_state_entries: material.current_state_entries.clone(),

                verified_snapshot: bootstrap_snapshot(&(realm_id.clone()), 0, &[], &[]),
            };
            install.verified_snapshot = bootstrap_snapshot(
                &install.realm_id,
                install.governance_generation,
                &install.visible_stream_heads,
                &install.current_state_entries,
            );
            install
        })
        .await
        .unwrap();
    assert_eq!(
        member
            .replica_stream_anchor(&realm_id)
            .await
            .unwrap()
            .unwrap()
            .anchored_head,
        Some(head.clone())
    );
    assert_eq!(
        summary_title(&member_pool, &realm_id, &alice)
            .await
            .as_deref(),
        Some("Fixture Realm")
    );

    // A chain node cannot skip the held head; the peer scan fills the prefix.
    let chain_node = |commit: &arkret_wire::RealmCommit| CommittedChainNode {
        local_service_id: member_station(),
        authority: governance_authority(&unit),
        commit: commit.clone(),
    };
    assert_code(
        &member
            .install_committed_chain_node(&chain_node(&message.authority_commit.commit))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    let AccountStreamScan::Page(prefix) = peer_page(
        &governance,
        scan_request(
            &realm_id,
            After(Some(join.authority_commit.commit.stream_position)),
            10,
        ),
        &member_station(),
    )
    .await
    else {
        panic!("the member Station is served its interval");
    };
    for item in &prefix.committed_events {
        let outcome = match item {
            arkret_wire::CommittedEventView::Full(view) => {
                let request = [&strand, &default]
                    .into_iter()
                    .find(|request| request.authority_commit.commit == view.commit)
                    .unwrap();
                member
                    .install_committed_replica(&replica(&unit, request, false))
                    .await
                    .unwrap()
            }
            arkret_wire::CommittedEventView::Withheld(view) => member
                .install_committed_chain_node(&chain_node(&view.commit))
                .await
                .unwrap(),
        };
        assert_eq!(outcome, CommittedReplicaOutcome::Stored);
    }
    assert_eq!(
        member
            .install_committed_chain_node(&chain_node(&message.authority_commit.commit))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Duplicate
    );
    assert_eq!(
        member_read(
            &member,
            &message.authority_commit.event.event_id,
            &alice,
            &member_station(),
        )
        .await,
        coland_storage::MemberCommittedEventRead::Read(Box::new(
            arkret_wire::CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
                commit: message.authority_commit.commit.clone(),
                event_disclosure: arkret_wire::EventDisclosure {
                    status: arkret_wire::EventDisclosureStatus::Withheld,
                },
            },)
        ))
    );
    assert!(
        member
            .committed_event(&message.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    // Bob joins on the governing Station; his join replica advances the
    // member Station's typed current.
    let bob_join = membership_request(&message.authority_commit, bob.clone(), &bob, "join");
    uow.commit_event(bob_join.clone()).await.unwrap();
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &bob_join, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        member_state(&member_pool, &realm_id, &bob).await.as_deref(),
        Some("join")
    );
    // A plaintext Message of a Realm that lists no plaintext service here is
    // refused by the recipient re-verification, although it is contiguous.
    let mut founder_previous = bob_join.authority_commit.clone();
    founder_previous.producer_signer_fact = unit
        .transactions
        .last()
        .unwrap()
        .producer_signer_fact
        .clone();
    let forged = sourced(next_request(
        &founder_previous,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&strand_id, "never held by the member Station"),
        at,
    ));
    uow.commit_event(forged.clone()).await.unwrap();
    assert_code(
        &member
            .install_committed_replica(&replica(&unit, &forged, false))
            .await
            .unwrap_err(),
        ConflictCode::CapabilityDenied,
    );

    // Alice's own scan on the member Station starts at her join and serves
    // the chain node as the withheld branch.
    let AccountStreamScan::Page(own) = member
        .scan_stream_for_account(
            &scan_request(&realm_id, After(None), 10),
            &alice_account,
            &member_station(),
        )
        .await
        .unwrap()
    else {
        panic!("an anchored held stream serves its hosted member");
    };
    let join_position = join.authority_commit.commit.stream_position;
    assert!(join_position > 0);
    assert!(
        member
            .committed_event(&unit.transactions[0].event.event_id)
            .await
            .unwrap()
            .is_none(),
        "the ordinary foreign replica must actually hold a since-join suffix"
    );
    let floor = own.readable_floor.clone().unwrap();
    assert_eq!(floor.oldest_position, join_position);
    assert_eq!(
        floor.floor_reason,
        arkret_wire::ReadableFloorReason::MembershipJoin
    );
    assert_eq!(
        rows(&own),
        vec![
            (join_position, true),
            (join_position + 1, true),
            (join_position + 2, true),
            (join_position + 3, false),
            (join_position + 4, true),
        ]
    );
    let AccountStreamScan::Page(before_genesis) = member
        .scan_stream_for_account(
            &scan_request(
                &realm_id,
                arkret_wire::StreamScanDirection::Before(Some(1)),
                1,
            ),
            &alice_account,
            &member_station(),
        )
        .await
        .unwrap()
    else {
        panic!("a missing replica Genesis must preserve the actual joined interval");
    };
    assert!(before_genesis.committed_events.is_empty());
    assert_eq!(before_genesis.readable_floor, own.readable_floor);

    // A single read on the member Station follows the same held interval:
    // another actor's Event from the hosted member's join on, the chain node
    // as withheld, nothing before a join and nothing for an outsider.
    let station = member_station();
    let outsider = remote_member("member-anchor-outsider");
    let strand_event = &strand.authority_commit.event.event_id;
    assert_eq!(
        read_shape(member_read(&member, strand_event, &alice, &station).await),
        Some(true)
    );
    assert_eq!(
        read_shape(
            member_read(
                &member,
                &default.authority_commit.event.event_id,
                &alice,
                &station
            )
            .await
        ),
        Some(true)
    );
    assert_eq!(
        read_shape(
            member_read(
                &member,
                &message.authority_commit.event.event_id,
                &alice,
                &station
            )
            .await
        ),
        Some(false)
    );
    assert_eq!(
        read_shape(
            member_read(
                &member,
                &bob_join.authority_commit.event.event_id,
                &alice,
                &station
            )
            .await
        ),
        Some(true)
    );
    assert_eq!(
        read_shape(
            member_read(
                &member,
                &forged.authority_commit.event.event_id,
                &alice,
                &station
            )
            .await
        ),
        None
    );
    assert_eq!(
        read_shape(
            member_read(
                &member,
                &unit.transactions[0].event.event_id,
                &alice,
                &station
            )
            .await
        ),
        None
    );
    assert_eq!(
        read_shape(member_read(&member, strand_event, &bob, &station).await),
        None
    );
    assert_eq!(
        read_shape(member_read(&member, strand_event, &outsider, &station).await),
        None
    );
    assert!(
        member
            .accepted_realm_reader(&realm_id, &alice)
            .await
            .unwrap()
    );
    assert!(member.accepted_realm_reader(&realm_id, &bob).await.unwrap());
    assert!(
        !member
            .accepted_realm_reader(&realm_id, &outsider)
            .await
            .unwrap()
    );

    // A since-join replica has no Realm genesis to replay. Its accepted
    // default pointer remains independent of the optional local Realm cache.
    let pointer = member
        .realm_default_strand_current(&realm_id)
        .await
        .unwrap();
    assert!(pointer.is_some());
    let persistence = coland_storage_postgres::PgPersistenceStore::new(member_pool.clone());
    let restarted = coland_services::projection::ProjectionService::new("member-anchor-restart");
    restarted
        .hydrate_from_persistence(
            &persistence,
            &hydration::BootstrapHydrationAdapter,
            [realm_id.clone()],
        )
        .await
        .unwrap();
    let restored = restarted.snapshot();
    assert!(!restored.realm_states.contains_key(realm_id.as_str()));
    assert_eq!(
        restored.strands[strand_id.as_str()].realm_id,
        realm_id.as_str()
    );
    assert_eq!(
        member
            .realm_default_strand_current(&realm_id)
            .await
            .unwrap(),
        pointer
    );
    let AccountStreamScan::Page(after_restart) = member
        .scan_stream_for_account(
            &scan_request(&realm_id, After(None), 10),
            &alice_account,
            &member_station(),
        )
        .await
        .unwrap()
    else {
        panic!("restart must preserve the proved member interval");
    };
    assert_eq!(after_restart.committed_events, own.committed_events);
    assert_eq!(after_restart.readable_floor, own.readable_floor);

    // A pointer alone cannot invent a Realm, even when its exact Commit is held.
    let mut conn = member_pool.get().await.unwrap();
    diesel::sql_query("UPDATE replica_stream_anchors SET anchor_commit_id=NULL,anchor_stream_position=NULL,anchored_at=NULL WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        member
            .realm_default_strand_current(&realm_id)
            .await
            .unwrap(),
        pointer
    );
    let refused = coland_services::projection::ProjectionService::new("unanchored-member-restart")
        .hydrate_from_persistence(
            &persistence,
            &hydration::BootstrapHydrationAdapter,
            [realm_id.clone()],
        )
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("without an anchored replica"),
        "{refused}"
    );
}

/// One ledger row of a claim this member Station issued as claim
/// destination, in `state`.
async fn member_claim(
    pool: &PgPool,
    claim_id: &str,
    state: &str,
) -> coland_storage::MlsWelcomeClaimLedgerKey {
    let key = coland_storage::MlsWelcomeClaimLedgerKey {
        source_id: STATION.to_owned(),
        claim_request_id: uuid::Uuid::now_v7().simple().to_string(),
        request_digest: format!("sha256:{}", "6".repeat(64)),
    };
    let now = chrono::Utc::now();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_id,claim_request_id,request_digest,key_package_use,keypackage_id,outcome, \
          terminal_receipt,consume_receipt,claim_expires_at_unix_ms,expires_at,state,updated_at) \
         VALUES ($1,$2,$3,'single_use',NULL,$4,NULL,NULL,$5,$6,$7,$8)",
    )
    .bind::<Text, _>(&key.source_id)
    .bind::<Text, _>(&key.claim_request_id)
    .bind::<Text, _>(&key.request_digest)
    .bind::<Jsonb, _>(serde_json::json!({"claims": [{"claim_id": claim_id}]}))
    .bind::<BigInt, _>(now.timestamp_millis() + 3_600_000)
    .bind::<BigInt, _>(now.timestamp() + 86_400)
    .bind::<Text, _>(state)
    .bind::<BigInt, _>(now.timestamp())
    .execute(&mut *conn)
    .await
    .unwrap();
    key
}

/// A Welcome of `commit` for `device` of `recipient`, verified by this member
/// Station against its ledger entry `claim`.
fn replicated_welcome(
    commit: &EventCommitRequest,
    recipient: &arkret_wire::ActorId,
    device: &str,
    claim_id: &str,
    claim: coland_storage::MlsWelcomeClaimLedgerKey,
) -> coland_storage::VerifiedMlsWelcome {
    let event = &commit.authority_commit.event;
    coland_storage::VerifiedMlsWelcome {
        delivery: arkret_wire::MlsWelcomeDelivery {
            welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
                "ak:mls_welcome_delivery:{}",
                uuid::Uuid::now_v7()
            ))
            .unwrap(),
            realm_id: event.realm_id.clone(),
            effective_scope: event.scope_ref.clone(),
            commit_event_ref: event.event_id.clone(),
            recipient_actor_id: recipient.clone(),
            recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                device_id: arkret_wire::DeviceId::new(device.to_owned()).unwrap(),
            },
            keypackage_claim_ref: arkret_wire::KeypackageClaimId::new(claim_id.to_owned()).unwrap(),
            ciphertext_b64: arkret_wire::Base64UrlString::new("V2VsY29tZQ".to_owned()).unwrap(),
            producer_proof: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: event
                    .producer_proof
                    .as_ref()
                    .unwrap()
                    .verification_method
                    .clone(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "5".repeat(64)))
                    .unwrap(),
                created_at: commit.authority_commit.commit.committed_at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        },
        claim: Some(claim),
        roster_witness: None,
    }
}

/// A signed fixture handed to storage after the serving layer has verified
/// both Station signatures and the exact committed-replication provenance.
/// This PG test checks atomic durability, not historical DID resolution.
fn recipient_roster_witness(
    commit: &EventCommitRequest,
    genesis_ref: &arkret_wire::EventId,
    welcome: &coland_storage::VerifiedMlsWelcome,
    claim_key: &coland_storage::MlsWelcomeClaimLedgerKey,
    authorization_event_ref: &arkret_wire::EventId,
) -> (
    coland_storage::VerifiedMlsRecipientRosterWitness,
    serde_json::Value,
) {
    use arkret_models_collaboration::mls_roster_authority::{
        MlsAddAuthorityAttestation, MlsAttestAddRequestBody,
    };
    use arkret_models_crypto::{
        KeyOperationSignature, KeyPackageClaimRecord, PeerKeyPackageClaimReceipt,
        PeerKeyPackagesClaimOutcome, PeerKeyPackagesClaimUnsignedRequest,
        peer_keypackage_claim_receipt_signing_bytes,
    };
    let delivery = &welcome.delivery;
    let at = commit.authority_commit.commit.committed_at;
    let verification_method = format!(
        "{}#station-key-1",
        device_authorization_history::did_web_station(&member_station())
    );
    let placeholder = || KeyOperationSignature {
        kid: arkret_wire::NonEmptyString::new(verification_method.clone()).unwrap(),
        signature_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
        sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
    };
    let record = KeyPackageClaimRecord {
        claim_id: delivery.keypackage_claim_ref.to_string(),
        keypackage_ref: "ak:keypackage:test".to_owned(),
        actor_id: delivery.recipient_actor_id.clone(),
        principal_id: delivery
            .recipient_actor_id
            .as_account_id()
            .unwrap()
            .principal_id
            .clone(),
        device_id: Some(match &delivery.recipient_endpoint {
            arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } => device_id.clone(),
            _ => unreachable!("fixture uses a device"),
        }),
        agent_id: None,
        agent_verification_method: None,
        keypackage: "AQ".to_owned(),
        capabilities: vec!["mls".to_owned()],
        device_authorize_event_id: Some(authorization_event_ref.clone()),
        agent_key_authorize_event_id: None,
        expires_at: at + chrono::Duration::hours(1),
        revocation_status: None,
        last_resort: None,
    };
    record.validate_shape().unwrap();
    let request: PeerKeyPackagesClaimUnsignedRequest = serde_json::from_value(serde_json::json!({
        "claim_request_id": claim_key.claim_request_id,
        "intended_realm_id": delivery.realm_id,
        "mls_group_id": delivery.effective_scope.canonical_mls_group_id().unwrap(),
        "claim_purpose": "realm_membership",
        "required_capabilities": ["mls"],
        "expires_at": arkret_canonical::format_timestamp_canonical(at + chrono::Duration::hours(1)),
    }))
    .unwrap();
    let mut receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: request.claim_request_id.clone(),
        request_digest: arkret_wire::Hash::new(claim_key.request_digest.clone()).unwrap(),
        claims_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&[&record]).unwrap(),
        )
        .unwrap(),
        source_id: STATION.parse().unwrap(),
        destination_id: member_station(),
        request,
        claimed_at: at,
        expires_at: at + chrono::Duration::hours(1),
        signature: placeholder(),
    };
    receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[19; 32],
        &verification_method,
        &peer_keypackage_claim_receipt_signing_bytes(&receipt).unwrap(),
    )
    .unwrap();
    let outcome = PeerKeyPackagesClaimOutcome {
        claim_request_id: receipt.claim_request_id.clone(),
        claims: vec![record],
        claim_receipt: receipt.clone(),
    };
    let mut attestation = MlsAddAuthorityAttestation {
        attestor_station_id: member_station(),
        realm_id: delivery.realm_id.clone(),
        effective_scope: delivery.effective_scope.clone(),
        mls_group_id: delivery.effective_scope.canonical_mls_group_id().unwrap(),
        genesis_event_ref: genesis_ref.clone(),
        commit_event_ref: delivery.commit_event_ref.clone(),
        commit_stream_position: commit.authority_commit.commit.stream_position,
        epoch: 1,
        welcome_id: delivery.welcome_id.clone(),
        claim_id: delivery.keypackage_claim_ref.clone(),
        actor_id: delivery.recipient_actor_id.clone(),
        endpoint: delivery.recipient_endpoint.clone(),
        authorization_event_ref: authorization_event_ref.clone(),
        leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode([7; 32]),
        )
        .unwrap(),
        claim_record_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&outcome.claims[0]).unwrap(),
        )
        .unwrap(),
        claim_receipt: receipt,
        attested_at: at,
        signature: placeholder(),
    };
    attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[19; 32],
        &verification_method,
        &attestation.signing_bytes().unwrap(),
    )
    .unwrap();
    let request = MlsAttestAddRequestBody {
        attestation,
        claim_outcome: outcome,
    };
    request.validate_claim_binding().unwrap();
    let json = serde_json::to_value(&request.claim_outcome).unwrap();
    (
        coland_storage::VerifiedMlsRecipientRosterWitness {
            accepted_genesis_event_ref: genesis_ref.clone(),
            signed_attest_add_request_canonical_json: arkret_canonical::canonical_json_bytes(
                &request,
            )
            .unwrap(),
            local_attestor_resolution: None,
        },
        json,
    )
}

/// The `ak.mls.commit` payload of a Commit over `base` at `previous_epoch`.
fn mls_commit_payload(
    realm_id: &arkret_wire::RealmId,
    base: &arkret_wire::EventId,
    previous_epoch: u64,
    commit_bytes: &[u8],
) -> serde_json::Value {
    let binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        realm_id.clone(),
        Some(base.clone()),
        previous_epoch,
        previous_epoch + 1,
        0,
    )
    .unwrap();
    let envelope = arkret_models_crypto::MlsCommitEnvelope {
        group_id: binding.mls_group_id().unwrap(),
        epoch: previous_epoch + 1,
        commit: arkret_wire::base64url::base64url_encode(commit_bytes),
        commit_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(commit_bytes))
            .unwrap(),
        ratchet_tree: None,
    };
    serde_json::to_value(
        arkret_models_crypto::MlsCommitPayload::new(base.clone(), 0, &envelope, binding).unwrap(),
    )
    .unwrap()
}

async fn queued_welcomes(pool: &PgPool) -> Vec<String> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        welcome_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT welcome_id FROM mls_welcome_deliveries ORDER BY welcome_id")
        .load::<Row>(&mut *conn)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.welcome_id)
        .collect()
}

async fn recipient_roster_outbox_count(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM mls_add_authority_attestation_outbox")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// encryption-and-audit.md §2.2 "跨站 recipient" and decision 0121 on the
/// member Station, which is the claim destination of its hosted recipients:
/// the re-verified Welcomes of a replicated `ak.mls.commit` are queued and
/// their claims bound in the replica transaction; a Welcome whose claim is no
/// longer live or whose recipient is no joined member is not queued and does
/// not block the replica; a replay of a Commit held through scan still queues
/// the Welcome not queued yet and answers `duplicate`; a second replay queues
/// nothing twice.
#[tokio::test]
async fn replicated_welcomes_queue_with_their_commit_replica_or_on_replay() {
    use coland_storage::MlsKeyPackageStore as _;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)",
        )
        .bind::<Text, _>(MEMBER_STATION)
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let device = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&member_station()),
    )
    .admit_founding_device(&persistence)
    .await
    .expect("accepted hosted recipient device");
    let bob = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        device.principal_id.clone(),
        member_station(),
    ));
    let unit = bootstrap_unit_with_join_rule("replica-welcomes", "public");
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let join = membership_request(last, bob.clone(), &bob, "join");
    store
        .install_committed_replica(&replica(&unit, &join, true))
        .await
        .unwrap();
    anchor_at_join(&store, &join, vec![joined_row(&join, &bob)]).await;
    let genesis_ref = join.authority_commit.event.event_id.clone();

    // A Commit carrying three Welcomes: one passes, one names a claim that is
    // no longer live, one names a recipient that is no joined member here.
    let commit = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::MlsCommit,
        &founder(),
        mls_commit_payload(&realm_id, &genesis_ref, 0, b"cross-station add"),
        last.commit.committed_at,
    ));
    let claim =
        |label: u8| format!("ak:keypackage_claim:01904100-0000-7000-8000-0000000c1a{label:02x}");
    let live = member_claim(&pool, &claim(1), "claimed").await;
    let expired = member_claim(&pool, &claim(2), "expired").await;
    let stranger_claim = member_claim(&pool, &claim(3), "claimed").await;
    let passing = replicated_welcome(&commit, &bob, &device.device_id, &claim(1), live);
    let welcomes = vec![
        passing.clone(),
        replicated_welcome(&commit, &bob, &device.device_id, &claim(2), expired),
        replicated_welcome(
            &commit,
            &remote_member("replica-stranger"),
            &device.device_id,
            &claim(3),
            stranger_claim,
        ),
    ];
    let mut item = replica(&unit, &commit, false);
    item.welcomes = welcomes.clone();
    assert!(
        store.install_committed_replica(&item).await.is_err(),
        "a Welcome cannot be queued without the signed Genesis selector"
    );
    assert!(
        store
            .committed_event_by_commit_id(&commit.authority_commit.commit.commit_id)
            .await
            .unwrap()
            .is_none(),
        "the missing-selector refusal rolls the replica back"
    );
    item.genesis_event_ref = Some(genesis_ref.clone());
    assert_eq!(
        store.install_committed_replica(&item).await.unwrap(),
        CommittedReplicaOutcome::Stored,
        "failing Welcomes never block the Commit replica"
    );
    assert_eq!(
        queued_welcomes(&pool).await,
        vec![passing.delivery.welcome_id.to_string()]
    );
    assert_eq!(
        coland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() }
            .get_claim_welcome_binding(&claim(1))
            .await
            .unwrap()
            .map(|binding| binding.welcome_id),
        Some(passing.delivery.welcome_id.to_string())
    );

    // The next Commit arrives through scan, without its Welcome; the item's
    // replay queues the Welcome and answers duplicate, once.
    let second = sourced(next_request(
        &commit.authority_commit,
        arkret_wire::EventKind::MlsCommit,
        &founder(),
        mls_commit_payload(
            &realm_id,
            &commit.authority_commit.event.event_id,
            1,
            b"second add",
        ),
        last.commit.committed_at,
    ));
    store
        .install_committed_replica(&replica(&unit, &second, false))
        .await
        .unwrap();
    let later = member_claim(&pool, &claim(4), "claimed").await;
    let late = replicated_welcome(&second, &bob, &device.device_id, &claim(4), later);
    for _ in 0..2 {
        assert_eq!(
            store
                .queue_replicated_welcomes(
                    &second.authority_commit.event,
                    &second.authority_commit.commit,
                    Some(&genesis_ref),
                    std::slice::from_ref(&late),
                    second.authority_commit.commit.committed_at,
                )
                .await
                .unwrap(),
            CommittedReplicaOutcome::Duplicate
        );
    }
    let mut expected = vec![
        passing.delivery.welcome_id.to_string(),
        late.delivery.welcome_id.to_string(),
    ];
    expected.sort();
    assert_eq!(queued_welcomes(&pool).await, expected);
}

/// The recipient's preverified signed Add proof is frozen with its exact
/// Welcome. A conflicting replay or a refused Welcome cannot leave a partial
/// queue/binding/outbox, and short-lived claim cleanup cannot erase the proof.
#[tokio::test]
async fn recipient_mls_add_attestation_outbox_is_atomic_durable_and_idempotent() {
    use coland_storage::MlsKeyPackageStore as _;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)",
        )
        .bind::<Text, _>(MEMBER_STATION)
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let device = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&member_station()),
    )
    .admit_founding_device(&persistence)
    .await
    .unwrap();
    let bob = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        device.principal_id.clone(),
        member_station(),
    ));
    let unit = bootstrap_unit_with_join_rule("roster-outbox", "public");
    let last = unit.transactions.last().unwrap();
    let realm_id = last.event.realm_id.clone();
    let join = membership_request(last, bob.clone(), &bob, "join");
    store
        .install_committed_replica(&replica(&unit, &join, true))
        .await
        .unwrap();
    anchor_at_join(&store, &join, vec![joined_row(&join, &bob)]).await;
    // This storage test treats the Genesis reference as an input already
    // verified by the serving layer. It does not assert MLS admission here.
    let genesis_ref = join.authority_commit.event.event_id.clone();
    let commit = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::MlsCommit,
        &founder(),
        mls_commit_payload(&realm_id, &genesis_ref, 0, b"recipient roster proof"),
        last.commit.committed_at,
    ));
    store
        .install_committed_replica(&replica(&unit, &commit, false))
        .await
        .unwrap();
    let claim_id = format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7());
    let claim = member_claim(&pool, &claim_id, "claimed").await;
    let mut first = replicated_welcome(&commit, &bob, &device.device_id, &claim_id, claim.clone());
    let (witness, outcome_json) = recipient_roster_witness(
        &commit,
        &genesis_ref,
        &first,
        &claim,
        &device.authorization_ref.event_id,
    );
    first.roster_witness = Some(witness.clone());
    {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "UPDATE peer_keypackage_claims SET outcome=$1 \
             WHERE source_id=$2 AND claim_request_id=$3 AND request_digest=$4",
        )
        .bind::<Jsonb, _>(outcome_json)
        .bind::<Text, _>(&claim.source_id)
        .bind::<Text, _>(&claim.claim_request_id)
        .bind::<Text, _>(&claim.request_digest)
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    for _ in 0..2 {
        assert_eq!(
            store
                .queue_replicated_welcomes(
                    &commit.authority_commit.event,
                    &commit.authority_commit.commit,
                    Some(&genesis_ref),
                    std::slice::from_ref(&first),
                    commit.authority_commit.commit.committed_at,
                )
                .await
                .unwrap(),
            CommittedReplicaOutcome::Duplicate
        );
    }
    assert_eq!(recipient_roster_outbox_count(&pool).await, 1);
    assert_eq!(
        queued_welcomes(&pool).await,
        vec![first.delivery.welcome_id.to_string()]
    );

    let wrong_genesis =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x47; 32]);
    assert!(
        store
            .queue_replicated_welcomes(
                &commit.authority_commit.event,
                &commit.authority_commit.commit,
                Some(&wrong_genesis),
                &[],
                commit.authority_commit.commit.committed_at,
            )
            .await
            .is_err(),
        "an exact Commit replay cannot change immutable Genesis provenance"
    );
    assert_eq!(recipient_roster_outbox_count(&pool).await, 1);

    // Same Welcome, different signed historical claim: the frozen row wins.
    let mut conflicting = first.clone();
    let other_auth =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x46; 32]);
    let (other_witness, _) =
        recipient_roster_witness(&commit, &genesis_ref, &first, &claim, &other_auth);
    conflicting.roster_witness = Some(other_witness);
    store
        .queue_replicated_welcomes(
            &commit.authority_commit.event,
            &commit.authority_commit.commit,
            Some(&genesis_ref),
            &[conflicting],
            commit.authority_commit.commit.committed_at,
        )
        .await
        .unwrap();
    assert_eq!(recipient_roster_outbox_count(&pool).await, 1);

    // A fresh claim's malformed witness is rejected *after* queue/binding
    // staging; its nested transaction rolls every such write back.
    let refused_claim_id = format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7());
    let refused_claim = member_claim(&pool, &refused_claim_id, "claimed").await;
    let mut refused = replicated_welcome(
        &commit,
        &bob,
        &device.device_id,
        &refused_claim_id,
        refused_claim,
    );
    refused.roster_witness = Some(witness);
    store
        .queue_replicated_welcomes(
            &commit.authority_commit.event,
            &commit.authority_commit.commit,
            Some(&genesis_ref),
            &[refused],
            commit.authority_commit.commit.committed_at,
        )
        .await
        .unwrap();
    assert_eq!(recipient_roster_outbox_count(&pool).await, 1);
    assert_eq!(
        queued_welcomes(&pool).await,
        vec![first.delivery.welcome_id.to_string()]
    );
    assert!(
        coland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() }
            .get_claim_welcome_binding(&refused_claim_id)
            .await
            .unwrap()
            .is_none()
    );

    // The claim ledger's normal retention does not own this durable proof.
    {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "DELETE FROM peer_keypackage_claims \
             WHERE source_id=$1 AND claim_request_id=$2 AND request_digest=$3",
        )
        .bind::<Text, _>(&claim.source_id)
        .bind::<Text, _>(&claim.claim_request_id)
        .bind::<Text, _>(&claim.request_digest)
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    assert_eq!(recipient_roster_outbox_count(&pool).await, 1);
    let proof: arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody =
        serde_json::from_slice(
            &first
                .roster_witness
                .as_ref()
                .unwrap()
                .signed_attest_add_request_canonical_json,
        )
        .unwrap();
    let frozen = store
        .mls_recipient_attestation(
            &proof.attestation.commit_event_ref,
            &proof.attestation.welcome_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&frozen).unwrap(),
        arkret_canonical::canonical_json_bytes(&proof).unwrap()
    );
    assert_eq!(
        store
            .pending_mls_recipient_attestations(32)
            .await
            .unwrap()
            .len(),
        1
    );
    let wrong_digest = arkret_wire::Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap();
    assert!(
        store
            .acknowledge_mls_recipient_attestation(&proof, &wrong_digest, chrono::Utc::now())
            .await
            .is_err()
    );
    assert_eq!(
        store
            .pending_mls_recipient_attestations(32)
            .await
            .unwrap()
            .len(),
        1
    );
    let digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&proof).unwrap()).unwrap();
    for _ in 0..2 {
        store
            .acknowledge_mls_recipient_attestation(&proof, &digest, chrono::Utc::now())
            .await
            .unwrap();
    }
    assert!(
        store
            .pending_mls_recipient_attestations(32)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .mls_recipient_attestation(
                &proof.attestation.commit_event_ref,
                &proof.attestation.welcome_id
            )
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(recipient_roster_outbox_count(&pool).await, 1);
}

/// Structural producer proofs isolate accepted-state replication and disclosure.
/// Real franking signatures are exercised separately in franking_receipt_commit.
#[tokio::test]
async fn circle_own_opening_join_anchors_remote_stream_and_membership_basis_expires() {
    heap_future(|| {
        circle_own_opening_join_anchors_remote_stream_and_membership_basis_expires_case()
    })
    .await;
}

async fn circle_own_opening_join_anchors_remote_stream_and_membership_basis_expires_case() {
    let governor_db = TestDatabase::lease().await;
    let replica_db = TestDatabase::lease().await;
    let pool = governor_db.pool();
    let governor = PgAuthorityCommitStore { pool: pool.clone() };
    let member = PgAuthorityCommitStore {
        pool: replica_db.pool(),
    };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let did = device_authorization_history::did_web_station(&ordinary_realm::station());
    let mut connection = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) ON CONFLICT(singleton) DO NOTHING")
        .bind::<Text,_>(ordinary_realm::station().as_str()).execute(&mut *connection).await.unwrap();
    drop(connection);
    let creator = arkret_wire::ActorId::account(
        ordinary_realm::human_profile::admit_without_profile(
            &pool,
            &ordinary_realm::station(),
            "circle-bootstrap-creator",
        )
        .await,
    );
    let unit = ordinary_realm::source_bootstrap(
        &pool,
        ordinary_realm::bootstrap_unit_for_account(
            &uuid::Uuid::now_v7().to_string(),
            creator.as_account_id().unwrap(),
            &did,
        ),
    )
    .await;
    let at = unit.transactions.last().unwrap().commit.committed_at;
    governor
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm = unit.transactions[0].event.realm_id.clone();
    let remote = remote_member("circle-replica-reader");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        remote.clone(),
        &remote,
        "join",
    );
    uow.commit_event(join.clone()).await.unwrap();
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &join, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let material = governor
        .member_station_bootstrap_material(
            &realm,
            remote.as_account_id().unwrap(),
            &join.authority_commit.commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    let realm_head = material
        .visible_stream_heads
        .iter()
        .find(|h| matches!(h.stream_ref, arkret_wire::CommitStreamRef::Realm { .. }))
        .unwrap()
        .clone();
    member
        .install_replica_anchor(&{
            let mut install = ReplicaAnchorInstall {
                realm_id: realm.clone(),
                join_commit_id: join.authority_commit.commit.commit_id.clone(),
                governance_generation: join.authority_commit.commit.governance_generation,
                snapshot_head: realm_head,
                visible_stream_heads: material.visible_stream_heads,
                current_state_entries: material.current_state_entries,

                verified_snapshot: bootstrap_snapshot(&(realm.clone()), 0, &[], &[]),
            };
            install.verified_snapshot = bootstrap_snapshot(
                &install.realm_id,
                install.governance_generation,
                &install.visible_stream_heads,
                &install.current_state_entries,
            );
            install
        })
        .await
        .unwrap();
    let create = heap_future(|| ordinary_realm::source_request(&pool, sourced(next_request_for_actor(
        &join.authority_commit,
        arkret_wire::EventKind::CircleCreate,
        creator.clone(),
        serde_json::json!({"object":{
            "schema":"ak.schema.circle.v1","realm_id":realm,"title":"Remote private","display":{"short_name":"Remote","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join","state":"active","created_by":creator,"created_at":at
        }}),
        at,
    )))).await;
    uow.commit_event(create.clone()).await.unwrap();
    assert!(
        fanout_rows(&pool, &create).await.is_empty(),
        "parent Realm membership does not disclose a Circle object"
    );
    let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let scope = arkret_wire::ScopeRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    // Public entry still requires its explicit capability; Realm membership
    // alone is only the enclosing scope floor (circle.md section 9).
    let root_event_ref = realm_root_event_ref(&pool, &realm).await;
    let grant = heap_future(|| {
        ordinary_realm::source_request(
            &pool,
            sourced(next_request_for_actor(
                &create.authority_commit,
                arkret_wire::EventKind::CapabilityGrant,
                creator.clone(),
                serde_json::json!({"grant":{
                    "schema":"ak.schema.capability.v1","realm_id":realm,
                    "issuer_id":creator,"subject":remote,"actions":["ak.circle.member.add"],
                    "resources":[{"kind":"circle","realm_id":realm,"circle_id":circle}],
                    "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,
                        "authority_event_ref":root_event_ref,"authority_generation":0}],
                    "issued_at":arkret_canonical::format_timestamp_canonical(at)
                }}),
                at,
            )),
        )
    })
    .await;
    uow.commit_event(grant).await.unwrap();
    let stream = arkret_wire::CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let circle_transition = |previous: &AuthorityCommitTransaction,
                             state: &str,
                             expected: Option<&str>| {
        let event = ordinary_realm::event_for_actor(
            arkret_wire::EventKind::CircleMemberState,
            scope.clone(),
            remote.clone(),
            {
                let mut payload = serde_json::json!({"circle_id":circle,"member_id":remote,"membership":state,"expected_membership":expected});
                if state == "join" {
                    payload["parent_membership_revision"] = serde_json::json!({
                        "commit_id": join.authority_commit.commit.commit_id,
                        "stream_position": join.authority_commit.commit.stream_position,
                    });
                }
                payload
            },
            at,
        );
        let mut request = ordinary_realm::request_for_event(previous, event, at);
        if previous.commit.stream_ref != stream {
            request.authority_commit.commit.stream_position = 0;
            request.authority_commit.commit.previous_commit_ref = None;
        }
        request.authority_commit.commit.stream_ref = stream.clone();
        sourced(request)
    };
    let circle_join = circle_transition(&create.authority_commit, "join", None);
    uow.commit_event(circle_join.clone()).await.unwrap();
    let join_rows = fanout_rows(&pool, &circle_join).await;
    assert_eq!(join_rows.len(), 1);
    let witnesses: Vec<RealmFanoutAuthorityWitness> =
        serde_json::from_value(join_rows[0].realm_fanout["authority_witnesses"].clone()).unwrap();
    assert_eq!(
        witnesses[0].membership_event_ref,
        join.authority_commit.event.event_id.to_string()
    );
    assert_eq!(
        witnesses[0].circle_membership_event_ref,
        Some(circle_join.authority_commit.event.event_id.clone())
    );
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &circle_join, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let mut connection = member.pool.get().await.unwrap();
    let metadata = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM circle_current_results WHERE circle_id=$1",
    )
    .bind::<Text, _>(circle.as_str())
    .get_result::<CountRow>(&mut *connection)
    .await
    .unwrap();
    assert_eq!(
        metadata.count, 0,
        "the private Circle Create must not be fabricated before bootstrap"
    );
    drop(connection);
    let account = remote.as_account_id().unwrap();
    let join_id = &circle_join.authority_commit.commit.commit_id;
    let join_floor = Some(circle_join.authority_commit.commit.stream_position);
    assert_eq!(
        member
            .member_station_bootstrap_floor(&realm, account, join_id)
            .await
            .unwrap(),
        join_floor,
        "the accepted pending Circle join proves its floor without fabricating current rows"
    );
    assert_eq!(
        member
            .member_station_bootstrap_floor(&realm, creator.as_account_id().unwrap(), join_id)
            .await
            .unwrap(),
        None,
        "another Account cannot borrow the pending opening join"
    );
    assert_eq!(
        member
            .member_station_bootstrap_floor(
                &realm,
                account,
                &create.authority_commit.commit.commit_id
            )
            .await
            .unwrap(),
        None,
        "the floor proof binds the exact opening Commit"
    );
    assert!(
        member
            .member_station_bootstrap_material(&realm, account, join_id)
            .await
            .unwrap()
            .is_none(),
        "a pending floor proof cannot authorize issuing a Snapshot"
    );
    // Simulate a local parent current advancing independently while bootstrap
    // is pending. The held Circle join still binds its original parent revision.
    let mut connection = member.pool.get().await.unwrap();
    let advance_parent = |delta: i64| {
        diesel::sql_query(
        "UPDATE member_state_current_results SET current_stream_position=current_stream_position+$3 \
         WHERE realm_id=$1 AND member_id=$2",
    ).bind::<Text,_>(realm.as_str()).bind::<Text,_>(remote.to_string()).bind::<BigInt,_>(delta)
    };
    assert_eq!(
        advance_parent(1).execute(&mut *connection).await.unwrap(),
        1
    );
    assert_eq!(
        member
            .member_station_bootstrap_floor(&realm, account, join_id)
            .await
            .unwrap(),
        None,
        "a pending Circle join cannot borrow a different parent current revision"
    );
    assert_eq!(
        advance_parent(-1).execute(&mut *connection).await.unwrap(),
        1
    );
    drop(connection);
    assert_eq!(
        member
            .member_station_bootstrap_floor(&realm, account, join_id)
            .await
            .unwrap(),
        join_floor
    );
    let pending_scan = arkret_wire::StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: stream.clone(),
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 16,
    };
    assert!(matches!(
        member
            .scan_stream_for_account(
                &pending_scan,
                remote.as_account_id().unwrap(),
                &member_station()
            )
            .await
            .unwrap(),
        coland_storage::AccountStreamScan::Unproved(
            "the Circle stream is pending its bootstrap anchor"
        )
    ));
    let material = governor
        .member_station_bootstrap_material(
            &realm,
            remote.as_account_id().unwrap(),
            &circle_join.authority_commit.commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    let circle_head = material
        .visible_stream_heads
        .iter()
        .find(|h| h.stream_ref == stream)
        .unwrap()
        .clone();
    assert_eq!(
        circle_head.commit_id,
        circle_join.authority_commit.commit.commit_id
    );
    member
        .install_replica_anchor(&{
            let mut install = ReplicaAnchorInstall {
                realm_id: realm.clone(),
                join_commit_id: circle_join.authority_commit.commit.commit_id.clone(),
                governance_generation: circle_join.authority_commit.commit.governance_generation,
                snapshot_head: circle_head,
                visible_stream_heads: material.visible_stream_heads.clone(),
                current_state_entries: material.current_state_entries.clone(),

                verified_snapshot: bootstrap_snapshot(&(realm.clone()), 0, &[], &[]),
            };
            install.verified_snapshot = bootstrap_snapshot(
                &install.realm_id,
                install.governance_generation,
                &install.visible_stream_heads,
                &install.current_state_entries,
            );
            install
        })
        .await
        .unwrap();
    assert!(
        member
            .replica_anchor_for_stream(&arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone()
            })
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        member
            .replica_anchor_for_stream(&stream)
            .await
            .unwrap()
            .is_some()
    );
    let scan = arkret_wire::StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: stream.clone(),
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 16,
    };
    assert_eq!(
        rows_of_circle_scan(
            member
                .scan_stream_for_account(&scan, remote.as_account_id().unwrap(), &member_station())
                .await
                .unwrap()
        ),
        vec![true]
    );
    // The Circle's creator joins as well, then writes a plaintext Message.
    // Alice's Station holds the Circle stream but is not in the Realm's
    // plaintext-visible service set, so it gets only the Message Commit via
    // peer scan. The next full replica must wait for that chain node.
    let circle_event = |previous: &AuthorityCommitTransaction,
                        kind: arkret_wire::EventKind,
                        payload: serde_json::Value| {
        let mut event =
            ordinary_realm::event_for_actor(kind, scope.clone(), creator.clone(), payload, at);
        ordinary_realm::bind_structural_human_device(&mut event);
        let mut request = ordinary_realm::request_for_event(previous, event, at);
        request.authority_commit.commit.stream_ref = stream.clone();
        sourced(request)
    };
    let creator_parent = ordinary_realm::parent_membership_revision(&pool, &realm, &creator).await;
    let creator_join = circle_event(
        &circle_join.authority_commit,
        arkret_wire::EventKind::CircleMemberState,
        serde_json::json!({"circle_id":circle,"member_id":creator,"membership":"join",
            "parent_membership_revision":creator_parent,"expected_membership":null}),
    );
    let creator_join = heap_future(|| ordinary_realm::source_request(&pool, creator_join)).await;
    uow.commit_event(creator_join.clone()).await.unwrap();
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &creator_join, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let strand = circle_event(
        &creator_join.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circle,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Withheld gap discussion"},"state":"active",
            "created_by":creator,"created_at":at}}),
    );
    let strand = heap_future(|| ordinary_realm::source_request(&pool, strand)).await;
    uow.commit_event(strand.clone()).await.unwrap();
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &strand, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let message = circle_event(
        &strand.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        message_payload(&strand_id, "Circle plaintext stays at the governor"),
    );
    let message = heap_future(|| ordinary_realm::source_request(&pool, message)).await;
    uow.commit_event(message.clone()).await.unwrap();
    assert!(fanout_rows(&pool, &message).await.is_empty());
    let leave = circle_transition(&message.authority_commit, "leave", Some("join"));
    uow.commit_event(leave.clone()).await.unwrap();
    assert_code(
        &member
            .install_committed_replica(&replica(&unit, &leave, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    assert!(
        member
            .committed_event(&leave.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none(),
        "the successor cannot skip a withheld Circle Commit"
    );
    let scan_gap = arkret_wire::StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: stream.clone(),
        direction: arkret_wire::StreamScanDirection::After(Some(
            strand.authority_commit.commit.stream_position,
        )),
        limit: 16,
    };
    let coland_storage::AccountStreamScan::Page(gap) =
        peer_page(&governor, scan_gap, &member_station()).await
    else {
        panic!("the hosting Station must receive a Circle peer scan")
    };
    assert_eq!(
        rows(&gap),
        vec![
            (message.authority_commit.commit.stream_position, false),
            (leave.authority_commit.commit.stream_position, true),
        ]
    );
    let arkret_wire::CommittedEventView::Withheld(withheld) = &gap.committed_events[0] else {
        panic!("plaintext Message must be withheld")
    };
    assert_eq!(withheld.commit, message.authority_commit.commit);
    assert!(
        !serde_json::to_string(&gap)
            .unwrap()
            .contains("Circle plaintext stays at the governor")
    );
    assert_eq!(
        member
            .install_committed_chain_node(&CommittedChainNode {
                local_service_id: member_station(),
                authority: governance_authority(&unit),
                commit: withheld.commit.clone(),
            })
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert!(
        member
            .committed_event(&message.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        member
            .install_committed_replica(&replica(&unit, &leave, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert!(
        !governor
            .realm_fanout_still_owed(
                &circle_join.authority_commit.event,
                &ordinary_realm::station(),
                &member_station(),
                &witnesses,
                at
            )
            .await
            .unwrap()
    );
    let leave_rows = fanout_rows(&pool, &leave).await;
    assert_eq!(
        leave_rows.len(),
        1,
        "departing hosted member is owed its terminating state"
    );
    member
        .install_committed_replica(&replica(&unit, &leave, false))
        .await
        .unwrap();
    assert!(matches!(
        member
            .scan_stream_for_account(&scan, remote.as_account_id().unwrap(), &member_station())
            .await
            .unwrap(),
        coland_storage::AccountStreamScan::Unproved("the caller has no held Circle join")
    ));
    assert!(
        governor
            .member_station_bootstrap_material(
                &realm,
                remote.as_account_id().unwrap(),
                &circle_join.authority_commit.commit.commit_id
            )
            .await
            .unwrap()
            .is_none(),
        "an old opening join cannot refresh current authorization after leave"
    );
}

fn rows_of_circle_scan(scan: coland_storage::AccountStreamScan) -> Vec<bool> {
    match scan {
        coland_storage::AccountStreamScan::Page(page) => page
            .committed_events
            .iter()
            .map(|event| matches!(event, arkret_wire::CommittedEventView::Full(_)))
            .collect(),
        other => panic!("Circle page expected: {other:?}"),
    }
}

/// Private source candidates never establish peer obligations. Shared candidates
/// also require an exact accepted source Event before sender revalidation.
#[tokio::test]
async fn private_confirmation_and_policy_ref_sources_are_never_owed_to_ordinary_peers() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = admit(&pool, "private-source-fanout", "public").await;
    let remote = remote_member("private-source-peer");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        remote.clone(),
        &remote,
        "join",
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    let at = join.authority_commit.commit.committed_at;
    let witnesses = [RealmFanoutAuthorityWitness {
        member_id: remote,
        membership_event_ref: join.authority_commit.event.event_id.to_string(),
        circle_membership_event_ref: None,
    }];
    for (kind, payload, expected) in [
        (
            arkret_wire::EventKind::AgentActionApprove,
            serde_json::json!({"approval_nonce":"private-controller-nonce"}),
            false,
        ),
        (
            arkret_wire::EventKind::PolicyAction,
            serde_json::json!({"policy_id":"private-policy-reference"}),
            false,
        ),
        (
            arkret_wire::EventKind::PolicyAction,
            serde_json::json!({"action_id":"shared-realm-action"}),
            true,
        ),
        (
            arkret_wire::EventKind::PolicySet,
            serde_json::json!({"policy_id":"shared-policy"}),
            true,
        ),
    ] {
        let request = next_request(&join.authority_commit, kind, &founder(), payload, at);
        let owed = store
            .realm_fanout_still_owed(
                &request.authority_commit.event,
                &ordinary_realm::station(),
                &member_station(),
                &witnesses,
                at,
            )
            .await;
        if expected {
            assert!(
                owed.is_err(),
                "an unaccepted candidate cannot establish fanout"
            );
            assert!(
                store
                    .committed_event(&request.authority_commit.event.event_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            assert!(!owed.unwrap(), "private sources never establish fanout");
        }
    }
}

fn peer_interval_decision(
    scan: coland_storage::PeerStreamScan,
) -> coland_storage::AccountStreamScan {
    match scan {
        coland_storage::PeerStreamScan::Page(page) => {
            coland_storage::AccountStreamScan::Page(arkret_wire::StreamScanOutcome {
                committed_events: page.committed_events,
                readable_floor: page.readable_floor,
                truncated: page.truncated,
            })
        }
        coland_storage::PeerStreamScan::NotAuthorized => {
            coland_storage::AccountStreamScan::NotAuthorized
        }
        coland_storage::PeerStreamScan::Unproved(reason) => {
            coland_storage::AccountStreamScan::Unproved(reason)
        }
    }
}
