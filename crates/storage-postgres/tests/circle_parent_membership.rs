//! `ak.vector.circle.parent_membership_revision.v1` on real PostgreSQL.
//!
//! A Circle join binds the exact parent Realm join revision (`circle.md`
//! section 9.1). Admission refuses any other revision, and effective Circle
//! membership compares the two durable typed currents of one cut: a parent
//! leave, ban or rejoin invalidates the old Circle join without any Circle
//! Event or rewritten canonical row, and only an explicit new Circle join
//! bound to the new revision restores it.

#[path = "support/historical_human.rs"]
mod historical_human;
use arkret_wire::{ActorId, CircleId, CommitStreamRef, EventKind, ScopeRef};
use coland_storage::{
    AccountStreamScan, AuthorityCommitStore, AuthorityCommitTransaction, ConflictCode,
    EventCommitRequest, EventCommitUnitOfWork, PersistenceError,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text};
use diesel_async::RunQueryDsl;
use historical_human::ordinary_realm;
use serde_json::{Value, json};

// Construct large native fixture futures in a separate synchronous frame.
// Returning the pinned allocation before polling avoids stacking construction
// temporaries on the parent poll frame in unoptimized Windows test builds.
#[inline(never)]
fn heap_future<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

// Clone retained originals outside the matrix poll frame. The protocol
// request and production unit of work are unchanged; callers retain only a
// small borrowed future while the request crosses the real transaction.
#[inline(never)]
async fn commit_request(
    uow: &PgEventCommitUnitOfWork,
    request: &EventCommitRequest,
) -> coland_storage::PersistenceResult<coland_storage::EventCommitOutcome> {
    uow.commit_event(request.clone()).await
}

fn remote_member(label: &str) -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:circle-parent-member-station.example")
            .unwrap(),
    ))
}

fn sourced(mut request: EventCommitRequest) -> EventCommitRequest {
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

fn realm_membership(
    previous: &AuthorityCommitTransaction,
    writer: &ActorId,
    member: &ActorId,
    state: &str,
    reason: &str,
) -> EventCommitRequest {
    sourced(ordinary_realm::next_request_for_actor(
        previous,
        EventKind::MemberState,
        writer.clone(),
        json!({"realm_id":previous.event.realm_id,"member_id":member,"membership":state,
            "reason":reason}),
        previous.commit.committed_at,
    ))
}

/// One Circle-stream Event by `actor` after `previous`, which is either the
/// Circle stream head or a Realm-stream Commit when the Circle stream is new.
fn circle_request(
    previous: &AuthorityCommitTransaction,
    circle: &CircleId,
    actor: &ActorId,
    payload: Value,
) -> EventCommitRequest {
    // Distinct transitions with equal payloads are distinct signed Events;
    // the content address includes created_at, not the later Commit cursor.
    let at = previous.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let event = ordinary_realm::event_for_actor(
        EventKind::CircleMemberState,
        ScopeRef::Circle {
            realm_id: previous.event.realm_id.clone(),
            circle_id: circle.clone(),
        },
        actor.clone(),
        payload,
        at,
    );
    let mut request = ordinary_realm::request_for_event(previous, event, at);
    let stream = CommitStreamRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    if previous.commit.stream_ref != stream {
        request.authority_commit.commit.stream_position = 0;
        request.authority_commit.commit.previous_commit_ref = None;
    }
    request.authority_commit.commit.stream_ref = stream;
    sourced(request)
}

fn circle_membership(
    circle: &CircleId,
    member: &ActorId,
    state: &str,
    expected: Value,
    parent: Option<&Value>,
) -> Value {
    let mut payload = json!({"circle_id":circle,"member_id":member,"membership":state,
        "expected_membership":expected});
    if let Some(parent) = parent {
        payload["parent_membership_revision"] = parent.clone();
    }
    payload
}

#[derive(diesel::QueryableByName)]
struct EffectiveRow {
    #[diesel(sql_type = Bool)]
    effective: bool,
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

/// The canonical Circle row and the effective judgment of the same cut.
async fn circle_member(pool: &PgPool, circle: &CircleId, member: &ActorId) -> EffectiveRow {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT circle_member_parent_join_current(realm_id,member_id,value) AS effective, \
         membership,current_commit_id,value FROM circle_member_state_current_states \
         WHERE circle_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(circle.as_str())
    .bind::<Text, _>(member.to_string())
    .get_result::<EffectiveRow>(&mut conn)
    .await
    .unwrap()
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn circle_stream_commits(pool: &PgPool, stream: &CommitStreamRef) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM realm_commits WHERE stream_ref=$1")
        .bind::<Jsonb, _>(serde_json::to_value(stream).unwrap())
        .get_result::<CountRow>(&mut conn)
        .await
        .unwrap()
        .count
}

async fn circle_scan_authorized(
    store: &PgAuthorityCommitStore,
    stream: &CommitStreamRef,
    member: &ActorId,
) -> bool {
    let request = arkret_wire::StreamScanRequestBody {
        realm_id: stream.realm_id().clone(),
        stream_ref: stream.clone(),
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 16,
    };
    match store
        .scan_stream_for_account(
            &request,
            member.as_account_id().unwrap(),
            &ordinary_realm::station(),
        )
        .await
        .unwrap()
    {
        AccountStreamScan::Page(_) => true,
        AccountStreamScan::NotAuthorized => false,
        other => panic!("unexpected Circle scan answer {other:?}"),
    }
}

fn refusal_code(error: &PersistenceError) -> Option<ConflictCode> {
    error.conflict_code()
}

async fn handoff_circle_proofs(
    pool: &PgPool,
    snapshot: &arkret_wire::RealmStateSnapshot,
    circle: &CircleId,
    member: &ActorId,
) -> Vec<Value> {
    #[derive(diesel::QueryableByName)]
    struct ProofRow {
        #[diesel(sql_type = Jsonb)]
        observation: Value,
        #[diesel(sql_type = Jsonb)]
        cut: Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
        #[diesel(sql_type = Bool)]
        proved: bool,
    }
    let mut conn = pool.get().await.unwrap();
    let mut proofs = Vec::new();
    for selector in [
        arkret_wire::CurrentSelector::Circle {
            circle_id: circle.clone(),
        },
        arkret_wire::CurrentSelector::CircleMemberState {
            circle_id: circle.clone(),
            member_actor_id: member.clone(),
        },
    ] {
        let arkret_wire::CurrentState::Value {
            source_stream_ref,
            revision,
            value,
            ..
        } = snapshot
            .current_state_entries
            .iter()
            .find(|entry| matches!(entry, arkret_wire::CurrentState::Value { selector: actual, .. } if actual == &selector))
            .expect("the actual complete handoff discloses this Circle current");
        let head = snapshot
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == source_stream_ref)
            .unwrap();
        let row = diesel::sql_query(
            "SELECT to_jsonb(r) AS observation,to_jsonb(h) AS cut,c.commit_json, \
             circle_current_row_proved(r.realm_id,r.selector,r.source_stream_ref, \
               r.current_commit_id,r.current_stream_position,r.value) AS proved \
             FROM replica_authorization_rows r \
             JOIN replica_authorization_cuts h ON h.realm_id=r.realm_id AND h.source_stream_ref=r.source_stream_ref \
             JOIN realm_commits c ON c.realm_id=r.realm_id AND c.stream_ref=r.source_stream_ref \
               AND c.commit_id=r.current_commit_id AND c.stream_position=r.current_stream_position \
             WHERE r.realm_id=$1 AND r.selector=$2",
        )
        .bind::<Text, _>(snapshot.realm_id.as_str())
        .bind::<Jsonb, _>(json!(selector))
        .get_result::<ProofRow>(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            row.observation["source_stream_ref"],
            json!(source_stream_ref)
        );
        assert_eq!(
            row.observation["current_commit_id"],
            json!(revision.commit_id)
        );
        assert_eq!(
            row.observation["current_stream_position"],
            json!(revision.stream_position)
        );
        assert_eq!(&row.observation["value"], value);
        assert_eq!(
            row.observation["observed_anchor_commit_id"],
            json!(head.commit_id)
        );
        assert_eq!(
            row.observation["observed_anchor_stream_position"],
            json!(head.stream_position)
        );
        assert!(!row.observation["circle_continuation_id"].is_null());
        assert_eq!(
            row.observation["circle_continuation_id"],
            row.cut["circle_continuation_id"]
        );
        assert_eq!(
            row.cut["circle_effect_base_commit_id"],
            json!(head.commit_id)
        );
        assert_eq!(
            row.cut["circle_effect_base_stream_position"],
            json!(head.stream_position)
        );
        assert_eq!(row.cut["head_commit_id"], json!(head.commit_id));
        assert_eq!(row.cut["head_stream_position"], json!(head.stream_position));
        let original: arkret_wire::RealmCommit = serde_json::from_value(row.commit_json).unwrap();
        assert_eq!(original.commit_id, revision.commit_id);
        assert_eq!(
            original.governance_generation,
            snapshot.governance_generation
        );
        assert!(
            row.proved,
            "full handoff must retain proof after final authority activation"
        );
        proofs.push(json!({"observation":row.observation,"cut":row.cut}));
    }
    proofs
}

async fn handoff_replay_footprint(pool: &PgPool) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Rows {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    let mut conn = pool.get().await.unwrap();
    let mut footprint = serde_json::Map::new();
    for table in [
        "realm_authorities",
        "canonical_events",
        "realm_commits",
        "circle_current_states",
        "circle_member_state_current_states",
        "member_state_current_states",
        "replica_authorization_rows",
        "replica_authorization_cuts",
        "replica_stream_anchors",
        "realm_state_snapshots",
        "realm_state_snapshot_issuances",
        "realm_state_snapshot_window_reservations",
        "idempotency_keys",
    ] {
        let query = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS value FROM {table} t"
        );
        let rows = diesel::sql_query(query)
            .get_result::<Rows>(&mut conn)
            .await
            .unwrap();
        footprint.insert(table.to_owned(), rows.value);
    }
    Value::Object(footprint)
}

#[tokio::test]
async fn circle_join_binds_the_exact_parent_join_and_parent_changes_invalidate_it() {
    for history in ["since_join", "all_history_for_current_members"] {
        heap_future(|| parent_revision_matrix(history, None)).await;
    }
}

#[tokio::test]
async fn signal_parent_cut_reset_controller_and_handoff_matrix() {
    for branch in ["reset", "controller", "handoff"] {
        heap_future(|| parent_revision_matrix("since_join", Some(branch))).await;
    }
}

async fn root_digest(pool: &PgPool, realm: &arkret_wire::RealmId) -> arkret_wire::Hash {
    #[derive(diesel::QueryableByName)]
    struct Root {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    let mut conn = pool.get().await.unwrap();
    let root=diesel::sql_query("SELECT jsonb_build_object('controller_actor_id',controller_actor_id,'controller_epoch',controller_epoch,'authority_generation',authority_generation,'authority_event_ref',authority_event_ref) AS value FROM realm_authority_root_current_states WHERE realm_id=$1")
        .bind::<Text,_>(realm.as_str()).get_result::<Root>(&mut conn).await.unwrap();
    arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&root.value).unwrap()).unwrap()
}

async fn parent_revision_matrix(history: &str, branch: Option<&str>) {
    // This matrix retains several exact requests across later assertions.
    // Keep its native source/fixture futures on the heap as well as the outer
    // matrix; the storage traits already return boxed futures themselves.
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    // Only the accepted bootstrap unit and creator survive this phase;
    // the larger native PCR/device fixture is not part of the matrix frame.
    let (unit, creator) = heap_future(|| async {
        let did = ordinary_realm::human_profile::station_did(&ordinary_realm::station());
        let fixture = heap_future(|| historical_human::HumanFixture::new(&pool, did)).await;
        ordinary_realm::human_profile::register_fixture_signer(
            &fixture.pcr.history.account,
            fixture.pcr.history.device_verification_method.clone(),
            fixture.pcr.history.founding_device_signing_seed,
        );
        let creator = ActorId::account(fixture.pcr.history.account.clone());
        heap_future(|| fixture.admit(&pool)).await;
        let unit = fixture.unit;
        (unit, creator)
    })
    .await;
    let at = unit.transactions.last().unwrap().commit.committed_at;
    let realm = unit.transactions[0].event.realm_id.clone();
    let alice = remote_member("circle-parent-alice");
    let realm_join = realm_membership(
        unit.transactions.last().unwrap(),
        &alice,
        &alice,
        "join",
        "first join",
    );
    let realm_join = heap_future(|| ordinary_realm::source_request(&pool, realm_join)).await;
    commit_request(&uow, &realm_join).await.unwrap();
    let create = heap_future(|| ordinary_realm::source_request(&pool, sourced(ordinary_realm::next_request_for_actor(
        &realm_join.authority_commit,
        EventKind::CircleCreate,
        creator.clone(),
        json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
            "title":"Parent bound","display":{"short_name":"Parent","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":history,
            "state":"active","created_by":creator,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    )))).await;
    commit_request(&uow, &create).await.unwrap();
    let circle = CircleId::from_event_id(&create.authority_commit.event.event_id);
    let stream = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let root_event_ref = {
        #[derive(diesel::QueryableByName)]
        struct RootRow {
            #[diesel(sql_type = Text)]
            authority_event_ref: String,
        }
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT authority_event_ref FROM realm_authority_root_current_states WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<RootRow>(&mut conn)
        .await
        .unwrap()
        .authority_event_ref
    };
    let grant = heap_future(|| ordinary_realm::source_request(&pool, sourced(ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::CapabilityGrant,
        creator.clone(),
        json!({"grant":{
            "schema":"ak.schema.capability.v1","realm_id":realm,
            "issuer_id":creator,"subject":alice,"actions":["ak.circle.member.add","ak.mls.genesis"],
            "resources":[{"kind":"circle","realm_id":realm,"circle_id":circle}],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,
                "authority_event_ref":root_event_ref,"authority_generation":"0"}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    )))).await;
    commit_request(&uow, &grant).await.unwrap();
    let first_parent = ordinary_realm::parent_membership_revision(&pool, &realm, &alice).await;
    assert_eq!(
        first_parent,
        json!({"commit_id":realm_join.authority_commit.commit.commit_id,
            "stream_position":realm_join.authority_commit.commit.stream_position})
    );

    // Admission: the revision is required on join, forbidden elsewhere, and
    // must be the parent current join exactly.
    heap_future(|| async {
        let missing = circle_request(
            &grant.authority_commit,
            &circle,
            &alice,
            circle_membership(&circle, &alice, "join", Value::Null, None),
        );
        let missing = heap_future(|| ordinary_realm::source_request(&pool, missing)).await;
        assert!(matches!(
            commit_request(&uow, &missing).await.unwrap_err(),
            PersistenceError::SchemaViolation(_)
        ));
        let mut foreign_revision = first_parent.clone();
        foreign_revision["commit_id"] = json!(create.authority_commit.commit.commit_id);
        let foreign = circle_request(
            &grant.authority_commit,
            &circle,
            &alice,
            circle_membership(
                &circle,
                &alice,
                "join",
                Value::Null,
                Some(&foreign_revision),
            ),
        );
        let foreign = heap_future(|| ordinary_realm::source_request(&pool, foreign)).await;
        let refused = commit_request(&uow, &foreign).await.unwrap_err();
        assert_eq!(
            refusal_code(&refused),
            Some(ConflictCode::FailedPrecondition)
        );
        assert!(
            refused
                .to_string()
                .contains("circle_member_must_be_realm_member")
        );
        // The same position number on another Commit is not the parent join.
        let mut shifted = first_parent.clone();
        shifted["stream_position"] = json!(realm_join.authority_commit.commit.stream_position + 1);
        let shifted = circle_request(
            &grant.authority_commit,
            &circle,
            &alice,
            circle_membership(&circle, &alice, "join", Value::Null, Some(&shifted)),
        );
        let shifted = heap_future(|| ordinary_realm::source_request(&pool, shifted)).await;
        assert_eq!(
            refusal_code(&commit_request(&uow, &shifted).await.unwrap_err()),
            Some(ConflictCode::FailedPrecondition)
        );
        assert_eq!(circle_stream_commits(&pool, &stream).await, 0);
    })
    .await;

    let circle_join = circle_request(
        &grant.authority_commit,
        &circle,
        &alice,
        circle_membership(&circle, &alice, "join", Value::Null, Some(&first_parent)),
    );
    let circle_join = heap_future(|| ordinary_realm::source_request(&pool, circle_join)).await;
    commit_request(&uow, &circle_join).await.unwrap();
    let joined = circle_member(&pool, &circle, &alice).await;
    assert!(joined.effective);
    assert_eq!(joined.value["parent_membership_revision"], first_parent);
    assert!(circle_scan_authorized(&store, &stream, &alice).await);

    let (genesis, binding, payload) = heap_future(|| async {
        let binding = arkret_models_crypto::MlsGovernanceBindingPayload::circle(
            realm.clone(),
            circle.clone(),
            None,
            0,
            0,
            0,
        )
        .unwrap();
        let payload = json!({
            "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref":format!("ak:blob:sha256:{}", "3".repeat(64)),
            "ratchet_tree_ref":format!("ak:blob:sha256:{}", "4".repeat(64)),
            "creator_leaf_authority":{
                "leaf_signature_key_base64url":arkret_canonical::base64url_encode([7_u8;32]),
                "endpoint":{"kind":"device","device_id":format!("ak:device:{}",uuid::Uuid::now_v7())},
                "authorization_event_ref":arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[8_u8;32]),
            },
            "governance_binding":binding,
            "created_at":arkret_canonical::format_timestamp_canonical(at),
        });
        let event = ordinary_realm::event_for_actor(
            EventKind::MlsGenesis,
            ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circle.clone(),
            },
            alice.clone(),
            payload.clone(),
            at,
        );
        let mut genesis = sourced(ordinary_realm::request_for_event(
            &circle_join.authority_commit,
            event,
            at,
        ));
        genesis.authority_commit.commit.stream_ref = stream.clone();
        let mut genesis = heap_future(|| ordinary_realm::source_request(&pool, genesis)).await;
        genesis.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
            effective_scope: ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circle.clone(),
            },
            base: None,
            epoch: 0,
            public_state: b"circle-public-state".to_vec(),
            member_principals: Default::default(),
            consumed_proposals: Vec::new(),
            public_blobs: Vec::new(),
        });
        (genesis, binding, payload)
    }).await;
    let activated = history == "since_join";
    if activated {
        commit_request(&uow, &genesis).await.unwrap();
    } else {
        assert_eq!(
            refusal_code(&commit_request(&uow, &genesis).await.unwrap_err()),
            Some(ConflictCode::FailedPrecondition)
        );
        assert_eq!(circle_stream_commits(&pool, &stream).await, 1);
    }
    let material_request =
        arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody {
            realm_id: realm.clone(),
            effective_scope: genesis.authority_commit.event.scope_ref.clone(),
            mls_group_id: binding.mls_group_id().unwrap(),
            epoch: Default::default(),
            group_state_event_id: genesis.authority_commit.event.event_id.clone(),
            caller_actor_id: Some(alice.clone()),
            target_commit_event_ref: Some(genesis.authority_commit.event.event_id.clone()),
            target_epoch: Some(0),
            group_info_ref: serde_json::from_value(payload["group_info_ref"].clone()).unwrap(),
            ratchet_tree_ref: serde_json::from_value(payload["ratchet_tree_ref"].clone()).unwrap(),
            max_response_bytes: None,
        };
    let roster_request =
        arkret_models_collaboration::mls_roster_authority::MlsRosterAuthorityReadRequestBody {
            realm_id: realm.clone(),
            effective_scope: material_request.effective_scope.clone(),
            mls_group_id: material_request.mls_group_id.clone(),
            genesis_event_ref: material_request.group_state_event_id.clone(),
            target_commit_event_ref: material_request.target_commit_event_ref.clone().unwrap(),
            target_epoch: 0,
            caller_actor_id: alice.clone(),
            cursor: None,
        };
    let mut parent_tail = grant.authority_commit.clone();
    if activated {
        let branch_complete = heap_future(|| async {
            assert!(matches!(
                store
                    .mls_member_group_state_material_read(
                        &material_request,
                        &ordinary_realm::station(),
                        None
                    )
                    .await
                    .unwrap(),
                coland_storage::MlsMemberGroupStateMaterialRead::Authorized { genesis: Some(_) }
            ));
            let signal_at =
                genesis.authority_commit.commit.committed_at + chrono::TimeDelta::seconds(1);
            let authority = store
                .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
 include_product_authority: false, product_agent: None,

                    scope: &material_request.effective_scope,
                    authority_commit_id: &genesis.authority_commit.commit.commit_id,
                    parent_realm_authority_commit_id: Some(&grant.authority_commit.commit.commit_id),
                    sender: &alice,
                    signal_class: arkret_wire::SignalClass::Session,
                    sent_at: signal_at,
                    at: signal_at,
                })
                .await
                .unwrap()
                .expect("signed Circle parent join proves the historical and current Signal cut");
            assert_eq!(authority.recipient_actors, vec![alice.clone()]);
            assert_eq!(
                authority.historical_mls_event_ref,
                genesis.authority_commit.event.event_id
            );
            for parent in [
                None,
                Some(&genesis.authority_commit.commit.commit_id),
                Some(&unit.transactions[0].commit.commit_id),
            ] {
                assert!(
                    store
                        .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
 include_product_authority: false, product_agent: None,

                            scope: &material_request.effective_scope,
                            authority_commit_id: &genesis.authority_commit.commit.commit_id,
                            parent_realm_authority_commit_id: parent,
                            sender: &alice,
                            signal_class: arkret_wire::SignalClass::Session,
                            sent_at: signal_at,
                            at: signal_at,
                        })
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            let moderation_at =
                genesis.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1);
            let moderation_grant = sourced(ordinary_realm::next_request_for_actor(
                &parent_tail,
                EventKind::CapabilityGrant,
                creator.clone(),
                json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":creator,
                    "subject":alice,"actions":["ak.call.moderate"],"resources":[{"kind":"circle","realm_id":realm,"circle_id":circle}],
                    "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":root_event_ref,"authority_generation":"0"}],
                    "issued_at":arkret_canonical::format_timestamp_canonical(moderation_at)}}),
                moderation_at,
            ));
            let moderation_grant =
                heap_future(|| ordinary_realm::source_request(&pool, moderation_grant)).await;
            commit_request(&uow, &moderation_grant).await.unwrap();
            // A later grant cannot retroactively authorize an older parent cut.
            assert!(
                store
                    .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
 include_product_authority: false, product_agent: None,

                        scope: &material_request.effective_scope,
                        authority_commit_id: &genesis.authority_commit.commit.commit_id,
                        parent_realm_authority_commit_id: Some(
                            &grant.authority_commit.commit.commit_id
                        ),
                        sender: &alice,
                        signal_class: arkret_wire::SignalClass::Moderation,
                        sent_at: signal_at,
                        at: signal_at,
                    })
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
 include_product_authority: false, product_agent: None,

                        scope: &material_request.effective_scope,
                        authority_commit_id: &genesis.authority_commit.commit.commit_id,
                        parent_realm_authority_commit_id: Some(
                            &moderation_grant.authority_commit.commit.commit_id
                        ),
                        sender: &alice,
                        signal_class: arkret_wire::SignalClass::Moderation,
                        sent_at: signal_at,
                        at: signal_at,
                    })
                    .await
                    .unwrap()
                    .is_some()
            );
            if let Some(branch) = branch {
                let scope = &material_request.effective_scope;
                let scope_head = &genesis.authority_commit.commit.commit_id;
                let original_parent = &moderation_grant.authority_commit.commit.commit_id;
                let mut tail = moderation_grant.authority_commit.clone();
                if branch == "reset" {
                    heap_future(|| async {
                    let reset = sourced(ordinary_realm::next_request_for_actor(
                        &tail,
                        EventKind::RealmAuthorityReset,
                        creator.clone(),
                        json!({"realm_id":realm,"expected_state_digest":root_digest(&pool,&realm).await}),
                        moderation_at + chrono::TimeDelta::milliseconds(1),
                    ));
                    let reset = heap_future(|| ordinary_realm::source_request(&pool, reset)).await;
                    commit_request(&uow, &reset).await.unwrap();
                    assert!(
                        store
                            .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
include_product_authority: false,
product_agent: None,
                                scope,
                                authority_commit_id: scope_head,
                                parent_realm_authority_commit_id: Some(original_parent),
                                sender: &alice,
                                signal_class: arkret_wire::SignalClass::Moderation,
                                sent_at: signal_at,
                                at: signal_at,
                            })
                            .await
                            .unwrap()
                            .is_none(),
                        "current root reset invalidates the old root-generation moderation grant"
                    );
                    }).await;
                } else if branch == "controller" {
                    heap_future(|| async {
                    let transfer = sourced(ordinary_realm::next_request_for_actor(
                        &tail,
                        EventKind::RealmOwnerTransfer,
                        creator.clone(),
                        json!({"realm_id":realm,"expected_state_digest":root_digest(&pool,&realm).await,
                            "patch":{"controller_actor_id":alice},"successor_acceptance":"storage-boundary-fixture"}),
                        moderation_at + chrono::TimeDelta::milliseconds(1),
                    ));
                    let transfer = heap_future(|| ordinary_realm::source_request(&pool, transfer)).await;
                    commit_request(&uow, &transfer).await.unwrap();
                    assert!(
                        store
                            .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
include_product_authority: false,
product_agent: None,
                                scope,
                                authority_commit_id: scope_head,
                                parent_realm_authority_commit_id: Some(original_parent),
                                sender: &alice,
                                signal_class: arkret_wire::SignalClass::Moderation,
                                sent_at: signal_at,
                                at: signal_at,
                            })
                            .await
                            .unwrap()
                            .is_some(),
                        "owner transfer preserves the already accepted ordinary grant"
                    );
                    tail = transfer.authority_commit;
                    let revoke = sourced(ordinary_realm::next_request_for_actor(
                        &tail,
                        EventKind::CapabilityRevoke,
                        alice.clone(),
                        json!({"grant_id":arkret_wire::GrantId::from_event_id(&moderation_grant.authority_commit.event.event_id),
                            "expected_revision":{"commit_id":original_parent,"stream_position":moderation_grant.authority_commit.commit.stream_position}}),
                        tail.commit.committed_at + chrono::TimeDelta::milliseconds(1),
                    ));
                    let revoke = heap_future(|| ordinary_realm::source_request(&pool, revoke)).await;
                    commit_request(&uow, &revoke).await.unwrap();
                    let transfer_back = sourced(ordinary_realm::next_request_for_actor(
                        &revoke.authority_commit,
                        EventKind::RealmOwnerTransfer,
                        alice.clone(),
                        json!({"realm_id":realm,"expected_state_digest":root_digest(&pool,&realm).await,
                            "patch":{"controller_actor_id":creator},"successor_acceptance":"storage-boundary-fixture"}),
                        revoke.authority_commit.commit.committed_at
                            + chrono::TimeDelta::milliseconds(1),
                    ));
                    let transfer_back =
                        heap_future(|| ordinary_realm::source_request(&pool, transfer_back)).await;
                    commit_request(&uow, &transfer_back).await.unwrap();
                    assert!(
                        store
                            .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
include_product_authority: false,
product_agent: None,
                                scope,
                                authority_commit_id: scope_head,
                                parent_realm_authority_commit_id: Some(original_parent),
                                sender: &alice,
                                signal_class: arkret_wire::SignalClass::Moderation,
                                sent_at: signal_at,
                                at: signal_at,
                            })
                            .await
                            .unwrap()
                            .is_none(),
                        "old controller authority cannot revive a revoked moderation grant"
                    );
                    }).await;
                } else {
                    heap_future(|| async {
                    let next_station =
                        arkret_wire::DidCoreId::new("ak:did_core:web:next-signal-station.example")
                            .unwrap();
                    let change = sourced(ordinary_realm::next_request_for_actor(
                        &tail,
                        EventKind::RealmGovernanceStationChange,
                        creator.clone(),
                        json!({"expected_governance_generation":"0","expected_realm_stream_commit_id":tail.commit.commit_id,
                            "new_governance_station_id":next_station}),
                        tail.commit.committed_at + chrono::TimeDelta::milliseconds(1),
                    ));
                    let change = heap_future(|| ordinary_realm::source_request(&pool, change)).await;
                    commit_request(&uow, &change).await.unwrap();
                    let mut heads = vec![
                        arkret_wire::CommitStreamHead {
                            stream_ref: change.authority_commit.commit.stream_ref.clone(),
                            stream_position: change.authority_commit.commit.stream_position,
                            commit_id: change.authority_commit.commit.commit_id.clone(),
                        },
                        arkret_wire::CommitStreamHead {
                            stream_ref: stream.clone(),
                            stream_position: genesis.authority_commit.commit.stream_position,
                            commit_id: scope_head.clone(),
                        },
                    ];
                    heads.sort_by(|a, b| a.stream_ref.cmp(&b.stream_ref));
                    let material = store.realm_state_snapshot_material(&realm).await.unwrap().unwrap();
                    assert_eq!(material.visible_stream_heads, heads);
                    let mut inventory = Vec::new();
                    for full in store.handoff_originals(&realm).await.unwrap() {
                        if full.commit.producer_signer_fact_digest.is_some() {
                            inventory.push(arkret_models_collaboration::authority_commit::HistoricalProducerSignerFactEntry {
                                target: arkret_wire::CommittedEventRef {
                                    event_id: full.event.event_id.clone(),
                                    commit_id: full.commit.commit_id.clone(),
                                    stream_ref: full.commit.stream_ref.clone(),
                                    stream_position: full.commit.stream_position,
                                },
                                producer_signer_fact: store.producer_signer_fact(&full.event, &full.commit).await.unwrap().unwrap(),
                            });
                        }
                    }
                    inventory.sort_by_key(|entry| (arkret_canonical::canonical_json_bytes(&entry.target.stream_ref).unwrap(),
                        entry.target.stream_position,entry.target.event_id.to_string(),entry.target.commit_id.to_string()));
                    let inventory_digest = arkret_models_collaboration::authority_commit::historical_signer_facts_digest(&inventory).unwrap();
                    let mut snapshot_signature =
                        ordinary_realm::signature(&ordinary_realm::station(), signal_at);
                    snapshot_signature.context = arkret_wire::DetachedSignatureContext::RealmSnapshot;
                    let mut snapshot = arkret_wire::RealmStateSnapshot {
                        purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
                        history_basis: None,
                        snapshot_id: arkret_wire::RealmSnapshotId::from_digest([0x91; 32]),
                        realm_id: realm.clone(),
                        governance_generation: 0,
                        visible_stream_heads: heads.clone(),
                        current_state_entries: material.current_state_entries,
                        retention_and_history_floor: material.retention_and_history_floor,
                        created_at: signal_at,
                        signature: snapshot_signature,
                    };
                    // Storage-only structural signatures remain separate from the
                    // real canonical Snapshot content address checked by the store.
                    let snapshot_identity = arkret_canonical::canonical::unsigned_value(
                        &snapshot,
                        &["snapshot_id", "signature"],
                    )
                    .unwrap();
                    snapshot.snapshot_id =
                        arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
                            arkret_canonical::canonical_json_bytes(&snapshot_identity).unwrap(),
                        ));
                    let mut old_signature =
                        ordinary_realm::signature(&ordinary_realm::station(), signal_at);
                    old_signature.context =
                        arkret_wire::DetachedSignatureContext::RealmAuthorityHandoffOld;
                    let mut new_signature = ordinary_realm::signature(&next_station, signal_at);
                    new_signature.context =
                        arkret_wire::DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance;
                    let (management, private_bytes) = store.export_management_private_state(&realm).await.unwrap();
                    store.import_management_private_state(&management, &private_bytes).await.unwrap();
                    let (_, reexported) = store.export_management_private_state(&realm).await.unwrap();
                    assert_eq!(reexported, private_bytes);
                    let handoff = arkret_wire::RealmAuthorityHandoff {
                        management_private_state_digest: Some(management.digest().unwrap()),
                        pcr_private_state_digest: None,
                        handoff_id: arkret_wire::RealmAuthorityHandoffId::from_digest([0x92; 32]),
                        realm_id: realm.clone(),
                        from_generation: 0,
                        to_generation: 1,
                        from_service_id: ordinary_realm::station(),
                        to_service_id: next_station,
                        final_stream_heads_digest: arkret_wire::Hash::new(
                            arkret_canonical::canonical_sha256(&heads).unwrap(),
                        )
                        .unwrap(),
                        snapshot_ref: snapshot.snapshot_id.clone(),
                        historical_signer_facts_digest: Some(inventory_digest),
                        change_event_ref: change.authority_commit.event.event_id.clone(),
                        change_commit_id: change.authority_commit.commit.commit_id.clone(),
                        old_authority_signature: old_signature,
                        new_authority_acceptance_signature: new_signature,
                    };
                    let before_handoff_member = circle_member(&pool, &circle, &alice).await;
                    assert_eq!(before_handoff_member.current_commit_id, circle_join.authority_commit.commit.commit_id.as_str());
                    assert_eq!(before_handoff_member.value, joined.value);
                    // Storage fixtures use structural signatures; the Garth verified-scan fixture
                    // independently verifies the real dual Ed25519 signatures and complete manifest.
                    store
                        .install_handoff_with_private_state(&handoff, &heads, &snapshot, None, &management)
                        .await
                        .unwrap();
                    let active = store.current_authority(&realm).await.unwrap().unwrap();
                    assert_eq!(active.generation, handoff.to_generation);
                    assert_eq!(active.service_id, handoff.to_service_id);
                    assert_eq!(active.authority_ref, arkret_wire::RealmCommitAuthorityRef::Handoff(handoff.handoff_id.clone()));
                    #[derive(diesel::QueryableByName)]
                    struct LocalStation {
                        #[diesel(sql_type = Text)]
                        station: String,
                    }
                    let local = diesel::sql_query("SELECT current_device_inventory_station() AS station")
                        .get_result::<LocalStation>(&mut pool.get().await.unwrap())
                        .await
                        .unwrap();
                    assert_eq!(local.station, handoff.from_service_id.as_str());
                    assert_ne!(active.service_id, handoff.from_service_id);
                    let after_handoff_member = circle_member(&pool, &circle, &alice).await;
                    assert_eq!(after_handoff_member.current_commit_id, before_handoff_member.current_commit_id);
                    assert_eq!(after_handoff_member.value, before_handoff_member.value);
                    assert_eq!(after_handoff_member.membership, before_handoff_member.membership);
                    assert!(after_handoff_member.effective);
                    let qualified_proofs = handoff_circle_proofs(&pool, &snapshot, &circle, &alice).await;
                    assert!(
                        store
                            .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
include_product_authority: false,
product_agent: None,
                                scope,
                                authority_commit_id: scope_head,
                                parent_realm_authority_commit_id: Some(original_parent),
                                sender: &alice,
                                signal_class: arkret_wire::SignalClass::Moderation,
                                sent_at: signal_at,
                                at: signal_at,
                            })
                            .await
                            .unwrap()
                            .is_some(),
                        "accepted complete handoff preserves an unchanged Circle head"
                    );
                    // Reuse the real outgoing Realm anchor, not Alice's Circle
                    // join hosted at another Station. Generation is the only
                    // stale property of this previously accepted full Snapshot.
                    let realm_stream = &change.authority_commit.commit.stream_ref;
                    let outgoing = store.replica_anchor_for_stream(realm_stream).await.unwrap()
                        .expect("complete handoff retains the creator's actual local Realm anchor");
                    assert_eq!(outgoing.member_account_id.station_id, handoff.from_service_id);
                    assert_eq!(ActorId::account(outgoing.member_account_id.clone()), creator);
                    assert!(outgoing.anchored_head.is_some());
                    assert!(snapshot.current_state_entries.iter().any(|entry| matches!(entry,
                        arkret_wire::CurrentState::Value {
                            selector: arkret_wire::CurrentSelector::MemberState { actor_id },
                            source_stream_ref, revision, value
                        } if actor_id == &creator && source_stream_ref == realm_stream
                            && revision.commit_id == outgoing.join_commit.commit_id
                            && revision.stream_position == outgoing.join_commit.stream_position
                            && value.get("membership").and_then(Value::as_str) == Some("join")
                    )));
                    let before_stale_snapshot = handoff_replay_footprint(&pool).await;
                    let stale_snapshot = coland_storage::ReplicaAnchorInstall {
                        realm_id: realm.clone(),
                        join_commit_id: outgoing.join_commit.commit_id.clone(),
                        governance_generation: snapshot.governance_generation,
                        snapshot_head: heads.iter().find(|head| &head.stream_ref == realm_stream).unwrap().clone(),
                        visible_stream_heads: snapshot.visible_stream_heads.clone(),
                        current_state_entries: snapshot.current_state_entries.clone(),
                        verified_snapshot: snapshot.clone(),
                    };
                    assert_eq!(stale_snapshot.governance_generation, handoff.from_generation);
                    let refused_snapshot = store.install_replica_anchor(&stale_snapshot).await.unwrap_err();
                    assert_eq!(refusal_code(&refused_snapshot), Some(ConflictCode::ForkQuarantine));
                    assert_eq!(handoff_replay_footprint(&pool).await, before_stale_snapshot,
                        "a delayed old-tenure Snapshot must not change any persisted observation or current");
                    assert_eq!(handoff_circle_proofs(&pool, &snapshot, &circle, &alice).await, qualified_proofs);
                    let mut stale = handoff.clone();
                    stale.handoff_id = arkret_wire::RealmAuthorityHandoffId::from_digest([0x93; 32]);
                    assert!(matches!(
                        store
                            .install_handoff_with_private_state(&stale, &heads, &snapshot, None, &management)
                            .await
                            .unwrap_err(),
                        PersistenceError::Conflict(_)
                    ));
                    let mut conn = pool.get().await.unwrap();
                    diesel::sql_query("DELETE FROM realm_state_snapshots WHERE snapshot_id=$1")
                        .bind::<Text, _>(snapshot.snapshot_id.as_str())
                        .execute(&mut conn)
                        .await
                        .unwrap();
                    drop(conn);
                    assert!(
                        store
                            .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
include_product_authority: false,
product_agent: None,
                                scope,
                                authority_commit_id: scope_head,
                                parent_realm_authority_commit_id: Some(original_parent),
                                sender: &alice,
                                signal_class: arkret_wire::SignalClass::Moderation,
                                sent_at: signal_at,
                                at: signal_at,
                            })
                            .await
                            .is_err(),
                        "missing durable handoff manifest cannot authorize an old generation head"
                    );
                    }).await;
                }
                assert_eq!(
                    circle_stream_commits(&pool, &stream).await,
                    2,
                    "authority decisions do not synthesize Circle Events or Commits"
                );
                println!(
                    "[signal-authority-matrix] branch={branch} real_postgres=1 scope_head_unchanged=1 assertions_passed=1"
                );
                return true;
            }
            let revoke = sourced(ordinary_realm::next_request_for_actor(
                &moderation_grant.authority_commit,
                EventKind::CapabilityRevoke,
                creator.clone(),
                json!({"grant_id":arkret_wire::GrantId::from_event_id(&moderation_grant.authority_commit.event.event_id),
                    "expected_revision":{"commit_id":moderation_grant.authority_commit.commit.commit_id,"stream_position":moderation_grant.authority_commit.commit.stream_position}}),
                moderation_at + chrono::TimeDelta::milliseconds(1),
            ));
            let revoke = heap_future(|| ordinary_realm::source_request(&pool, revoke)).await;
            commit_request(&uow, &revoke).await.unwrap();
            assert!(
                store
                    .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
 include_product_authority: false, product_agent: None,

                        scope: &material_request.effective_scope,
                        authority_commit_id: &genesis.authority_commit.commit.commit_id,
                        parent_realm_authority_commit_id: Some(
                            &moderation_grant.authority_commit.commit.commit_id
                        ),
                        sender: &alice,
                        signal_class: arkret_wire::SignalClass::Moderation,
                        sent_at: signal_at,
                        at: signal_at,
                    })
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(circle_stream_commits(&pool, &stream).await, 2);
            parent_tail = revoke.authority_commit;
            assert!(matches!(
                store
                    .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
                    .await
                    .unwrap(),
                coland_storage::MlsRosterAuthorityRead::Authorized { facts: Some(_) }
            ));
            false
        }).await;
        if branch_complete {
            return;
        }
    }
    // The parent leave/rejoin/ban assertions form a separate bounded phase.
    heap_future(|| async {
        let circle_head = if activated {
            genesis.authority_commit.clone()
        } else {
            circle_join.authority_commit.clone()
        };

        // A renewed since-join Circle floor hides the old MLS target. The
        // all-history fixture has no accepted MLS target to disclose.
        let same_parent_leave = circle_request(
            &circle_head,
            &circle,
            &alice,
            circle_membership(&circle, &alice, "leave", json!("join"), None),
        );
        let same_parent_leave =
            heap_future(|| ordinary_realm::source_request(&pool, same_parent_leave)).await;
        commit_request(&uow, &same_parent_leave).await.unwrap();
        let same_parent_join = circle_request(
            &same_parent_leave.authority_commit,
            &circle,
            &alice,
            circle_membership(&circle, &alice, "join", json!("leave"), Some(&first_parent)),
        );
        let same_parent_join = heap_future(|| ordinary_realm::source_request(&pool, same_parent_join)).await;
        commit_request(&uow, &same_parent_join).await.unwrap();
        let answer = store
            .mls_member_group_state_material_read(&material_request, &ordinary_realm::station(), None)
            .await
            .unwrap();
        let roster = store
            .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
            .await
            .unwrap();
        {
            assert!(matches!(
                answer,
                coland_storage::MlsMemberGroupStateMaterialRead::NotFound
            ));
            assert!(matches!(
                roster,
                coland_storage::MlsRosterAuthorityRead::NotFound
            ));
            let member = arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody {
                realm_id: roster_request.realm_id.clone(), effective_scope: roster_request.effective_scope.clone(),
                mls_group_id: roster_request.mls_group_id.clone(), target_commit_event_ref: roster_request.target_commit_event_ref.clone(),
                target_epoch: roster_request.target_epoch, caller_actor_id: roster_request.caller_actor_id.clone(), cursor: None,
            };
            assert!(matches!(
                store
                    .mls_member_roster_selector(&member, &ordinary_realm::station())
                    .await
                    .unwrap(),
                coland_storage::MlsMemberRosterSelectorRead::NotFound
            ));
        }
        let joined = circle_member(&pool, &circle, &alice).await;
        let circle_head = same_parent_join.authority_commit.clone();

        // Parent leave: the old Circle join is effective-invalid at once; no
        // Circle Event is synthesized and the canonical row is not rewritten.
        let realm_leave = realm_membership(&parent_tail, &alice, &alice, "leave", "parent leave");
        let realm_leave = heap_future(|| ordinary_realm::source_request(&pool, realm_leave)).await;
        commit_request(&uow, &realm_leave).await.unwrap();
        let after_leave = circle_member(&pool, &circle, &alice).await;
        if activated {
            let signal_at =
                realm_leave.authority_commit.commit.committed_at + chrono::TimeDelta::seconds(1);
            assert!(
                store
                    .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
 include_product_authority: false, product_agent: None,

                        scope: &material_request.effective_scope,
                        authority_commit_id: &genesis.authority_commit.commit.commit_id,
                        parent_realm_authority_commit_id: Some(
                            &grant.authority_commit.commit.commit_id
                        ),
                        sender: &alice,
                        signal_class: arkret_wire::SignalClass::Session,
                        sent_at: signal_at,
                        at: signal_at,
                    })
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(!after_leave.effective);
        assert_eq!(after_leave.membership, "join");
        assert_eq!(after_leave.current_commit_id, joined.current_commit_id);
        assert_eq!(after_leave.value, joined.value);
        assert_eq!(
            circle_stream_commits(&pool, &stream).await,
            if activated { 4 } else { 3 }
        );
        assert!(!circle_scan_authorized(&store, &stream, &alice).await);
        assert!(matches!(
            store
                .mls_member_group_state_material_read(
                    &material_request,
                    &ordinary_realm::station(),
                    None
                )
                .await
                .unwrap(),
            coland_storage::MlsMemberGroupStateMaterialRead::NotFound
        ));
        assert!(matches!(
            store
                .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
                .await
                .unwrap(),
            coland_storage::MlsRosterAuthorityRead::NotFound
        ));

        // Parent rejoin: a new revision never revives the old Circle join.
        let rejoin = realm_membership(
            &realm_leave.authority_commit,
            &alice,
            &alice,
            "join",
            "parent rejoin",
        );
        let rejoin = heap_future(|| ordinary_realm::source_request(&pool, rejoin)).await;
        commit_request(&uow, &rejoin).await.unwrap();
        let second_parent = ordinary_realm::parent_membership_revision(&pool, &realm, &alice).await;
        assert_ne!(second_parent, first_parent);
        let after_rejoin = circle_member(&pool, &circle, &alice).await;
        if activated {
            let signal_at = rejoin.authority_commit.commit.committed_at + chrono::TimeDelta::seconds(1);
            assert!(
                store
                    .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
 include_product_authority: false, product_agent: None,

                        scope: &material_request.effective_scope,
                        authority_commit_id: &genesis.authority_commit.commit.commit_id,
                        parent_realm_authority_commit_id: Some(
                            &grant.authority_commit.commit.commit_id
                        ),
                        sender: &alice,
                        signal_class: arkret_wire::SignalClass::Session,
                        sent_at: signal_at,
                        at: signal_at,
                    })
                    .await
                    .unwrap()
                    .is_none(),
                "parent rejoin cannot revive an old Signal cut"
            );
        }
        assert!(!after_rejoin.effective);
        assert_eq!(after_rejoin.value, joined.value);
        assert_eq!(
            circle_stream_commits(&pool, &stream).await,
            if activated { 4 } else { 3 }
        );
        assert!(!circle_scan_authorized(&store, &stream, &alice).await);
        assert!(matches!(
            store
                .mls_member_group_state_material_read(
                    &material_request,
                    &ordinary_realm::station(),
                    None
                )
                .await
                .unwrap(),
            coland_storage::MlsMemberGroupStateMaterialRead::NotFound
        ));
        assert!(matches!(
            store
                .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
                .await
                .unwrap(),
            coland_storage::MlsRosterAuthorityRead::NotFound
        ));
        // The old revision is no longer the parent current join.
        let stale = circle_request(
            &circle_head,
            &circle,
            &alice,
            circle_membership(&circle, &alice, "join", json!("leave"), Some(&first_parent)),
        );
        let stale = heap_future(|| ordinary_realm::source_request(&pool, stale)).await;
        assert_eq!(
            refusal_code(&commit_request(&uow, &stale).await.unwrap_err()),
            Some(ConflictCode::FailedPrecondition)
        );
        // A leave never carries the revision.
        let misplaced = circle_request(
            &circle_head,
            &circle,
            &alice,
            circle_membership(
                &circle,
                &alice,
                "leave",
                json!("join"),
                Some(&second_parent),
            ),
        );
        let misplaced = heap_future(|| ordinary_realm::source_request(&pool, misplaced)).await;
        assert!(matches!(
            commit_request(&uow, &misplaced).await.unwrap_err(),
            PersistenceError::SchemaViolation(_)
        ));
        // Only an explicit leave then a new join bound to the new revision
        // restores the Circle.
        let circle_leave = circle_request(
            &circle_head,
            &circle,
            &alice,
            circle_membership(&circle, &alice, "leave", json!("join"), None),
        );
        let circle_leave = heap_future(|| ordinary_realm::source_request(&pool, circle_leave)).await;
        commit_request(&uow, &circle_leave).await.unwrap();
        let circle_rejoin = circle_request(
            &circle_leave.authority_commit,
            &circle,
            &alice,
            circle_membership(
                &circle,
                &alice,
                "join",
                json!("leave"),
                Some(&second_parent),
            ),
        );
        let circle_rejoin = heap_future(|| ordinary_realm::source_request(&pool, circle_rejoin)).await;
        commit_request(&uow, &circle_rejoin).await.unwrap();
        let restored = circle_member(&pool, &circle, &alice).await;
        assert!(restored.effective);
        assert_eq!(restored.value["parent_membership_revision"], second_parent);
        // Even all-history policy cannot authorize a historical Circle cut whose
        // join belongs to the previous parent Realm join instance.
        assert!(matches!(
            store
                .mls_member_group_state_material_read(
                    &material_request,
                    &ordinary_realm::station(),
                    None
                )
                .await
                .unwrap(),
            coland_storage::MlsMemberGroupStateMaterialRead::NotFound
        ));
        assert!(matches!(
            store
                .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
                .await
                .unwrap(),
            coland_storage::MlsRosterAuthorityRead::NotFound
        ));
        assert!(circle_scan_authorized(&store, &stream, &alice).await);

        // Parent ban invalidates exactly like leave.
        let ban = realm_membership(
            &rejoin.authority_commit,
            &creator,
            &alice,
            "ban",
            "parent ban",
        );
        let ban = heap_future(|| ordinary_realm::source_request(&pool, ban)).await;
        commit_request(&uow, &ban).await.unwrap();
        let after_ban = circle_member(&pool, &circle, &alice).await;
        assert!(!after_ban.effective);
        assert_eq!(after_ban.value, restored.value);
        assert_eq!(
            circle_stream_commits(&pool, &stream).await,
            if activated { 6 } else { 5 }
        );
        assert!(!circle_scan_authorized(&store, &stream, &alice).await);
        assert!(matches!(
            store
                .mls_member_group_state_material_read(
                    &material_request,
                    &ordinary_realm::station(),
                    None
                )
                .await
                .unwrap(),
            coland_storage::MlsMemberGroupStateMaterialRead::NotFound
        ));
        assert!(matches!(
            store
                .mls_roster_authority_read(&roster_request, &ordinary_realm::station(), None)
                .await
                .unwrap(),
            coland_storage::MlsRosterAuthorityRead::NotFound
        ));
    }).await;
}
