#[path = "support/historical_human.rs"]
mod historical_human;

use arkret_wire::{ActorId, CommitStreamRef, EventKind};
use coland_storage::{AuthorityCommitStore, AuthorityCommitTransaction, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};
use historical_human::ordinary_realm;

fn membership(
    previous: &AuthorityCommitTransaction,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
    state: &str,
    expected: Option<&str>,
    parent: Option<serde_json::Value>,
) -> coland_storage::EventCommitRequest {
    let scope = arkret_wire::ScopeRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    let event = ordinary_realm::event_for_actor(
        EventKind::CircleMemberState,
        scope,
        actor.clone(),
        {
            let mut payload = serde_json::json!({"circle_id":circle,"member_id":actor,"membership":state,"expected_membership":expected});
            if let Some(parent) = parent {
                payload["parent_membership_revision"] = parent;
            }
            payload
        },
        previous.commit.committed_at,
    );
    let mut request =
        ordinary_realm::request_for_event(previous, event, previous.commit.committed_at);
    let stream = CommitStreamRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    if previous.commit.stream_ref != stream {
        request.authority_commit.commit.stream_position = 0;
        request.authority_commit.commit.previous_commit_ref = None;
    }
    request.authority_commit.commit.stream_ref = stream;
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

#[tokio::test]
async fn durable_circle_directory_and_member_details_follow_accepted_current() {
    Box::pin(check_circle_convenience("realm_members")).await;
    Box::pin(check_circle_convenience("members")).await;
    Box::pin(check_remote_snapshot_without_create_history(
        "realm_members",
    ))
    .await;
    Box::pin(check_remote_snapshot_without_create_history("members")).await;
}

async fn check_circle_convenience(visibility: &str) {
    use arkret_models_collaboration::governance::circle::{CircleMembership, CircleReadView};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let did = ordinary_realm::human_profile::station_did(&ordinary_realm::station());
    let fixture = historical_human::HumanFixture::new(&pool, did).await;
    ordinary_realm::human_profile::register_fixture_signer(
        &fixture.pcr.history.account,
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    fixture.admit(&pool).await;
    let unit = fixture.unit;
    let head = unit.transactions.last().unwrap();
    let realm = head.event.realm_id.clone();
    let at = head.commit.committed_at;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let short = "Durable";
    let create = ordinary_realm::next_request_for_actor(
        head,
        EventKind::CircleCreate,
        actor.clone(),
        serde_json::json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,"title":short,
            "display":{"short_name":short,"color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":visibility,"join_rule":"public","history_access":"since_join","state":"active",
            "created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    let create = Box::pin(ordinary_realm::source_request(&pool, create)).await;
    uow.commit_event(create.clone()).await.unwrap();
    let id = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let before = store.circle_view_for_actor(&id, &actor).await.unwrap();
    let listed = store.circle_views_for_actor(&realm, &actor).await.unwrap();
    assert!(
        before.is_none(),
        "Realm membership and Circle creation confer no full CircleView access ({visibility})"
    );
    assert!(
        listed.is_empty(),
        "the full-view list must not leak title or creator to non-members ({visibility})"
    );
    let before_read = store.circle_read_for_actor(&id, &actor).await.unwrap();
    let before_list = store.circle_reads_for_actor(&realm, &actor).await.unwrap();
    if visibility == "realm_members" {
        let CircleReadView::Preview(preview) = before_read.unwrap() else {
            panic!("Realm member must see closed preview before joining");
        };
        assert_eq!(before_list.len(), 1);
        assert_eq!(
            serde_json::to_value(&preview)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            7
        );
        assert_eq!(
            serde_json::to_value(&preview.display)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            serde_json::to_value(preview.member_count_bucket).unwrap(),
            "0"
        );
        assert_eq!(preview.opaque_commitment.len(), 64);
        assert!(
            preview
                .opaque_commitment
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    } else {
        assert!(before_read.is_none());
        assert!(before_list.is_empty());
    }
    let parent = ordinary_realm::parent_membership_revision(&database.pool(), &realm, &actor).await;
    let join = membership(
        &create.authority_commit,
        &id,
        &actor,
        "join",
        None,
        Some(parent),
    );
    let join = Box::pin(ordinary_realm::source_request(&pool, join)).await;
    uow.commit_event(join.clone()).await.unwrap();
    let joined = store
        .circle_view_for_actor(&id, &actor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.viewer_membership, Some(CircleMembership::Join));
    assert_eq!(joined.member_ids, vec![actor.clone()]);
    check_native_current_requires_create_history(&pool, &store, &id, &actor).await;
    assert!(matches!(
        store.circle_read_for_actor(&id, &actor).await.unwrap(),
        Some(CircleReadView::Full(_))
    ));
    assert_eq!(
        store
            .circle_views_for_actor(&realm, &actor)
            .await
            .unwrap()
            .len(),
        1,
        "a joined member can list the full CircleView ({visibility})"
    );
    let leave = membership(
        &join.authority_commit,
        &id,
        &actor,
        "leave",
        Some("join"),
        None,
    );
    let leave = Box::pin(ordinary_realm::source_request(&pool, leave)).await;
    uow.commit_event(leave).await.unwrap();
    let ended = store.circle_view_for_actor(&id, &actor).await.unwrap();
    assert!(
        ended.is_none(),
        "leaving closes the full-view read ({visibility})"
    );
    assert_eq!(
        store
            .circle_read_for_actor(&id, &actor)
            .await
            .unwrap()
            .is_some(),
        visibility == "realm_members"
    );
    assert!(
        store
            .circle_views_for_actor(&realm, &actor)
            .await
            .unwrap()
            .is_empty()
    );
}

async fn check_native_current_requires_create_history(
    pool: &coland_storage_postgres::PgPool,
    store: &PgAuthorityCommitStore,
    id: &arkret_wire::CircleId,
    actor: &ActorId,
) {
    use diesel::sql_types::{BigInt, Text};
    use diesel_async::RunQueryDsl;

    let mut conn = pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct CoveringEvent {
        #[diesel(sql_type=BigInt)]
        event_pk: i64,
    }
    let covering = diesel::sql_query("SELECT c.event_pk FROM realm_commits c JOIN circle_current_states r ON r.current_commit_id=c.commit_id WHERE r.circle_id=$1")
        .bind::<Text,_>(id.as_str()).get_result::<CoveringEvent>(&mut *conn).await.unwrap();
    // A retained continuity Commit carries no readable producer Event.
    diesel::sql_query("UPDATE realm_commits SET event_pk=NULL WHERE commit_id=(SELECT current_commit_id FROM circle_current_states WHERE circle_id=$1)")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
    assert!(store.circle_view_for_actor(id, actor).await.is_err());
    diesel::sql_query("UPDATE realm_commits c SET event_pk=$2 FROM circle_current_states r WHERE r.circle_id=$1 AND c.commit_id=r.current_commit_id")
        .bind::<Text,_>(id.as_str()).bind::<BigInt,_>(covering.event_pk).execute(&mut *conn).await.unwrap();
}

/// A foreign current is materialized from the governor's actual qualified
/// snapshot. The member never receives the earlier CircleCreate original.
async fn check_remote_snapshot_without_create_history(visibility: &str) {
    use arkret_models_collaboration::governance::circle::CircleMembership;
    use diesel_async::RunQueryDsl;

    let mut origin_config = coland_test_support::app_config();
    origin_config.public_base_url = "https://circle-convenience-member.example".into();
    origin_config.notary_signing_key_seed = Some([83; 32]);
    let (origin_state, member_pool) = coland_test_support::app_state_with_pool(origin_config);
    let member = Box::pin(historical_human::HumanFixture::new(
        &member_pool,
        origin_state.service_did(),
    ))
    .await;
    register_human_signer(&member);

    let mut governor_config = coland_test_support::app_config();
    governor_config.public_base_url = "https://circle-convenience-governor.example".into();
    governor_config.notary_signing_key_seed = Some([83; 32]);
    let (governor_state, governor_pool) = coland_test_support::app_state_with_pool(governor_config);
    let governor = Box::pin(historical_human::HumanFixture::new(
        &governor_pool,
        governor_state.service_did(),
    ))
    .await;
    register_human_signer(&governor);
    Box::pin(governor.admit(&governor_pool)).await;
    let unit = &governor.unit;
    let last = unit.transactions.last().unwrap();
    let realm = last.event.realm_id.clone();
    let actor = ActorId::account(member.pcr.history.account.clone());
    let governor_store = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let member_store = PgAuthorityCommitStore {
        pool: member_pool.clone(),
    };
    let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    let at = last.commit.committed_at;
    let create = ordinary_realm::next_request_for_actor(
        last,
        EventKind::CircleCreate,
        last.event.actor_id.clone(),
        serde_json::json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
            "title":"Snapshot circle","display":{"short_name":"Snapshot","color_token":"blue",
                "symbol":{"glyph":"lock"}},"directory_visibility":visibility,
            "join_rule":"public","history_access":"since_join","state":"active",
            "created_by":last.event.actor_id,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    let create = Box::pin(ordinary_realm::source_request(&governor_pool, create)).await;
    Box::pin(uow.commit_event(create.clone())).await.unwrap();
    let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);

    let realm_join = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::MemberState,
        actor.clone(),
        serde_json::json!({"realm_id":realm,"member_id":actor,"membership":"join"}),
        at,
    );
    let realm_join = Box::pin(forwarded_member_request(
        &origin_state,
        &member_pool,
        &governor_state.service_did(),
        &governor.pcr.history.account.station_id,
        realm_join,
    ))
    .await;
    Box::pin(uow.commit_event(realm_join.clone()))
        .await
        .unwrap();
    let realm_opening = opening_replica(unit, &realm_join, &member.pcr.history.account);
    Box::pin(member_store.install_committed_replica(&realm_opening))
        .await
        .unwrap();
    let realm_anchor = Box::pin(qualified_member_snapshot(
        &governor_store,
        &governor_state,
        &realm_join,
        &member.pcr.history.account,
    ))
    .await;
    Box::pin(member_store.install_replica_anchor(&realm_anchor))
        .await
        .unwrap();

    // Public Circle entry still needs the caller's own, exactly scoped action
    // (circle.md section 9). Parent Realm membership alone is not that grant.
    #[derive(diesel::QueryableByName)]
    struct RootRef {
        #[diesel(sql_type = diesel::sql_types::Text)]
        authority_event_ref: String,
    }
    let mut conn = governor_pool.get().await.unwrap();
    let root = diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_states WHERE realm_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(realm.as_str())
    .get_result::<RootRef>(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let mut grant = ordinary_realm::next_request_for_actor(
        &realm_join.authority_commit,
        EventKind::CapabilityGrant,
        last.event.actor_id.clone(),
        serde_json::json!({"grant":{
            "schema":"ak.schema.capability.v1","realm_id":realm,
            "issuer_id":last.event.actor_id,"subject":actor,
            "actions":["ak.circle.member.add"],
            "resources":[{"kind":"circle","realm_id":realm,"circle_id":circle}],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,
                "authority_event_ref":root.authority_event_ref,
                "authority_generation":last.expected_authority.generation.to_string()}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    grant.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        grant.authority_commit.event.clone(),
    ));
    let grant = Box::pin(ordinary_realm::source_request(&governor_pool, grant)).await;
    Box::pin(uow.commit_event(grant)).await.unwrap();

    let parent = Box::pin(ordinary_realm::parent_membership_revision(
        &governor_pool,
        &realm,
        &actor,
    ))
    .await;
    let circle_join = membership(
        &create.authority_commit,
        &circle,
        &actor,
        "join",
        None,
        Some(parent),
    );
    let circle_join = Box::pin(forwarded_member_request(
        &origin_state,
        &member_pool,
        &governor_state.service_did(),
        &governor.pcr.history.account.station_id,
        circle_join,
    ))
    .await;
    Box::pin(uow.commit_event(circle_join.clone()))
        .await
        .unwrap();
    let circle_opening = opening_replica(unit, &circle_join, &member.pcr.history.account);
    Box::pin(member_store.install_committed_replica(&circle_opening))
        .await
        .unwrap();
    let full_anchor = Box::pin(qualified_member_snapshot(
        &governor_store,
        &governor_state,
        &realm_join,
        &member.pcr.history.account,
    ))
    .await;
    Box::pin(member_store.install_replica_anchor(&full_anchor))
        .await
        .unwrap();

    assert!(
        member_store
            .committed_event(&create.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none(),
        "the real remote snapshot must not import the historical CircleCreate original"
    );
    let view = member_store
        .circle_view_for_actor(&circle, &actor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.viewer_membership, Some(CircleMembership::Join));
    assert_eq!(view.member_ids, vec![actor.clone()]);
    assert_eq!(
        member_store
            .circle_views_for_actor(&realm, &actor)
            .await
            .unwrap()
            .len(),
        1
    );
    check_remote_snapshot_tampering(&member_pool, &member_store, &circle, &actor).await;
}

fn register_human_signer(fixture: &historical_human::HumanFixture) {
    ordinary_realm::human_profile::register_fixture_signer(
        &fixture.pcr.history.account,
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
}

// This is the same real origin-produced, governor-bound evidence path used by
// forwarded_producer_device_evidence and the foreign space-parent snapshot case.
async fn forwarded_member_request(
    origin: &coland_http::state::AppState,
    origin_pool: &coland_storage_postgres::PgPool,
    governor_did: &arkret_wire::Did,
    governor_station: &arkret_wire::DidCoreId,
    request: coland_storage::EventCommitRequest,
) -> coland_storage::EventCommitRequest {
    let mut request = Box::pin(ordinary_realm::source_request(origin_pool, request)).await;
    let evidence = Box::pin(coland_http::test_fresh_producer_device_evidence(
        origin,
        &request.authority_commit.event,
        governor_station,
    ))
    .await
    .unwrap()
    .unwrap();
    let core = &evidence.device_projection_attestation.attestation;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
        &evidence,
        &request.authority_commit.event,
        &request.authority_commit.event.actor_id.as_account_id().unwrap().station_id,
        governor_station,
        &core.event_authorization.forward_body_digest,
        arkret_canonical::DigestSuite::Sha256,
        core.attested_at,
    )
    .unwrap()
    .into_fact();
    request.authority_commit.producer_signer_fact = Some(fact.clone().into());
    request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    request.authority_commit.commit.committed_at = core.attested_at;
    request.self_producer_guard = None;
    request.forwarded_producer_evidence =
        Some(coland_storage::ForwardedProducerDeviceEvidence::new(evidence, fact).unwrap());
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    historical_human::seal_commit(&mut request.authority_commit.commit, governor_did);
    request
}

fn opening_replica(
    unit: &coland_storage::OrdinaryRealmBootstrapCommitUnit,
    request: &coland_storage::EventCommitRequest,
    account: &arkret_wire::AccountId,
) -> coland_storage::CommittedReplica {
    coland_storage::CommittedReplica {
        local_service_id: account.station_id.clone(),
        authority: unit.transactions[0].expected_authority.clone(),
        historical_commit: None,
        event: request.authority_commit.event.clone(),
        commit: request.authority_commit.commit.clone(),
        producer_signer_fact: request.authority_commit.producer_signer_fact.clone(),
        genesis_event_ref: None,
        role: coland_storage::CommittedReplicaRole::OpeningJoin {
            member_account_id: account.clone(),
        },
        received_at: request.authority_commit.commit.committed_at,
        welcomes: Vec::new(),
    }
}

async fn qualified_member_snapshot(
    governor: &PgAuthorityCommitStore,
    state: &coland_http::state::AppState,
    realm_join: &coland_storage::EventCommitRequest,
    account: &arkret_wire::AccountId,
) -> coland_storage::ReplicaAnchorInstall {
    let commit = &realm_join.authority_commit.commit;
    let material = Box::pin(governor.member_station_bootstrap_material(
        &commit.realm_id,
        account,
        &commit.commit_id,
    ))
    .await
    .unwrap()
    .unwrap();
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        state.service_verification_method("notary-key").unwrap(),
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
        chrono::Utc::now(),
    )
    .unwrap();
    let realm_head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == commit.stream_ref)
        .unwrap()
        .clone();
    coland_storage::ReplicaAnchorInstall {
        realm_id: commit.realm_id.clone(),
        join_commit_id: commit.commit_id.clone(),
        governance_generation: snapshot.governance_generation,
        snapshot_head: realm_head,
        visible_stream_heads: snapshot.visible_stream_heads.clone(),
        current_state_entries: snapshot.current_state_entries.clone(),
        verified_snapshot: snapshot,
    }
}

async fn check_remote_snapshot_tampering(
    pool: &coland_storage_postgres::PgPool,
    store: &PgAuthorityCommitStore,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
) {
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::RunQueryDsl;

    #[derive(diesel::QueryableByName)]
    struct OriginalValue {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let original = diesel::sql_query("SELECT value FROM replica_authorization_rows WHERE selector=jsonb_build_object('kind','circle','circle_id',$1::text)")
        .bind::<Text, _>(circle.as_str()).get_result::<OriginalValue>(&mut *conn).await.unwrap();
    // The real qualified row no longer agrees with the materialized value.
    diesel::sql_query("UPDATE replica_authorization_rows SET value=jsonb_set(value,'{title}','\"different current\"') WHERE selector=jsonb_build_object('kind','circle','circle_id',$1::text)")
        .bind::<Text, _>(circle.as_str()).execute(&mut *conn).await.unwrap();
    assert!(store.circle_view_for_actor(circle, actor).await.is_err());
    // Restore only the exact archived value, never manufacture row/cut proof.
    diesel::sql_query("UPDATE replica_authorization_rows SET value=$2 WHERE selector=jsonb_build_object('kind','circle','circle_id',$1::text)")
        .bind::<Text, _>(circle.as_str()).bind::<Jsonb, _>(original.value).execute(&mut *conn).await.unwrap();
    assert!(
        store
            .circle_view_for_actor(circle, actor)
            .await
            .unwrap()
            .is_some()
    );
    // Equal positions from a different Commit are not the same verified cut.
    // Preserve the base/end CHECK when this real snapshot seeded both at H;
    // the row's actual observation still names the original Commit at H.
    assert_eq!(diesel::sql_query("UPDATE replica_authorization_cuts h SET head_commit_id='different-commit',circle_effect_base_commit_id=CASE WHEN h.circle_effect_base_stream_position=h.head_stream_position THEN 'different-commit' ELSE h.circle_effect_base_commit_id END FROM circle_current_states r WHERE r.circle_id=$1 AND h.realm_id=r.realm_id AND h.source_stream_ref=r.source_stream_ref")
        .bind::<Text, _>(circle.as_str()).execute(&mut *conn).await.unwrap(), 1);
    assert!(store.circle_view_for_actor(circle, actor).await.is_err());
}
