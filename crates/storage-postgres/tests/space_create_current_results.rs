//! `ak.space.create` writes all three registered current families atomically.
//! The HTTP guarded-unit tests separately prove capability denial before
//! entering this UoW; this suite exercises its PG cut, parent basis and CAS.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::next_request;
use serde_json::{Value, json};
use soland_storage::{AuthorityCommitStore, EventCommitUnitOfWork, EventProjectionStoreRegistry};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};

fn founder() -> arkret_wire::DidCoreId {
    ordinary_realm::human_profile::account(&ordinary_realm::station(), "ordinary-founder")
        .principal_id
}

async fn human_bootstrap(
    pool: &PgPool,
    seed: &str,
) -> soland_storage::OrdinaryRealmBootstrapCommitUnit {
    let account = Box::pin(ordinary_realm::human_profile::admit(
        pool,
        &ordinary_realm::station(),
        "ordinary-founder",
    ))
    .await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        seed,
        &account,
        &ordinary_realm::human_profile::station_did(&ordinary_realm::station()),
    );
    Box::pin(ordinary_realm::source_bootstrap(pool, unit)).await
}

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Current {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn current(pool: &PgPool, table: &str, space_id: &arkret_wire::SpaceId) -> Current {
    let mut conn = pool.get().await.unwrap();
    let query = format!(
        "SELECT current_commit_id,current_stream_position,value FROM {table} WHERE space_id=$1"
    );
    diesel::sql_query(query)
        .bind::<Text, _>(space_id.as_str())
        .get_result(&mut conn)
        .await
        .unwrap()
}

async fn count(pool: &PgPool, table: &str, realm_id: &arkret_wire::RealmId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    let query = format!("SELECT COUNT(*) AS count FROM {table} WHERE realm_id=$1");
    let row: Count = diesel::sql_query(query)
        .bind::<Text, _>(realm_id.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
    row.count
}

async fn cut_counts(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> [i64; 5] {
    let mut counts = [0; 5];
    for (index, table) in [
        "canonical_events",
        "realm_commits",
        "space_current_results",
        "space_parent_current_results",
        "space_child_scope_policy_current_results",
    ]
    .iter()
    .enumerate()
    {
        counts[index] = count(pool, table, realm_id).await;
    }
    counts
}

fn payload(
    realm_id: &arkret_wire::RealmId,
    actor_id: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
    kind: &str,
    title: &str,
    parent_id: Option<&arkret_wire::SpaceId>,
    policy: Option<Value>,
) -> Value {
    let mut object = json!({
        "schema": "ak.schema.space.v1",
        "realm_id": realm_id,
        "kind": kind,
        "title": title,
        "created_by": actor_id,
        "created_at": arkret_canonical::format_timestamp_canonical(at),
    });
    if let Some(parent_id) = parent_id {
        object["parent_space_id"] = json!(parent_id);
    }
    if let Some(policy) = policy {
        object["child_scope_policy"] = policy;
    }
    json!({"object": object})
}

#[tokio::test]
async fn space_lifecycle_narrow_allow_and_space_deny_override_realm_allow_at_the_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    for denied in [false, true] {
        let unit = human_bootstrap(
            &pool,
            if denied {
                "space-lifecycle-deny"
            } else {
                "space-lifecycle-allow"
            },
        )
        .await;
        PgAuthorityCommitStore { pool: pool.clone() }
            .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
            .await
            .unwrap();
        let mut head = unit.transactions.last().unwrap().clone();
        let realm = head.event.realm_id.clone();
        let owner = head.event.actor_id.clone();
        let at = head.commit.committed_at;
        let account = ordinary_realm::human_profile::admit(
            &pool,
            &ordinary_realm::station(),
            if denied {
                "space-lifecycle-denied-member"
            } else {
                "space-lifecycle-allowed-member"
            },
        )
        .await;
        let member = arkret_wire::ActorId::account(account);
        let join = ordinary_realm::next_human_request_for_actor(
            &head,
            arkret_wire::EventKind::MemberState,
            member.clone(),
            json!({"realm_id":realm,"member_id":member,"membership":"join","reason":"Space lifecycle narrow grant fixture"}),
            at,
        );
        let join = ordinary_realm::source_request(&pool, join).await;
        uow.commit_event(join.clone()).await.unwrap();
        head = join.authority_commit;
        let create = ordinary_realm::next_human_request_for_actor(
            &head,
            arkret_wire::EventKind::SpaceCreate,
            owner.clone(),
            payload(&realm, &owner, at, "list", "Lifecycle list", None, None),
            at,
        );
        let create = ordinary_realm::source_request(&pool, create).await;
        let id = arkret_wire::SpaceId::from_event_id(&create.authority_commit.event.event_id);
        uow.commit_event(create.clone()).await.unwrap();
        head = create.authority_commit;
        if denied {
            let archive = ordinary_realm::next_human_request_for_actor(
                &head,
                arkret_wire::EventKind::SpaceArchive,
                owner.clone(),
                json!({"space_id":id}),
                at,
            );
            let archive = ordinary_realm::source_request(&pool, archive).await;
            uow.commit_event(archive.clone()).await.unwrap();
            head = archive.authority_commit;
        }
        let narrow = arkret_wire::WireResourceSelector::space(realm.clone(), id.clone());
        let mut grants = vec![(json!([narrow]), None)];
        if denied {
            grants = vec![
                (
                    json!([arkret_wire::WireResourceSelector::realm(realm.clone())]),
                    None,
                ),
                (
                    json!([arkret_wire::WireResourceSelector::space(
                        realm.clone(),
                        id.clone()
                    )]),
                    Some(
                        json!([{"constraint_kind":"scope_limitation","effect":"deny","denied_space_ids":[id]}]),
                    ),
                ),
            ];
        }
        for (resources, constraints) in grants {
            let mut body = json!({"grant":{
                "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":owner,"subject":member,
                "actions":["ak.space.archive","ak.space.restore","ak.space.tombstone"],"resources":resources,
                "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,
                    "authority_event_ref":unit.transactions[0].event.event_id,"authority_generation":0}],
                "issued_at":arkret_canonical::format_timestamp_canonical(at)
            }});
            if let Some(constraints) = constraints {
                body["grant"]["constraints"] = constraints;
            }
            let grant = ordinary_realm::next_human_request_for_actor(
                &head,
                arkret_wire::EventKind::CapabilityGrant,
                owner.clone(),
                body,
                at,
            );
            let grant = ordinary_realm::source_request(&pool, grant).await;
            uow.commit_event(grant.clone()).await.unwrap();
            head = grant.authority_commit;
        }
        for (kind, state) in [
            (arkret_wire::EventKind::SpaceArchive, "archived"),
            (arkret_wire::EventKind::SpaceRestore, "active"),
            (arkret_wire::EventKind::SpaceTombstone, "tombstoned"),
        ] {
            let request = ordinary_realm::next_human_request_for_actor(
                &head,
                kind.clone(),
                member.clone(),
                json!({"space_id":id}),
                at,
            );
            let request = ordinary_realm::source_request(&pool, request).await;
            let before = space_write_footprint(&pool, &realm).await;
            if denied {
                assert_eq!(
                    uow.commit_event(request).await.unwrap_err().conflict_code(),
                    Some(soland_storage::ConflictCode::CapabilityDenied),
                    "{kind}"
                );
                assert_eq!(space_write_footprint(&pool, &realm).await, before, "{kind}");
                assert_eq!(
                    current(&pool, "space_current_results", &id).await.value["state"],
                    "archived"
                );
            } else {
                assert!(
                    uow.commit_event(request.clone())
                        .await
                        .unwrap()
                        .event_inserted
                );
                let metadata = current(&pool, "space_current_results", &id).await;
                assert_eq!(metadata.value["state"], state);
                assert_eq!(
                    metadata.current_commit_id,
                    request.authority_commit.commit.commit_id.as_str()
                );
                assert_eq!(
                    metadata.current_stream_position,
                    request.authority_commit.commit.stream_position as i64
                );
                let accepted = space_write_footprint(&pool, &realm).await;
                assert!(
                    !uow.commit_event(request.clone())
                        .await
                        .unwrap()
                        .event_inserted
                );
                assert_eq!(
                    space_write_footprint(&pool, &realm).await,
                    accepted,
                    "{kind}"
                );
                head = request.authority_commit;
            }
        }
    }
}

async fn space_write_footprint(pool: &PgPool, realm: &arkret_wire::RealmId) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events WHERE realm_id=$1),'commits',(SELECT count(*) FROM realm_commits WHERE realm_id=$1),'space',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY space_id),'[]'::jsonb) FROM space_current_results s WHERE realm_id=$1),'parent',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY space_id),'[]'::jsonb) FROM space_parent_current_results s WHERE realm_id=$1),'policy',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY space_id),'[]'::jsonb) FROM space_child_scope_policy_current_results s WHERE realm_id=$1),'outbox',(SELECT count(*) FROM event_federation_outbox o JOIN canonical_events e ON e.pk=o.event_pk WHERE e.realm_id=$1)) AS value")
        .bind::<Text,_>(realm.as_str()).get_result::<Row>(&mut conn).await.unwrap().value
}

#[tokio::test]
async fn space_parent_narrow_space_allow_and_deny_use_the_child_resource_at_the_cut() {
    Box::pin(space_parent_narrow_resource_cases()).await;
}

async fn space_parent_narrow_resource_cases() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let opened = Box::pin(ordinary_realm::open_human_discussion(
        &pool,
        "space-parent-narrow-grants",
    ))
    .await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut head = opened.head.authority_commit;
    let realm = head.event.realm_id.clone();
    let owner = head.event.actor_id.clone();
    let at = head.commit.committed_at;
    let account = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "space-parent-member",
    ))
    .await;
    let member = arkret_wire::ActorId::account(account);
    let join = ordinary_realm::next_human_request_for_actor(
        &head,
        arkret_wire::EventKind::MemberState,
        member.clone(),
        json!({"realm_id":realm,"member_id":member,"membership":"join","reason":"narrow Space capability fixture"}),
        at,
    );
    let join = Box::pin(ordinary_realm::source_request(&pool, join)).await;
    Box::pin(uow.commit_event(join.clone())).await.unwrap();
    head = join.authority_commit;
    let mut ids = Vec::new();
    for kind in ["board", "list"] {
        let create = ordinary_realm::next_human_request_for_actor(
            &head,
            arkret_wire::EventKind::SpaceCreate,
            owner.clone(),
            payload(&realm, &owner, at, kind, kind, None, None),
            at,
        );
        let create = Box::pin(ordinary_realm::source_request(&pool, create)).await;
        ids.push(arkret_wire::SpaceId::from_event_id(
            &create.authority_commit.event.event_id,
        ));
        Box::pin(uow.commit_event(create.clone())).await.unwrap();
        head = create.authority_commit;
    }
    let board = &ids[0];
    let child = &ids[1];
    let grant_body = |resources: Value, constraints: Value| {
        json!({"grant":{
            "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":owner,"subject":member,
            "actions":["ak.space.parent"],"resources":resources,"constraints":constraints,
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,
                "authority_event_ref":opened.unit.transactions[0].event.event_id,"authority_generation":0}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)
        }})
    };
    let mut narrow = grant_body(
        json!([arkret_wire::WireResourceSelector::space(
            realm.clone(),
            child.clone()
        )]),
        json!([]),
    );
    narrow["grant"]
        .as_object_mut()
        .unwrap()
        .remove("constraints");
    let grant = ordinary_realm::next_human_request_for_actor(
        &head,
        arkret_wire::EventKind::CapabilityGrant,
        owner.clone(),
        narrow,
        at,
    );
    let grant = Box::pin(ordinary_realm::source_request(&pool, grant)).await;
    Box::pin(uow.commit_event(grant.clone())).await.unwrap();
    head = grant.authority_commit;
    let attach = ordinary_realm::next_human_request_for_actor(
        &head,
        arkret_wire::EventKind::SpaceParent,
        member.clone(),
        json!({"space_id":child,"parent_space_id":board,"expected_parent_space_id":null}),
        at,
    );
    let attach = Box::pin(ordinary_realm::source_request(&pool, attach)).await;
    Box::pin(uow.commit_event(attach.clone())).await.unwrap();
    head = attach.authority_commit;
    let accepted = current(&pool, "space_parent_current_results", child).await;
    assert_eq!(accepted.value, json!({"parent_space_id":board}));
    let unrelated = ordinary_realm::next_human_request_for_actor(
        &head,
        arkret_wire::EventKind::SpaceParent,
        member.clone(),
        json!({"space_id":board,"parent_space_id":null,"expected_parent_space_id":null}),
        at,
    );
    let unrelated = Box::pin(ordinary_realm::source_request(&pool, unrelated)).await;
    let before = cut_counts(&pool, &realm).await;
    assert_eq!(
        Box::pin(uow.commit_event(unrelated))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::CapabilityDenied)
    );
    assert_eq!(cut_counts(&pool, &realm).await, before);
    assert_eq!(
        current(&pool, "space_parent_current_results", child).await,
        accepted
    );
    let mut broad = grant_body(
        json!([arkret_wire::WireResourceSelector::realm(realm.clone())]),
        json!([]),
    );
    broad["grant"]
        .as_object_mut()
        .unwrap()
        .remove("constraints");
    for body in [
        broad,
        grant_body(
            json!([arkret_wire::WireResourceSelector::space(
                realm.clone(),
                child.clone()
            )]),
            json!([{"constraint_kind":"scope_limitation","effect":"deny","denied_space_ids":[child]}]),
        ),
    ] {
        let grant = ordinary_realm::next_human_request_for_actor(
            &head,
            arkret_wire::EventKind::CapabilityGrant,
            owner.clone(),
            body,
            at,
        );
        let grant = Box::pin(ordinary_realm::source_request(&pool, grant)).await;
        Box::pin(uow.commit_event(grant.clone())).await.unwrap();
        head = grant.authority_commit;
    }
    let denied = ordinary_realm::next_human_request_for_actor(
        &head,
        arkret_wire::EventKind::SpaceParent,
        member,
        json!({"space_id":child,"parent_space_id":null,"expected_parent_space_id":board}),
        at,
    );
    let denied = Box::pin(ordinary_realm::source_request(&pool, denied)).await;
    let before = cut_counts(&pool, &realm).await;
    let metadata = current(&pool, "space_current_results", child).await;
    let policy = current(&pool, "space_child_scope_policy_current_results", child).await;
    assert_eq!(
        Box::pin(uow.commit_event(denied))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::CapabilityDenied)
    );
    assert_eq!(cut_counts(&pool, &realm).await, before);
    assert_eq!(
        current(&pool, "space_parent_current_results", child).await,
        accepted
    );
    assert_eq!(
        current(&pool, "space_current_results", child).await,
        metadata
    );
    assert_eq!(
        current(&pool, "space_child_scope_policy_current_results", child).await,
        policy
    );
}

#[tokio::test]
async fn space_parent_attach_detach_cas_and_refusals_preserve_the_durable_cut() {
    Box::pin(space_parent_attach_detach_cases()).await;
}

async fn space_parent_attach_detach_cases() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = Box::pin(human_bootstrap(&pool, "space-parent-authority")).await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let realm = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let root = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm,
            &last.event.actor_id,
            at,
            "board",
            "Board",
            None,
            None,
        ),
        at,
    );
    let root = ordinary_realm::source_request(&pool, root).await;
    let root_id = arkret_wire::SpaceId::from_event_id(&root.authority_commit.event.event_id);
    uow.commit_event(root.clone()).await.unwrap();
    let child = next_request(
        &root.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(&realm, &last.event.actor_id, at, "list", "List", None, None),
        at,
    );
    let child = ordinary_realm::source_request(&pool, child).await;
    let child_id = arkret_wire::SpaceId::from_event_id(&child.authority_commit.event.event_id);
    uow.commit_event(child.clone()).await.unwrap();
    let metadata = current(&pool, "space_current_results", &child_id).await;
    let policy = current(&pool, "space_child_scope_policy_current_results", &child_id).await;
    let attached = next_request(
        &child.authority_commit,
        arkret_wire::EventKind::SpaceParent,
        &founder(),
        json!({"space_id":child_id,"parent_space_id":root_id,"expected_parent_space_id":null}),
        at,
    );
    let attached = ordinary_realm::source_request(&pool, attached).await;
    assert!(
        uow.commit_event(attached.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let parent = current(&pool, "space_parent_current_results", &child_id).await;
    assert_eq!(parent.value, json!({"parent_space_id":root_id}));
    assert_eq!(
        parent.current_commit_id,
        attached.authority_commit.commit.commit_id.as_str()
    );
    assert_eq!(
        parent.current_stream_position,
        attached.authority_commit.commit.stream_position as i64
    );
    assert_eq!(
        current(&pool, "space_current_results", &child_id).await,
        metadata
    );
    assert_eq!(
        current(&pool, "space_child_scope_policy_current_results", &child_id).await,
        policy
    );
    let counts = cut_counts(&pool, &realm).await;
    assert!(
        !uow.commit_event(attached.clone())
            .await
            .unwrap()
            .event_inserted
    );
    assert_eq!(cut_counts(&pool, &realm).await, counts);
    assert_eq!(
        current(&pool, "space_parent_current_results", &child_id).await,
        parent
    );

    let foreign_unit = Box::pin(human_bootstrap(&pool, "space-parent-other-realm")).await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(
            &foreign_unit,
            foreign_unit.transactions[0].commit.committed_at,
        )
        .await
        .unwrap();
    let foreign_last = foreign_unit.transactions.last().unwrap();
    let foreign = next_request(
        foreign_last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &foreign_last.event.realm_id,
            &foreign_last.event.actor_id,
            foreign_last.commit.committed_at,
            "board",
            "Other",
            None,
            None,
        ),
        foreign_last.commit.committed_at,
    );
    let foreign = ordinary_realm::source_request(&pool, foreign).await;
    let foreign_id = arkret_wire::SpaceId::from_event_id(&foreign.authority_commit.event.event_id);
    uow.commit_event(foreign).await.unwrap();
    let foreign_current = current(&pool, "space_current_results", &foreign_id).await;
    let visible_foreign = soland_storage_postgres::account_snapshot_material(
        &pool,
        &foreign_last.event.realm_id,
        &arkret_wire::AccountId::new(founder(), ordinary_realm::station()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(visible_foreign.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentRow::Value {selector: arkret_wire::CurrentSelector::Space {space_id}, revision, value, ..}
            if space_id == &foreign_id && value == &foreign_current.value
                && revision.commit_id.as_str() == foreign_current.current_commit_id
                && revision.stream_position as i64 == foreign_current.current_stream_position
    )));
    let hidden_owner = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "space-parent-hidden-owner",
    ))
    .await;
    let hidden_unit = ordinary_realm::bootstrap_unit_for_account(
        "space-parent-hidden-realm",
        &hidden_owner,
        &ordinary_realm::human_profile::station_did(&ordinary_realm::station()),
    );
    let hidden_unit = ordinary_realm::source_bootstrap(&pool, hidden_unit).await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(
            &hidden_unit,
            hidden_unit.transactions[0].commit.committed_at,
        )
        .await
        .unwrap();
    let hidden_last = hidden_unit.transactions.last().unwrap();
    let hidden = next_request(
        hidden_last,
        arkret_wire::EventKind::SpaceCreate,
        &hidden_owner.principal_id,
        payload(
            &hidden_last.event.realm_id,
            &hidden_last.event.actor_id,
            hidden_last.commit.committed_at,
            "board",
            "Hidden",
            None,
            None,
        ),
        hidden_last.commit.committed_at,
    );
    let hidden = ordinary_realm::source_request(&pool, hidden).await;
    let hidden_id = arkret_wire::SpaceId::from_event_id(&hidden.authority_commit.event.event_id);
    uow.commit_event(hidden).await.unwrap();
    let hidden_read = soland_storage_postgres::account_snapshot_material(
        &pool,
        &hidden_last.event.realm_id,
        &arkret_wire::AccountId::new(founder(), ordinary_realm::station()),
    )
    .await
    .unwrap_err();
    assert!(
        hidden_read
            .to_string()
            .contains("not a joined member with a provable readable floor"),
        "{hidden_read}"
    );
    let stranger = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "space-parent-stranger",
    ))
    .await
    .principal_id;
    for (actor, body, reason) in [
        (
            founder(),
            json!({"space_id":child_id,"parent_space_id":null,"expected_parent_space_id":null}),
            "space_parent_mismatch",
        ),
        (
            founder(),
            json!({"space_id":child_id,"parent_space_id":child_id,"expected_parent_space_id":root_id}),
            "space_parent_cycle",
        ),
        (
            founder(),
            json!({"space_id":root_id,"parent_space_id":child_id,"expected_parent_space_id":null}),
            "space_parent_cycle",
        ),
        (
            founder(),
            json!({"space_id":child_id,"parent_space_id":foreign_id,"expected_parent_space_id":root_id}),
            "space_realm_mismatch",
        ),
        (
            founder(),
            json!({"space_id":child_id,"parent_space_id":hidden_id,"expected_parent_space_id":root_id}),
            "space_parent_unreadable",
        ),
        (
            stranger,
            json!({"space_id":child_id,"parent_space_id":null,"expected_parent_space_id":root_id}),
            "capability_denied",
        ),
    ] {
        let request = next_request(
            &attached.authority_commit,
            arkret_wire::EventKind::SpaceParent,
            &actor,
            body,
            at,
        );
        let request = ordinary_realm::source_request(&pool, request).await;
        let before = cut_counts(&pool, &realm).await;
        let root_before = current(&pool, "space_parent_current_results", &root_id).await;
        let footprint_before = space_write_footprint(&pool, &realm).await;
        let error = uow.commit_event(request).await.unwrap_err();
        let expected_code = match reason {
            "space_parent_mismatch" => Some(soland_storage::ConflictCode::SpaceParentMismatch),
            "space_parent_unreadable" => Some(soland_storage::ConflictCode::SpaceParentUnreadable),
            "space_realm_mismatch" => Some(soland_storage::ConflictCode::SpaceRealmMismatch),
            "capability_denied" => Some(soland_storage::ConflictCode::CapabilityDenied),
            _ => Some(soland_storage::ConflictCode::FailedPrecondition),
        };
        assert_eq!(error.conflict_code(), expected_code, "{reason}: {error}");
        assert!(error.to_string().contains(reason), "{reason}: {error}");
        assert_eq!(space_write_footprint(&pool, &realm).await, footprint_before);
        assert_eq!(cut_counts(&pool, &realm).await, before);
        assert_eq!(
            current(&pool, "space_parent_current_results", &child_id).await,
            parent
        );
        assert_eq!(
            current(&pool, "space_parent_current_results", &root_id).await,
            root_before
        );
        assert_eq!(
            current(&pool, "space_current_results", &child_id).await,
            metadata
        );
        assert_eq!(
            current(&pool, "space_child_scope_policy_current_results", &child_id).await,
            policy
        );
    }
    let detached = next_request(
        &attached.authority_commit,
        arkret_wire::EventKind::SpaceParent,
        &founder(),
        json!({"space_id":child_id,"parent_space_id":null,"expected_parent_space_id":root_id}),
        at,
    );
    let detached = ordinary_realm::source_request(&pool, detached).await;
    assert!(
        uow.commit_event(detached.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let root_parent = current(&pool, "space_parent_current_results", &child_id).await;
    assert_eq!(root_parent.value, json!({"parent_space_id":null}));
    let before = cut_counts(&pool, &realm).await;
    assert!(!uow.commit_event(detached).await.unwrap().event_inserted);
    assert_eq!(cut_counts(&pool, &realm).await, before);
    assert_eq!(
        current(&pool, "space_parent_current_results", &child_id).await,
        root_parent
    );
}

#[tokio::test]
async fn space_create_root_and_child_have_three_sibling_results_and_exact_replay() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = human_bootstrap(&pool, "space-create-root-child").await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let realm_id = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let baseline = cut_counts(&pool, &realm_id).await;

    let root = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "board",
            "Board",
            None,
            Some(json!({"kind":"allow_any"})),
        ),
        at,
    );
    let root = ordinary_realm::source_request(&pool, root).await;
    let root_id = arkret_wire::SpaceId::from_event_id(&root.authority_commit.event.event_id);
    assert!(uow.commit_event(root.clone()).await.unwrap().event_inserted);
    let root_space = current(&pool, "space_current_results", &root_id).await;
    let root_parent = current(&pool, "space_parent_current_results", &root_id).await;
    let root_policy = current(&pool, "space_child_scope_policy_current_results", &root_id).await;
    assert_eq!(root_space.value["id"], json!(root_id));
    assert_eq!(root_space.value["state"], "active");
    assert!(root_space.value.get("parent_space_id").is_none());
    assert!(root_space.value.get("child_scope_policy").is_none());
    assert_eq!(root_parent.value, json!({"parent_space_id": null}));
    assert_eq!(root_policy.value, json!({"kind":"allow_any"}));
    for row in [&root_space, &root_parent, &root_policy] {
        assert_eq!(
            row.current_commit_id,
            root.authority_commit.commit.commit_id.as_str()
        );
        assert_eq!(
            row.current_stream_position,
            root.authority_commit.commit.stream_position as i64
        );
    }

    let child = next_request(
        &root.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "list",
            "List",
            Some(&root_id),
            None,
        ),
        at,
    );
    let child = ordinary_realm::source_request(&pool, child).await;
    let child_id = arkret_wire::SpaceId::from_event_id(&child.authority_commit.event.event_id);
    assert!(
        uow.commit_event(child.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let child_space = current(&pool, "space_current_results", &child_id).await;
    let child_parent = current(&pool, "space_parent_current_results", &child_id).await;
    let child_policy = current(&pool, "space_child_scope_policy_current_results", &child_id).await;
    assert_eq!(child_space.value["id"], json!(child_id));
    assert_eq!(child_parent.value, json!({"parent_space_id": root_id}));
    assert_eq!(child_policy.value, Value::Null);
    let current_snapshot = soland_storage_postgres::PgPersistenceStore::new(pool.clone())
        .object_current_snapshot()
        .snapshot()
        .await
        .unwrap();
    assert_eq!(current_snapshot.spaces.len(), 2);
    let root_current = current_snapshot
        .spaces
        .iter()
        .find(|space| space.id.as_ref() == Some(&root_id))
        .unwrap();
    let child_current = current_snapshot
        .spaces
        .iter()
        .find(|space| space.id.as_ref() == Some(&child_id))
        .unwrap();
    assert_eq!(root_current.title.as_deref(), Some("Board"));
    assert_eq!(child_current.parent_space_id.as_ref(), Some(&root_id));
    assert_eq!(
        cut_counts(&pool, &realm_id).await,
        [baseline[0] + 2, baseline[1] + 2, 2, 2, 2]
    );
    let before_retry = cut_counts(&pool, &realm_id).await;
    assert!(
        !uow.commit_event(child.clone())
            .await
            .unwrap()
            .event_inserted
    );
    assert_eq!(cut_counts(&pool, &realm_id).await, before_retry);
    assert_eq!(
        current(&pool, "space_current_results", &child_id).await,
        child_space
    );

    let snapshot = soland_storage_postgres::account_snapshot_material(
        &pool,
        &realm_id,
        &arkret_wire::AccountId::new(founder(), ordinary_realm::station()),
    )
    .await
    .unwrap()
    .unwrap();
    for (space_id, metadata, parent, policy) in [
        (&root_id, &root_space, &root_parent, &root_policy),
        (&child_id, &child_space, &child_parent, &child_policy),
    ] {
        for (selector, expected) in [
            (
                arkret_wire::CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                metadata,
            ),
            (
                arkret_wire::CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                parent,
            ),
            (
                arkret_wire::CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                policy,
            ),
        ] {
            assert!(snapshot.current_state_entries.iter().any(|entry| matches!(
                entry,
                arkret_wire::TypedCurrentRow::Value {
                    selector: found,
                    revision,
                    value,
                    ..
                } if found == &selector
                    && revision.commit_id.as_str() == expected.current_commit_id
                    && revision.stream_position as i64 == expected.current_stream_position
                    && value == &expected.value
            )));
        }
    }
    let (list, _) = PgAuthorityCommitStore { pool: pool.clone() }
        .object_projection_lists_for_actor(
            &realm_id,
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                founder(),
                ordinary_realm::station(),
            )),
            false,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(list.total, 2);
    let root_row = list
        .spaces
        .iter()
        .find(|row| row.space_id == root_id)
        .unwrap();
    assert_eq!(root_row.parent_space_id, None);
    let child_row = list
        .spaces
        .iter()
        .find(|row| row.space_id == child_id)
        .unwrap();
    assert_eq!(child_row.parent_space_id.as_ref(), Some(&root_id));
    Box::pin(assert_space_create_capability_denied(
        &pool,
        &child.authority_commit,
    ))
    .await;
}

async fn assert_space_create_capability_denied(
    pool: &PgPool,
    previous: &soland_storage::AuthorityCommitTransaction,
) {
    let account = Box::pin(ordinary_realm::human_profile::admit(
        pool,
        &ordinary_realm::station(),
        "space-create-nonmember",
    ))
    .await;
    let actor = arkret_wire::ActorId::account(account.clone());
    let request = next_request(
        previous,
        arkret_wire::EventKind::SpaceCreate,
        &account.principal_id,
        payload(
            &previous.event.realm_id,
            &actor,
            previous.commit.committed_at,
            "board",
            "Nonmember board",
            None,
            None,
        ),
        previous.commit.committed_at,
    );
    let request = Box::pin(ordinary_realm::source_request(pool, request)).await;
    arkret_schema::validate_event_for_submit(&request.authority_commit.event).unwrap();
    let before = space_write_footprint(pool, &previous.event.realm_id).await;
    assert_eq!(
        Box::pin(PgEventCommitUnitOfWork::new(pool.clone()).commit_event(request))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(soland_storage::ConflictCode::CapabilityDenied)
    );
    assert_eq!(
        space_write_footprint(pool, &previous.event.realm_id).await,
        before
    );
}

#[tokio::test]
async fn space_create_unknown_parent_and_stale_stream_leave_no_pg_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = human_bootstrap(&pool, "space-create-zero-write").await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let realm_id = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let missing_id = arkret_wire::SpaceId::from_event_id(&last.event.event_id);
    let intruder =
        ordinary_realm::human_profile::admit(&pool, &ordinary_realm::station(), "space-intruder")
            .await
            .principal_id;
    let intruder_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        intruder.clone(),
        ordinary_realm::station(),
    ));
    let denied = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &intruder,
        payload(
            &realm_id,
            &intruder_actor,
            at,
            "board",
            "Intruder board",
            None,
            None,
        ),
        at,
    );
    let denied = ordinary_realm::source_request(&pool, denied).await;
    let baseline = cut_counts(&pool, &realm_id).await;
    let error = uow.commit_event(denied).await.unwrap_err().to_string();
    assert!(error.contains("capability_denied"), "{error}");
    assert_eq!(cut_counts(&pool, &realm_id).await, baseline);

    let missing_parent = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "list",
            "Orphan",
            Some(&missing_id),
            None,
        ),
        at,
    );
    let missing_parent = ordinary_realm::source_request(&pool, missing_parent).await;
    let error = uow
        .commit_event(missing_parent)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("space_parent_unreadable"), "{error}");
    assert_eq!(cut_counts(&pool, &realm_id).await, baseline);

    let root = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "board",
            "Board",
            None,
            None,
        ),
        at,
    );
    let root = ordinary_realm::source_request(&pool, root).await;
    assert!(uow.commit_event(root).await.unwrap().event_inserted);
    let after = cut_counts(&pool, &realm_id).await;
    let stale = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "board",
            "Stale",
            None,
            None,
        ),
        at,
    );
    let stale = ordinary_realm::source_request(&pool, stale).await;
    assert!(uow.commit_event(stale).await.is_err());
    assert_eq!(cut_counts(&pool, &realm_id).await, after);
}

#[tokio::test]
async fn space_create_child_policy_denial_leaves_event_commit_and_all_results_untouched() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = human_bootstrap(&pool, "space-create-policy-denial").await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let realm_id = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let root = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "board",
            "Encrypted-only board",
            None,
            Some(json!({"kind":"require_e2ee"})),
        ),
        at,
    );
    let root = ordinary_realm::source_request(&pool, root).await;
    let root_id = arkret_wire::SpaceId::from_event_id(&root.authority_commit.event.event_id);
    uow.commit_event(root.clone()).await.unwrap();
    let before = cut_counts(&pool, &realm_id).await;
    let child = next_request(
        &root.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "list",
            "Plaintext list",
            Some(&root_id),
            None,
        ),
        at,
    );
    let child = ordinary_realm::source_request(&pool, child).await;
    let error = uow.commit_event(child).await.unwrap_err().to_string();
    assert!(error.contains("policy_violation"), "{error}");
    assert_eq!(cut_counts(&pool, &realm_id).await, before);
    assert_eq!(
        current(&pool, "space_child_scope_policy_current_results", &root_id)
            .await
            .value,
        json!({"kind":"require_e2ee"})
    );
}
