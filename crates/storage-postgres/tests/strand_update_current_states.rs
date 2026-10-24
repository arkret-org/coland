//! `ak.strand.update` advances its target value at the accepted RealmCommit cut.
//! Every rejected update leaves the Event, Commit and current value untouched.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{next_request, open_discussion};
use serde_json::{Value, json};

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

async fn current(
    pool: &coland_storage_postgres::PgPool,
    strand_id: &arkret_wire::StrandId,
) -> Current {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value \
         FROM strand_current_states WHERE strand_id=$1",
    )
    .bind::<Text, _>(strand_id.as_str())
    .get_result(&mut conn)
    .await
    .unwrap()
}

async fn realm_counts(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> (i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let events: Count =
        diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
    let commits: Count =
        diesel::sql_query("SELECT COUNT(*) AS count FROM realm_commits WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
    (events.count, commits.count)
}

fn digest(value: &Value) -> String {
    arkret_canonical::sha256_digest(arkret_canonical::canonical_json_bytes(value).unwrap())
}

#[tokio::test]
async fn strand_scope_rebind_returns_the_contract_reason_without_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = Box::pin(open_discussion(&pool, "strand-scope-rebind")).await;
    let head = &discussion.head.authority_commit;
    let before = current(&pool, &discussion.strand_id).await;
    let counts = realm_counts(&pool, &head.event.realm_id).await;
    let request = Box::pin(ordinary_realm::source_request(&pool, next_request(
        head,
        arkret_wire::EventKind::StrandUpdate,
        head.event.actor_id.signing_principal_id(),
        json!({"target_ref":discussion.strand_id,"patch":{
            "scope_circle_id":{"$op":"set","value":arkret_wire::CircleId::from_event_id(&head.event.event_id)}
        }}),
        head.commit.committed_at,
    ))).await;
    let event_id = request.authority_commit.event.event_id.clone();
    let error = uow.commit_event(request).await.unwrap_err();
    assert!(
        matches!(error, coland_storage::PersistenceError::Conflict(ref detail)
        if detail == "failed_precondition: scope_rebind_forbidden"),
        "{error}"
    );
    assert_eq!(current(&pool, &discussion.strand_id).await, before);
    assert_eq!(realm_counts(&pool, &head.event.realm_id).await, counts);
    assert!(
        coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn synthesis_content_update_preserves_track_controls_and_refuses_inactive_tracks_atomically()
{
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = Box::pin(open_discussion(&pool, "synthesis-content-current")).await;
    let realm = discussion.head.authority_commit.event.realm_id.clone();
    let at = discussion.head.authority_commit.commit.committed_at;
    let update = |head: &coland_storage::AuthorityCommitTransaction, body: &str| {
        next_request(
            head,
            arkret_wire::EventKind::StrandUpdate,
            &discussion
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id()
                .clone(),
            json!({"target_ref": discussion.strand_id, "patch": {
                "tracks.synthesis.content": {"$op":"set", "value": {
                    "kind":"ak.content.text", "body":body
                }}
            }}),
            at,
        )
    };
    let before = current(&pool, &discussion.strand_id).await;
    let counts = realm_counts(&pool, &realm).await;
    assert!(
        uow.commit_event(
            Box::pin(ordinary_realm::source_request(
                &pool,
                update(&discussion.head.authority_commit, "Absent track")
            ))
            .await
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("track_disabled")
    );
    assert_eq!(current(&pool, &discussion.strand_id).await, before);
    assert_eq!(realm_counts(&pool, &realm).await, counts);
    let enable = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::StrandTracksUpdate,
            &discussion
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id()
                .clone(),
            json!({"target_ref": discussion.strand_id, "patch": {
                "tracks.synthesis.enabled": {"$op":"set", "value":true},
                "tracks.synthesis.is_primary": {"$op":"set", "value":false}
            }}),
            at,
        ),
    ))
    .await;
    uow.commit_event(enable.clone()).await.unwrap();
    let write = Box::pin(ordinary_realm::source_request(
        &pool,
        update(&enable.authority_commit, "Accepted synthesis"),
    ))
    .await;
    uow.commit_event(write.clone()).await.unwrap();
    let accepted = current(&pool, &discussion.strand_id).await;
    assert_eq!(
        accepted.value["tracks"]["synthesis"]["content"]["body"],
        "Accepted synthesis"
    );
    assert_eq!(accepted.value["tracks"]["synthesis"]["is_primary"], false);
    let disable = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &write.authority_commit,
            arkret_wire::EventKind::StrandTracksUpdate,
            &discussion
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id()
                .clone(),
            json!({"target_ref": discussion.strand_id, "patch": {
                "tracks.synthesis.enabled": {"$op":"set", "value":false}
            }}),
            at,
        ),
    ))
    .await;
    uow.commit_event(disable.clone()).await.unwrap();
    let before = current(&pool, &discussion.strand_id).await;
    let counts = realm_counts(&pool, &realm).await;
    assert!(
        uow.commit_event(
            Box::pin(ordinary_realm::source_request(
                &pool,
                update(&disable.authority_commit, "Disabled track")
            ))
            .await
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("track_disabled")
    );
    assert_eq!(current(&pool, &discussion.strand_id).await, before);
    assert_eq!(realm_counts(&pool, &realm).await, counts);
}

#[tokio::test]
async fn strand_update_current_cas_and_rejection_are_one_pg_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = Box::new(Box::pin(open_discussion(&pool, "strand-update-current-cas")).await);
    let realm_id = discussion.head.authority_commit.event.realm_id.clone();
    let at = discussion.head.authority_commit.commit.committed_at;
    let before = current(&pool, &discussion.strand_id).await;
    let baseline = realm_counts(&pool, &realm_id).await;

    let accepted = Box::new(
        Box::pin(ordinary_realm::source_request(
            &pool,
            next_request(
                &discussion.head.authority_commit,
                arkret_wire::EventKind::StrandUpdate,
                &discussion
                    .head
                    .authority_commit
                    .event
                    .actor_id
                    .signing_principal_id()
                    .clone(),
                json!({
                    "target_ref": discussion.strand_id,
                    "expected_state_digest": digest(&before.value),
                    "patch": {"metadata.title": {"$op":"set", "value":"Accepted title"}},
                }),
                at,
            ),
        ))
        .await,
    );
    let outcome = uow.commit_event((*accepted).clone()).await.unwrap();
    assert!(outcome.event_inserted);
    let after = current(&pool, &discussion.strand_id).await;
    assert_eq!(after.value["metadata"]["title"], "Accepted title");
    let store = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        discussion
            .head
            .authority_commit
            .event
            .actor_id
            .signing_principal_id()
            .clone(),
        ordinary_realm::station(),
    ));
    let (_, list) = store
        .object_projection_lists_for_actor(&realm_id, &actor, false)
        .await
        .unwrap()
        .unwrap();
    let listed = list
        .strands
        .iter()
        .find(|row| row.strand_id == discussion.strand_id)
        .unwrap();
    assert_eq!(listed.title.as_deref(), Some("Accepted title"));
    assert!(listed.is_default);
    let outsider = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:read-outsider.example").unwrap(),
        ordinary_realm::station(),
    ));
    assert!(
        store
            .object_projection_lists_for_actor(&realm_id, &outsider, false)
            .await
            .unwrap()
            .is_none()
    );
    // Message target visibility and the Realm lifecycle roster read the same
    // accepted joined cut as the lists.
    assert_eq!(
        store
            .visible_strand_scope_for_actor(&realm_id, &discussion.strand_id, &actor)
            .await
            .unwrap(),
        Some(arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone()
        })
    );
    assert_eq!(
        store
            .visible_strand_scope_for_actor(&realm_id, &discussion.strand_id, &outsider)
            .await
            .unwrap(),
        None
    );
    let roster = store
        .accepted_realm_roster(&realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(roster.controller_actor_id, actor);
    assert!(roster.joined_members.contains(&actor));
    assert!(!roster.joined_members.contains(&outsider));
    assert_eq!(
        after.current_commit_id,
        accepted.authority_commit.commit.commit_id.as_str()
    );
    assert_eq!(
        after.current_stream_position,
        accepted.authority_commit.commit.stream_position as i64
    );
    assert_eq!(
        realm_counts(&pool, &realm_id).await,
        (baseline.0 + 1, baseline.1 + 1)
    );

    // Updating the already disclosed Strand family must keep member bootstrap
    // available, with the accepted value and its exact current revision.
    let account = arkret_wire::AccountId::new(
        discussion
            .head
            .authority_commit
            .event
            .actor_id
            .signing_principal_id()
            .clone(),
        ordinary_realm::station(),
    );
    let snapshot = coland_storage_postgres::account_snapshot_material(&pool, &realm_id, &account)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| matches!(
        entry,
        arkret_wire::CurrentState::Value { selector: arkret_wire::CurrentSelector::Strand { strand_id }, revision, value, .. }
            if strand_id == &discussion.strand_id
                && revision.commit_id.as_str() == after.current_commit_id
                && revision.stream_position == after.current_stream_position as u64
                && value == &after.value
    )));

    let duplicate = uow.commit_event((*accepted).clone()).await.unwrap();
    assert!(!duplicate.event_inserted);
    assert_eq!(current(&pool, &discussion.strand_id).await, after);
    assert_eq!(
        realm_counts(&pool, &realm_id).await,
        (baseline.0 + 1, baseline.1 + 1)
    );

    let head = &accepted.authority_commit;
    let stale = Box::new(
        Box::pin(ordinary_realm::source_request(
            &pool,
            next_request(
                head,
                arkret_wire::EventKind::StrandUpdate,
                &discussion
                    .head
                    .authority_commit
                    .event
                    .actor_id
                    .signing_principal_id()
                    .clone(),
                json!({
                    "target_ref": discussion.strand_id,
                    "expected_state_digest": digest(&before.value),
                    "patch": {"metadata.title": {"$op":"set", "value":"Stale title"}},
                }),
                at,
            ),
        ))
        .await,
    );
    let unknown = Box::new(Box::pin(ordinary_realm::source_request(&pool, next_request(
        head,
        arkret_wire::EventKind::StrandUpdate,
        &discussion
            .head
            .authority_commit
            .event
            .actor_id
            .signing_principal_id()
            .clone(),
        json!({
            "target_ref": arkret_wire::StrandId::from_event_id(&accepted.authority_commit.event.event_id),
            "patch": {"metadata.title": {"$op":"set", "value":"Unknown title"}},
        }),
        at,
    ))).await);
    let forbidden = Box::new(
        Box::pin(ordinary_realm::source_request(
            &pool,
            next_request(
                head,
                arkret_wire::EventKind::StrandUpdate,
                &discussion
                    .head
                    .authority_commit
                    .event
                    .actor_id
                    .signing_principal_id()
                    .clone(),
                json!({
                    "target_ref": discussion.strand_id,
                    "patch": {"stage": {"$op":"set", "value":"done"}},
                }),
                at,
            ),
        ))
        .await,
    );
    let outsider = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "strand-update-outsider",
    ))
    .await;
    let not_joined = Box::new(
        Box::pin(ordinary_realm::source_request(
            &pool,
            next_request(
                head,
                arkret_wire::EventKind::StrandUpdate,
                &outsider.principal_id,
                json!({
                    "target_ref": discussion.strand_id,
                    "patch": {"metadata.title": {"$op":"set", "value":"Unauthorized title"}},
                }),
                at,
            ),
        ))
        .await,
    );
    for (request, reason) in [
        (stale, "expected_state_digest"),
        (unknown, "target is absent"),
        (forbidden, "forbidden"),
        (not_joined, "capability_denied"),
    ] {
        let error = uow.commit_event(*request).await.unwrap_err().to_string();
        assert!(error.contains(reason), "{error}");
        assert_eq!(current(&pool, &discussion.strand_id).await, after);
        assert_eq!(
            realm_counts(&pool, &realm_id).await,
            (baseline.0 + 1, baseline.1 + 1)
        );
    }
}

#[tokio::test]
async fn strand_update_calendar_profile_requires_ref_and_subtree_together() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = Box::pin(open_discussion(&pool, "strand-update-calendar-pair")).await;
    let author = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let realm_id = discussion.head.authority_commit.event.realm_id.clone();
    let at = discussion.head.authority_commit.commit.committed_at;
    let schedule = json!({
        "start": "2026-06-22",
        "end": "2026-06-23",
        "timezone": "UTC",
        "tzdb_version": "2025b",
        "all_day": true,
        "status": "confirmed"
    });
    let accepted = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::StrandUpdate,
            &author,
            json!({
                "target_ref": discussion.strand_id,
                "patch": {
                    "schema_refs": {"$op":"set", "value":["ak.schema.calendar_event.v1"]},
                    "metadata.fields.calendar": {"$op":"set", "value":schedule},
                },
            }),
            at,
        ),
    ))
    .await;
    uow.commit_event(accepted.clone()).await.unwrap();
    let confirmed = current(&pool, &discussion.strand_id).await;
    assert_eq!(
        confirmed.value["schema_refs"],
        json!(["ak.schema.calendar_event.v1"])
    );
    assert_eq!(confirmed.value["metadata"]["fields"]["calendar"], schedule);
    async fn source(
        pool: &PgPool,
        strand: &arkret_wire::StrandId,
    ) -> arkret_wire::CalendarScheduleSourceValue {
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type=Jsonb)]
            value: Value,
        }
        let mut conn = pool.get().await.unwrap();
        let row = diesel::sql_query("SELECT calendar_schedule_source_value AS value FROM strand_current_states WHERE strand_id=$1")
            .bind::<Text,_>(strand.as_str()).get_result::<Row>(&mut conn).await.unwrap();
        serde_json::from_value(row.value).unwrap()
    }
    let initial = source(&pool, &discussion.strand_id).await;
    assert_eq!(
        initial.source.as_ref().unwrap().event_id,
        accepted.authority_commit.event.event_id
    );
    assert_eq!(
        initial.strand_revision.commit_id,
        accepted.authority_commit.commit.commit_id
    );
    let title = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &accepted.authority_commit,
        arkret_wire::EventKind::StrandUpdate,
        &author,
        json!({"target_ref":discussion.strand_id,"patch":{"metadata.title":{"$op":"set","value":"Renamed calendar"}}}),
        at,
    ))).await;
    uow.commit_event(title.clone()).await.unwrap();
    let renamed = source(&pool, &discussion.strand_id).await;
    assert_eq!(renamed.source, initial.source);
    assert_eq!(
        renamed.strand_revision.commit_id,
        title.authority_commit.commit.commit_id
    );
    let same_schedule = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &title.authority_commit,
        arkret_wire::EventKind::StrandUpdate,
        &author,
        json!({"target_ref":discussion.strand_id,"patch":{"metadata.fields.calendar":{"$op":"set","value":schedule}}}),
        at,
    ))).await;
    uow.commit_event(same_schedule.clone()).await.unwrap();
    let repeated = source(&pool, &discussion.strand_id).await;
    assert_eq!(
        repeated.source.as_ref().unwrap().event_id,
        same_schedule.authority_commit.event.event_id
    );
    assert_ne!(repeated.source, initial.source);
    let accepted = same_schedule;
    let confirmed = current(&pool, &discussion.strand_id).await;
    let counts = realm_counts(&pool, &realm_id).await;

    let unpaired = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &accepted.authority_commit,
            arkret_wire::EventKind::StrandUpdate,
            &author,
            json!({
                "target_ref": discussion.strand_id,
                "patch": {"schema_refs": {"$op":"unset"}},
            }),
            at,
        ),
    ))
    .await;
    let error = uow.commit_event(unpaired).await.unwrap_err().to_string();
    assert!(error.contains("calendar_activation_mismatch"), "{error}");
    assert_eq!(current(&pool, &discussion.strand_id).await, confirmed);
    assert_eq!(realm_counts(&pool, &realm_id).await, counts);
}
