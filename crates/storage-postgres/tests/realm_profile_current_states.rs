//! Realm profile replacement and its revision share the Event transaction.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};
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

async fn family_current(
    pool: &coland_storage_postgres::PgPool,
    realm: &arkret_wire::RealmId,
    family: &str,
) -> Current {
    if family == "scope_read_receipt_policy" {
        let mut conn = pool.get().await.unwrap();
        return diesel::sql_query("SELECT current_commit_id,current_stream_position,value FROM scope_read_receipt_policy_current_states WHERE realm_id=$1 AND scope_ref->>'kind'='realm'")
            .bind::<Text,_>(realm.as_str()).get_result(&mut conn).await.unwrap();
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value \
         FROM realm_bootstrap_current_states WHERE realm_id=$1 AND state_family=$2",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(family)
    .get_result(&mut conn)
    .await
    .unwrap()
}

async fn current(pool: &coland_storage_postgres::PgPool, realm: &arkret_wire::RealmId) -> Current {
    family_current(pool, realm, "realm_profile").await
}

async fn commits(pool: &coland_storage_postgres::PgPool, realm: &arkret_wire::RealmId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM realm_commits WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

#[tokio::test]
async fn profile_replacement_unset_replay_and_denial_share_the_pg_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = open_discussion(&pool, "realm-profile-current").await;
    let realm = discussion.realm_id();
    let mut head = discussion.head.authority_commit;
    let founder = head.event.actor_id.signing_principal_id().clone();
    for payload in [
        json!({"schema":"ak.schema.realm_profile.v1","title":"Updated","summary":"Summary"}),
        json!({"schema":"ak.schema.realm_profile.v1","title":"Cleared"}),
    ] {
        let request = next_request(
            &head,
            arkret_wire::EventKind::RealmProfile,
            &founder,
            payload.clone(),
            head.commit.committed_at,
        );
        let request = Box::pin(ordinary_realm::source_request(&pool, request)).await;
        assert!(
            uow.commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        let row = current(&pool, &realm).await;
        assert_eq!(row.value, payload);
        assert_eq!(
            row.current_commit_id,
            request.authority_commit.commit.commit_id.as_str()
        );
        assert_eq!(
            row.current_stream_position,
            request.authority_commit.commit.stream_position as i64
        );
        let count = commits(&pool, &realm).await;
        assert!(
            !uow.commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        assert_eq!(current(&pool, &realm).await, row);
        assert_eq!(commits(&pool, &realm).await, count);
        head = request.authority_commit;
    }
    let before = current(&pool, &realm).await;
    let count = commits(&pool, &realm).await;
    let outsider = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "profile-outsider",
    ))
    .await;
    let denied = next_request(
        &head,
        arkret_wire::EventKind::RealmProfile,
        &outsider.principal_id,
        json!({"schema":"ak.schema.realm_profile.v1","title":"Denied"}),
        head.commit.committed_at,
    );
    let denied = Box::pin(ordinary_realm::source_request(&pool, denied)).await;
    assert!(uow.commit_event(denied).await.is_err());
    assert_eq!(current(&pool, &realm).await, before);
    assert_eq!(commits(&pool, &realm).await, count);
}

#[tokio::test]
async fn read_receipt_policy_replacement_snapshot_replay_and_denial_share_the_pg_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = open_discussion(&pool, "read-receipt-policy-current").await;
    let realm = discussion.realm_id();
    let mut head = discussion.head.authority_commit;
    let founder = head.event.actor_id.signing_principal_id().clone();
    for payload in [
        json!({"disclosure":"required","visibility":"private"}),
        json!({"disclosure":"disabled"}),
    ] {
        let request = next_request(
            &head,
            arkret_wire::EventKind::ScopeReadReceiptPolicy,
            &founder,
            payload.clone(),
            head.commit.committed_at,
        );
        let request = Box::pin(ordinary_realm::source_request(&pool, request)).await;
        assert!(
            uow.commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        let row = family_current(&pool, &realm, "scope_read_receipt_policy").await;
        assert_eq!(row.value, payload);
        assert_eq!(
            row.current_commit_id,
            request.authority_commit.commit.commit_id.as_str()
        );
        assert_eq!(
            row.current_stream_position,
            request.authority_commit.commit.stream_position as i64
        );
        let snapshot = PgAuthorityCommitStore { pool: pool.clone() }
            .realm_state_snapshot_material_for_account(
                &realm,
                request
                    .authority_commit
                    .event
                    .actor_id
                    .as_account_id()
                    .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let policies = snapshot
            .current_state_entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    arkret_wire::CurrentState::Value {
                        selector: arkret_wire::CurrentSelector::ScopeReadReceiptPolicy {
                            scope_ref: arkret_wire::ScopeRef::Realm { .. }
                        },
                        ..
                    }
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(policies.len(), 1);
        assert!(
            matches!(policies[0], arkret_wire::CurrentState::Value {source_stream_ref,revision,value,..}
            if *source_stream_ref == request.authority_commit.commit.stream_ref && revision.commit_id == request.authority_commit.commit.commit_id && revision.stream_position == request.authority_commit.commit.stream_position && *value == payload)
        );
        let count = commits(&pool, &realm).await;
        assert!(
            !uow.commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        assert_eq!(
            family_current(&pool, &realm, "scope_read_receipt_policy").await,
            row
        );
        assert_eq!(commits(&pool, &realm).await, count);
        head = request.authority_commit;
    }
    let before = family_current(&pool, &realm, "scope_read_receipt_policy").await;
    let count = commits(&pool, &realm).await;
    let outsider = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "receipt-policy-outsider",
    ))
    .await;
    for (actor, payload) in [
        (outsider.principal_id, json!({"disclosure":"optional"})),
        (founder.clone(), json!({})),
        (founder.clone(), json!({"disclosure":"sometimes"})),
        (founder.clone(), json!({"visibility":"anonymous"})),
        (
            founder.clone(),
            json!({"disclosure":"optional","visibility":null}),
        ),
        (
            founder.clone(),
            json!({"visibility":"members","scope_overrides_allowed":null}),
        ),
        (
            founder,
            json!({"disclosure":"optional","child_privacy_tightening_against_required":true}),
        ),
    ] {
        let request = next_request(
            &head,
            arkret_wire::EventKind::ScopeReadReceiptPolicy,
            &actor,
            payload,
            head.commit.committed_at,
        );
        let request = Box::pin(ordinary_realm::source_request(&pool, request)).await;
        let event_id = request.authority_commit.event.event_id.clone();
        assert!(uow.commit_event(request).await.is_err());
        assert!(
            PgAuthorityCommitStore { pool: pool.clone() }
                .committed_event(&event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            family_current(&pool, &realm, "scope_read_receipt_policy").await,
            before
        );
        assert_eq!(commits(&pool, &realm).await, count);
    }
}
