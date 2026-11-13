//! Device-directory relationship cuts use accepted membership, not UI caches.
use super::*;

async fn membership(
    pool: &PgPool,
    previous: &coland_storage::AuthorityCommitTransaction,
    actor: &ActorId,
    membership: &str,
) -> coland_storage::AuthorityCommitTransaction {
    let at = previous.commit.committed_at + chrono::Duration::milliseconds(1);
    let request = ordinary_realm::next_human_request_for_actor(
        previous,
        EventKind::MemberState,
        actor.clone(),
        json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":membership}),
        at,
    );
    let request = ordinary_realm::source_request(pool, request).await;
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request.clone())
        .await
        .unwrap();
    request.authority_commit
}

#[tokio::test]
async fn directory_relationship_tracks_native_join_leave_and_exact_station_without_projection() {
    let database = TestDatabase::lease().await;
    let pool = database.db().pool.unwrap();
    let discussion = ordinary_realm::open_discussion_with_history(
        &pool,
        "directory-current-relationship",
        "all_history_for_current_members",
    )
    .await;
    let founder = discussion.unit.transactions[0].event.actor_id.clone();
    let target = ActorId::account(
        ordinary_realm::human_profile::admit(
            &pool,
            &ordinary_realm::station(),
            "directory-newcomer",
        )
        .await,
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(
        store
            .device_directory_shared_realm(&founder, &target)
            .await
            .unwrap()
            .is_none()
    );
    let joined = membership(&pool, &discussion.head.authority_commit, &target, "join").await;
    let realm = discussion.realm_id();
    assert_eq!(
        store
            .device_directory_shared_realm(&founder, &target)
            .await
            .unwrap(),
        Some(realm.clone())
    );
    assert_eq!(
        store
            .device_directory_shared_realm(&target, &founder)
            .await
            .unwrap(),
        Some(realm.clone())
    );
    // Equal principal components at another Station cannot borrow either join.
    let other_station = ActorId::account(arkret_wire::AccountId::new(
        target.signing_principal_id().clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:unrelated-directory-station.example").unwrap(),
    ));
    assert!(
        store
            .device_directory_shared_realm(&founder, &other_station)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .device_directory_shared_realm(&other_station, &founder)
            .await
            .unwrap()
            .is_none()
    );
    let left = membership(&pool, &joined, &target, "leave").await;
    assert!(
        store
            .device_directory_shared_realm(&founder, &target)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .device_directory_shared_realm(&target, &founder)
            .await
            .unwrap()
            .is_none()
    );
    let rejoined = membership(&pool, &left, &target, "join").await;
    assert_eq!(
        store
            .device_directory_shared_realm(&founder, &target)
            .await
            .unwrap(),
        Some(realm)
    );
    membership(&pool, &rejoined, &founder, "leave").await;
    assert!(
        store
            .device_directory_shared_realm(&founder, &target)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .device_directory_shared_realm(&target, &founder)
            .await
            .unwrap()
            .is_none()
    );
}
