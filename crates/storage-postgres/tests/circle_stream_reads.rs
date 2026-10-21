#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "Each integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use arkret_wire::{
    ActorId, CommitStreamRef, CurrentSelector, EventKind, StreamScanDirection, StreamScanRequest,
    TypedCurrentRow,
};
use coland_storage::{
    AccountStreamScan, AuthorityCommitStore, AuthorityCommitTransaction, EventCommitUnitOfWork,
    MemberCommittedEventRead,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};

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

fn page(result: AccountStreamScan) -> arkret_wire::StreamScanOutcome {
    match result {
        AccountStreamScan::Page(page) => page,
        other => panic!("expected an authorized Circle page: {other:?}"),
    }
}

#[tokio::test]
async fn exact_circle_membership_bounds_snapshot_bootstrap_scan_and_point_reads() {
    check_circle_reads("since_join").await;
}

#[tokio::test]
async fn circle_all_history_requires_current_membership_and_uses_its_own_genesis() {
    check_circle_reads("all_history_for_current_members").await;
}

async fn check_circle_reads(history: &str) {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station(ordinary_realm::station().as_str());
    let pool = database.pool();
    let did = device_authorization_history::did_web_station(&ordinary_realm::station());
    let account = ordinary_realm::human_profile::admit_without_profile(
        &pool,
        &ordinary_realm::station(),
        &uuid::Uuid::now_v7().to_string(),
    )
    .await;
    let actor = ActorId::account(account);
    let account = actor.as_account_id().unwrap();
    let unit = ordinary_realm::source_bootstrap(
        &pool,
        ordinary_realm::bootstrap_unit_for_account(
            &uuid::Uuid::now_v7().to_string(),
            account,
            &did,
        ),
    )
    .await;
    let head = unit.transactions.last().unwrap();
    let at = head.commit.committed_at;
    let realm = head.event.realm_id.clone();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let create = ordinary_realm::next_request_for_actor(
        head,
        EventKind::CircleCreate,
        actor.clone(),
        serde_json::json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
            "title":"Private membership cut","display":{"short_name":"Private","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":history,"state":"active",
            "created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    let create = ordinary_realm::source_request(&pool, create).await;
    uow.commit_event(create.clone()).await.unwrap();
    let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let stream = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let request = StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: stream.clone(),
        direction: StreamScanDirection::After(None),
        limit: 32,
    };
    let issuer = ordinary_realm::station();
    assert!(matches!(
        store
            .scan_stream_for_account(&request, account, &issuer)
            .await
            .unwrap(),
        AccountStreamScan::NotAuthorized
    ));
    let hidden = store
        .realm_state_snapshot_material_for_account(&realm, account)
        .await
        .unwrap()
        .unwrap();
    assert!(!hidden.current_state_entries.iter().any(|row| matches!(
        row,
        TypedCurrentRow::Value {
            selector: CurrentSelector::Circle { .. },
            ..
        }
    )));
    let parent = ordinary_realm::parent_membership_revision(&database.pool(), &realm, &actor).await;
    let join = membership(
        &create.authority_commit,
        &circle,
        &actor,
        "join",
        None,
        Some(parent.clone()),
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    let first = page(
        store
            .scan_stream_for_account(&request, account, &issuer)
            .await
            .unwrap(),
    );
    assert_eq!(first.committed_events.len(), 1);
    assert_eq!(first.committed_events[0].commit().stream_ref, stream);
    assert_eq!(first.readable_floor.as_ref().unwrap().oldest_position, 0);
    assert!(matches!(
        store
            .committed_event_for_member(&join.authority_commit.event.event_id, &actor, &issuer)
            .await
            .unwrap(),
        MemberCommittedEventRead::Read(_)
    ));
    assert_eq!(
        store
            .member_station_bootstrap_floor(
                &realm,
                account,
                &join.authority_commit.commit.commit_id,
            )
            .await
            .unwrap(),
        Some(join.authority_commit.commit.stream_position)
    );
    let bootstrap = store
        .member_station_bootstrap_material(&realm, account, &join.authority_commit.commit.commit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bootstrap
            .retention_and_history_floor
            .stream_floors
            .iter()
            .find(|floor| floor.stream_ref == stream)
            .unwrap()
            .oldest_position,
        0
    );
    assert_ne!(
        bootstrap
            .retention_and_history_floor
            .stream_floors
            .iter()
            .find(|floor| matches!(floor.stream_ref, CommitStreamRef::Realm { .. }))
            .unwrap()
            .oldest_position,
        head.commit.stream_position,
        "Circle join must not replace the parent Realm's floor"
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = arkret_wire::DidUrl::new(format!("{did}#authority")).unwrap();
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let issued = store
        .issue_realm_state_snapshot_for_account(&realm, account, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .issued_realm_state_snapshot(&realm, account, &issued.snapshot_id, &issuer)
            .await
            .unwrap(),
        Some(issued.clone())
    );
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    assert!(
        store
            .issue_stream_history_snapshot_for_account(
                &realm,
                account,
                &issuer,
                &realm_stream,
                Some(&arkret_wire::RealmCommitId::from_digest([0xee; 32])),
                &sign
            )
            .await
            .is_err(),
        "a stale or forged opening join must not issue a history original"
    );
    let realm_history = store
        .issue_stream_history_snapshot_for_account(
            &realm,
            account,
            &issuer,
            &realm_stream,
            None,
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    let circle_history = store
        .issue_stream_history_snapshot_for_account(&realm, account, &issuer, &stream, None, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        realm_history.purpose,
        arkret_wire::RealmSnapshotPurpose::StreamHistory
    );
    assert!(realm_history.require_full_recovery().is_err());
    assert!(
        realm_history
            .current_state_entries
            .iter()
            .all(|row| !matches!(
                row,
                TypedCurrentRow::Value {
                    selector: CurrentSelector::Circle { .. } | CurrentSelector::Sidecar { .. },
                    ..
                }
            ))
    );
    assert_eq!(realm_history.visible_stream_heads.len(), 1);
    assert!(
        circle_history
            .history_basis
            .as_ref()
            .unwrap()
            .accepted_dependency_refs
            .len()
            >= 1
    );
    assert_ne!(realm_history.snapshot_id, issued.snapshot_id);
    for narrow in [&realm_history, &circle_history] {
        assert_eq!(
            store
                .issued_realm_state_snapshot(&realm, account, &narrow.snapshot_id, &issuer)
                .await
                .unwrap()
                .as_ref(),
            Some(narrow)
        );
    }
    let leave = membership(
        &join.authority_commit,
        &circle,
        &actor,
        "leave",
        Some("join"),
        None,
    );
    let leave = ordinary_realm::source_request(&pool, leave).await;
    uow.commit_event(leave.clone()).await.unwrap();
    assert!(matches!(
        store
            .scan_stream_for_account(&request, account, &issuer)
            .await
            .unwrap(),
        AccountStreamScan::NotAuthorized
    ));
    assert!(matches!(
        store
            .committed_event_for_member(&join.authority_commit.event.event_id, &actor, &issuer)
            .await
            .unwrap(),
        MemberCommittedEventRead::NotVisible
    ));
    assert!(
        store
            .member_station_bootstrap_material(
                &realm,
                account,
                &join.authority_commit.commit.commit_id
            )
            .await
            .unwrap()
            .is_none()
    );
    let ended = page(peer_interval_decision(
        store
            .scan_stream_for_peer(&request, &issuer, &issuer)
            .await
            .unwrap(),
    ));
    assert_eq!(
        ended.committed_events.last().unwrap().commit().commit_id,
        leave.authority_commit.commit.commit_id
    );
    assert!(matches!(
        ended.committed_events.last().unwrap(),
        arkret_wire::CommittedEventView::Full(_)
    ));
    assert!(
        store
            .committed_event_for_peer(&leave.authority_commit.event.event_id, &issuer, &issuer)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .issued_realm_state_snapshot(&realm, account, &issued.snapshot_id, &issuer)
            .await
            .is_err(),
        "leaving the Circle must withdraw its old heads and state"
    );
    assert_eq!(
        store
            .issued_realm_state_snapshot(&realm, account, &realm_history.snapshot_id, &issuer)
            .await
            .unwrap(),
        Some(realm_history)
    );
    assert!(
        store
            .issued_realm_state_snapshot(&realm, account, &circle_history.snapshot_id, &issuer)
            .await
            .is_err(),
        "target-scope loss still withdraws its own narrow basis"
    );
    let rejoin = membership(
        &leave.authority_commit,
        &circle,
        &actor,
        "join",
        Some("leave"),
        Some(parent),
    );
    let rejoin = ordinary_realm::source_request(&pool, rejoin).await;
    uow.commit_event(rejoin.clone()).await.unwrap();
    let current = page(
        store
            .scan_stream_for_account(&request, account, &issuer)
            .await
            .unwrap(),
    );
    let expected_floor = if history == "since_join" { 2 } else { 0 };
    assert_eq!(
        current.readable_floor.as_ref().unwrap().oldest_position,
        expected_floor
    );
    assert_eq!(
        current.committed_events.len(),
        if history == "since_join" { 1 } else { 3 }
    );
    assert_eq!(
        current.committed_events.last().unwrap().commit().commit_id,
        rejoin.authority_commit.commit.commit_id
    );
    let prior_read = store
        .committed_event_for_member(&join.authority_commit.event.event_id, &actor, &issuer)
        .await
        .unwrap();
    if history == "since_join" {
        assert!(matches!(prior_read, MemberCommittedEventRead::NotVisible));
    } else {
        assert!(matches!(prior_read, MemberCommittedEventRead::Read(_)));
    }
    // State values alone remain readable below a new floor, but an exact
    // original carrying an older signed floor is no longer disclosable.
    let reread = store
        .issued_realm_state_snapshot(&realm, account, &issued.snapshot_id, &issuer)
        .await;
    if history == "since_join" {
        assert!(reread.is_err());
    } else {
        assert_eq!(reread.unwrap(), Some(issued));
    }
    let peer = page(peer_interval_decision(
        store
            .scan_stream_for_peer(&request, &issuer, &issuer)
            .await
            .unwrap(),
    ));
    assert_eq!(
        peer.readable_floor.as_ref().unwrap().oldest_position,
        expected_floor
    );
    assert!(
        store
            .member_station_bootstrap_material(
                &realm,
                account,
                &join.authority_commit.commit.commit_id
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .member_station_bootstrap_material(
                &realm,
                account,
                &rejoin.authority_commit.commit.commit_id
            )
            .await
            .unwrap()
            .is_some()
    );
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
