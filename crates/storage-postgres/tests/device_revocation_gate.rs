//! Real durable current-device checks: exact attempts replay, later checks
//! of the same business intent obtain a new current decision.
use arkret_wire::{CommitStreamRef, CommittedEventRef, DeviceRevocationDeniedAction};
use chrono::{DateTime, TimeDelta, Utc};
use coland_storage::{
    DeviceRevocationGateLinearizationRequest, DeviceRevocationGateSelector,
    DeviceRevocationGateStatus, DeviceRevocationStore, DeviceRevocationTransition,
    PersistenceError,
};
use coland_storage_postgres::PgDeviceRevocationStore;
use coland_storage_postgres::test_database::TestDatabase;

fn committed(seed: u8, position: u64) -> CommittedEventRef {
    let event =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32]);
    CommittedEventRef {
        event_id: event.clone(),
        commit_id: arkret_wire::RealmCommitId::new(
            event.as_str().replace("ak:event:", "ak:realm_commit:"),
        )
        .unwrap(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [3; 32],
            )),
        },
        stream_position: position,
    }
}

fn request() -> DeviceRevocationGateLinearizationRequest {
    let selector = DeviceRevocationGateSelector {
        principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:gate-holder.example").unwrap(),
        station_id: arkret_wire::DidCoreId::new("ak:did_core:web:gate-station.example").unwrap(),
        device_id: "gate-holder-device".to_owned(),
        authorization_ref: committed(1, 1),
    };
    DeviceRevocationGateLinearizationRequest {
        principal_id: selector.principal_id.clone(),
        station_id: selector.station_id.clone(),
        device_id: selector.device_id.clone(),
        expected_authorization_ref: Some(selector.authorization_ref.clone()),
        origin_current_selector: Some(selector),
        action_class: DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
        intent_digest: format!("sha256:{}", "a".repeat(64)),
        requested_at: DateTime::parse_from_rfc3339("2026-11-07T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
    }
}

#[tokio::test]
async fn later_checks_of_one_intent_are_fresh_and_still_reject_revocation() {
    let database = TestDatabase::lease().await;
    let store = PgDeviceRevocationStore {
        pool: database.pool(),
    };
    let original = request();
    let first = store.linearize_gate(original.clone()).await.unwrap();
    assert_eq!(first.status, DeviceRevocationGateStatus::Active);
    let replay = store.linearize_gate(original.clone()).await.unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&replay).unwrap()
    );

    let mut later = original.clone();
    later.requested_at += TimeDelta::seconds(1);
    let second = store.linearize_gate(later.clone()).await.unwrap();
    assert_eq!(second.linearization_seq, first.linearization_seq + 1);
    assert_eq!(second.linearized_at, later.requested_at);
    assert_eq!(
        second.expires_at,
        later.requested_at + TimeDelta::seconds(30)
    );

    let mut changed = later.clone();
    changed.expected_authorization_ref = None;
    assert!(matches!(
        store.linearize_gate(changed).await,
        Err(PersistenceError::Conflict(_))
    ));
    let replay = store.linearize_gate(later.clone()).await.unwrap();
    assert_eq!(replay.linearization_seq, second.linearization_seq);

    // An expired previous gate cannot prevent a fresh decision for the same
    // still-uncommitted business intent.
    later.requested_at += TimeDelta::seconds(31);
    let third = store.linearize_gate(later.clone()).await.unwrap();
    assert_eq!(third.linearization_seq, second.linearization_seq + 1);
    assert_eq!(third.status, DeviceRevocationGateStatus::Active);
    let transition = DeviceRevocationTransition {
        selector: original.origin_current_selector.clone().unwrap(),
        revoke_ref: committed(2, 2),
        committed_at: later.requested_at + TimeDelta::seconds(1),
    };
    store.commit_revocation(&transition).await.unwrap();
    later.requested_at += TimeDelta::seconds(2);
    let denied = store.linearize_gate(later).await.unwrap();
    assert_eq!(denied.linearization_seq, third.linearization_seq + 1);
    assert_eq!(
        denied.status,
        DeviceRevocationGateStatus::Revoked {
            revoke_ref: transition.revoke_ref,
            committed_at: transition.committed_at,
        }
    );
}

#[tokio::test]
async fn concurrent_exact_attempts_share_one_durable_linearization() {
    let database = TestDatabase::lease().await;
    let store = PgDeviceRevocationStore {
        pool: database.pool(),
    };
    let original = request();
    let outcomes =
        futures_util::future::join_all((0..8).map(|_| store.linearize_gate(original.clone())))
            .await;
    let outcomes = outcomes.into_iter().map(Result::unwrap).collect::<Vec<_>>();
    let first = &outcomes[0];
    for outcome in &outcomes {
        assert_eq!(
            serde_json::to_value(outcome).unwrap(),
            serde_json::to_value(first).unwrap()
        );
    }
    let mut later = original;
    later.requested_at += TimeDelta::seconds(1);
    assert_eq!(
        store.linearize_gate(later).await.unwrap().linearization_seq,
        first.linearization_seq + 1
    );
}
