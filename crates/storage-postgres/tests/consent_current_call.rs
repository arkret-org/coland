//! Real holder-PCR current cuts for the registered call consumers.

#[path = "../../test-support/src/device_authorization_history.rs"]
#[expect(
    dead_code,
    reason = "This binary uses the accepted PCR subset of the shared fixture."
)]
mod device_authorization_history;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[expect(
    dead_code,
    reason = "This binary uses the accepted PCR subset of the shared fixture."
)]
mod pcr_genesis;

use arkret_models_collaboration::call_invitation::*;
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_wire::{ActorId, EventKind};
use coland_storage::{ConsentAdmissionOutcome, ConsentCurrentStore};
use coland_storage_postgres::PgConsentCurrentStore;
use coland_storage_postgres::test_database::TestDatabase;

#[path = "support/consent_current_call.rs"]
mod support;

#[tokio::test]
async fn full_peer_current_preserves_scopes_and_native_call_gates_use_only_the_requested_scope() {
    use serde_json::json;
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = support::fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let peer = ActorId::account(f.history.account.clone());
    let request = support::call_request(&f, peer.clone());
    let full_request = ConsentCurrentReadRequestBody {
        holder_account_id: f.history.account.clone(),
        peer: ConsentPeer::Actor {
            actor_id: peer.clone(),
        },
        audience_actor_id: ActorId::service(f.history.account.station_id.clone()),
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    let before = support::read_current(&store, &full_request, &f.history.account.station_id)
        .await
        .unwrap()
        .unwrap();
    assert!(before.records.is_empty());
    let event = support::write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        json!({"peer":full_request.peer,"expected_current":{"state":"never_written"},"permissions":[{"consent_scope":"voice_call"},{"consent_scope":"presence","expires_at":"2020-01-01T00:00:00.000Z","constraints":[{"unknown":true}]}]}),
    );
    let ConsentAdmissionOutcome::Committed(active) = store.admit(event).await.unwrap() else {
        panic!("initial")
    };
    assert!(
        support::call_permitted_at_native_cut(&store, &request, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let full = support::read_current(&store, &full_request, &f.history.account.station_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(full.records.len(), 1);
    assert_eq!(full.records[0].value.permissions.len(), 2);
    assert_eq!(full.head.commit_id, active.commit.commit_id);
    let mut video = request.clone();
    video.invitation.media.video = true;
    assert!(
        !support::call_permitted_at_native_cut(&store, &video, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let mut other = request.clone();
    let mut account = f.history.account.clone();
    account.station_id = "ak:did_core:web:other.example".parse().unwrap();
    other.invitation.inviter_actor_id = ActorId::account(account);
    assert!(
        !support::call_permitted_at_native_cut(&store, &other, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let empty = support::write(
        &f,
        &active.commit,
        EventKind::ConsentReplace,
        json!({"peer":full_request.peer,"expected_current":{"state":"present","revision":active.view().revision},"permissions":[]}),
    );
    store.admit(empty).await.unwrap();
    assert!(
        !support::call_permitted_at_native_cut(&store, &request, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let full = support::read_current(&store, &full_request, &f.history.account.station_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(full.records.len(), 1);
    assert!(full.records[0].value.permissions.is_empty());
    assert!(
        support::read_current(
            &store,
            &full_request,
            &"ak:did_core:web:other.example".parse().unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
}
