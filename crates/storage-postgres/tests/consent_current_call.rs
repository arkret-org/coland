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
use arkret_models_collaboration::consent_operations::*;
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_wire::{ActorId, EventKind};
use coland_storage::{ConsentAdmissionOutcome, ConsentCurrentStore};
use coland_storage_postgres::PgConsentCurrentStore;
use coland_storage_postgres::test_database::TestDatabase;

#[path = "support/consent_current_call.rs"]
mod support;

#[tokio::test]
async fn consent_full_holder_current_and_call_cut_keep_exact_peers_empty_and_independent_scopes() {
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
    assert!(
        !support::call_permitted_at_native_cut(&store, &request, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let payload = |revision: Option<arkret_wire::CurrentRevision>, scopes: &[&str]| serde_json::json!({"peer":full_request.peer,"expected_current":revision.map_or(serde_json::json!({"state":"never_written"}),|r|serde_json::json!({"state":"present","revision":r})),"permissions":scopes.iter().map(|s|serde_json::json!({"consent_scope":s})).collect::<Vec<_>>()});
    let first = support::write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        payload(None, &["voice_call", "video_call"]),
    );
    let ConsentAdmissionOutcome::Committed(active) = store.admit(first).await.unwrap() else {
        panic!("initial full-set")
    };
    assert!(
        support::call_permitted_at_native_cut(&store, &request, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let narrowed = support::write(
        &f,
        &active.commit,
        EventKind::ConsentReplace,
        payload(Some(active.view().revision), &["voice_call"]),
    );
    let ConsentAdmissionOutcome::Committed(narrowed) = store.admit(narrowed).await.unwrap() else {
        panic!("narrow full-set")
    };
    let full = support::read_current(&store, &full_request, &f.history.account.station_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(full.records.len(), 1);
    assert_eq!(full.records[0].value.permissions.len(), 1);
    assert_eq!(full.head.commit_id, narrowed.commit.commit_id);
    assert!(
        support::call_permitted_at_native_cut(&store, &request, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let mut expanded = request.clone();
    expanded.invitation.media.video = true;
    assert!(
        !support::call_permitted_at_native_cut(&store, &expanded, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let mut other = request.clone();
    let mut account = f.history.account.clone();
    account.station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    other.invitation.inviter_actor_id = ActorId::account(account);
    assert!(
        !support::call_permitted_at_native_cut(&store, &other, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let empty = support::write(
        &f,
        &narrowed.commit,
        EventKind::ConsentReplace,
        payload(Some(narrowed.view().revision), &[]),
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
            &"ak:did_core:web:other-station.example".parse().unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
}
