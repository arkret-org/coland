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
use arkret_wire::{ActorId, ConsentScope, EventKind};
use coland_storage::{ConsentAdmissionOutcome, ConsentCurrentStore};
use coland_storage_postgres::PgConsentCurrentStore;
use coland_storage_postgres::test_database::TestDatabase;

#[path = "support/consent_current_call.rs"]
mod support;

#[tokio::test]
async fn consent_full_holder_current_and_call_cut_keep_exact_peers_revoke_and_independent_scopes() {
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
        consent_scope: ConsentScope::VoiceCall,
        audience_actor_id: ActorId::service(f.history.account.station_id.clone()),
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    let before = support::read_current(&store, &full_request, &f.history.account.station_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.realm_id, f.unit.transactions[0].event.realm_id);
    assert!(before.records.is_empty());
    assert!(
        !support::call_permitted_at_native_cut(&store, &request, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let any_id = "ak:consent:01964137-0000-7000-8000-000000000031";
    let voice_id = "ak:consent:01964137-0000-7000-8000-000000000032";
    let any = support::write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentGrant,
        serde_json::json!({"consent_id":any_id,"peer":full_request.peer,"consent_scope":"any"}),
    );
    let ConsentAdmissionOutcome::Committed(any) = store.admit(any).await.unwrap() else {
        panic!("any grant")
    };
    let voice = support::write(
        &f,
        &any.commit,
        EventKind::ConsentGrant,
        serde_json::json!({"consent_id":voice_id,"peer":full_request.peer,"consent_scope":"voice_call"}),
    );
    let ConsentAdmissionOutcome::Committed(voice) = store.admit(voice).await.unwrap() else {
        panic!("voice grant")
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
    assert_eq!(full.records.len(), 2);
    assert_eq!(full.head.commit_id, voice.commit.commit_id);
    let revoke = support::write(
        &f,
        &voice.commit,
        EventKind::ConsentRevoke,
        serde_json::json!({"consent_id":any_id,"expected_revision":any.view().revision}),
    );
    let ConsentAdmissionOutcome::Committed(revoked) = store.admit(revoke).await.unwrap() else {
        panic!("revoke any")
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
    assert_eq!(full.records.len(), 2);
    assert_eq!(
        full.records
            .iter()
            .filter(|r| r.value.status == ConsentState::Revoked)
            .count(),
        1
    );
    assert_eq!(full.head.commit_id, revoked.commit.commit_id);
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
    other.envelope.sender_actor_id = other.invitation.inviter_actor_id.clone();
    other.invitation.envelope_digest = call_invitation_envelope_digest(&other.envelope).unwrap();
    assert!(
        !support::call_permitted_at_native_cut(&store, &other, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
    let revoke = support::write(
        &f,
        &revoked.commit,
        EventKind::ConsentRevoke,
        serde_json::json!({"consent_id":voice_id,"expected_revision":voice.view().revision}),
    );
    store.admit(revoke).await.unwrap();
    assert!(
        !support::call_permitted_at_native_cut(&store, &request, &f.history.account.station_id)
            .await
            .unwrap()
            .unwrap()
    );
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
