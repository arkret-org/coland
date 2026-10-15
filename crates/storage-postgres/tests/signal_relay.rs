//! Shared exact-digest suppression at the transient relay storage boundary.
use std::sync::Arc;

use arkret_wire::*;
use coland_storage::{SignalRelayRecord, SignalRelayStore};
use coland_storage_postgres::PgSignalRelayStore;
use coland_storage_postgres::test_database::TestDatabase;
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;

fn record() -> SignalRelayRecord {
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [31; 32],
    ));
    let actor = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000002801").unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut envelope = SignalEnvelope {
        realm_id: realm.clone(),
        scope_ref: ScopeRef::Realm { realm_id: realm },
        sender_actor_id: actor,
        sender_device_id: Some(device.clone()),
        authority_commit_id: RealmCommitId::from_digest([32; 32]),
        parent_realm_authority_commit_id: None,
        signal_class: SignalClass::Session,
        sent_at: at,
        expires_at: at + chrono::Duration::seconds(30),
        encrypted_payload: SignalEncryptedPayload {
            scheme: SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: SignalKeyRef {
                group_state_ref: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [33; 32],
                )
                .to_string(),
            },
            purpose: SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 0,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
        },
        proof: SignalProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new(format!("did:web:alice.example#{device}")).unwrap(),
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            domain: None,
            audience: None,
            jws: "a..b".to_owned(),
        },
    };
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    envelope.validate_structural().unwrap();
    SignalRelayRecord {
        realm_id: envelope.realm_id.to_string(),
        scope_ref: envelope.scope_ref.clone(),
        sender_actor_id: envelope.sender_actor_id.to_string(),
        sender_device_id: Some(device.to_string()),
        signal_class: envelope.signal_class,
        envelope_digest: envelope.envelope_digest().unwrap().to_string(),
        sent_at: at,
        expires_at: envelope.expires_at,
        envelope,
        call_invitation: None,
        position: 0,
    }
}

#[derive(diesel::QueryableByName)]
struct Progress {
    #[diesel(sql_type=BigInt)]
    next_position: i64,
}

#[tokio::test]
async fn eight_process_equivalent_racers_allocate_and_insert_exactly_once() {
    let database = TestDatabase::lease().await;
    let relay = Arc::new(PgSignalRelayStore {
        pool: database.pool(),
    });
    let record = record();
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let relay = relay.clone();
        let barrier = barrier.clone();
        let record = record.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            relay.append(record).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    assert!(!relay.append(record.clone()).await.unwrap());
    let rows = relay.list_for_realm(&record.realm_id).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].position, 1);
    assert_eq!(rows[0].envelope, record.envelope);
    let mut conn = database.pool().get().await.unwrap();
    let progress =
        diesel::sql_query("SELECT next_position FROM signal_relay_position WHERE realm_id=$1")
            .bind::<Text, _>(&record.realm_id)
            .get_result::<Progress>(&mut *conn)
            .await
            .unwrap();
    assert_eq!(progress.next_position, 1);
}

#[tokio::test]
async fn one_exact_envelope_retains_each_complete_holder_direction_independently() {
    use arkret_models_collaboration::call_invitation::*;
    let database = TestDatabase::lease().await;
    let relay = PgSignalRelayStore {
        pool: database.pool(),
    };
    let mut first = record();
    let holder = AccountId::new(
        "ak:did_core:web:bob.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    first.call_invitation = Some(CallInvitationEnvelope {
        inviter_actor_id: first.envelope.sender_actor_id.clone(),
        holder_account_id: holder.clone(),
        scope_ref: first.scope_ref.clone(),
        call_id: "ak:call:ARzVic5s2NUShp82C8GPo-shbkm7isUWyvILLThc3aNL"
            .parse()
            .unwrap(),
        media: CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
        envelope_digest: call_invitation_envelope_digest(&first.envelope).unwrap(),
        expires_at: first.expires_at,
        proof: CallInvitationProof {
            verification_method: first.envelope.proof.verification_method.clone(),
            jws: "a..b".into(),
        },
    });
    let mut second = first.clone();
    second
        .call_invitation
        .as_mut()
        .unwrap()
        .holder_account_id
        .station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    assert!(relay.append(first.clone()).await.unwrap());
    assert!(!relay.append(first.clone()).await.unwrap());
    assert!(relay.append(second.clone()).await.unwrap());
    assert!(!relay.append(second.clone()).await.unwrap());
    let rows = relay.list_for_realm(&first.realm_id).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].call_invitation, first.call_invitation);
    assert_eq!(rows[1].call_invitation, second.call_invitation);
    assert_eq!(rows[0].envelope, rows[1].envelope);
}
