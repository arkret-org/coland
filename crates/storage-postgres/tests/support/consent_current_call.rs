use arkret_models_collaboration::call_invitation::*;
use arkret_wire::{
    ActorId, DetachedSignatureContext, Did, DidUrl, EventKind, RealmCommit, RealmCommitId,
};
use coland_storage::{AuthorityCommitTransaction, ConsentAdmissionWrite};
use coland_storage_postgres::{PgPersistenceStore, PgPool};
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;

use super::{device_authorization_history, pcr_genesis};

pub async fn fixture(pool: &PgPool) -> pcr_genesis::PcrGenesisFixture {
    let fixture = pcr_genesis::PcrGenesisFixture::new(Did::new("did:web:coland.example").unwrap());
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) ON CONFLICT(singleton) DO NOTHING")
        .bind::<Text,_>(fixture.history.account.station_id.as_str()).execute(&mut conn).await.unwrap();
    drop(conn);
    fixture
        .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
        .await
        .unwrap();
    fixture
}

pub fn write(
    f: &pcr_genesis::PcrGenesisFixture,
    previous: &RealmCommit,
    kind: EventKind,
    payload: serde_json::Value,
) -> ConsentAdmissionWrite {
    let at = previous.committed_at + chrono::TimeDelta::seconds(1);
    let mut event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: previous.realm_id.clone(),
        },
        f.history.account.principal_id.clone(),
        f.history.account.station_id.clone(),
        payload,
        at,
    )
    .unwrap();
    event.authorization_ref = Some(f.unit.transactions[0].event.event_id.clone().into());
    event = device_authorization_history::sign_event(
        event,
        f.history.device_verification_method.clone(),
        f.history.founding_device_signing_seed,
    );
    let mut commit = previous.clone();
    commit.event_ref = event.event_id.clone();
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.committed_at = at;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new("did:web:coland.example#authority").unwrap(),
        at,
        &SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED),
    )
    .unwrap();
    ConsentAdmissionWrite {
        transaction: AuthorityCommitTransaction {
            expected_authority: f.unit.transactions[1].expected_authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
    }
}

pub fn call_request(
    f: &pcr_genesis::PcrGenesisFixture,
    peer: ActorId,
) -> CallInvitationAdmissionRequestBody {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut envelope:arkret_wire::SignalEnvelope=serde_json::from_value(serde_json::json!({
        "realm_id":f.unit.transactions[0].event.realm_id,
        "scope_ref":arkret_wire::ScopeRef::Realm{realm_id:f.unit.transactions[0].event.realm_id.clone()},
        "sender_actor_id":peer,"sender_device_id":f.history.founding_device_id,
        "authority_commit_id":f.unit.transactions[1].commit.commit_id,
        "signal_class":"setup","sent_at":at,"expires_at":at+chrono::Duration::seconds(120),
        "encrypted_payload":{"scheme":arkret_wire::SIGNAL_AEAD_SCHEME,"key_ref":{"group_state_ref":f.unit.transactions[1].event.event_id},"purpose":arkret_wire::SIGNAL_AEAD_PURPOSE,"aead_profile":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519","epoch":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"Q2lwaGVydGV4dFBsYWNlaG9sZGVy"},
        "proof":{"kind":"detached_jws","verification_method":f.history.device_verification_method,"envelope_digest":format!("sha256:{}","0".repeat(64)),"jws":"AA..AA"}
    })).unwrap();
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    let signer = SigningKey::from_bytes(&f.history.founding_device_signing_seed);
    envelope.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &signer,
        &envelope.proof_binding_bytes().unwrap(),
    )
    .unwrap();
    envelope.validate_structural().unwrap();
    let mut invitation = CallInvitationEnvelope {
        inviter_actor_id: peer,
        holder_account_id: f.history.account.clone(),
        scope_ref: envelope.scope_ref.clone(),
        call_id: "ak:call:ARzVic5s2NUShp82C8GPo-shbkm7isUWyvILLThc3aNL"
            .parse()
            .unwrap(),
        media: CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
        envelope_digest: call_invitation_envelope_digest(&envelope).unwrap(),
        expires_at: envelope.expires_at,
        proof: CallInvitationProof {
            verification_method: envelope.proof.verification_method.to_string(),
            jws: String::new(),
        },
    };
    arkret_signatures::call_invitation::sign_call_invitation(&mut invitation, &signer).unwrap();
    CallInvitationAdmissionRequestBody {
        subject_actor_id: ActorId::account(f.history.account.clone()),
        invitation,
        envelope,
        admission_phase: CallInvitationAdmissionPhase::ProductDelivery,
        audience_actor_id: ActorId::service(f.history.account.station_id.clone()),
        subject_device_id: f.history.founding_device_id.clone(),
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        focus_id: None,
        desired_media: None,
    }
}

pub async fn read_current(
    store: &impl coland_storage::ConsentCurrentStore,
    request: &arkret_models_collaboration::call_invitation::ConsentCurrentReadRequestBody,
    service: &arkret_wire::DidCoreId,
) -> coland_storage::PersistenceResult<Option<coland_storage::ConsentCurrentCut>> {
    let cut = store
        .read_cut(
            &request.holder_account_id,
            &request.peer,
            request.consent_scope,
            None,
        )
        .await?;
    Ok((cut.service_id == *service).then_some(cut))
}

pub async fn call_permitted_at_native_cut(
    store: &impl coland_storage::ConsentCurrentStore,
    request: &CallInvitationAdmissionRequestBody,
    service: &arkret_wire::DidCoreId,
) -> coland_storage::PersistenceResult<Option<bool>> {
    let scope = request.invitation.media.consent_scope();
    let peer = arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
        actor_id: request.invitation.inviter_actor_id.clone(),
    };
    let cut = store
        .read_cut(
            &request.invitation.holder_account_id,
            &peer,
            scope,
            Some(&request.subject_device_id),
        )
        .await?;
    Ok((cut.service_id == *service).then(|| {
        cut.device_admitted
            && cut.records.iter().any(|record| {
                record.permits(
                    &request.invitation.inviter_actor_id,
                    scope,
                    cut.evaluated_at,
                )
            })
    }))
}
