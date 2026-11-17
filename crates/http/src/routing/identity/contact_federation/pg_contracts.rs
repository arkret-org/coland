//! Production Contact control namespace over actual accepted PG identities.
//! The authenticated service argument is the handler's existing verified port;
//! these tests do not claim RFC 9421 transport or provider enrollment HTTP.

use std::sync::Arc;

use arkret_identity::service_identity::{
    DidCoreIdentityKeyRef, DidCoreIdentityState, LocalDidCoreIdentity,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use coland_storage::IdentityStoreRegistry as _;
use coland_storage_postgres::{Db, PgPersistenceStore};
use coland_test_support::agent_origin::OriginFixture;
use coland_test_support::device_authorization_history::DeviceHistoryFixtureOptions;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use rand_chacha::rand_core::SeedableRng as _;

use super::*;

pub(crate) async fn fixture_and_state() -> (OriginFixture, AppState) {
    // The actual signing key is published by a genuinely verified WebVH
    // lineage under both original assertion methods used by this consumer.
    let endpoint = CanonicalServiceUrl::new("https://contact-contract.example/").unwrap();
    let registration =
        ServiceRegistrationKey::new(arkret_wire::ServiceKind::Station, endpoint).unwrap();
    let seed = [29; 32];
    let inception =
        arkret_signatures::webvh::prepare_service_registration_inception_with_did_key_seed(
            &mut rand_chacha::ChaCha20Rng::from_seed([37; 32]),
            &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://contact-identity.example/".parse().unwrap(),
                registration_key: &registration,
                also_known_as: &[],
                version_created_at: "2026-09-01T00:00:00Z".parse().unwrap(),
                did_key_fragment: Some("notary-key"),
            },
            &seed,
        )
        .unwrap();
    let fixture = Box::pin(OriginFixture::with_service_inception(inception)).await;
    let owner = &fixture.controller.history.account;
    PgPersistenceStore::new(fixture.pool.clone())
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: owner.principal_id.clone(),
            station_id: owner.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let config = crate::config::AppConfig {
        public_base_url: "https://contact-contract.example/".into(),
        notary_signing_key_seed: Some(seed),
        ..crate::config::AppConfig::test_default()
    };
    let key_ref = DidCoreIdentityKeyRef::new("fixture:contact-service-signing-key").unwrap();
    let identity = DidCoreIdentityState::Ready {
        identity: LocalDidCoreIdentity {
            service_id: fixture.station.clone(),
            did: fixture.station_did.clone(),
            registration_key: registration,
            provider: None,
            signing_key_refs: vec![key_ref.clone()],
            active_signing_key_ref: key_ref,
            control_key_ref: DidCoreIdentityKeyRef::new("fixture:contact-control-key").unwrap(),
            version_id: fixture.inception_log["versionId"].as_str().unwrap().into(),
            last_verified_at: fixture.genesis.commit.committed_at,
        },
    };
    let commitment = arkret_models_identity::ResolutionCommitment {
        did: fixture.station_did.clone(),
        method_history_head: arkret_canonical::canonical_sha256(&fixture.inception_log).unwrap(),
        version_id: fixture.inception_log["versionId"].as_str().unwrap().into(),
    };
    let state = AppState::new_with_service_identity(
        config,
        Db {
            pool: Some(fixture.pool.clone()),
        },
        Arc::new(PgPersistenceStore::new(fixture.pool.clone())),
        identity,
        commitment,
        seed,
    );
    (fixture, state)
}

pub(crate) async fn admit_peer(fixture: &OriginFixture, seed: u8) -> PcrGenesisFixture {
    let peer = PcrGenesisFixture::new_with(
        fixture.station_did.clone(),
        DeviceHistoryFixtureOptions {
            local_id: format!("contact-peer-{seed}"),
            founding_device_signing_seed: [seed.wrapping_add(2); 32],
            founding_device_id: arkret_wire::DeviceId::new(format!("ak:device:{}", Uuid::now_v7()))
                .unwrap(),
            ..Default::default()
        },
    );
    Box::pin(peer.admit_into(&PgPersistenceStore::new(fixture.pool.clone())))
        .await
        .unwrap();
    peer
}

fn current_request(
    fixture: &OriginFixture,
    state: &AppState,
    requester: &PcrGenesisFixture,
    key: &str,
) -> PeerContactSubmitRequestBody {
    PeerContactSubmitRequestBody::CurrentRefresh {
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        requester: ContactPeer::Human {
            account_id: requester.history.account.clone(),
        },
        trust_domain_id: state.config().trust_domain.clone(),
        initial_contact_round_id: None,
        known_version: 0,
        grant_event_refs: vec![],
        contact_address: PeerContactAddress::for_recipient(
            ContactPeer::Human {
                account_id: fixture.controller.history.account.clone(),
            },
            arkret_models_identity::ServiceResolutionCarrier::Inline {
                inline: fixture.history.clone(),
            },
        ),
    }
}

fn verify_original_receipt(fixture: &OriginFixture, outcome: &PeerContactSubmitResponseBody) {
    outcome.validate().unwrap();
    let PeerContactSubmitResponseBody::ControlDeferred(body) = outcome else {
        panic!("an absent Contact direction must remain opaque deferred")
    };
    let receipt = &body.control_receipt;
    let document = arkret_identity::authenticated_service_document_at(
        &fixture.history,
        &fixture.station,
        receipt.received_at,
    )
    .unwrap();
    let public = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &document,
        receipt.signature.verification_method.as_str(),
    )
    .unwrap();
    assert_eq!(public, fixture.issuer.verifying_key());
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &receipt.signature.jws,
            &receipt.canonical_signing_bytes().unwrap(),
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: public.to_bytes().to_vec(),
            },
        )
        .unwrap();
}

#[tokio::test]
async fn peer_control_same_wire_key_isolated_by_full_requester_and_exact_first_winner() {
    let (fixture, state) = Box::pin(fixture_and_state()).await;
    let bob = Box::pin(admit_peer(&fixture, 131)).await;
    let carol = Box::pin(admit_peer(&fixture, 141)).await;
    let key = format!("contact-control-{}", Uuid::now_v7());
    let request = current_request(&fixture, &state, &bob, &key);
    let other = current_request(&fixture, &state, &carol, &key);
    for body in [&request, &other] {
        let PeerContactSubmitRequestBody::CurrentRefresh {
            contact_address, ..
        } = body
        else {
            unreachable!()
        };
        contact_address.validate_shape().unwrap();
    }
    let (left, right) = tokio::join!(
        handle_current_refresh(&state, &request, fixture.station.as_str()),
        handle_current_refresh(&state, &request, fixture.station.as_str()),
    );
    let first = left.unwrap();
    let exact = right.unwrap();
    assert_eq!(
        canonical::canonical_json_bytes(&first).unwrap(),
        canonical::canonical_json_bytes(&exact).unwrap()
    );
    verify_original_receipt(&fixture, &first);
    let separate = handle_current_refresh(&state, &other, fixture.station.as_str())
        .await
        .unwrap();
    verify_original_receipt(&fixture, &separate);
    let first_peer = ContactPeer::Human {
        account_id: bob.history.account.clone(),
    };
    let other_peer = ContactPeer::Human {
        account_id: carol.history.account.clone(),
    };
    let (actor, first_key) = contact_control_identity(&first_peer, &key).unwrap();
    let (other_actor, other_key) = contact_control_identity(&other_peer, &key).unwrap();
    assert_eq!(actor, ActorId::service(fixture.station.clone()));
    assert_eq!(actor, other_actor);
    assert_ne!(first_key, other_key);
    let original = state
        .jobs()
        .scoped_idempotency_record(&actor, CONTACT_CONTROL_OPERATION, &first_key)
        .await
        .unwrap()
        .unwrap();
    let original_other = state
        .jobs()
        .scoped_idempotency_record(&other_actor, CONTACT_CONTROL_OPERATION, &other_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        original.response_body,
        serde_json::to_value(&first).unwrap()
    );
    assert_eq!(
        original_other.response_body,
        serde_json::to_value(&separate).unwrap()
    );
    let mut changed = request.clone();
    let PeerContactSubmitRequestBody::CurrentRefresh { known_version, .. } = &mut changed else {
        unreachable!()
    };
    *known_version = 1;
    let conflict = handle_current_refresh(&state, &changed, fixture.station.as_str())
        .await
        .unwrap_err();
    assert_eq!(conflict.code, crate::error::ErrorCode::DuplicateConflict);
    assert_eq!(conflict.http_status().as_u16(), 409);
    let wrong_source =
        arkret_wire::DidCoreId::new("ak:did_core:web:unrelated-contact-source.example").unwrap();
    assert!(
        handle_current_refresh(&state, &request, wrong_source.as_str())
            .await
            .is_err()
    );
    let after = state
        .jobs()
        .scoped_idempotency_record(&actor, CONTACT_CONTROL_OPERATION, &first_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        canonical::canonical_json_bytes(&after.response_body).unwrap(),
        canonical::canonical_json_bytes(&original.response_body).unwrap()
    );
    assert_eq!(after.request_hash, original.request_hash);
    let holder = ContactPeer::Human {
        account_id: fixture.controller.history.account.clone(),
    };
    for requester in [&first_peer, &other_peer] {
        assert!(
            state
                .contacts()
                .contact_any(&holder.contact_actor_id(), &requester.contact_actor_id(),)
                .await
                .unwrap()
                .is_none()
        );
    }
}
