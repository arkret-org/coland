//! Pure signed-original certificate regressions, not PG or first-admission tests.

#[path = "support/organization_origin.rs"]
mod organization_origin;

use arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact;
use arkret_signatures::{Ed25519DetachedJwsSigner, PublicKeyMaterial, SignEventOptions};
use arkret_wire::*;
use chrono::Duration;
use ed25519_dalek::SigningKey;
use organization_origin::OrganizationFixture;
use serde_json::json;

fn fact(fixture: &OrganizationFixture) -> OrganizationGenesisSignerFact {
    let document = serde_json::from_value(fixture.organization_state()).unwrap();
    OrganizationGenesisSignerFact {
        event_id: fixture
            .write
            .request
            .event_submission
            .event
            .event_id
            .clone(),
        method_history_evidence: arkret_identity::build_webvh_method_history_evidence(
            &document,
            fixture.write.organization_log_entries.clone(),
            fixture.write.organization_witness_records.clone(),
        )
        .unwrap(),
        approval_signatures: fixture
            .write
            .request
            .event_submission
            .approval_signatures
            .clone(),
        producer_resolution: fixture.write.producer_service_resolution.clone(),
        public_key_base64url: None,
    }
}

fn cover(
    fixture: &OrganizationFixture,
    fact: &OrganizationGenesisSignerFact,
) -> CommittedEventFullView {
    let event = fixture.write.request.event_submission.event.clone();
    let mut commit = fixture.write.transaction.commit.clone();
    commit.realm_id = event.realm_id.clone();
    commit.stream_ref = CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    commit.event_ref = event.event_id.clone();
    commit.authority_ref = RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(
            &arkret_canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap(),
        )
        .unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(&fixture.governor.did_key_id).unwrap(),
        commit.committed_at,
        &SigningKey::from_bytes(&fixture.governor.did_key_seed),
    )
    .unwrap();
    CommittedEventFullView { event, commit }
}

fn bundle(
    fixture: &OrganizationFixture,
    original: &CommittedEventFullView,
    fact: &OrganizationGenesisSignerFact,
) -> (RealmAuthorityBundle, arkret_identity::RealmAuthorityKeyMap) {
    bundle_for_service(&fixture.governor, original, fact)
}

fn bundle_for_service(
    governor: &arkret_signatures::webvh::PreparedInception,
    original: &CommittedEventFullView,
    fact: &OrganizationGenesisSignerFact,
) -> (RealmAuthorityBundle, arkret_identity::RealmAuthorityKeyMap) {
    let service = detached_signature_service_id(&original.commit.signature).unwrap();
    let at = original.commit.committed_at;
    let method = DidUrl::new(&governor.did_key_id).unwrap();
    let key = SigningKey::from_bytes(&governor.did_key_seed);
    let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
        service.clone(),
        "station".into(),
        serde_json::from_value(governor.log_entry["state"].clone()).unwrap(),
        vec![governor.log_entry.clone()],
        vec![],
        at,
    )
    .unwrap();
    let head = CommitStreamHead {
        stream_ref: original.commit.stream_ref.clone(),
        stream_position: 0,
        commit_id: original.commit.commit_id.clone(),
    };
    let mut current = RealmAuthorityCurrentAssertion {
        realm_id: original.event.realm_id.clone(),
        current_generation: 0,
        current_service_id: service.clone(),
        last_handoff_ref: None,
        realm_stream_head: head.clone(),
        nonce: Base64UrlString::new("native-org-certificate-nonce").unwrap(),
        expires_at: at + Duration::seconds(30),
        signature: original.commit.signature.clone(),
    };
    current.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&current, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        method.clone(),
        at,
        &key,
    )
    .unwrap();
    let bundle = RealmAuthorityBundle {
        realm_id: original.event.realm_id.clone(),
        genesis_event: original.event.clone(),
        genesis_commit: original.commit.clone(),
        producer_signer_fact: Some(serde_json::to_value(fact).unwrap()),
        authority_transitions: vec![],
        current_generation: 0,
        current_service_id: service,
        current_route_record: serde_json::to_value(resolution).unwrap(),
        realm_stream_head: head,
        bundle_issued_at: at,
        current_assertion: current,
    };
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    keys.insert_at(
        &method,
        at,
        PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    );
    (bundle, keys)
}

fn verify(
    bundle: &RealmAuthorityBundle,
    keys: &arkret_identity::RealmAuthorityKeyMap,
) -> std::result::Result<
    arkret_identity::VerifiedRealmAuthority,
    arkret_identity::RealmAuthorityChainError,
> {
    arkret_identity::verify_realm_authority_bundle(
        bundle,
        &arkret_identity::RealmAuthorityFreshness::new(
            bundle.bundle_issued_at + Duration::seconds(1),
            bundle.current_assertion.nonce.clone(),
        ),
        keys,
    )
}

#[test]
fn real_service_finite_quorum_and_delegation_establish_only_the_original_governor() {
    for (delegated, quorum) in [(false, false), (false, true), (true, false)] {
        let fixture = OrganizationFixture::new(delegated, quorum);
        let fact = fact(&fixture);
        let original = cover(&fixture, &fact);
        let (bundle, keys) = bundle(&fixture, &original, &fact);
        let verified = verify(&bundle, &keys).unwrap();
        assert_eq!(verified.current_generation(), 0);
        assert_eq!(verified.current_service_id(), &bundle.current_service_id);
        let before = arkret_canonical::canonical_json_bytes(&fact).unwrap();
        let decoded: OrganizationGenesisSignerFact = serde_json::from_slice(&before).unwrap();
        assert_eq!(decoded, fact);
        assert_eq!(
            decoded.digest().unwrap(),
            original.commit.producer_signer_fact_digest.unwrap()
        );
    }
}

#[test]
fn a_governors_real_self_signatures_do_not_replace_missing_org_approval() {
    let fixture = OrganizationFixture::new(false, false);
    let mut source = fact(&fixture);
    source.approval_signatures = None;
    // G can sign the altered fact and its entire response, but cannot invent Org intent.
    let original = cover(&fixture, &source);
    let (bundle, keys) = bundle(&fixture, &original, &source);
    assert!(verify(&bundle, &keys).is_err());
}

#[test]
fn delegated_service_requires_its_independent_real_key_not_the_governors_key() {
    let mut fixture = OrganizationFixture::new(true, false);
    let mut event = fixture.write.request.event_submission.event.clone();
    event.producer_proof = None;
    let mut authored =
        AuthoredEvent::finalize_with_digest_suite(event, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(
            fixture.governor.did_key_seed,
            &fixture.producer.did_key_id,
        ),
        SignEventOptions::new().with_created_at(fixture.write.queued_at - Duration::seconds(2)),
    )
    .unwrap();
    fixture.write.request.event_submission.event = authored.into_event();
    let source = fact(&fixture);
    let original = cover(&fixture, &source);
    let (bundle, keys) = bundle(&fixture, &original, &source);
    assert!(verify(&bundle, &keys).is_err());
}

#[test]
fn finite_device_uses_original_minimal_key_after_exact_org_intent() {
    use arkret_test_kit::pcr_genesis::{HumanPcrFixtureInput, HumanPcrOriginalsFixture};
    let mut fixture = OrganizationFixture::new(false, false);
    let endpoint: url::Url = "https://native-org-executor.example/".parse().unwrap();
    let station = fixture.write.source_service_id.clone();
    let created_at = fixture.write.request.event_submission.event.created_at;
    let human = HumanPcrOriginalsFixture::webvh(HumanPcrFixtureInput {
        station_id: &station,
        endpoint: &endpoint,
        root_seed: [81; 32],
        next_root_seed: [82; 32],
        device_seed: [83; 32],
        device_hpke_private_key: [84; 32],
        device_id: DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(),
        genesis_salt: GenesisSalt::new(arkret_canonical::base64url_encode([85; 32])).unwrap(),
        created_at: created_at - Duration::seconds(1),
    })
    .unwrap();
    let mut event = fixture.write.request.event_submission.event.clone();
    event.executed_by = Some(ActorId::account(human.account.clone()));
    event.producer_proof = None;
    let mut authored =
        AuthoredEvent::finalize_with_digest_suite(event, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(
            human.device_signing_key.to_bytes(),
            human.device_verification_method.as_str(),
        ),
        SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    fixture.write.request.event_submission = EventAdmissionSubmission::new(authored.into_event());
    fixture.add_approval(
        33,
        DidUrl::new(format!("{}#organization-control", fixture.organization_did)).unwrap(),
        fixture.write.queued_at - Duration::seconds(1),
    );
    let mut source = fact(&fixture);
    source.producer_resolution = None;
    source.public_key_base64url = Some(
        Base64UrlString::new(arkret_canonical::base64url_encode(
            human.device_signing_key.verifying_key().to_bytes(),
        ))
        .unwrap(),
    );
    let original = cover(&fixture, &source);
    let (bundle, keys) = bundle(&fixture, &original, &source);
    verify(&bundle, &keys).unwrap();
    // These are genuine prepared Human originals, not a live accepted Device or session.
    arkret_identity::verify_pcr_genesis_events(
        &human.unit,
        &human.anchor,
        &ActorId::account(human.account),
    )
    .unwrap();
}

#[test]
fn original_cut_is_stable_and_two_role_or_null_carriers_fail_closed() {
    let mut fixture = OrganizationFixture::new(false, false);
    let source = fact(&fixture);
    let original = cover(&fixture, &source);
    let (bundle, keys) = bundle(&fixture, &original, &source);
    verify(&bundle, &keys).unwrap();
    let mut next = fixture.organization_state();
    next["arkret_governance"] = json!({"threshold":{"min_signature_count":1,"allowed_kids":[format!("{}#later-policy",fixture.organization_did)]}});
    fixture.append_organization_state(next, original.commit.committed_at + Duration::seconds(1));
    // Public verification never resolves today's policy or reconstructs the frozen fact.
    verify(&bundle, &keys).unwrap();
    let mut value = serde_json::to_value(&bundle).unwrap();
    value["producer_signer_fact"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<RealmAuthorityBundle>(value).is_err());
    let mut both = serde_json::to_value(&source).unwrap();
    both["public_key_base64url"] = json!(arkret_canonical::base64url_encode([91; 32]));
    let parsed: OrganizationGenesisSignerFact = serde_json::from_value(both).unwrap();
    assert!(parsed.validate().is_err());
    for field in [
        "approval_signatures",
        "producer_resolution",
        "public_key_base64url",
    ] {
        let mut row = serde_json::to_value(&source).unwrap();
        row[field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<OrganizationGenesisSignerFact>(row).is_err());
    }
    for field in [
        "organization_method_history_evidence",
        "producer_service_resolution",
    ] {
        let mut row = serde_json::to_value(&source).unwrap();
        row[field] = json!({});
        assert!(serde_json::from_value::<OrganizationGenesisSignerFact>(row).is_err());
    }
}

#[test]
fn another_real_governor_cannot_reseal_the_unchanged_org_selected_genesis() {
    for delegated in [false, true] {
        let fixture = OrganizationFixture::new(delegated, false);
        let source = fact(&fixture);
        let original = cover(&fixture, &source);
        let (legitimate, keys) = bundle(&fixture, &original, &source);
        verify(&legitimate, &keys).unwrap();
        let event_bytes = arkret_canonical::canonical_json_bytes(&original.event).unwrap();
        let source_bytes = arkret_canonical::canonical_json_bytes(&source).unwrap();
        let approvals =
            arkret_canonical::canonical_json_bytes(&source.approval_signatures).unwrap();

        // S is a different genuine native Service with its own independently
        // valid key/history. It did not become the G selected by this Event.
        let attacker = &fixture.producer;
        let attacker_method = DidUrl::new(&attacker.did_key_id).unwrap();
        let attacker_key = SigningKey::from_bytes(&attacker.did_key_seed);
        let material = PublicKeyMaterial::Ed25519Raw {
            bytes: attacker_key.verifying_key().to_bytes().to_vec(),
        };
        let mut forged = original.clone();
        forged.commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::unsigned_value(&forged.commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            attacker_method,
            forged.commit.committed_at,
            &attacker_key,
        )
        .unwrap();
        forged.commit.verify_commit_id_matches_content().unwrap();
        arkret_signatures::detached_object::verify_detached_object_signature(
            &forged.commit.signature,
            &arkret_canonical::unsigned_value(&forged.commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            &material,
        )
        .unwrap();
        let (forged_bundle, attacker_keys) = bundle_for_service(attacker, &forged, &source);
        arkret_signatures::detached_object::verify_detached_object_signature(
            &forged_bundle.current_assertion.signature,
            &arkret_canonical::unsigned_value(&forged_bundle.current_assertion, &["signature"])
                .unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            &material,
        )
        .unwrap();
        assert_ne!(
            forged_bundle.current_service_id,
            legitimate.current_service_id
        );
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&forged_bundle.genesis_event).unwrap(),
            event_bytes
        );
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&source).unwrap(),
            source_bytes
        );
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&source.approval_signatures).unwrap(),
            approvals
        );
        assert_eq!(
            forged.commit.producer_signer_fact_digest,
            original.commit.producer_signer_fact_digest
        );
        let error = source
            .validate_commit_binding(
                &forged,
                forged.event.event_id.digest_suite_code().digest_suite(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("governor selected"), "{error}");
        assert!(verify(&forged_bundle, &attacker_keys).is_err());
    }
}
