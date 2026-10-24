#[path = "../../test-support/src/device_authorization_history.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared device history fixture."
)]
mod device_history_fixture;

use arkret_identity::build_authenticated_webvh_service_resolution;
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizePayload, device_authorize_payload_digest,
};
use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput;
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestationCore, DeviceStatus,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_models_identity::{
    AccountDeviceSignerEvidence, IdentityBindingPurpose, IdentityCreationControlProofKind,
    PCR_GENESIS_UNIT_KINDS, UnsignedIdentityCreationControlProof,
    UnsignedIdentityCreationControlProofBody,
};
use arkret_signatures::device_projection::sign_device_projection_attestation;
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception,
};
use arkret_wire::{
    AccountId, CommittedEventRef, DeviceId, Did, DidCoreId, DidKey, DidUrl, Hash, IdempotencyKey,
    NonEmptyString, PcrGenesisUnit, RealmCommitAuthorityRef, ServiceKind, TrustDomainId, WebOrigin,
};
use chrono::{Duration, Utc};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority, PcrGenesisCommitUnit,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAccountDeviceSignerEvidenceArchive, PgAuthorityCommitStore};
use device_history_fixture::{DeviceHistoryFixture, DeviceHistoryFixtureOptions};
use diesel::sql_types::{BigInt, Text};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn hash(value: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(value.as_bytes())).unwrap()
}

fn genesis_unit(station: DidCoreId, fixture: &DeviceHistoryFixture) -> PcrGenesisCommitUnit {
    let created_at = fixture.commits[0].committed_at;
    let evidence = arkret_signatures::webvh::sign_registration_did_evidence_draft(
        &fixture.inception,
        created_at,
        &[70; 32],
    )
    .unwrap()
    .accept(created_at)
    .unwrap();
    let create = fixture.events[0].clone();
    let authorize = fixture.events[1].clone();
    let authorize_value =
        serde_json::Value::Object(authorize.payload.clone().into_iter().collect());
    let create_digest =
        Hash::new(arkret_canonical::canonical_sha256(&create.payload).unwrap()).unwrap();
    let authorize_digest =
        device_authorize_payload_digest(&authorize_value, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    let proof = arkret_signatures::webvh::sign_identity_creation_control_proof(
        UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
            proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
            challenge_id: "fixture-challenge".into(),
            challenge: "fixture-challenge-value".into(),
            purpose: IdentityBindingPurpose::AccountBindingAndPcrGenesis,
            account_subject: hash("fixture-account"),
            principal_id: fixture.account.principal_id.clone(),
            did: fixture.did.clone(),
            registration_anchor_digest: fixture.registration_anchor.canonical_digest().unwrap(),
            did_version_id: evidence.version_id.clone(),
            control_key_digest: evidence.control_key_digest.clone(),
            pcr_realm_id: create.realm_id.clone(),
            realm_create_payload_digest: create_digest,
            founding_authorize_payload_digest: authorize_digest,
            initial_session_request_digest: hash("fixture-initial-session"),
            genesis_unit_kinds: PCR_GENESIS_UNIT_KINDS,
            identity_creation_lease_id: "fixture-lease".into(),
            lease_fence: 1,
            dpop_jkt: "fixture-thumbprint".into(),
            audience_id: station.clone(),
            origin: WebOrigin::new("https://principal.example").unwrap(),
            trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            issued_at: created_at,
            expires_at: created_at + Duration::minutes(5),
            verification_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &SigningKey::from_bytes(&[70; 32]).verifying_key().to_bytes(),
            ),
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        })
        .unwrap(),
        &[70; 32],
    )
    .unwrap();
    let submission = PcrGenesisAdmissionInput {
        account_authority_id: station.clone(),
        principal_id: fixture.account.principal_id.clone(),
        did: fixture.did.clone(),
        pcr_realm_id: create.realm_id.clone(),
        did_version_id: evidence.version_id.clone(),
        control_key_digest: evidence.control_key_digest.clone(),
        idempotency_key: IdempotencyKey::new(uuid::Uuid::now_v7().to_string()).unwrap(),
        registration_request_digest: hash("fixture-registration"),
        principal_registration_anchor: fixture.registration_anchor.clone(),
        registration_did_evidence: evidence,
        identity_creation_control_proof: proof,
        genesis_unit: PcrGenesisUnit {
            events: [create.clone(), authorize.clone()],
        },
    };
    let authority = CurrentRealmAuthority {
        realm_id: create.realm_id.clone(),
        generation: 0,
        service_id: station,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(create.event_id.clone()),
        last_handoff_ref: None,
    };
    let transactions = [
        (create, fixture.commits[0].clone()),
        (authorize, fixture.commits[1].clone()),
    ]
    .map(|(event, commit)| AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        event,
        commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    });
    let exact_request_body = serde_json::to_vec(&submission).unwrap();
    PcrGenesisCommitUnit {
        submission,
        exact_request_body,
        transactions,
    }
}

#[tokio::test]
async fn exact_signed_root_is_immutable_and_scoped_after_real_pcr_genesis() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let inception_at: chrono::DateTime<Utc> = "2026-09-11T00:00:00Z".parse().unwrap();
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new("https://station.example/").unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_created_at: inception_at,
            did_key_fragment: None,
        },
    )
    .unwrap();
    let station_did = Did::new(inception.did.clone()).unwrap();
    let station = arkret_wire::project_did_to_core_id(&station_did).unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(station.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let fixture = DeviceHistoryFixture::new_with(
        station_did.clone(),
        DeviceHistoryFixtureOptions {
            local_id: format!("evidence-{}", uuid::Uuid::now_v7().simple()),
            ..Default::default()
        },
    );
    let unit = genesis_unit(station.clone(), &fixture);
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&unit, fixture.commits[0].committed_at)
        .await
        .unwrap();
    let source: CommittedEventRef = CommittedEventRef {
        event_id: fixture.events[1].event_id.clone(),
        commit_id: fixture.commits[1].commit_id.clone(),
        stream_ref: fixture.commits[1].stream_ref.clone(),
        stream_position: fixture.commits[1].stream_position,
    };
    let payload: DeviceAuthorizePayload = serde_json::from_value(serde_json::Value::Object(
        fixture.events[1].payload.clone().into_iter().collect(),
    ))
    .unwrap();
    let attested_at: chrono::DateTime<Utc> = "2026-09-24T00:00:00Z".parse().unwrap();
    let service_resolution = build_authenticated_webvh_service_resolution(
        station.clone(),
        "station".into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        attested_at,
    )
    .unwrap();
    let attestation = sign_device_projection_attestation(
        DeviceProjectionAttestationCore {
            account_id: fixture.account.clone(),
            device_id: fixture.founding_device_id.clone(),
            device_signing_key_did: DidKey::new(payload.device_public_key_did.as_str()).unwrap(),
            hpke_key: NonEmptyString::new(payload.hpke_key.as_str()).unwrap(),
            device_authorize_event_id: source.event_id.clone(),
            authorized_generation_ref: 1,
            device_status: DeviceStatus::Active,
            authorization_window: DeviceAuthorizationWindow {
                not_before: payload.not_before,
                expires_at: None,
            },
            attested_at,
            expires_at: attested_at + Duration::minutes(5),
        },
        DidUrl::new(inception.did_key_id.clone()).unwrap(),
        &SigningKey::from_bytes(&inception.did_key_seed),
    )
    .unwrap();
    let evidence = AccountDeviceSignerEvidence {
        device_projection_attestation: attestation,
        service_resolution,
    };
    let archive = PgAccountDeviceSignerEvidenceArchive::new(pool.clone());
    // Hold both inserts after their repeatable-read cuts have been observed.
    // Releasing them forces the second identical root to cross a concurrent
    // commit. Its retry must revalidate the entire accepted/current closure.
    let mut barrier = pool.get().await.unwrap();
    barrier
        .batch_execute(
            "CREATE FUNCTION hold_evidence_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN PERFORM pg_advisory_xact_lock(19390001); RETURN NEW; END $$; \
         CREATE TRIGGER hold_evidence_insert BEFORE INSERT ON account_device_signer_evidence \
         FOR EACH ROW EXECUTE FUNCTION hold_evidence_insert(); \
         SELECT pg_advisory_lock(19390001)",
        )
        .await
        .unwrap();
    let mut jobs = Vec::new();
    for _ in 0..2 {
        let archive = archive.clone();
        let evidence = evidence.clone();
        let source = source.clone();
        jobs.push(tokio::spawn(async move {
            archive.retain_current(&evidence, &source).await
        }));
    }
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let both_waiting = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting = diesel::sql_query(
                "SELECT count(*)::bigint AS count FROM pg_stat_activity \
                 WHERE datname=current_database() AND wait_event='advisory' \
                 AND pid<>pg_backend_pid()",
            )
            .get_result::<Waiting>(&mut barrier)
            .await
            .unwrap();
            if waiting.count == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    barrier
        .batch_execute("SELECT pg_advisory_unlock(19390001)")
        .await
        .unwrap();
    let mut outcomes = Vec::new();
    for job in jobs {
        outcomes.push(job.await.unwrap());
    }
    barrier
        .batch_execute(
            "DROP TRIGGER hold_evidence_insert ON account_device_signer_evidence; \
         DROP FUNCTION hold_evidence_insert()",
        )
        .await
        .unwrap();
    both_waiting.expect("both identical roots observed their cuts before the first commit");
    for outcome in outcomes {
        assert_eq!(outcome.unwrap(), evidence.signer_evidence_ref().unwrap());
    }
    let reference_value = serde_json::to_value(evidence.signer_evidence_ref().unwrap()).unwrap();
    let rows = diesel::sql_query(
        "SELECT count(*)::bigint AS count FROM account_device_signer_evidence WHERE evidence_ref=$1",
    ).bind::<Text, _>(reference_value.as_str().unwrap())
        .get_result::<Waiting>(&mut barrier).await.unwrap();
    assert_eq!(
        rows.count, 1,
        "concurrent identical roots have one immutable row"
    );
    drop(barrier);
    let reference = archive.retain(&evidence, &source).await.unwrap();
    assert_eq!(
        archive.retain_current(&evidence, &source).await.unwrap(),
        reference
    );
    assert_eq!(archive.retain(&evidence, &source).await.unwrap(), reference);
    let restored = archive
        .get(&fixture.account, &fixture.founding_device_id, &reference)
        .await
        .unwrap()
        .expect("accepted evidence is retained");
    assert_eq!(restored.signer_evidence_ref().unwrap(), reference);
    assert_eq!(
        arkret_canonical::canonical::canonical_json_bytes(&restored).unwrap(),
        arkret_canonical::canonical::canonical_json_bytes(&evidence).unwrap()
    );
    let other_account = AccountId::new(
        DidCoreId::new("ak:did_core:webvh:z6mkother").unwrap(),
        station,
    );
    assert!(
        archive
            .get(&other_account, &fixture.founding_device_id, &reference)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        archive
            .get(
                &fixture.account,
                &DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap(),
                &reference
            )
            .await
            .unwrap()
            .is_none()
    );
    let mut wrong_source = source.clone();
    wrong_source.stream_position += 1;
    assert!(archive.retain(&evidence, &wrong_source).await.is_err());
    let mut check = pool.get().await.unwrap();
    check
        .batch_execute(
            "CREATE SEQUENCE evidence_retention_attempts; \
         CREATE FUNCTION fail_evidence_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN PERFORM nextval('evidence_retention_attempts'); \
         RAISE EXCEPTION 'fixture serialization cut' USING ERRCODE='40001'; END $$; \
         CREATE TRIGGER fail_evidence_insert BEFORE INSERT ON account_device_signer_evidence \
         FOR EACH ROW EXECUTE FUNCTION fail_evidence_insert()",
        )
        .await
        .unwrap();
    let error = archive
        .retain_current(&evidence, &wrong_source)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no exact accepted PCR authorization Commit")
    );
    let attempts = diesel::sql_query(
        "SELECT (CASE WHEN is_called THEN last_value ELSE 0 END)::bigint AS count \
         FROM evidence_retention_attempts",
    )
    .get_result::<Waiting>(&mut check)
    .await
    .unwrap();
    assert_eq!(
        attempts.count, 0,
        "invalid authority never reaches insertion or retries"
    );
    let error = archive
        .retain_current(&evidence, &source)
        .await
        .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::TemporarilyUnavailable)
    );
    let attempts =
        diesel::sql_query("SELECT last_value::bigint AS count FROM evidence_retention_attempts")
            .get_result::<Waiting>(&mut check)
            .await
            .unwrap();
    assert_eq!(
        attempts.count, 3,
        "serialization retries have a closed budget"
    );
    check
        .batch_execute(
            "DROP TRIGGER fail_evidence_insert ON account_device_signer_evidence; \
         DROP FUNCTION fail_evidence_insert(); DROP SEQUENCE evidence_retention_attempts",
        )
        .await
        .unwrap();
    drop(check);
    let unchanged = archive
        .get(&fixture.account, &fixture.founding_device_id, &reference)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(unchanged).unwrap(),
        serde_json::to_value(&evidence).unwrap()
    );
    let mut forged = evidence.clone();
    forged
        .device_projection_attestation
        .attestation
        .authorized_generation_ref = 2;
    assert!(archive.retain(&forged, &source).await.is_err());

    // This is a genuine origin signature over the wrong device key. Its
    // cryptography succeeds, but the accepted authority Event did not grant it.
    let mut wrong_key_core = evidence.device_projection_attestation.attestation.clone();
    wrong_key_core.device_signing_key_did = DidKey::new(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[44; 32]).verifying_key().to_bytes(),
        )
    ))
    .unwrap();
    let wrong_key_attestation = sign_device_projection_attestation(
        wrong_key_core,
        DidUrl::new(inception.did_key_id.clone()).unwrap(),
        &SigningKey::from_bytes(&inception.did_key_seed),
    )
    .unwrap();
    let wrong_key_evidence = AccountDeviceSignerEvidence {
        device_projection_attestation: wrong_key_attestation,
        service_resolution: evidence.service_resolution.clone(),
    };
    let error = archive
        .retain(&wrong_key_evidence, &source)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("differs from accepted authorization payload")
    );
}
