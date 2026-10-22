//! Backend attempt-budget contracts. These do not claim that a fixture Device
//! or Agent has accepted authorization, or that any KeyPackage was claimed.

use arkret_models_crypto::{PeerKeyPackageRequesterAuthorization, PeerKeyPackagesClaimRequestBody};
use coland_storage::{MlsKeyPackageStore, PeerKeyPackageClaimRateDecision as Decision};
use coland_storage_postgres::{PgMlsKeyPackageStore, PgPool};
use diesel_async::RunQueryDsl;
use ed25519_dalek::{Signer as _, SigningKey};

fn account(principal: &str, station: &str) -> arkret_wire::AccountId {
    arkret_wire::AccountId {
        principal_id: arkret_wire::DidCoreId::new(format!("ak:did_core:web:{principal}.example"))
            .unwrap(),
        station_id: arkret_wire::DidCoreId::new(format!("ak:did_core:web:{station}.example"))
            .unwrap(),
    }
}

fn request(
    requester: arkret_wire::AccountId,
    target: arkret_wire::AccountId,
) -> PeerKeyPackagesClaimRequestBody {
    let signed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let method = format!(
        "did:{}#ak:device:01964137-0000-7000-8000-000000000002",
        requester
            .principal_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .unwrap()
    );
    let event = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"budget-component-authorization-shape"),
    );
    let realm = arkret_wire::RealmId::from_event_id(&event);
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let mut body = PeerKeyPackagesClaimRequestBody {
        claim_request_id: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            [
                uuid::Uuid::new_v4().into_bytes(),
                uuid::Uuid::new_v4().into_bytes(),
            ]
            .concat(),
        ))
        .unwrap(),
        service_binding: arkret_models_crypto::KeyPackagesClaimServiceBinding {
            source_id: requester.station_id.clone(),
            destination_id: target.station_id.clone(),
        },
        target_account_id: Some(target),
        target_actor_id: None,
        requester_account_id: Some(requester),
        requester_actor_id: None,
        intended_realm_id: realm,
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        claim_purpose: arkret_models_crypto::PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: vec![arkret_wire::NonEmptyString::new("ak.content.v1").unwrap()],
        expires_at: signed_at + chrono::Duration::minutes(4),
        target_device_ids: vec![
            arkret_wire::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap(),
        ],
        target_keypackage_ref: None,
        target_agent_id: None,
        target_agent_verification_method: None,
        target_agent_key_authorize_event_id: None,
        timeout_ms: None,
        strand_id: None,
        pair_key: None,
        last_resort_allowed: None,
        requester_authorization: PeerKeyPackageRequesterAuthorization::Device {
            verification_method: arkret_wire::DidUrl::new(&method).unwrap(),
            requester_device_id: arkret_wire::DeviceId::new(
                "ak:device:01964137-0000-7000-8000-000000000002",
            )
            .unwrap(),
            device_authorize_event_id: event,
            signed_at,
            signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
                &method, &[0; 64],
            )
            .unwrap(),
        },
    };
    resign(&mut body, &SigningKey::from_bytes(&[171; 32]));
    body
}

fn resign(body: &mut PeerKeyPackagesClaimRequestBody, key: &SigningKey) {
    let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        &body.requester_authorization,
    )
    .unwrap();
    let (method, signature) = match &mut body.requester_authorization {
        PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            signature,
            ..
        }
        | PeerKeyPackageRequesterAuthorization::Agent {
            verification_method,
            signature,
            ..
        }
        | PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method,
            signature,
            ..
        } => (verification_method, signature),
    };
    *signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
        method.as_str(),
        &key.sign(&bytes).to_bytes(),
    )
    .unwrap();
    body.validate_shape().unwrap();
}

async fn attempts(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM keypackage_claim_attempts")
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn limited_attempts(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM keypackage_claim_attempts WHERE rejection_reason='keypackage_claim_rate_limited'").get_result::<Count>(&mut *conn).await.unwrap().count
}

#[tokio::test]
async fn realm_requester_retains_exact_original_even_without_an_allocated_package() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let worker = PgMlsKeyPackageStore { pool: pool.clone() };
    let mut body = request(
        account("requester", "source"),
        account("target", "destination"),
    );
    let PeerKeyPackageRequesterAuthorization::Device {
        requester_device_id,
        device_authorize_event_id,
        signed_at,
        ..
    } = body.requester_authorization.clone()
    else {
        unreachable!()
    };
    let method = format!(
        "did:webvh:zRealmRequesterFixture:requester.example#{}",
        requester_device_id
    );
    body.requester_authorization = PeerKeyPackageRequesterAuthorization::RealmDevice {
        verification_method: arkret_wire::DidUrl::new(&method).unwrap(),
        requester_device_id,
        device_authorize_event_id,
        signed_at,
        signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
            &method, &[0; 64],
        )
        .unwrap(),
    };
    body.requester_account_id = None;
    body.requester_actor_id = Some(arkret_wire::ActorId::realm(arkret_wire::RealmActorId::new(
        body.intended_realm_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:webvh:zRealmRequesterFixture").unwrap(),
    )));
    resign(&mut body, &SigningKey::from_bytes(&[171; 32]));
    assert_eq!(
        worker.record_peer_claim_attempt(&body).await.unwrap(),
        Decision::Allowed
    );
    let digest = arkret_canonical::canonical_sha256(&body).unwrap();
    let original = worker
        .peer_claim_original(body.claim_request_id.as_str(), &digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&original).unwrap(),
        arkret_canonical::canonical_json_bytes(&body).unwrap()
    );
    assert!(
        worker
            .get_peer_claim(
                body.service_binding.source_id.as_str(),
                body.claim_request_id.as_str()
            )
            .await
            .unwrap()
            .is_none()
    );
    let mut changed = body.clone();
    changed.timeout_ms = Some(1);
    resign(&mut changed, &SigningKey::from_bytes(&[171; 32]));
    assert_eq!(
        worker.record_peer_claim_attempt(&changed).await.unwrap(),
        Decision::DuplicateConflict
    );
    assert!(
        worker
            .peer_claim_original(
                body.claim_request_id.as_str(),
                &arkret_canonical::canonical_sha256(&changed).unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    let mut conn = pool.get().await.unwrap();
    // A source recovery row and an ordinary recipient row may coexist on one
    // Station. This fixture tests persistence ownership, not Device admission.
    diesel::sql_query("INSERT INTO realm_keypackage_claim_sources(source_id,claim_request_id,request_digest,request_body,governing_realm_id) VALUES($1,$2,$3,$4,$5)")
        .bind::<diesel::sql_types::Text,_>(body.service_binding.source_id.as_str())
        .bind::<diesel::sql_types::Text,_>(body.claim_request_id.as_str())
        .bind::<diesel::sql_types::Text,_>(&digest)
        .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(&body).unwrap())
        .bind::<diesel::sql_types::Text,_>(body.intended_realm_id.as_str())
        .execute(&mut *conn).await.unwrap();
    drop(conn);
    let source = worker
        .realm_claim_source(
            body.service_binding.source_id.as_str(),
            body.claim_request_id.as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(source.result.is_none());
    assert_eq!(
        serde_json::to_value(&source.request).unwrap(),
        serde_json::to_value(&body).unwrap()
    );
    assert!(
        worker
            .peer_claim_original(body.claim_request_id.as_str(), &digest)
            .await
            .unwrap()
            .is_some(),
        "identical source and recipient originals are one original, not ambiguous"
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE keypackage_claim_sources SET request_body=jsonb_set(request_body,'{timeout_ms}','2'::jsonb)")
        .execute(&mut *conn).await.unwrap();
    assert!(
        worker
            .peer_claim_original(body.claim_request_id.as_str(), &digest)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_terminal_receipts_return_the_first_durable_bytes() {
    use coland_storage::PeerKeyPackageClaimLedgerRecord;
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let first = PgMlsKeyPackageStore { pool: pool.clone() };
    let second = PgMlsKeyPackageStore { pool };
    // This is a persistence race test, not a claim-signature admission fixture.
    let row = PeerKeyPackageClaimLedgerRecord {
        source_id: "ak:did_core:web:source.example".into(),
        claim_request_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        request_digest: format!("sha256:{}", "a".repeat(64)),
        key_package_use: "single_use".into(),
        keypackage_id: None,
        outcome: Some(serde_json::json!({"original":"unchanged"})),
        terminal_receipt: None,
        consume_receipt: None,
        claim_expires_at_unix_ms: Some(1000),
        expires_at: 10000,
        state: "expired".into(),
        updated_at: 1,
    };
    first.record_peer_claim_terminal(&row).await.unwrap();
    let a = serde_json::json!({"signature":"first-candidate"});
    let b = serde_json::json!({"signature":"second-candidate"});
    let (left, right) = tokio::join!(
        first.attach_peer_claim_terminal_receipt(
            &row.source_id,
            &row.claim_request_id,
            &row.request_digest,
            &a,
            2
        ),
        second.attach_peer_claim_terminal_receipt(
            &row.source_id,
            &row.claim_request_id,
            &row.request_digest,
            &b,
            3
        ),
    );
    let left = left.unwrap().unwrap();
    let right = right.unwrap().unwrap();
    assert_eq!(left, right);
    let replay = second
        .attach_peer_claim_terminal_receipt(
            &row.source_id,
            &row.claim_request_id,
            &row.request_digest,
            &serde_json::json!({"signature":"later-key"}),
            4,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay, left);
    assert_eq!(replay.outcome, row.outcome);
    assert!(
        second
            .attach_peer_claim_terminal_receipt(
                &row.source_id,
                &row.claim_request_id,
                "wrong-digest",
                &a,
                5
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_workers_share_requester_budget_before_any_claim_outcome() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut commands = Vec::new();
    let mut tasks = Vec::new();
    for index in 0..6 {
        let body = request(
            account("same-requester", "source"),
            account(&format!("target-{index}"), "destination"),
        );
        commands.push(body.clone());
        let worker = PgMlsKeyPackageStore { pool: pool.clone() };
        tasks.push(tokio::spawn(async move {
            worker.record_peer_claim_attempt(&body).await.unwrap()
        }));
    }
    let mut allowed = 0;
    let mut limited = 0;
    let worker = PgMlsKeyPackageStore { pool: pool.clone() };
    for (command, task) in commands.iter().zip(tasks) {
        let decision = task.await.unwrap();
        match decision {
            Decision::Allowed => allowed += 1,
            Decision::RateLimited => limited += 1,
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            worker.record_peer_claim_attempt(command).await.unwrap(),
            decision,
            "a second worker must recover the original decision even before a business ledger exists"
        );
        let mut changed = command.clone();
        changed.timeout_ms = Some(1);
        resign(&mut changed, &SigningKey::from_bytes(&[171; 32]));
        assert_eq!(
            worker.record_peer_claim_attempt(&changed).await.unwrap(),
            Decision::DuplicateConflict
        );
        assert!(
            worker
                .get_peer_claim(
                    command.service_binding.source_id.as_str(),
                    command.claim_request_id.as_str()
                )
                .await
                .unwrap()
                .is_none(),
            "a budget decision is not a fabricated claim ledger fact"
        );
    }
    assert_eq!((allowed, limited), (5, 1));
    assert_eq!(
        attempts(&pool).await,
        6,
        "retries and digest conflicts never charge twice"
    );
    assert_eq!(
        limited_attempts(&pool).await,
        1,
        "the registered reason remains in the private audit record"
    );
    for index in 0..5 {
        let body = request(
            account("same-requester", "another-source"),
            account(&format!("other-target-{index}"), "destination"),
        );
        assert_eq!(
            worker.record_peer_claim_attempt(&body).await.unwrap(),
            Decision::Allowed,
            "same principal on another Station has an independent Account budget"
        );
    }
    assert!(
        worker.snapshot_all().await.unwrap().is_empty(),
        "attempt accounting cannot fabricate a KeyPackage or receipt"
    );
}

#[tokio::test]
async fn target_budget_spans_sources_but_keeps_the_complete_target_account() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let worker = PgMlsKeyPackageStore { pool: pool.clone() };
    for index in 0..6 {
        let body = request(
            account("requester", &format!("source-{index}")),
            account("same-target", "destination-a"),
        );
        assert_eq!(
            worker.record_peer_claim_attempt(&body).await.unwrap(),
            if index < 5 {
                Decision::Allowed
            } else {
                Decision::RateLimited
            },
            "rotating Source Service cannot reset the target's budget"
        );
    }
    for index in 0..5 {
        let body = request(
            account("requester", &format!("source-{index}")),
            account("same-target", "destination-b"),
        );
        assert_eq!(
            worker.record_peer_claim_attempt(&body).await.unwrap(),
            Decision::Allowed,
            "another Station's target Account is not merged by principal component"
        );
    }
}

fn agent_request(
    index: u8,
    target_agent: &str,
    requester_agent: &str,
) -> PeerKeyPackagesClaimRequestBody {
    let mut body = request(
        account("placeholder", "source"),
        account("placeholder", "destination"),
    );
    let event = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes([index]),
    );
    let method = format!("did:web:{requester_agent}.example#runtime-{index}");
    let signed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    body.requester_account_id = None;
    body.requester_authorization = PeerKeyPackageRequesterAuthorization::Agent {
        verification_method: arkret_wire::DidUrl::new(&method).unwrap(),
        requester_agent_id: arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:{requester_agent}.example"
        ))
        .unwrap(),
        agent_key_authorize_event_id: event.clone(),
        signed_at,
        signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
            &method, &[0; 64],
        )
        .unwrap(),
    };
    body.target_account_id = None;
    body.target_device_ids.clear();
    body.target_agent_id = Some(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{target_agent}.example")).unwrap(),
    );
    body.target_agent_verification_method = Some(
        arkret_wire::DidUrl::new(format!("did:web:{target_agent}.example#runtime-{index}"))
            .unwrap(),
    );
    body.target_agent_key_authorize_event_id = Some(event);
    resign(&mut body, &SigningKey::from_bytes(&[index + 1; 32]));
    body
}

#[tokio::test]
async fn agent_branch_identity_survives_runtime_key_and_method_rotation() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let worker = PgMlsKeyPackageStore { pool: pool.clone() };
    for index in 0..6 {
        let body = agent_request(index, &format!("target-{index}"), "same-requester");
        assert_eq!(
            worker.record_peer_claim_attempt(&body).await.unwrap(),
            if index < 5 {
                Decision::Allowed
            } else {
                Decision::RateLimited
            }
        );
    }
    for index in 0..6 {
        let body = agent_request(index, "same-target", &format!("requester-{index}"));
        assert_eq!(
            worker.record_peer_claim_attempt(&body).await.unwrap(),
            if index < 5 {
                Decision::Allowed
            } else {
                Decision::RateLimited
            }
        );
    }
}

#[tokio::test]
async fn database_clock_controls_attempt_window_and_expired_rows_are_pruned() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let worker = PgMlsKeyPackageStore { pool: pool.clone() };
    for index in 0..5 {
        let body = request(
            account("requester", "source"),
            account(&format!("target-{index}"), "destination"),
        );
        assert_eq!(
            worker.record_peer_claim_attempt(&body).await.unwrap(),
            Decision::Allowed
        );
    }
    let mut old_signed = request(
        account("requester", "source"),
        account("fresh-target", "destination"),
    );
    let PeerKeyPackageRequesterAuthorization::Device { signed_at, .. } =
        &mut old_signed.requester_authorization
    else {
        unreachable!()
    };
    *signed_at -= chrono::Duration::seconds(61);
    old_signed.expires_at = *signed_at + chrono::Duration::minutes(4);
    resign(&mut old_signed, &SigningKey::from_bytes(&[171; 32]));
    assert_eq!(
        worker.record_peer_claim_attempt(&old_signed).await.unwrap(),
        Decision::RateLimited,
        "a caller timestamp cannot make the database's six current attempts span different windows"
    );
    let mut expired = request(
        account("expired-requester", "source"),
        account("expired-target", "destination"),
    );
    let PeerKeyPackageRequesterAuthorization::Device { signed_at, .. } =
        &mut expired.requester_authorization
    else {
        unreachable!()
    };
    *signed_at -= chrono::Duration::minutes(5);
    expired.expires_at = *signed_at + chrono::Duration::minutes(4);
    resign(&mut expired, &SigningKey::from_bytes(&[171; 32]));
    assert_eq!(
        worker.record_peer_claim_attempt(&expired).await.unwrap(),
        Decision::Unavailable
    );
    assert_eq!(attempts(&pool).await, 6);
    assert_eq!(
        worker.prune_peer_claim_attempts().await.unwrap(),
        0,
        "current retry decisions remain durable"
    );
    let mut conn = pool.get().await.unwrap();
    // Advance only the private counter fixture's retention metadata. No
    // Account/PCR/claim/KeyPackage fact is manufactured or rewritten.
    diesel::sql_query("UPDATE keypackage_claim_attempts SET attempted_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '1 second'").execute(&mut *conn).await.unwrap();
    drop(conn);
    assert_eq!(worker.prune_peer_claim_attempts().await.unwrap(), 6);
    assert_eq!(attempts(&pool).await, 0);
    assert!(worker.snapshot_all().await.unwrap().is_empty());
}
