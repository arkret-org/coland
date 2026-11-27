// Included inside realm_actor_mls_fixture; all recipients are real accepted Devices.
async fn admission_authorize_recipient(
    fixture: &Fixture,
    candidate: &RealmActorCreatePayload,
    key_seed: u8,
    deadline: chrono::DateTime<chrono::Utc>,
) -> coland_storage::AppletManagedDeviceAuthority {
    let deadline = arkret_canonical::normalize_timestamp_canonical(deadline);
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .applet_realm_actor_creations(&fixture.realm, &candidate.applet_id, None)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.event.payload.get("actor_id") == Some(&json!(candidate.actor_id)))
        .unwrap();
    let device = boxed_step(|| {
        super::realm_native_fixture::authorize_obligation_device(
            fixture,
            candidate,
            &accepted.commit,
            key_seed,
            deadline,
        )
    })
    .await;
    fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap()
}

#[allow(
    clippy::too_many_arguments,
    reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit."
)]
async fn admission_add_boundary_recipient(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    source: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
    recipient: &coland_storage::AppletManagedDeviceAuthority,
    seed: &[u8; 32],
    lifetime: chrono::Duration,
) -> (
    arkret_mls::ArkretMlsIdentity,
    arkret_wire::MlsWelcomeDelivery,
    arkret_wire::CommittedEventFullView,
    KeyPackagesClaimResponseBody,
) {
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        recipient.actor_id.clone(),
        recipient.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(seed)),
    )
    .unwrap();
    let upload = admission_upload(&identity, recipient, seed, false);
    let reference = boxed_step(|| admission_native_upload(fixture, recipient, seed, &upload)).await;
    let mut request = admission_signed_claim(
        source,
        recipient,
        &candidate.creation_scope,
        &reference,
        false,
    );
    request.expires_at =
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now() + lifetime);
    let input = keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::RealmDevice {
        verification_method,
        signature,
        ..
    } = &mut request.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        verification_method.as_str(),
        &input,
    )
    .unwrap();
    request.validate_shape().unwrap();
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            source,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(request),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real signed recipient claim: {value}"
    );
    let claim: KeyPackagesClaimResponseBody = serde_json::from_value(value).unwrap();
    assert_eq!(claim.claim_receipt.request, request.unsigned_request());
    assert_eq!(claim.claims.len(), 1);
    assert_eq!(claim.claims[0].actor_id, recipient.actor_id);
    assert_eq!(
        claim.claims[0].device_id.as_ref(),
        Some(&recipient.device_id)
    );
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&candidate.creation_scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let binding = MlsGovernanceBindingPayload::new(
        candidate.creation_scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let added = group
        .add_member_with_governance_binding(
            &arkret_mls::mls_key_package_record_from_claim(&claim.claims[0]).unwrap(),
            &binding,
        )
        .unwrap();
    let payload = super::realm_actor_mls_fixture::commit_payload(
        fixture,
        group,
        current.current_mls_commit_event_ref.clone(),
        current.current_key_access_revision,
        &added.commit,
        binding,
    )
    .await
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[79; 32]),
        source.native_did.clone(),
        DidUrl::new(format!("{}#{}", source.native_did, source.device_id)).unwrap(),
    );
    let event = signed_event(
        package,
        candidate.actor_id.clone(),
        candidate.creation_scope.clone(),
        EventKind::MlsCommit,
        json!(payload),
        Some(child),
        &signer,
    );
    let at = event.created_at;
    let method = DidUrl::new(format!("{}#{}", source.native_did, source.device_id)).unwrap();
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: fixture.realm.clone(),
        effective_scope: candidate.creation_scope.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: recipient.actor_id.clone(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient.device_id.clone(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref,
        ciphertext_base64url: added.welcome.ciphertext_base64url,
        producer_proof: arkret_signatures::detached_object::sign_detached_object(
            &Value::Null,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            method.clone(),
            at,
            &SigningKey::from_bytes(&[79; 32]),
        )
        .unwrap(),
    };
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        method,
        at,
        &SigningKey::from_bytes(&[79; 32]),
    )
    .unwrap();
    let submission = SelfAuthoritySubmitRequestBody::MlsCommit(arkret_wire::MlsCommitSubmission {
        recovery_source: None,

        commit_event: event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    let (status, accepted) = boxed_step(|| {
        device_post(
            fixture,
            source,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(submission),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual native Add for independent handoff boundary: {accepted}"
    );
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let original = arkret_wire::CommittedEventFullView {
        event: original.event,
        commit: original.commit,
    };
    group.install_accepted_commit(&original, &current).unwrap();
    boxed_step(|| obligation_install_native_roster(fixture, source, &[79; 32], &original, group))
        .await;
    (identity, welcome, original, claim)
}

async fn admission_prepared_queue_boundaries(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    source: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    let authority = boxed_step(|| {
        admission_authorize_recipient(
            fixture,
            candidate,
            94,
            chrono::Utc::now() + chrono::Duration::minutes(15),
        )
    })
    .await;
    let (_identity, welcome, _original, claim) = boxed_step(|| {
        admission_add_boundary_recipient(
            fixture,
            package,
            candidate,
            source,
            child,
            group,
            &authority,
            &[94; 32],
            chrono::Duration::seconds(60),
        )
    })
    .await;
    boxed_step(|| {
        super::realm_native_fixture::native_prepared_queue_handoff_boundaries(
            fixture,
            &authority,
            &[94; 32],
            &welcome,
            claim.claim_receipt.expires_at,
        )
    })
    .await;
}

async fn admission_native_mls_writer_expiry(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    source: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    use diesel_async::{RunQueryDsl as _, SimpleAsyncConnection as _};
    #[derive(diesel::QueryableByName)]
    struct Pid {
        #[diesel(sql_type=diesel::sql_types::Integer)]
        pid: i32,
    }
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        waiting: bool,
    }
    #[derive(diesel::QueryableByName)]
    struct Nonce {
        #[diesel(sql_type=diesel::sql_types::Text)]
        nonce: String,
        #[diesel(sql_type=diesel::sql_types::Timestamptz)]
        consumed_at: chrono::DateTime<chrono::Utc>,
    }
    let deadline = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(45),
    );
    let authority =
        boxed_step(|| admission_authorize_recipient(fixture, candidate, 97, deadline)).await;
    let (identity, welcome, original, claim) = boxed_step(|| {
        admission_add_boundary_recipient(
            fixture,
            package,
            candidate,
            source,
            child,
            group,
            &authority,
            &[97; 32],
            chrono::Duration::minutes(4),
        )
    })
    .await;
    assert!(claim.claim_receipt.expires_at > deadline + chrono::Duration::minutes(2));
    let mut joined = Box::new(
        arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
            identity, &welcome, &original,
        )
        .unwrap(),
    );
    boxed_step(|| {
        obligation_install_native_roster(fixture, &authority, &[97; 32], &original, &mut joined)
    })
    .await;
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&candidate.creation_scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let binding = MlsGovernanceBindingPayload::new(
        candidate.creation_scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let update = joined
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let payload = super::realm_actor_mls_fixture::commit_payload(
        fixture,
        &joined,
        current.current_mls_commit_event_ref.clone(),
        current.current_key_access_revision,
        &update,
        binding,
    )
    .await
    .unwrap();
    let event = signed_event(
        package,
        candidate.actor_id.clone(),
        candidate.creation_scope.clone(),
        EventKind::MlsCommit,
        json!(payload),
        Some(child),
        &Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[97; 32]),
            authority.native_did.clone(),
            DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id)).unwrap(),
        ),
    );
    let request = SelfAuthoritySubmitRequestBody::MlsCommit(arkret_wire::MlsCommitSubmission {
        recovery_source: None,

        commit_event: event.clone(),
        welcomes: vec![],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    request.validate().unwrap();
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let mut holder = fixture.pool.get().await.unwrap();
    let key = 8_477_600_i64;
    // This is the real MLS state upsert after authentication/producer and
    // initial admission, not a Realm lock that could stop authentication.
    holder.batch_execute(&format!("CREATE FUNCTION test_native_mls_finalization_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.value->>'current_mls_commit_event_ref'=TG_ARGV[0] THEN PERFORM pg_advisory_xact_lock(TG_ARGV[1]::bigint); END IF; RETURN NEW; END $$; CREATE TRIGGER test_native_mls_finalization_wait AFTER INSERT OR UPDATE ON mls_group_current_states FOR EACH ROW EXECUTE FUNCTION test_native_mls_finalization_wait('{}','{}');",event.event_id.as_str().replace('\'',"''"),key)).await.unwrap();
    let prior=diesel::sql_query("SELECT nonce,consumed_at FROM applet_managed_device_nonces WHERE actor_id=$1 AND device_id=$2")
        .bind::<diesel::sql_types::Jsonb,_>(json!(authority.actor_id)).bind::<diesel::sql_types::Text,_>(authority.device_id.as_str())
        .load::<Nonce>(&mut holder).await.unwrap();
    holder.batch_execute("BEGIN").await.unwrap();
    let pid = diesel::sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Pid>(&mut holder)
        .await
        .unwrap()
        .pid;
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<diesel::sql_types::BigInt, _>(key)
        .execute(&mut holder)
        .await
        .unwrap();
    let post = obligation_recipient_post(
        fixture,
        &authority,
        &[97; 32],
        "/_arkret/self/events",
        ServiceOperationId::SelfEventsCommandSubmitV1,
        json!(request),
    );
    let gate = async {
        let mut observer = fixture.pool.get().await.unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let observed = loop {
            let row=diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND $1=ANY(pg_blocking_pids(a.pid)) AND a.query ILIKE '%INSERT INTO mls_group_current_states%' AND a.wait_event_type='Lock' AND a.wait_event='advisory') AS waiting")
                .bind::<diesel::sql_types::Integer,_>(pid).get_result::<Waiting>(&mut observer).await.unwrap();
            if row.waiting {
                break true;
            }
            if std::time::Instant::now() >= until || chrono::Utc::now() >= deadline {
                break false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        let nonces=diesel::sql_query("SELECT nonce,consumed_at FROM applet_managed_device_nonces WHERE actor_id=$1 AND device_id=$2")
            .bind::<diesel::sql_types::Jsonb,_>(json!(authority.actor_id)).bind::<diesel::sql_types::Text,_>(authority.device_id.as_str())
            .load::<Nonce>(&mut observer).await.unwrap();
        let fresh = nonces
            .iter()
            .filter(|n| !prior.iter().any(|p| p.nonce == n.nonce))
            .collect::<Vec<_>>();
        let authenticated = observed
            && chrono::Utc::now() < deadline
            && fresh.len() == 1
            && fresh[0].consumed_at < deadline;
        drop(observer);
        if observed {
            tokio::time::sleep(
                (deadline - chrono::Utc::now()).to_std().unwrap_or_default()
                    + std::time::Duration::from_millis(80),
            )
            .await;
        }
        holder.batch_execute("ROLLBACK").await.unwrap();
        (observed, authenticated)
    };
    let (outcome, (observed, authenticated)) = tokio::join!(
        tokio::time::timeout(std::time::Duration::from_secs(75), post),
        gate
    );
    holder.batch_execute("DROP TRIGGER test_native_mls_finalization_wait ON mls_group_current_states; DROP FUNCTION test_native_mls_finalization_wait();").await.unwrap();
    drop(holder);
    assert!(
        observed,
        "native MLS Event must reach its actual state writer before expiry"
    );
    assert!(
        authenticated,
        "real HTTP native nonce/current authentication must precede the actual writer wait"
    );
    let (status, problem) =
        outcome.expect("actual native MLS Event must terminate after owned writer lock release");
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expired Device after actual native MLS Event writer: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/device_unauthorized"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before,
        "Event/Commit/current/quota/queue all roll back at final physical cut"
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(group.epoch(), current.epoch);
}
