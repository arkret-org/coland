//! Real accepted managed Device origins; no remote business acceptance is implied.
use diesel_async::SimpleAsyncConnection as _;

use super::*;

fn destination() -> arkret_wire::DidCoreId {
    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
    use arkret_signatures::webvh::{
        ServiceRegistrationInceptionInput, prepare_service_registration_inception,
    };
    use rand_chacha::rand_core::SeedableRng as _;
    let registration = ServiceRegistrationKey::new(
        arkret_wire::ServiceKind::Station,
        CanonicalServiceUrl::new("https://native-forward-governor.example/").unwrap(),
    )
    .unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([194; 32]);
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_time: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            did_key_fragment: None,
        },
    )
    .unwrap();
    arkret_wire::project_did_to_core_id(&Did::new(inception.did.clone()).unwrap()).unwrap()
}

async fn archive(fixture: &Fixture) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY evidence_ref),'[]'::jsonb) AS value FROM account_device_signer_evidence r")
        .get_result::<Row>(&mut conn).await.unwrap().value
}

async fn writer_fault(fixture: &Fixture, enable: bool) {
    let mut conn = fixture.pool.get().await.unwrap();
    conn.batch_execute("DROP TRIGGER IF EXISTS test_native_forward_source_failure ON account_device_signer_evidence; DROP FUNCTION IF EXISTS test_native_forward_source_failure();").await.unwrap();
    if enable {
        conn.batch_execute("CREATE FUNCTION test_native_forward_source_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'native forward origin writer fault'; END $$; CREATE TRIGGER test_native_forward_source_failure BEFORE INSERT ON account_device_signer_evidence FOR EACH ROW EXECUTE FUNCTION test_native_forward_source_failure();").await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_forward_origin_retains_actual_sources_and_refuses_pair_signature_and_writer_failures()
 {
    tokio::spawn(native_phase(|| async {
        let context = native_phase(native_sources_setup).await;
        let fixture = &context.fixture;
        native_phase(|| writer_fault(fixture, false)).await;
        let destination = destination();
        assert_ne!(destination, fixture.state.service_core_id());
        let circle = native_phase(|| fixture.new_circle_scope()).await;
        let founder = ActorId::account(fixture.pcr.history.account.clone());
        let parent = ordinary_realm::parent_membership_revision(&fixture.pool, &fixture.realm, &founder).await;
        let join = fixture.admin_event(EventKind::CircleMemberState, circle.clone(), json!({
            "circle_id":circle.circle_id().unwrap(),"member_id":founder,"membership":"join",
            "expected_membership":null,"parent_membership_revision":parent
        }));
        native_phase(|| accepted_admin_domain_event(fixture, join)).await;

        let create = fixture.admin_event(EventKind::StrandCreate, circle.clone(), json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":fixture.realm,"scope_circle_id":circle.circle_id().unwrap(),
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Real foreign scope"},
            "state":"active","created_by":ActorId::account(fixture.pcr.history.account.clone()),
            "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
        }}));
        let circle_strand = arkret_wire::StrandId::from_event_id(&create.event_id);
        native_phase(|| accepted_admin_domain_event(fixture, create)).await;
        let unknown_strand = arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256, [195; 32],
        ));

        for (index, (authority, key, grant)) in context.actors.iter().enumerate() {
            let event = native_message(fixture, &context.install, authority, key, grant, &context.strand, "original native forward source");
            let before = native_phase(|| business(fixture)).await;
            let evidence = native_phase(|| coland_http::test_fresh_producer_device_evidence(
                &fixture.state, &event, &destination,
            )).await.unwrap().expect("actual managed Device source");
            assert_eq!(before, native_phase(|| business(fixture)).await);
            let core = &evidence.device_projection_attestation.attestation;
            assert_eq!(core.account_id, authority.account_id);
            assert_eq!(core.device_id, authority.device_id);
            assert_eq!(core.device_authorize_event_id, authority.selector.authorization_ref.event_id);
            assert_eq!(core.event_authorization.authorization_ref, authority.selector.authorization_ref);
            let request = arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequest {
                branch: arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
                event_submission: arkret_wire::EventAdmissionSubmission::new(event.clone()),
                mls_genesis_material: None,
                producer_device_evidence: None,
                producer_managed_provenance: None,
                producer_agent_evidence: None,
            };
            let digest = arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request).unwrap();
            let verified = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
                &evidence, &event, &fixture.state.service_core_id(), &destination, &digest,
                fixture.realm.digest_suite_code().digest_suite(), chrono::Utc::now(),
            ).unwrap().into_fact();
            assert_eq!(verified.actor, event.actor_id);
            assert_eq!(verified.key.authorization_ref, authority.selector.authorization_ref);
            let reference = coland_storage::forwarded_producer_device_evidence_ref(&evidence).unwrap();
            let stored = fixture.state.test_persistence().account_device_signer_evidence()
                .get_forward(&authority.account_id, &authority.device_id, &reference).await.unwrap().unwrap();
            assert_eq!(stored, evidence);
            for (destination, digest) in [
                (fixture.state.service_core_id(), digest.clone()),
                (destination.clone(), "sha256:0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap()),
            ] {
                assert!(arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_producer(
                    &evidence, &event, &fixture.state.service_core_id(), &destination, &digest,
                    fixture.realm.digest_suite_code().digest_suite(), chrono::Utc::now(),
                ).is_err());
            }
            let before_archive = native_phase(|| archive(fixture)).await;
            for target in [&unknown_strand, &circle_strand] {
                let mismatched = native_message(fixture, &context.install, authority, key, grant, target, "source must derive the actual Strand scope");
                assert!(native_phase(|| coland_http::test_fresh_producer_device_evidence(
                    &fixture.state, &mismatched, &destination,
                )).await.is_err());
                assert_eq!(before_archive, native_phase(|| archive(fixture)).await);
                assert_eq!(before, native_phase(|| business(fixture)).await);
            }

            let mut missing_applet = event.clone();
            missing_applet.applet_id = None;
            let missing_applet = sign_managed_device_event(missing_applet, authority, key, arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()));
            let wrong_key = SigningKey::from_bytes(&[201; 32]);
            let wrong_signature = sign_managed_device_event(event.clone(), authority, &wrong_key, arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()));
            for refused in [&missing_applet, &wrong_signature] {
                assert!(native_phase(|| coland_http::test_fresh_producer_device_evidence(
                    &fixture.state, refused, &destination,
                )).await.is_err());
                assert_eq!(before_archive, native_phase(|| archive(fixture)).await);
                assert_eq!(before, native_phase(|| business(fixture)).await);
            }
            native_phase(|| writer_fault(fixture, true)).await;
            let result = native_phase(|| coland_http::test_fresh_producer_device_evidence(
                &fixture.state, &event, &destination,
            )).await;
            native_phase(|| writer_fault(fixture, false)).await;
            assert!(result.is_err());
            assert_eq!(before_archive, native_phase(|| archive(fixture)).await);
            assert_eq!(before, native_phase(|| business(fixture)).await);

            // A real Principal-signed replacement removes publication authority.
            let bundle = if index == 0 { &context.ghost_bundle } else { &context.install.bot_body["managed_actor_bundle"] };
            let narrowed = native_phase(|| authorize_scopes(
                fixture, &context.install, bundle, &context.namespace, key,
                authority.device_id.clone(), json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read"]}]),
            )).await;
            let denied_event = native_message(fixture, &context.install, &narrowed, key, grant, &context.strand, "narrowed original pair");
            let before = native_phase(|| business(fixture)).await;
            assert!(native_phase(|| coland_http::test_fresh_producer_device_evidence(
                &fixture.state, &denied_event, &destination,
            )).await.is_err());
            assert_eq!(before, native_phase(|| business(fixture)).await);
            assert_eq!(before_archive, native_phase(|| archive(fixture)).await);
        }
    })).await.unwrap();
}

async fn expiry_during_writer_wait(
    context: &NativeSourcesContext,
    index: usize,
    archive_writer: bool,
) {
    let fixture = &context.fixture;
    let (original, key, grant) = &context.actors[index];
    let bundle = if index == 0 {
        &context.ghost_bundle
    } else {
        &context.install.bot_body["managed_actor_bundle"]
    };
    let expiry = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(4),
    );
    let authority = native_phase(|| authorize_scopes_until(
        fixture, &context.install, bundle, &context.namespace, key, original.device_id.clone(),
        json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read","ak.message.create"]}]), Some(expiry),
    )).await;
    let event = native_message(
        fixture,
        &context.install,
        &authority,
        key,
        grant,
        &context.strand,
        "forward source expires at the actual writer",
    );
    let destination = destination();
    let before = native_phase(|| business(fixture)).await;
    let before_archive = native_phase(|| archive(fixture)).await;
    let mut blocker = fixture.pool.get().await.unwrap();
    blocker.batch_execute("BEGIN").await.unwrap();
    if archive_writer {
        blocker
            .batch_execute("LOCK TABLE account_device_signer_evidence IN SHARE MODE")
            .await
            .unwrap();
    } else {
        diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
            .bind::<diesel::sql_types::Text, _>(authority.pcr_realm_id.as_str())
            .execute(&mut blocker)
            .await
            .unwrap();
    }
    let state = fixture.state.clone();
    let waiting = tokio::spawn(native_phase(move || async move {
        coland_http::test_fresh_producer_device_evidence(&state, &event, &destination).await
    }));
    let observed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            waiting: bool,
        }
        loop {
            let mut observer = fixture.pool.get().await.unwrap();
            let query = if archive_writer { "%INSERT INTO account_device_signer_evidence%" } else { "%realm_authorities%" };
            let row = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query ILIKE $1) AS waiting")
                .bind::<diesel::sql_types::Text, _>(query).get_result::<Row>(&mut observer).await.unwrap();
            if row.waiting { break; }
            drop(observer);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await;
    let still_live = chrono::Utc::now() < expiry;
    if observed.is_ok() && still_live {
        let until = (expiry - chrono::Utc::now()).to_std().unwrap_or_default()
            + std::time::Duration::from_millis(80);
        tokio::time::sleep(until).await;
    }
    blocker.batch_execute("ROLLBACK").await.unwrap();
    let result = waiting.await.unwrap();
    assert!(
        observed.is_ok() && still_live,
        "the real source writer must wait while its Device is still live"
    );
    assert!(result.is_err(), "expired source must roll back: {result:?}");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("device_unauthorized"),
        "expiry must preserve its registered native Device refusal"
    );
    assert_eq!(before_archive, native_phase(|| archive(fixture)).await);
    assert_eq!(before, native_phase(|| business(fixture)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_forward_source_rechecks_physical_device_expiry_at_both_real_writer_waits() {
    tokio::spawn(native_phase(|| async {
        let context = native_phase(native_sources_setup).await;
        native_phase(|| writer_fault(&context.fixture, false)).await;
        for index in 0..context.actors.len() {
            for archive_writer in [false, true] {
                native_phase(|| expiry_during_writer_wait(&context, index, archive_writer)).await;
            }
        }
    }))
    .await
    .unwrap();
}
