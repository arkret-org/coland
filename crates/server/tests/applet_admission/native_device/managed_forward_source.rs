//! Real four-original source, native Service history and immutable cold recovery.

use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, PeerAuthorityForwardEventRequest, PeerAuthoritySubmitRequest,
};
use diesel_async::SimpleAsyncConnection as _;

use super::*;

async fn private_archive(fixture: &Fixture) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object(\
        'device',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY evidence_ref),'[]'::jsonb) FROM account_device_signer_evidence r),\
        'request',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY evidence_ref),'[]'::jsonb) FROM account_device_managed_forward_requests r),\
        'creation',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY provision_event_pk),'[]'::jsonb) FROM applet_managed_creation_service_sources r)) AS value")
        .get_result::<Row>(&mut conn).await.unwrap().value
}

async fn request_writer_fault(fixture: &Fixture, enabled: bool) {
    let mut conn = fixture.pool.get().await.unwrap();
    conn.batch_execute("DROP TRIGGER IF EXISTS test_managed_forward_request_failure ON account_device_managed_forward_requests; DROP FUNCTION IF EXISTS test_managed_forward_request_failure();").await.unwrap();
    if enabled {
        conn.batch_execute("CREATE FUNCTION test_managed_forward_request_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'managed complete request writer fault'; END $$; CREATE TRIGGER test_managed_forward_request_failure BEFORE INSERT ON account_device_managed_forward_requests FOR EACH ROW EXECUTE FUNCTION test_managed_forward_request_failure();").await.unwrap();
    }
}

fn unsigned(event: Event) -> PeerAuthoritySubmitRequest {
    PeerAuthoritySubmitRequest::AuthorityForwardEvent(PeerAuthorityForwardEventRequest {
        branch: AuthorityForwardBranch::AuthorityForward,
        event_submission: arkret_wire::EventAdmissionSubmission::new(event),
        mls_genesis_material: None,
        producer_device_evidence: None,
        producer_managed_provenance: None,
        producer_agent_evidence: None,
    })
}

fn resign_source_binding(fixture: &Fixture, request: &mut PeerAuthorityForwardEventRequest) {
    let digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(request)
            .unwrap();
    let evidence = request.producer_device_evidence.as_mut().unwrap();
    let attestation = &evidence.device_projection_attestation;
    let mut core = attestation.attestation.clone();
    core.event_authorization.forward_body_digest = digest;
    evidence.device_projection_attestation =
        arkret_signatures::device_projection::sign_forward_device_projection_attestation(
            core,
            attestation.proof.verification_method.clone(),
            fixture.state.notary_signing_key().as_ref(),
        )
        .unwrap();
}

async fn authorities(
    fixture: &Fixture,
    request: &PeerAuthorityForwardEventRequest,
) -> (
    std::collections::BTreeMap<arkret_wire::RealmId, arkret_identity::VerifiedRealmAuthority>,
    arkret_identity::RealmAuthorityKeyMap,
) {
    let source = request.producer_managed_provenance.as_ref().unwrap();
    let station = &request
        .producer_device_evidence
        .as_ref()
        .unwrap()
        .service_resolution;
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    let mut authorities = std::collections::BTreeMap::new();
    for current in [
        &source.current.profile.commit,
        &source.current.accountability.commit,
    ] {
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        nonce_bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let nonce =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(nonce_bytes))
                .unwrap();
        let body = arkret_canonical::canonical_json_bytes(&arkret_wire::AuthorityBundleRequest {
            realm_id: current.realm_id.clone(),
            nonce: nonce.clone(),
        })
        .unwrap();
        let mut response = TestClient::post("http://localhost/_arkret/open/realm-authority/bundle")
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
                true,
            )
            .add_header("content-type", "application/json", true)
            .body(body)
            .send(&service(fixture.state.clone()))
            .await;
        if response.status_code != Some(StatusCode::OK) {
            panic!("{}", response.take_string().await.unwrap());
        }
        let bundle: arkret_wire::RealmAuthorityBundle = response.take_json().await.unwrap();
        assert!(
            bundle.authority_transitions.is_empty(),
            "fixture uses actual original tenures"
        );
        for signature in [
            &bundle.genesis_commit.signature,
            &bundle.current_assertion.signature,
            &current.signature,
        ] {
            let doc = arkret_identity::authenticated_service_document_at(
                station,
                &fixture.state.service_core_id(),
                signature.created_at,
            )
            .unwrap();
            let key = arkret_identity::public_key_material_from_document(
                &doc,
                &signature.verification_method,
            )
            .unwrap();
            keys.insert_at(&signature.verification_method, signature.created_at, key);
        }
        let authority = arkret_identity::verify_realm_authority_bundle(
            &bundle,
            &arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce),
            &keys,
        )
        .unwrap();
        authorities.insert(current.realm_id.clone(), authority);
    }
    (authorities, keys)
}

fn principal_history_refusals(
    source: &arkret_models_collaboration::authority_commit::ForwardManagedActorProvenance,
) {
    let original = &source.creation.provision.event;
    let payload: AppletManagedActorProvisionPayload =
        serde_json::from_value(serde_json::to_value(&original.payload).unwrap()).unwrap();
    let document = arkret_identity::verify_applet_managed_initial_resolution(
        &payload,
        source.creation.provision.commit.committed_at,
    )
    .unwrap();
    assert_eq!(document.id, payload.initial_resolution.did);
    let (_, entries, _) = payload.method_history_evidence.webvh_material();
    let inception_time: chrono::DateTime<chrono::Utc> =
        entries[0]["versionTime"].as_str().unwrap().parse().unwrap();
    assert!(
        arkret_identity::verify_applet_managed_initial_resolution(
            &payload,
            inception_time - chrono::Duration::seconds(1)
        )
        .is_err()
    );
    for receipt in [false, true] {
        let mut bytes = serde_json::to_value(&payload).unwrap();
        if receipt {
            bytes["method_history_evidence"]["evidence"]["document_digest"] =
                json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        } else {
            bytes["method_history_evidence"]["log_entries"][0]["proof"][0]["proofValue"] =
                json!("zInvalid");
        }
        let corrupted: AppletManagedActorProvisionPayload = serde_json::from_value(bytes).unwrap();
        corrupted.validate().unwrap();
        assert!(
            arkret_identity::verify_applet_managed_initial_resolution(
                &corrupted,
                source.creation.provision.commit.committed_at
            )
            .is_err(),
            "shape-valid original Principal proof or method receipt corruption must fail independently of C's outer Event proof"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_first_forward_closes_four_real_originals_and_retains_exact_private_request() {
    tokio::spawn(native_phase(|| async {
        let context = native_phase(native_sources_setup).await;
        let fixture = &context.fixture;
        native_phase(|| request_writer_fault(fixture, false)).await;
        let destination = super::forward_source::destination();
        for (authority, key, grant) in &context.actors {
            let event = native_message(fixture, &context.install, authority, key, grant, &context.strand, "complete original source");
            let before = native_phase(|| business(fixture)).await;
            let before_private = native_phase(|| private_archive(fixture)).await;
            native_phase(|| request_writer_fault(fixture, true)).await;
            let refused = native_phase(|| coland_http::test_fresh_forward_request(
                &fixture.state, unsigned(event.clone()), &destination,
            )).await;
            native_phase(|| request_writer_fault(fixture, false)).await;
            assert!(refused.is_err());
            assert_eq!(before_private, native_phase(|| private_archive(fixture)).await,
                "a later complete-request writer failure must roll back the earlier Device evidence insert");
            assert_eq!(before, native_phase(|| business(fixture)).await);
            let request = native_phase(|| coland_http::test_fresh_forward_request(
                &fixture.state, unsigned(event.clone()), &destination,
            )).await.unwrap();
            assert_eq!(before, native_phase(|| business(fixture)).await);
            let PeerAuthoritySubmitRequest::AuthorityForwardEvent(body) = &request else { panic!("original Event branch"); };
            let source = body.producer_managed_provenance.as_ref().unwrap();
            principal_history_refusals(source);
            assert_eq!(source.creation.entries().len(), 4);
            assert_eq!(source.service_resolution.service_id, context.install.package.service_id);
            assert_eq!(source.current.profile.realm_id, authority.pcr_realm_id);
            let (authorities, keys) = native_phase(|| authorities(fixture, body)).await;
            {
            let verifier = arkret_identity::managed_actor_provenance::ManagedForwardVerificationContext {
                source_service_id: &fixture.state.service_core_id(),
                destination_service_id: &destination,
                applet_id: &authority.applet_id,
                applet_service_id: &context.install.package.service_id,
                digest_suite: fixture.realm.digest_suite_code().digest_suite(),
                now: chrono::Utc::now(),
                authorities: &authorities,
                authority_keys: &keys,
            };
            let verified = arkret_identity::managed_actor_provenance::verify_forwarded_managed_event_request(body, &verifier).unwrap();
            assert_eq!(verified.account(), &authority.account_id);
            let evidence = body.producer_device_evidence.as_ref().unwrap();
            let digest = arkret_models_collaboration::authority_commit::authority_forward_body_digest(body).unwrap();
            let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
                evidence, &event, &fixture.state.service_core_id(), &destination, &digest,
                event.realm_id.digest_suite_code().digest_suite(), chrono::Utc::now(),
            ).unwrap().into_fact();
            let document = arkret_identity::authenticated_service_document_at(
                &source.service_resolution, &context.install.package.service_id,
                source.creation.provision.event.created_at,
            ).unwrap();
            let mut retained = coland_storage::ForwardedProducerDeviceEvidence::new(evidence.clone(), fact).unwrap();
            retained.managed = Some(Box::new(coland_storage::ForwardedManagedActorSource::new(verified.clone(), &event, document).unwrap()));
            retained.ensure_managed_binding(&event, chrono::Utc::now()).unwrap();
            let mut different_body = body.clone();
            different_body.producer_managed_provenance.as_mut().unwrap().current.expires_at -= chrono::Duration::seconds(1);
            resign_source_binding(fixture, &mut different_body);
            let changed_digest = arkret_models_collaboration::authority_commit::authority_forward_body_digest(&different_body).unwrap();
            arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
                different_body.producer_device_evidence.as_ref().unwrap(), &event,
                &fixture.state.service_core_id(), &destination, &changed_digest,
                event.realm_id.digest_suite_code().digest_suite(), chrono::Utc::now(),
            ).unwrap();
            retained.evidence = different_body.producer_device_evidence.unwrap();
            // An independently valid origin signature over a different body cannot
            // borrow the original token, even when the producer Event is unchanged.
            assert!(retained.ensure_managed_binding(&event, chrono::Utc::now()).is_err());
            for attack in [0, 1, 2, 3] {
                let mut wrong = body.clone();
                match attack {
                    0 => wrong.producer_managed_provenance.as_mut().unwrap().creation.profile.event = event.clone(),
                    1 => wrong.producer_managed_provenance.as_mut().unwrap().current.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1),
                    2 => wrong.producer_device_evidence.as_mut().unwrap().device_projection_attestation.attestation.authorization_window.expires_at = None,
                    _ => wrong.producer_managed_provenance = None,
                }
                // Keep origin crypto valid so these exercise the managed
                // source rules rather than merely a changed body digest.
                resign_source_binding(fixture, &mut wrong);
                assert!(arkret_identity::managed_actor_provenance::verify_forwarded_managed_event_request(&wrong, &verifier).is_err());
            }
            verified.ensure_live(source.current.expires_at).unwrap_err();
            }
            let evidence = body.producer_device_evidence.as_ref().unwrap();
            let reference = coland_storage::forwarded_producer_device_evidence_ref(evidence).unwrap();
            let cold = coland_storage_postgres::PgAccountDeviceSignerEvidenceArchive::new(fixture.pool.clone());
            let recovered = coland_storage::AccountDeviceSignerEvidenceStore::get_managed_forward(&cold,
                &authority.account_id, &authority.device_id, &reference,
            ).await.unwrap().unwrap();
            assert_eq!(arkret_canonical::canonical_json_bytes(&recovered).unwrap(), arkret_canonical::canonical_json_bytes(&request).unwrap());
            assert_eq!(before, native_phase(|| business(fixture)).await);
        }
    })).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn circle_created_managed_sources_preserve_original_circle_and_pcr_streams() {
    tokio::spawn(native_phase(|| async {
        let fixture = native_phase(Fixture::new).await;
        let scope = native_phase(|| fixture.new_circle_scope()).await;
        let founder = ActorId::account(fixture.pcr.history.account.clone());
        let parent = ordinary_realm::parent_membership_revision(&fixture.pool, &fixture.realm, &founder).await;
        let join = fixture.admin_event(EventKind::CircleMemberState, scope.clone(), json!({
            "circle_id":scope.circle_id().unwrap(),"member_id":founder,"membership":"join",
            "expected_membership":null,"parent_membership_revision":parent
        }));
        native_phase(|| accepted_admin_domain_event(&fixture, join)).await;
        let create = fixture.admin_event(EventKind::StrandCreate, scope.clone(), json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":fixture.realm,"scope_circle_id":scope.circle_id().unwrap(),
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Circle creation source"},
            "state":"active","created_by":founder,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
        }}));
        let strand = arkret_wire::StrandId::from_event_id(&create.event_id);
        native_phase(|| accepted_admin_domain_event(&fixture, create)).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = NativeAppletService::new(
            &format!("ak:applet:{}", uuid::Uuid::now_v7()), &namespace, &fixture.state.service_core_id(),
        );
        let install = native_phase(|| fixture.install_package_in_scope(true, native.package.clone(), &namespace, scope.clone())).await;
        let ghost = native_phase(|| fixture.ghost_body(&install, &namespace, "circle-created-ghost")).await;
        let (status, outcome) = native_phase(|| fixture.ghost_commit(&install, &ghost, "circle-created-ghost")).await;
        assert_eq!(status, StatusCode::CREATED, "{outcome}");
        let destination = super::forward_source::destination();
        for (bundle, seed) in [(&install.bot_body["managed_actor_bundle"], 211), (&ghost["managed_actor_bundle"], 212)] {
            let key = SigningKey::from_bytes(&[seed;32]);
            let authority = native_phase(|| authorize_scopes(
                &fixture, &install, bundle, &namespace, &key,
                DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(),
                json!([{"effective_scope":scope,"actions":["ak.message.create"]}]),
            )).await;
            // This boundary verifies the origin source only. Business membership
            // and terminal-grant admission remain the governor's independent AND.
            let mut event = native_message(&fixture, &install, &authority, &key, &install.bot_outcome.authorization_ref, &strand, "Circle-created native origin");
            event.scope_ref = scope.clone();
            let event = sign_managed_device_event(event, &authority, &key, arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()));
            let before = native_phase(|| business(&fixture)).await;
            let request = native_phase(|| coland_http::test_fresh_forward_request(&fixture.state, unsigned(event), &destination)).await.unwrap();
            let PeerAuthoritySubmitRequest::AuthorityForwardEvent(body) = request else { panic!("Event source"); };
            let source = body.producer_managed_provenance.as_ref().unwrap();
            let circle_stream = arkret_wire::CommitStreamRef::from_scope(&scope, Some(fixture.realm.clone())).unwrap();
            assert_eq!(source.creation.provision.commit.stream_ref, circle_stream);
            assert_eq!(source.creation.accountability.commit.stream_ref, circle_stream);
            assert_eq!(source.current.accountability.commit.stream_ref, circle_stream);
            assert_eq!(source.creation.pcr_genesis.commit.stream_ref, arkret_wire::CommitStreamRef::Realm { realm_id: authority.pcr_realm_id.clone() });
            let (authorities, keys) = native_phase(|| authorities(&fixture, &body)).await;
            {
            let context = arkret_identity::ManagedForwardVerificationContext {
                source_service_id: &fixture.state.service_core_id(), destination_service_id: &destination,
                applet_id: &install.package.applet_id, applet_service_id: &install.package.service_id,
                digest_suite: fixture.realm.digest_suite_code().digest_suite(), now: chrono::Utc::now(),
                authorities: &authorities, authority_keys: &keys,
            };
            arkret_identity::verify_forwarded_managed_event_request(&body, &context).unwrap();
            }
            assert_eq!(before, native_phase(|| business(&fixture)).await);
        }
    })).await.unwrap();
}
