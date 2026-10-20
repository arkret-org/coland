//! Applet acceptance through registered HTTP operations and real PostgreSQL.
//! PCR and Realm bootstrap use the production storage units as prerequisites;
//! each tested Applet request verifies real StandardGrant/DPoP and producer proofs.

#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use arkret_identifiers::{AppletId, Did, EventId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::{
    CapabilityGrantCreateBody, CapabilityGrantPayload,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint, IssuerAuthorityRef,
};
use arkret_models_integration::applet::*;
use arkret_models_integration::*;
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignedRequestParts, sign_http_message_for_scenario,
};
use arkret_wire::{ActorId, Event, EventKind, ScopeRef};
use base64::Engine as _;
use coland_http::config::AppConfig;
use coland_http::state::AppState;
use coland_storage::AuthorityCommitStore;
use coland_storage_postgres::{PgAuthorityCommitStore, PgPool};
use coland_test_support::AppStateTestExt as _;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use diesel_async::RunQueryDsl as _;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

// TestClient otherwise polls the server inside the scenario's own poll stack.
// Each real connection gets its own default-stack task; dropping the caller
// aborts that task, and response-body handoff guards remain owned by Response.
struct FixtureService(AppState);

fn service(state: AppState) -> FixtureService {
    FixtureService(state)
}

impl salvo::test::SendTarget for &FixtureService {
    async fn call(self, request: salvo::Request) -> salvo::Response {
        let state = self.0.clone();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move { coland_http::service(state).handle(request).await });
        tasks.join_next().await.unwrap().unwrap()
    }
}

#[tokio::test]
async fn controller_cannot_directly_grant_business_authority_to_managed_bot() {
    use coland_storage::EventCommitUnitOfWork as _;
    let fixture = Fixture::new().await;
    let installed = fixture.install(false).await;
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        serde_json::to_value(CapabilityGrantPayload {
            grant: CapabilityGrantCreateBody {
                schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                realm_id: Some(fixture.realm.clone()),
                issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
                subject: CapabilitySubject::Actor(installed.bot_outcome.bot_actor_id.clone()),
                actions: vec!["ak.message.create".to_owned()],
                resources: vec![arkret_wire::WireResourceSelector::realm(
                    fixture.realm.clone(),
                )],
                constraints: vec![GrantConstraint::applet_authority(
                    installed.package.applet_id.clone(),
                    ActorId::service(installed.package.service_id.clone()),
                    installed.package.registration_epoch.clone(),
                )],
                issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                    realm_id: fixture.realm.clone(),
                    authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
                    authority_generation: 0,
                }],
                issued_at: chrono::Utc::now(),
            },
        })
        .unwrap(),
    );
    let before = authority_snapshot(&fixture.pool).await;
    let request = admin_domain_request(&fixture, event).await;
    assert!(
        coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone())
            .commit_event(request)
            .await
            .is_err()
    );
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_devices_require_independent_principal_and_possession_on_service_ingress() {
    use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
    use arkret_wire::DeviceId;
    use coland_storage::DeviceRevocationStore as _;
    use ed25519_dalek::Signer as _;
    let fixture = Box::pin(Fixture::new()).await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let installed =
        Box::pin(fixture.install_package(true, native.package.clone(), &namespace)).await;
    let body = fixture
        .ghost_body(&installed, &namespace, "device-first")
        .await;
    let (status, ghost) = fixture
        .ghost_commit(&installed, &body, "device-ghost")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{ghost}");
    for bundle in [
        installed.bot_body["managed_actor_bundle"].clone(),
        body["managed_actor_bundle"].clone(),
    ] {
        let provision = &bundle["managed_actor_provision_event"]["payload"];
        let actor: ActorId = serde_json::from_value(provision["actor_id"].clone()).unwrap();
        let did = provision["initial_resolution"]["did"].as_str().unwrap();
        let local = did.rsplit(':').next().unwrap();
        let controller_seed = deterministic_managed_actor_seed(&format!(
            "{}:{local}:controller:{}",
            safe_did_token(&namespace),
            installed.package.service_id
        ));
        let controller = SigningKey::from_bytes(&controller_seed);
        let device = SigningKey::from_bytes(&[117; 32]);
        let device_id = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        let now =
            chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
        let mut payload:DeviceAuthorizePayload=serde_json::from_value(json!({
            "device_id":device_id,"device_public_key_did":format!("did:key:{}",arkret_canonical::ed25519_pubkey_to_did_key_multibase(device.verifying_key().as_bytes())),
            "hpke_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[119;32]),"algorithms":["Ed25519"],"device_key_algorithm":"Ed25519",
            "authorized_by":actor.signing_principal_id(),"scopes":[{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.event.read","ak.object.read_content","ak.self.blob.command.presign.v1","ak.self.blob.resource.get.v1","ak.self.blob.resource.head.v1","ak.self.blob.upload.create.v1"]}],"not_before":now-chrono::Duration::seconds(1),"expires_at":now+chrono::Duration::hours(1),
            "authorization_binding_kind":"applet_managed_delegation","authorized_generation_ref":1,"device_signature":"AA","applet_id":installed.package.applet_id
        })).unwrap();
        payload.device_signature =
            serde_json::from_value(json!(arkret_canonical::base64url_encode(
                device
                    .sign(
                        &payload
                            .device_possession_signature_input(actor.as_account_id().unwrap())
                            .unwrap()
                    )
                    .to_bytes()
            )))
            .unwrap();
        let realm: arkret_wire::RealmId = arkret_wire::RealmId::from_event_id(
            &serde_json::from_value(bundle["pcr_genesis_event"]["event_id"].clone()).unwrap(),
        );
        let device_authority = coland_storage_postgres::PgDeviceRevocationStore {
            pool: fixture.pool.clone(),
        };
        assert!(
            device_authority
                .applet_managed_device_authority(actor.as_account_id().unwrap(), &device_id, now)
                .await
                .unwrap()
                .is_none()
        );
        let sign = |payload: &DeviceAuthorizePayload, key: SigningKey, method: String| {
            let mut event = arkret_wire::test_support::raw_event_for_actor_at(
                EventKind::DeviceAuthorize.as_str(),
                ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                actor.clone(),
                serde_json::to_value(payload).unwrap(),
                now,
            )
            .unwrap();
            event.producer_proof = None;
            let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
            let signer = Ed25519PayloadSigner::new(
                key,
                Did::new(did).unwrap(),
                arkret_wire::DidUrl::new(method).unwrap(),
            );
            arkret_signatures::sign_event(
                &mut authored,
                &signer,
                arkret_signatures::SignEventOptions::new(),
            )
            .unwrap();
            authored.into_event()
        };
        let request = |event: Event| {
            serde_json::to_value(
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(event),
                ),
            )
            .unwrap()
        };
        let valid = sign(
            &payload,
            controller.clone(),
            format!("{did}#managed-controller"),
        );
        let application = coland_services::authority_commit::AuthorityCommitApplication::new(
            coland_services::persistence::PersistenceHandle::from_shared(
                fixture.state.test_persistence(),
            ),
            0,
        );
        let carrier = coland_storage::AppletControlCarrier {
            service_id: installed.package.service_id.clone(),
            verification_method: installed.package.webhook_auth.key_ref.clone(),
            public_key: applet_service_signing_key(&installed.package.webhook_auth.key_ref)
                .verifying_key()
                .to_bytes(),
        };
        let station_method = fixture
            .state
            .service_verification_method("notary-key")
            .unwrap();
        let mut competing = payload.clone();
        competing.device_id = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        competing.device_signature =
            serde_json::from_value(json!(arkret_canonical::base64url_encode(
                device
                    .sign(
                        &competing
                            .device_possession_signature_input(actor.as_account_id().unwrap())
                            .unwrap()
                    )
                    .to_bytes()
            )))
            .unwrap();
        let competing = sign(
            &competing,
            controller.clone(),
            format!("{did}#managed-controller"),
        );
        let stale_cut = application
            .prepare_self_event_transaction(
                &competing,
                &fixture.state.service_core_id(),
                station_method.clone(),
                fixture.state.notary_signing_key().as_ref(),
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        let before = authority_snapshot(&fixture.pool).await;
        for event in [
            sign(
                &payload,
                applet_service_signing_key(&installed.package.webhook_auth.key_ref),
                format!("{did}#managed-controller"),
            ),
            sign(&payload, controller.clone(), format!("{did}#{device_id}")),
            {
                let mut wrong = payload.clone();
                wrong.authorized_generation_ref = 2;
                wrong.device_signature =
                    serde_json::from_value(json!(arkret_canonical::base64url_encode(
                        device
                            .sign(
                                &wrong
                                    .device_possession_signature_input(
                                        actor.as_account_id().unwrap()
                                    )
                                    .unwrap()
                            )
                            .to_bytes()
                    )))
                    .unwrap();
                sign(
                    &wrong,
                    controller.clone(),
                    format!("{did}#managed-controller"),
                )
            },
            {
                let mut wrong = payload.clone();
                wrong.device_signature =
                    serde_json::from_value(json!(arkret_canonical::base64url_encode([7; 64])))
                        .unwrap();
                sign(
                    &wrong,
                    controller.clone(),
                    format!("{did}#managed-controller"),
                )
            },
        ] {
            let (status, result) = fixture
                .service_post(
                    &installed.package,
                    "/_arkret/self/events",
                    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                    &request(event),
                    "device-invalid",
                )
                .await;
            assert!(!status.is_success(), "{result}");
            assert_eq!(
                before,
                authority_snapshot(&fixture.pool).await,
                "refused managed authorize must write nothing"
            );
        }
        let mut uninstalled = payload.clone();
        uninstalled.scopes = Some(serde_json::from_value(json!([{
            "effective_scope":{"kind":"realm","realm_id":"ak:realm:AVpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpa"},
            "actions":["ak.event.read"]
        }])).unwrap());
        uninstalled.device_signature =
            serde_json::from_value(json!(arkret_canonical::base64url_encode(
                device
                    .sign(
                        &uninstalled
                            .device_possession_signature_input(actor.as_account_id().unwrap())
                            .unwrap()
                    )
                    .to_bytes()
            )))
            .unwrap();
        let event = sign(
            &uninstalled,
            controller.clone(),
            format!("{did}#managed-controller"),
        );
        let (status, result) = fixture
            .service_post(
                &installed.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &request(event),
                "device-uninstalled-scope",
            )
            .await;
        assert!(!status.is_success(), "{result}");
        assert_eq!(before, authority_snapshot(&fixture.pool).await);
        for reused in [
            controller.clone(),
            applet_service_signing_key(&installed.package.webhook_auth.key_ref),
        ] {
            let mut wrong = payload.clone();
            wrong.device_public_key_did = arkret_wire::NonEmptyString::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    reused.verifying_key().as_bytes()
                )
            ))
            .unwrap();
            wrong.device_signature =
                serde_json::from_value(json!(arkret_canonical::base64url_encode(
                    reused
                        .sign(
                            &wrong
                                .device_possession_signature_input(actor.as_account_id().unwrap())
                                .unwrap()
                        )
                        .to_bytes()
                )))
                .unwrap();
            let event = sign(
                &wrong,
                controller.clone(),
                format!("{did}#managed-controller"),
            );
            let (status, result) = fixture
                .service_post(
                    &installed.package,
                    "/_arkret/self/events",
                    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                    &request(event),
                    "device-key-reuse",
                )
                .await;
            assert!(!status.is_success(), "{result}");
            assert_eq!(
                before,
                authority_snapshot(&fixture.pool).await,
                "carrier and controller keys cannot become Device keys"
            );
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let deleted = diesel::sql_query(
            "DELETE FROM pcr_device_generation_current_results WHERE realm_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(realm.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
        assert_eq!(deleted, 1);
        drop(conn);
        let missing = authority_snapshot(&fixture.pool).await;
        assert!(
            device_authority
                .applet_managed_device_authority(actor.as_account_id().unwrap(), &device_id, now)
                .await
                .is_err(),
            "missing PCR generation is not an absent managed Device"
        );
        let (status, refused) = fixture
            .service_post(
                &installed.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &request(valid.clone()),
                "device-missing-generation",
            )
            .await;
        assert!(!status.is_success(), "{refused}");
        assert_eq!(
            missing,
            authority_snapshot(&fixture.pool).await,
            "authorize cannot initialize missing generation"
        );
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO pcr_device_generation_current_results SELECT r.* FROM jsonb_populate_recordset(NULL::pcr_device_generation_current_results,$1) r WHERE realm_id=$2")
            .bind::<diesel::sql_types::Jsonb,_>(&before["device_generations"]).bind::<diesel::sql_types::Text,_>(realm.as_str()).execute(&mut *conn).await.unwrap();
        drop(conn);
        assert_eq!(before, authority_snapshot(&fixture.pool).await);
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("CREATE FUNCTION fail_managed_device() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'managed device fault'; END $$").execute(&mut *conn).await.unwrap();
        diesel::sql_query("CREATE TRIGGER fail_managed_device BEFORE INSERT ON pcr_device_authorization_current_results FOR EACH ROW EXECUTE FUNCTION fail_managed_device()").execute(&mut *conn).await.unwrap();
        drop(conn);
        let (status, fault) = fixture
            .service_post(
                &installed.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &request(valid.clone()),
                "device-rollback",
            )
            .await;
        let after_fault = authority_snapshot(&fixture.pool).await;
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(
            "DROP TRIGGER fail_managed_device ON pcr_device_authorization_current_results",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        diesel::sql_query("DROP FUNCTION fail_managed_device()")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        assert!(!status.is_success(), "{fault}");
        assert_eq!(
            before, after_fault,
            "device current failure must roll back Event and Commit"
        );
        let (status, result) = fixture
            .service_post(
                &installed.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &request(valid.clone()),
                "device-first",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        let accepted_authority = device_authority
            .applet_managed_device_authority(actor.as_account_id().unwrap(), &device_id, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            accepted_authority.account_id,
            *actor.as_account_id().unwrap()
        );
        assert_eq!(
            accepted_authority.selector.authorization_ref.event_id,
            valid.event_id
        );
        assert_eq!(
            accepted_authority.public_key,
            device.verifying_key().to_bytes()
        );
        assert_eq!(accepted_authority.native_did.as_str(), did);
        assert_eq!(accepted_authority.pcr_realm_id, realm);
        assert_eq!(accepted_authority.applet_id, installed.package.applet_id);
        assert_eq!(
            accepted_authority.source_service_id,
            installed.package.service_id
        );
        assert_eq!(accepted_authority.current_device_generation_ref, 1);
        let mut native_draft = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::MemberState.as_str(),
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            actor.clone(),
            json!({"member_id": actor, "membership":"join"}),
            now,
        )
        .unwrap();
        native_draft.applet_id = Some(installed.package.applet_id.clone());
        native_draft.authorization_ref =
            Some(installed.bot_outcome.authorization_ref.clone().into());
        let native_event =
            sign_managed_device_event(native_draft.clone(), &accepted_authority, &device, now);
        let producer_before = authority_snapshot(&fixture.pool).await;
        let producer_authority = device_authority
            .applet_managed_event_producer(&native_event, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(producer_authority, accepted_authority);
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .prepare_account_device_signer_fact(&native_event, now)
                .await
                .is_err(),
            "a Device source cannot predate the actual authorization acceptance"
        );
        let historical_at = chrono::Utc::now();
        let historical = fixture
            .state
            .test_persistence()
            .authority_commits()
            .prepare_account_device_signer_fact(&native_event, historical_at)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(historical.actor, actor);
        assert_eq!(historical.device_id, device_id);
        assert_eq!(
            historical.key.authorization_ref,
            accepted_authority.selector.authorization_ref
        );
        assert_eq!(
            historical.key.public_key_b64u.as_str(),
            arkret_canonical::base64url_encode(device.verifying_key().to_bytes())
        );
        let source = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&valid.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(historical.accepted_at, source.commit.committed_at);
        assert_eq!(historical.key.revision.commit_id, source.commit.commit_id);
        assert_eq!(
            historical.key.revision.stream_position,
            source.commit.stream_position
        );
        assert_eq!(
            historical.key.governance_generation,
            source.commit.governance_generation
        );
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
            &native_event, &historical, fixture.realm.digest_suite_code().digest_suite(),
        ).unwrap();

        assert!(
            !producer_authority.scopes.permits(
                &native_event.scope_ref,
                &[arkret_wire::CapabilityActionId::AppletJoin]
            ),
            "a verified producer is not a business action authorization"
        );
        for wrong in [
            sign_managed_device_event(native_draft.clone(), &accepted_authority, &controller, now),
            sign_managed_device_event(
                native_draft.clone(),
                &accepted_authority,
                &applet_service_signing_key(&installed.package.webhook_auth.key_ref),
                now,
            ),
            {
                let mut draft = native_draft.clone();
                draft.applet_id = Some(
                    arkret_wire::AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7()))
                        .unwrap(),
                );
                sign_managed_device_event(draft, &accepted_authority, &device, now)
            },
            {
                let mut draft = native_draft.clone();
                draft.actor_id = ActorId::service(installed.package.service_id.clone());
                draft.executed_by = Some(actor.clone());
                sign_managed_device_event(draft, &accepted_authority, &device, now)
            },
            {
                let mut draft = native_draft.clone();
                draft.created_at =
                    accepted_authority.not_before - chrono::Duration::milliseconds(1);
                sign_managed_device_event(draft, &accepted_authority, &device, now)
            },
            sign_managed_device_event(
                native_draft.clone(),
                &accepted_authority,
                &device,
                accepted_authority.expires_at,
            ),
            {
                let mut wrong = native_event.clone();
                wrong
                    .payload
                    .insert("membership".to_owned(), json!("leave"));
                wrong
            },
            {
                let mut wrong = native_event.clone();
                wrong.producer_proof = None;
                wrong
            },
        ] {
            assert!(
                device_authority
                    .applet_managed_event_producer(&wrong, now)
                    .await
                    .is_err(),
                "neither carrier nor controller nor rewritten original is a Device producer"
            );
            assert_eq!(producer_before, authority_snapshot(&fixture.pool).await);
            assert!(
                fixture
                    .state
                    .test_persistence()
                    .authority_commits()
                    .prepare_account_device_signer_fact(&wrong, now)
                    .await
                    .is_err(),
                "historical source must verify the actual managed Device original"
            );
        }
        let mut non_device_method = native_event.clone();
        non_device_method
            .producer_proof
            .as_mut()
            .unwrap()
            .verification_method =
            arkret_wire::DidUrl::new(format!("{did}#managed-controller")).unwrap();
        assert!(
            device_authority
                .applet_managed_event_producer(&non_device_method, now)
                .await
                .unwrap()
                .is_none(),
            "another signer branch must never be mistaken for a successful managed Device proof"
        );
        assert!(
            device_authority
                .applet_managed_event_producer(&native_event, accepted_authority.expires_at)
                .await
                .is_err()
        );
        assert_eq!(producer_before, authority_snapshot(&fixture.pool).await);
        let account = actor.as_account_id().unwrap();
        let mut conn = fixture.pool.get().await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            count: i64,
        }
        let human_rows = diesel::sql_query(
            "SELECT count(*) AS count FROM accounts WHERE principal_id=$1 AND station_id=$2",
        )
        .bind::<diesel::sql_types::Text, _>(account.principal_id.as_str())
        .bind::<diesel::sql_types::Text, _>(account.station_id.as_str())
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap();
        assert_eq!(
            human_rows.count, 0,
            "native managed identity must not create a Human Account"
        );
        // The legacy device mirror is never transport authority.
        diesel::sql_query("UPDATE devices SET device_key='untrusted-mirror',verification_state='unverified' WHERE actor_id=$1 AND device_id=$2")
            .bind::<diesel::sql_types::Text,_>(account.principal_id.as_str()).bind::<diesel::sql_types::Text,_>(device_id.as_str())
            .execute(&mut *conn).await.unwrap();
        drop(conn);
        assert_eq!(
            device_authority
                .applet_managed_device_authority(account, &device_id, now)
                .await
                .unwrap()
                .unwrap()
                .public_key,
            device.verifying_key().to_bytes()
        );
        assert!(
            device_authority
                .applet_managed_device_authority(
                    account,
                    &device_id,
                    payload.not_before - chrono::Duration::milliseconds(1)
                )
                .await
                .is_err()
        );
        assert!(
            device_authority
                .applet_managed_device_authority(
                    account,
                    &device_id,
                    payload.expires_at.flatten().unwrap()
                )
                .await
                .is_err()
        );
        assert!(
            device_authority
                .applet_managed_device_authority(
                    account,
                    &DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(),
                    now
                )
                .await
                .unwrap()
                .is_none()
        );
        exercise_managed_device_http_authentication(&fixture, &accepted_authority, &device).await;
        let committed = authority_snapshot(&fixture.pool).await;
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("UPDATE pcr_device_authorization_current_results SET current_stream_position=current_stream_position+1 WHERE realm_id=$1 AND device_id=$2")
            .bind::<diesel::sql_types::Text,_>(realm.as_str()).bind::<diesel::sql_types::Text,_>(device_id.as_str())
            .execute(&mut *conn).await.unwrap();
        drop(conn);
        let corrupt_position = authority_snapshot(&fixture.pool).await;
        assert!(
            device_authority
                .applet_managed_device_authority(account, &device_id, now)
                .await
                .is_err(),
            "authorization payload and Commit ID cannot excuse a false source position"
        );
        assert!(
            device_authority
                .pcr_device_admission(account, &device_id, now)
                .await
                .is_err()
        );
        assert_eq!(
            corrupt_position,
            authority_snapshot(&fixture.pool).await,
            "an unavailable current must not repair itself while authenticating"
        );
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("UPDATE pcr_device_authorization_current_results SET current_stream_position=current_stream_position-1 WHERE realm_id=$1 AND device_id=$2")
            .bind::<diesel::sql_types::Text,_>(realm.as_str()).bind::<diesel::sql_types::Text,_>(device_id.as_str())
            .execute(&mut *conn).await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct ProjectionRow {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            value: Value,
        }
        let original_projection = diesel::sql_query(
            "SELECT projection AS value FROM principal_resolutions WHERE pcr_realm_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(realm.as_str())
        .get_result::<ProjectionRow>(&mut *conn)
        .await
        .unwrap()
        .value;
        diesel::sql_query("UPDATE principal_resolutions SET projection=jsonb_set(projection,'{version_id}',to_jsonb('corrupt-version'::text)) WHERE pcr_realm_id=$1")
            .bind::<diesel::sql_types::Text,_>(realm.as_str()).execute(&mut *conn).await.unwrap();
        drop(conn);
        assert!(
            device_authority
                .applet_managed_device_authority(account, &device_id, now)
                .await
                .is_err(),
            "resolution projection must match the actual latest accepted writer"
        );
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("UPDATE principal_resolutions SET projection=$2 WHERE pcr_realm_id=$1")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .bind::<diesel::sql_types::Jsonb, _>(&original_projection)
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        assert_eq!(committed, authority_snapshot(&fixture.pool).await);
        let (status, retry) = fixture
            .service_post(
                &installed.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &request(valid.clone()),
                "device-retry",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{retry}");
        assert_eq!(committed, authority_snapshot(&fixture.pool).await);
        let mut replacement = payload.clone();
        let replacement_key = SigningKey::from_bytes(&[118; 32]);
        replacement.device_public_key_did = arkret_wire::NonEmptyString::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                replacement_key.verifying_key().as_bytes()
            )
        ))
        .unwrap();
        replacement.scopes = Some(
            serde_json::from_value(json!([{
                "effective_scope":{"kind":"realm","realm_id":fixture.realm},
                "actions":["ak.event.read", "ak.object.read_content"]
            }]))
            .unwrap(),
        );
        replacement.device_signature =
            serde_json::from_value(json!(arkret_canonical::base64url_encode(
                replacement_key
                    .sign(
                        &replacement
                            .device_possession_signature_input(actor.as_account_id().unwrap())
                            .unwrap()
                    )
                    .to_bytes()
            )))
            .unwrap();
        let event = sign(
            &replacement,
            controller.clone(),
            format!("{did}#managed-controller"),
        );
        let (status, replaced) = fixture
            .service_post(
                &installed.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &request(event.clone()),
                "device-replacement",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{replaced}");
        let replaced_authority = device_authority
            .applet_managed_device_authority(account, &device_id, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            replaced_authority.selector.authorization_ref.event_id,
            event.event_id
        );
        assert_ne!(replaced_authority.selector, accepted_authority.selector);
        assert_eq!(
            replaced_authority.public_key,
            replacement_key.verifying_key().to_bytes()
        );
        assert_eq!(replaced_authority.current_device_generation_ref, 1);
        let Some(
            arkret_models_collaboration::events_payloads::DeviceAuthorizationScopes::AppletManaged(
                expected_scopes,
            ),
        ) = &replacement.scopes
        else {
            panic!("managed scopes");
        };
        assert_eq!(&replaced_authority.scopes, expected_scopes);
        let after_replacement = authority_snapshot(&fixture.pool).await;
        assert!(
            device_authority
                .applet_managed_event_producer(&native_event, now)
                .await
                .is_err(),
            "old Event signature cannot use a replacement's current key"
        );
        let replacement_producer =
            sign_managed_device_event(native_draft, &replaced_authority, &replacement_key, now);
        assert_eq!(replacement_producer.event_id, native_event.event_id);
        assert_eq!(
            device_authority
                .applet_managed_event_producer(&replacement_producer, now)
                .await
                .unwrap()
                .unwrap(),
            replaced_authority
        );

        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .prepare_account_device_signer_fact(&native_event, now)
                .await
                .is_err()
        );
        let replacement_fact = fixture
            .state
            .test_persistence()
            .authority_commits()
            .prepare_account_device_signer_fact(&replacement_producer, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            replacement_fact.key.authorization_ref,
            historical.key.authorization_ref
        );
        assert_ne!(
            replacement_fact.key.public_key_b64u,
            historical.key.public_key_b64u
        );
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
            &native_event, &historical, fixture.realm.digest_suite_code().digest_suite(),
        ).unwrap();
        assert_eq!(after_replacement, authority_snapshot(&fixture.pool).await);
        let stale_metadata = managed_device_metadata(&accepted_authority);
        assert!(
            device_authority
                .consume_applet_managed_device_nonce(
                    &accepted_authority,
                    &stale_metadata,
                    chrono::Utc::now() + chrono::Duration::seconds(60),
                )
                .await
                .is_err(),
            "signature verification before replacement cannot consume a nonce afterwards"
        );
        let mut stale_response = managed_device_http_request(
            &fixture.state,
            &accepted_authority,
            &stale_metadata,
            arkret_wire::ServiceOperationId::SelfCurrentResultsReadExactV1,
            &device,
        )
        .send(
            &coland_http::test_applet_managed_device_authentication_service(fixture.state.clone()),
        )
        .await;
        assert_eq!(stale_response.status_code, Some(StatusCode::UNAUTHORIZED));
        let _: Value = stale_response.take_json().await.unwrap();
        assert_eq!(after_replacement, authority_snapshot(&fixture.pool).await);
        let (status, replayed) = fixture
            .service_post(
                &installed.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &request(valid.clone()),
                "device-replay-original",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{replayed}");
        assert_eq!(
            after_replacement,
            authority_snapshot(&fixture.pool).await,
            "original replay must not overwrite replacement current"
        );
        assert_eq!(
            before["device_generations"], after_replacement["device_generations"],
            "authorize must preserve the generation writer and revision"
        );
        let store = PgAuthorityCommitStore {
            pool: fixture.pool.clone(),
        };
        let stale = store
            .admit_applet_managed_device_authorization(&stale_cut, &carrier)
            .await
            .unwrap_err();
        assert_eq!(
            stale.conflict_code(),
            Some(coland_storage::ConflictCode::CasConflict)
        );
        let expired = application
            .prepare_self_event_transaction(
                &valid,
                &fixture.state.service_core_id(),
                station_method.clone(),
                fixture.state.notary_signing_key().as_ref(),
                payload.expires_at.flatten().unwrap() + chrono::Duration::seconds(1),
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .admit_applet_managed_device_authorization(&expired, &carrier)
                .await
                .unwrap(),
            coland_storage::AcceptedDeviceAuthorizationOutcome::Duplicate(_)
        ));
        assert_eq!(
            after_replacement,
            authority_snapshot(&fixture.pool).await,
            "stale cut and expired replay must leave current untouched"
        );
        // The accepted Device remains a restricted Device, including on the
        // existing Account Authority relay unit for ordinary pairing.
        let mut upward = payload.clone();
        upward.authorization_binding_kind=arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::AcceptedDevice;
        upward.authorized_by =
            arkret_models_collaboration::events_payloads::DeviceOrPrincipalRef::DeviceId(
                device_id.clone(),
            );
        upward.applet_id = None;
        upward.scopes = None;
        upward.device_id = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        upward.pairing_challenge_transcript_digest = Some(
            Hash::new(
                arkret_canonical::canonical_sha256(&json!("real pairing target challenge"))
                    .unwrap(),
            )
            .unwrap(),
        );
        upward.device_signature =
            serde_json::from_value(json!(arkret_canonical::base64url_encode(
                device
                    .sign(
                        &upward
                            .device_possession_signature_input(actor.as_account_id().unwrap())
                            .unwrap()
                    )
                    .to_bytes()
            )))
            .unwrap();
        let upward = sign(&upward, device.clone(), format!("{did}#{device_id}"));
        let denied = application
            .admit_accepted_device_authorization(
                &upward,
                &fixture.state.service_core_id(),
                station_method,
                fixture.state.notary_signing_key().as_ref(),
                chrono::Utc::now(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            denied.conflict_code(),
            Some(coland_storage::ConflictCode::DeviceUnauthorized)
        );
        assert_eq!(
            after_replacement,
            authority_snapshot(&fixture.pool).await,
            "managed Device cannot gain upward delegation"
        );
        let store = coland_storage_postgres::PgDeviceRevocationStore {
            pool: fixture.pool.clone(),
        };
        assert_eq!(
            store
                .pcr_device_generation(actor.as_account_id().unwrap())
                .await
                .unwrap()
                .unwrap()
                .current_device_generation_ref,
            1
        );
        assert!(
            store
                .pcr_device_authorization_key(actor.as_account_id().unwrap(), &device_id)
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_pcr_genesis_initializes_generation_without_a_device_and_rejects_corrupt_current() {
    use coland_storage::DeviceRevocationStore as _;
    use diesel::sql_types::Text;

    let fixture = Box::pin(Fixture::new()).await;
    let installed = Box::pin(fixture.install(true)).await;
    let body = fixture
        .ghost_body(&installed, install_namespace(&installed), "generation")
        .await;
    let before = authority_snapshot(&fixture.pool).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("CREATE FUNCTION fail_managed_generation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'managed generation fault'; END $$")
        .execute(&mut *conn).await.unwrap();
    diesel::sql_query("CREATE TRIGGER fail_managed_generation BEFORE INSERT ON pcr_device_generation_current_results FOR EACH ROW EXECUTE FUNCTION fail_managed_generation()")
        .execute(&mut *conn).await.unwrap();
    drop(conn);
    let (status, failed) = fixture
        .ghost_commit(&installed, &body, "generation-fault")
        .await;
    let after_failure = authority_snapshot(&fixture.pool).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query(
        "DROP TRIGGER fail_managed_generation ON pcr_device_generation_current_results",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query("DROP FUNCTION fail_managed_generation()")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(!status.is_success(), "{failed}");
    assert_eq!(
        before, after_failure,
        "generation failure must roll back the whole creation"
    );
    let (status, outcome) = fixture
        .ghost_commit(&installed, &body, "generation-fault")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{outcome}");
    let ghost: GhostActorProvisionOutcome = serde_json::from_value(outcome.clone()).unwrap();
    let devices = coland_storage_postgres::PgDeviceRevocationStore {
        pool: fixture.pool.clone(),
    };
    let candidate =
        arkret_wire::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    for actor in [&installed.bot_outcome.bot_actor_id, &ghost.ghost_actor_id] {
        let account = actor.as_account_id().unwrap();
        assert_eq!(
            devices
                .pcr_device_generation(account)
                .await
                .unwrap()
                .unwrap()
                .current_device_generation_ref,
            1
        );
        assert!(
            devices
                .pcr_device_authorization_key(account, &candidate)
                .await
                .unwrap()
                .is_none()
        );
        let realm = if actor == &ghost.ghost_actor_id {
            &ghost.principal_control_realm_id
        } else {
            &installed.bot_outcome.principal_control_realm_id
        };
        let head = coland_http::test_accepted_device_generation_commit_head(
            &fixture.state,
            account.principal_id.as_str(),
            realm,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(head.stream_ref.realm_id(), realm);
        assert_eq!(
            head.stream_position, 1,
            "the accepted Profile follows the device-free genesis"
        );
    }
    let accepted = authority_snapshot(&fixture.pool).await;
    let (status, replay) = fixture
        .ghost_commit(&installed, &body, "generation-another-key")
        .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay, outcome);
    assert_eq!(accepted, authority_snapshot(&fixture.pool).await);
    let realm = ghost.principal_control_realm_id.as_str();
    let account = ghost.ghost_actor_id.as_account_id().unwrap();
    for mutation in [
        "UPDATE pcr_device_generation_current_results SET value='{\"current_device_generation_ref\":2}' WHERE realm_id=$1",
        "UPDATE pcr_device_generation_current_results SET current_stream_position=1 WHERE realm_id=$1",
        "UPDATE pcr_device_generation_current_results SET current_commit_id=(SELECT commit_id FROM realm_commits WHERE realm_id=$1 ORDER BY stream_position DESC LIMIT 1) WHERE realm_id=$1",
        "DELETE FROM pcr_device_generation_current_results WHERE realm_id=$1",
    ] {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(mutation)
            .bind::<Text, _>(realm)
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        let damaged = authority_snapshot(&fixture.pool).await;
        assert!(
            devices.pcr_device_generation(account).await.is_err(),
            "{mutation}"
        );
        assert!(
            devices
                .pcr_device_authorization_key(account, &candidate)
                .await
                .is_err(),
            "{mutation}"
        );
        assert_eq!(
            damaged,
            authority_snapshot(&fixture.pool).await,
            "a read must not repair authority"
        );
        let (status, replay) = fixture
            .ghost_commit(&installed, &body, "generation-another-key")
            .await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay, outcome);
        assert_eq!(damaged, authority_snapshot(&fixture.pool).await);
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("DELETE FROM pcr_device_generation_current_results WHERE realm_id=$1")
            .bind::<Text, _>(realm)
            .execute(&mut *conn)
            .await
            .unwrap();
        diesel::sql_query("INSERT INTO pcr_device_generation_current_results SELECT r.* FROM jsonb_populate_recordset(NULL::pcr_device_generation_current_results,$1) r WHERE realm_id=$2")
            .bind::<diesel::sql_types::Jsonb,_>(&accepted["device_generations"])
            .bind::<Text,_>(realm).execute(&mut *conn).await.unwrap();
    }
    assert_eq!(accepted, authority_snapshot(&fixture.pool).await);
    let genesis_id = body["managed_actor_bundle"]["pcr_genesis_event"]["event_id"]
        .as_str()
        .unwrap();
    let mut conn = fixture.pool.get().await.unwrap();
    let delivered = diesel::sql_query("UPDATE applet_authoring_completions SET delivered_at=accepted_at WHERE context#>>'{committed_request,managed_actor_bundle,pcr_genesis_event,event_id}'=$1")
        .bind::<Text,_>(genesis_id).execute(&mut *conn).await.unwrap();
    assert_eq!(delivered, 1);
    drop(conn);
    assert!(
        coland_http::test_accepted_device_generation_commit_head(
            &fixture.state,
            account.principal_id.as_str(),
            &ghost.principal_control_realm_id,
        )
        .await
        .unwrap()
        .is_some(),
        "delivered completion evidence remains a historical root"
    );
    let mut conn = fixture.pool.get().await.unwrap();
    let removed = diesel::sql_query("DELETE FROM applet_authoring_completions WHERE context#>>'{committed_request,managed_actor_bundle,pcr_genesis_event,event_id}'=$1")
        .bind::<Text,_>(genesis_id).execute(&mut *conn).await.unwrap();
    assert_eq!(removed, 1);
    drop(conn);
    assert!(
        coland_http::test_accepted_device_generation_commit_head(
            &fixture.state,
            account.principal_id.as_str(),
            &ghost.principal_control_realm_id,
        )
        .await
        .is_err(),
        "a cached head cannot replace missing original Service evidence"
    );
}

#[tokio::test]
async fn one_installation_creates_multiple_independent_bots() {
    let fixture = Fixture::new().await;
    let installed = fixture.install(false).await;
    let (second, body) = fixture
        .provision_bot(
            &installed.package,
            install_namespace(&installed),
            installed.outcome.registration_event_ref.clone(),
        )
        .await;
    assert_ne!(installed.bot_outcome.bot_actor_id, second.bot_actor_id);
    assert_ne!(
        installed.bot_outcome.principal_control_realm_id,
        second.principal_control_realm_id
    );
    let before = authority_snapshot(&fixture.pool).await;
    let (status, replay) = fixture
        .service_post(
            &installed.package,
            &format!(
                "/_arkret/self/applets/{}/bots/provision",
                installed.package.applet_id
            ),
            arkret_wire::ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
            &body,
            "second-bot-retry",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay, serde_json::to_value(&second).unwrap());
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
}

#[tokio::test]
async fn ghost_creation_quota_rolls_back_with_the_unit_and_counts_exact_retry_once() {
    let fixture = Fixture::new().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let package = signed_applet_package(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
        None,
    );
    let quota = serde_json::from_value(json!({
        "constraint_kind":"quota", "constraint_subkind":"rate", "effect":"allow",
        "max_operations":1, "period":"P1D", "constraint_scope":"per_realm"
    }))
    .unwrap();
    let installed = fixture
        .install_package_with_ghost_quota(
            true,
            package,
            &namespace,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            Some(quota),
        )
        .await;
    let body = fixture
        .ghost_body(&installed, &namespace, "quota-first")
        .await;
    let before = authority_snapshot(&fixture.pool).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(
            "CREATE FUNCTION fail_applet_profile_write() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'applet profile write fault'; END $$",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        diesel::sql_query(
            "CREATE TRIGGER fail_applet_profile_write BEFORE INSERT OR UPDATE \
             ON actor_profile_current_results FOR EACH ROW EXECUTE FUNCTION fail_applet_profile_write()",
        ).execute(&mut *conn).await.unwrap();
    }
    let (status, failed) = fixture.ghost_commit(&installed, &body, "quota-first").await;
    let failed_snapshot = authority_snapshot(&fixture.pool).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(
            "DROP TRIGGER fail_applet_profile_write ON actor_profile_current_results",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        diesel::sql_query("DROP FUNCTION fail_applet_profile_write()")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "late write fault was not reached: {failed}"
    );
    assert_eq!(failed["type"], "https://arkret.org/problems/internal_error");
    assert_eq!(
        before, failed_snapshot,
        "failed unit consumed quota or retained business state"
    );
    let (status, accepted) = fixture.ghost_commit(&installed, &body, "quota-first").await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");
    let after = authority_snapshot(&fixture.pool).await;
    assert_eq!(after["quota_counters"].as_array().unwrap().len(), 1);
    assert_eq!(after["quota_counters"][0]["consumed"], 1);
    assert_eq!(after["quota_consumptions"].as_array().unwrap().len(), 1);
    let (status, replay) = fixture.ghost_commit(&installed, &body, "quota-retry").await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(accepted, replay);
    assert_eq!(after, authority_snapshot(&fixture.pool).await);
    let mut changed = body.clone();
    let mut proof = changed["managed_actor_bundle"]["proof"]["jws"]
        .as_str()
        .unwrap()
        .to_owned();
    let signature_start = proof.rfind('.').unwrap() + 1;
    let replacement = if proof.as_bytes()[signature_start] == b'A' {
        "B"
    } else {
        "A"
    };
    proof.replace_range(signature_start..signature_start + 1, replacement);
    changed["managed_actor_bundle"]["proof"]["jws"] = json!(proof);
    let (status, refused) = fixture
        .ghost_commit(&installed, &changed, "quota-mutated-retry")
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(
        refused["type"],
        "https://arkret.org/problems/duplicate_conflict"
    );
    assert_eq!(after, authority_snapshot(&fixture.pool).await);
    let second = fixture
        .ghost_body(&installed, &namespace, "quota-second")
        .await;
    let exhausted_before = authority_snapshot(&fixture.pool).await;
    let (status, refused) = fixture
        .ghost_commit(&installed, &second, "quota-second")
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{refused}");
    assert_eq!(refused["type"], "https://arkret.org/problems/rate_limited");
    assert_eq!(exhausted_before, authority_snapshot(&fixture.pool).await);
}

#[tokio::test]
async fn ghost_mapping_quota_is_atomic_and_exact_retries_do_not_reconsume_creation() {
    let mut fixture = Fixture::new().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let package = signed_applet_package(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
        None,
    );
    let quota = |max_operations| {
        serde_json::from_value(json!({
            "constraint_kind":"quota", "constraint_subkind":"rate", "effect":"allow",
            "max_operations":max_operations, "period":"P1D", "constraint_scope":"per_realm"
        }))
        .unwrap()
    };
    let creation_install = fixture
        .install_package_with_ghost_quota(
            true,
            package.clone(),
            &namespace,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            Some(quota(2)),
        )
        .await;
    let mut originals = Vec::new();
    for external in ["mapping-first", "mapping-second"] {
        let body = fixture
            .ghost_body(&creation_install, &namespace, external)
            .await;
        let (status, original) = fixture
            .ghost_commit(&creation_install, &body, external)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{original}");
        originals.push(original);
    }
    let creation_snapshot = authority_snapshot(&fixture.pool).await;
    let creation_counter = creation_snapshot["quota_counters"].as_array().unwrap();
    assert_eq!(creation_counter.len(), 1);
    assert_eq!(creation_counter[0]["consumed"], 2);
    let creation_grant = creation_counter[0]["grant_id"].clone();

    fixture.new_realm().await;
    let mapping_install = fixture
        .install_package_with_ghost_quota(
            true,
            package,
            &namespace,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            Some(quota(1)),
        )
        .await;
    let mapping = fixture
        .ghost_body(&mapping_install, &namespace, "mapping-first")
        .await;
    assert!(
        mapping
            .get("managed_actor_bundle")
            .is_none_or(Value::is_null)
    );
    let before = authority_snapshot(&fixture.pool).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("CREATE FUNCTION fail_ghost_mapping_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'mapping write fault'; END $$")
            .execute(&mut *conn).await.unwrap();
        diesel::sql_query("CREATE TRIGGER fail_ghost_mapping_write BEFORE INSERT OR UPDATE ON applet_installations FOR EACH ROW EXECUTE FUNCTION fail_ghost_mapping_write()")
            .execute(&mut *conn).await.unwrap();
    }
    let (status, refusal) = fixture
        .ghost_commit(&mapping_install, &mapping, "mapping-fault")
        .await;
    assert!(status.is_server_error(), "{status}: {refusal}");
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("DROP TRIGGER fail_ghost_mapping_write ON applet_installations")
            .execute(&mut *conn)
            .await
            .unwrap();
        diesel::sql_query("DROP FUNCTION fail_ghost_mapping_write()")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let (status, mapped) = fixture
        .ghost_commit(&mapping_install, &mapping, "mapping-fault")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{mapped}");
    let after = authority_snapshot(&fixture.pool).await;
    for key in [
        "events",
        "commits",
        "profiles",
        "completions",
        "outbox",
        "event_outbox",
    ] {
        assert_eq!(before[key], after[key], "mapping created {key}");
    }
    for key in [
        "ghost_actor_id",
        "managed_actor_provision_ref",
        "principal_control_realm_id",
        "profile_event_ref",
        "accountability_grant_ref",
    ] {
        assert_eq!(originals[0][key], mapped[key], "mapping changed {key}");
    }
    let counters = after["quota_counters"].as_array().unwrap();
    assert_eq!(counters.len(), 2);
    for counter in counters {
        assert_eq!(
            counter["consumed"],
            if counter["grant_id"] == creation_grant {
                json!(2)
            } else {
                json!(1)
            }
        );
    }
    assert_eq!(after["quota_consumptions"].as_array().unwrap().len(), 3);
    for key in ["mapping-fault", "mapping-new-http-key"] {
        let (status, replay) = fixture.ghost_commit(&mapping_install, &mapping, key).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(mapped, replay);
        assert_eq!(after, authority_snapshot(&fixture.pool).await);
    }
    let second = fixture
        .ghost_body(&mapping_install, &namespace, "mapping-second")
        .await;
    let exhausted_before = authority_snapshot(&fixture.pool).await;
    let (status, refusal) = fixture
        .ghost_commit(&mapping_install, &second, "mapping-exhausted")
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{refusal}");
    assert_eq!(refusal["type"], "https://arkret.org/problems/rate_limited");
    assert_eq!(exhausted_before, authority_snapshot(&fixture.pool).await);

    // A replaced current preview does not invalidate an accepted operation.
    let (status, replay) = fixture
        .ghost_commit(&mapping_install, &mapping, "mapping-after-preview")
        .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(mapped, replay);
    assert_eq!(exhausted_before, authority_snapshot(&fixture.pool).await);
    let mut forged = mapping;
    forged["existing_managed_actor"]["profile_event_ref"] =
        serde_json::to_value(&mapping_install.outcome.registration_event_ref).unwrap();
    let (status, _) = fixture
        .ghost_commit(&mapping_install, &forged, "mapping-forged")
        .await;
    assert!(status.is_client_error());
    assert_eq!(exhausted_before, authority_snapshot(&fixture.pool).await);
}

#[tokio::test]
async fn ghost_reuse_across_realms_preserves_anchors_without_events_or_completion() {
    let mut fixture = Fixture::new().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let package = signed_applet_package(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
        None,
    );
    let first = fixture
        .install_package(true, package.clone(), &namespace)
        .await;
    let creation = fixture
        .ghost_body(&first, &namespace, "remote-same-account")
        .await;
    fixture.new_realm().await;
    let second = fixture.install_package(true, package, &namespace).await;
    let stale_creation = fixture
        .ghost_body(&second, &namespace, "remote-same-account")
        .await;
    assert!(
        stale_creation
            .get("managed_actor_bundle")
            .is_some_and(|value| !value.is_null())
    );
    let (status, original) = fixture
        .ghost_commit(&first, &creation, "ghost-original")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{original}");
    let before_stale = authority_snapshot(&fixture.pool).await;
    let (status, refusal) = fixture
        .ghost_commit(&second, &stale_creation, "ghost-stale-create")
        .await;
    assert!(status.is_client_error(), "{refusal}");
    assert_eq!(before_stale, authority_snapshot(&fixture.pool).await);
    assert_ne!(
        first.outcome.registration_event_ref,
        second.outcome.registration_event_ref
    );
    let mapping = fixture
        .ghost_body(&second, &namespace, "remote-same-account")
        .await;
    assert!(
        mapping
            .get("managed_actor_bundle")
            .is_none_or(Value::is_null)
    );
    let before = authority_snapshot(&fixture.pool).await;
    let (status, reused) = fixture.ghost_commit(&second, &mapping, "ghost-reuse").await;
    assert_eq!(status, StatusCode::CREATED, "{reused}");
    let after = authority_snapshot(&fixture.pool).await;
    for key in ["events", "commits", "profiles", "completions", "outbox"] {
        assert_eq!(before[key], after[key], "reuse changed {key}");
    }
    for key in [
        "ghost_actor_id",
        "managed_actor_provision_ref",
        "principal_control_realm_id",
        "profile_event_ref",
        "accountability_grant_ref",
    ] {
        assert_eq!(original[key], reused[key], "immutable anchor {key}");
    }
    assert_ne!(original["authorization_ref"], reused["authorization_ref"]);
    let (status, replay) = fixture.ghost_commit(&second, &mapping, "ghost-reuse").await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(reused, replay);
    assert_eq!(after, authority_snapshot(&fixture.pool).await);
    let mut forged = mapping.clone();
    forged["existing_managed_actor"]["profile_event_ref"] =
        serde_json::to_value(&second.outcome.registration_event_ref).unwrap();
    let (status, _) = fixture
        .ghost_commit(&second, &forged, "ghost-forged-reuse")
        .await;
    assert!(status.is_client_error());
    assert_eq!(after, authority_snapshot(&fixture.pool).await);
}

#[tokio::test]
async fn realm_and_circle_installations_preserve_registration_instance_and_ghost_reuse() {
    let fixture = Fixture::new().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let package = native.package.clone();
    let first = fixture
        .install_package(true, package.clone(), &namespace)
        .await;
    let original_body = fixture
        .ghost_body(&first, &namespace, "same-scope-account")
        .await;
    let (status, original) = fixture
        .ghost_commit(&first, &original_body, "realm-ghost")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{original}");
    let create = fixture.admin_event(EventKind::CircleCreate, ScopeRef::Realm { realm_id: fixture.realm.clone() }, json!({"object":{
        "schema":"ak.schema.circle.v1","realm_id":fixture.realm,"title":"Applet scope","display":{"short_name":format!("Applet-{}",&uuid::Uuid::now_v7().simple().to_string()[24..]),"color_token":"blue","symbol":{"glyph":"lock"}},
        "directory_visibility":"members","join_rule":"public","history_access":"since_join","state":"active","created_by":ActorId::account(fixture.pcr.history.account.clone()),"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }}));
    let circle = arkret_wire::CircleId::from_event_id(&create.event_id);
    accepted_admin_domain_event(&fixture, create).await;
    let second = fixture
        .install_package_in_scope(
            true,
            package,
            &namespace,
            ScopeRef::Circle {
                realm_id: fixture.realm.clone(),
                circle_id: circle,
            },
        )
        .await;
    assert_ne!(
        first.outcome.registration_event_ref,
        second.outcome.registration_event_ref
    );
    // The newer Circle assertion must not expire the Realm installation.
    fixture
        .provision_bot(
            &first.package,
            &namespace,
            first.outcome.registration_event_ref.clone(),
        )
        .await;
    let reuse = fixture
        .ghost_body(&second, &namespace, "same-scope-account")
        .await;
    assert!(reuse.get("managed_actor_bundle").is_none_or(Value::is_null));
    let before = authority_snapshot(&fixture.pool).await;
    let (status, mapped) = fixture
        .ghost_commit(&second, &reuse, "circle-ghost-reuse")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{mapped}");
    let after = authority_snapshot(&fixture.pool).await;
    for key in ["events", "commits", "profiles", "completions", "outbox"] {
        assert_eq!(before[key], after[key], "reuse changed {key}");
    }
    for key in [
        "ghost_actor_id",
        "managed_actor_provision_ref",
        "principal_control_realm_id",
        "profile_event_ref",
        "accountability_grant_ref",
    ] {
        assert_eq!(original[key], mapped[key]);
    }
    assert_ne!(original["authorization_ref"], mapped["authorization_ref"]);
    let new_realm_ghost = fixture
        .ghost_body(&first, &namespace, "realm-remains-active")
        .await;
    let (status, outcome) = fixture
        .ghost_commit(&first, &new_realm_ghost, "realm-after-circle")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{outcome}");
    let path = format!(
        "/_arkret/self/applets/{}/authority/material",
        second.package.applet_id
    );
    let (status,material)=fixture.service_post(&second.package,&path,arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,&json!({"effective_scope":second.body["authoring_request_basis"]["effective_scope"],"grant_ids":second.outcome.capability_grant_refs}),"circle-authority-material").await;
    assert_eq!(status, StatusCode::OK, "{material}");
    assert_eq!(
        material["current_results"][0]["effective_stream_head"]["stream_ref"]["kind"],
        "circle"
    );
    let mixed = json!({"effective_scope":second.body["authoring_request_basis"]["effective_scope"],"grant_ids":first.outcome.capability_grant_refs});
    let (status, _) = fixture
        .service_post(
            &second.package,
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &mixed,
            "authority-wrong-scope",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reproof_of_unchanged_security_snapshot_preserves_registration_instance() {
    let fixture = Fixture::new().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let first = fixture
        .install_package(true, native.package.clone(), &namespace)
        .await;
    let pending = fixture
        .ghost_body(&first, &namespace, "reproved-snapshot")
        .await;
    let mut reproved = first.package.clone();
    resign_native_applet_package(&mut reproved);
    assert_eq!(
        first.package.registration_epoch,
        reproved.registration_epoch
    );
    assert_ne!(first.package.proof, reproved.proof);
    let scope = fixture.new_circle_scope().await;
    let second = fixture
        .install_package_in_scope(true, reproved, &namespace, scope)
        .await;
    assert_ne!(
        first.outcome.registration_event_ref,
        second.outcome.registration_event_ref
    );
    let (status, result) = fixture
        .ghost_commit(&first, &pending, "old-anchor-after-reproof")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
}

#[tokio::test]
async fn authority_material_keeps_original_registration_after_same_scope_replacement() {
    let fixture = Fixture::new().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let first = fixture
        .install_package(false, native.package.clone(), &namespace)
        .await;
    let path = format!(
        "/_arkret/self/applets/{}/authority/material",
        first.package.applet_id
    );
    let body = json!({"effective_scope":ScopeRef::Realm {realm_id:fixture.realm.clone()},"grant_ids":first.outcome.capability_grant_refs});
    let operation = arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1;
    let (status, original) = fixture
        .service_post(
            &first.package,
            &path,
            operation,
            &body,
            "before-replacement",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{original}");
    let mut changed = first.package.clone();
    changed.base_url = "https://changed.applet.example".to_owned();
    resign_native_applet_package(&mut changed);
    assert_ne!(first.package.registration_epoch, changed.registration_epoch);
    let replacement = replace_installation_closed_unit(&fixture, &first, changed).await;
    let replacement_grant_id = replacement.capability_grant_refs[0].clone();
    let before = authority_snapshot(&fixture.pool).await;
    let (status, historical) = fixture
        .service_post(&first.package, &path, operation, &body, "old-parent-audit")
        .await;
    assert_eq!(status, StatusCode::OK, "{historical}");
    assert_eq!(historical["registration"], original["registration"]);
    assert_eq!(historical["grant_events"], original["grant_events"]);
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let mixed = json!({"effective_scope":ScopeRef::Realm {realm_id:fixture.realm.clone()},"grant_ids":[first.outcome.capability_grant_refs[0],replacement_grant_id]});
    let (status, refused) = fixture
        .service_post(
            &first.package,
            &path,
            operation,
            &mixed,
            "mixed-registration-sources",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
}

#[tokio::test]
async fn restored_registration_value_does_not_revive_closed_instance() {
    use arkret_event_draft::EventPayloadExt as _;
    let fixture = Fixture::new().await;
    let whole_second = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let probe=fixture.admin_event_at(EventKind::CircleCreate,ScopeRef::Realm{realm_id:fixture.realm.clone()},json!({"object":{
        "schema":"ak.schema.circle.v1","realm_id":fixture.realm,"title":"Whole second","display":{"short_name":"Whole-second","color_token":"blue","symbol":{"glyph":"lock"}},
        "directory_visibility":"members","join_rule":"public","history_access":"since_join","state":"active","created_by":ActorId::account(fixture.pcr.history.account.clone()),"created_at":arkret_canonical::format_timestamp_canonical(whole_second)
    }}),whole_second);
    assert_eq!(
        probe
            .as_circle_create()
            .unwrap_or_else(|error| panic!(
                "actual fixture must preserve the canonical whole-second SDK payload: {error}; {:?}",
                probe.payload
            ))
            .object
            .created_at,
        whole_second
    );
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let applet = format!("ak:applet:{}", uuid::Uuid::now_v7());
    let native = NativeAppletService::new(&applet, &namespace, &fixture.state.service_core_id());
    let package = native.package.clone();
    let first = fixture
        .install_package(true, package.clone(), &namespace)
        .await;
    let stale = fixture
        .ghost_body(&first, &namespace, "closed-instance")
        .await;
    let mut changed = package.clone();
    changed.base_url = "https://changed.applet.example".to_owned();
    resign_native_applet_package(&mut changed);
    let changed_scope = fixture.new_circle_scope().await;
    fixture
        .install_package_in_scope(true, changed, &namespace, changed_scope)
        .await;
    let restored_scope = fixture.new_circle_scope().await;
    fixture
        .install_package_in_scope(true, package, &namespace, restored_scope)
        .await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .ghost_commit(&first, &stale, "closed-instance-retry")
        .await;
    assert!(status.is_client_error(), "{rejection}");
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    // Closed business provenance remains readable only for its original Service's audit.
    let audit_path = format!(
        "/_arkret/self/applets/{}/authority/material",
        first.package.applet_id
    );
    let (status,audit)=fixture.service_post(&first.package,&audit_path,arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,&json!({"effective_scope":first.body["authoring_request_basis"]["effective_scope"],"grant_ids":first.outcome.capability_grant_refs}),"closed-instance-audit").await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    assert_eq!(
        audit["registration"]["event"]["event_id"],
        serde_json::to_value(&first.outcome.registration_event_ref).unwrap()
    );
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
}

#[tokio::test]
async fn service_authority_material_returns_accepted_same_cut_and_restricted_revocation_audit() {
    use arkret_models_collaboration::applet_installation_authority::{
        AppletAuthorityMaterialOutcome, AppletAuthorityMaterialRequestBody,
    };
    use arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome;
    let fixture = Fixture::new().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let installed = fixture
        .install_package(true, native.package.clone(), &namespace)
        .await;
    let request = AppletAuthorityMaterialRequestBody {
        effective_scope: ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        grant_ids: installed.outcome.capability_grant_refs.clone(),
    };
    let body = serde_json::to_value(&request).unwrap();
    let path = format!(
        "/_arkret/self/applets/{}/authority/material",
        installed.package.applet_id
    );
    let before = authority_snapshot(&fixture.pool).await;
    let (status, response) = fixture
        .service_post(
            &installed.package,
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &body,
            "authority-material",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        before,
        authority_snapshot(&fixture.pool).await,
        "authority material read wrote state"
    );
    let outcome: AppletAuthorityMaterialOutcome = serde_json::from_value(response).unwrap();
    outcome.validate_structural().unwrap();
    assert_eq!(
        outcome.registration.event.event_id,
        installed.outcome.registration_event_ref
    );
    for full in std::iter::once(&outcome.registration).chain(&outcome.grant_events) {
        let evidence = full
            .producer_device_evidence
            .as_ref()
            .expect("original Account Device root is portable");
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(evidence, &fixture.pcr.history.account, &fixture.pcr.history.founding_device_id).unwrap();
        assert_eq!(
            evidence
                .device_projection_attestation
                .attestation
                .attested_at,
            full.commit.committed_at
        );
        assert!(full.commit.producer_signer_fact_digest.is_some());
    }
    assert_eq!(outcome.grant_events.len(), request.grant_ids.len());
    assert_eq!(outcome.current_results.len(), request.grant_ids.len());
    for (id, (full, current)) in request
        .grant_ids
        .iter()
        .zip(outcome.grant_events.iter().zip(&outcome.current_results))
    {
        assert_eq!(
            arkret_wire::GrantId::from_event_id(&full.event.event_id),
            *id
        );
        assert_eq!(full.commit.event_ref, full.event.event_id);
        let ExactCurrentResultsReadOutcome::Present {
            realm_id,
            governance_generation,
            effective_stream_head,
            entry,
        } = current
        else {
            panic!("authority material cannot claim absence")
        };
        assert_eq!(*realm_id, fixture.realm);
        assert_eq!(*governance_generation, 0);
        let arkret_models_collaboration::exact_current_results::ExactCurrentResultEntry::CapabilityGrant(current)=entry else {panic!("unexpected current selector")};
        assert_eq!(current.selector.grant_id, *id);
        assert_eq!(current.revision.commit_id, full.commit.commit_id);
        assert_eq!(current.source_stream_ref, effective_stream_head.stream_ref);
        assert!(current.revision.stream_position <= effective_stream_head.stream_position);
    }
    let other = fixture.install(false).await;
    let mut foreign = body.clone();
    foreign["grant_ids"] = serde_json::to_value(&other.outcome.capability_grant_refs).unwrap();
    let before = authority_snapshot(&fixture.pool).await;
    let (status, denied) = fixture
        .service_post(
            &installed.package,
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &foreign,
            "authority-cross-subject",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{denied}");
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let mut repeated = body.clone();
    repeated["grant_ids"] = json!([request.grant_ids[0], request.grant_ids[0]]);
    let (status, _) = fixture
        .service_post(
            &installed.package,
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &repeated,
            "authority-duplicate",
        )
        .await;
    assert!(status.is_client_error());
    fixture.revoke(&installed).await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, audit) = fixture
        .service_post(
            &installed.package,
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &body,
            "authority-revoked-audit",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    let audit: AppletAuthorityMaterialOutcome = serde_json::from_value(audit).unwrap();
    assert_eq!(
        audit.registration.event.event_id,
        installed.outcome.registration_event_ref
    );
    for (original, current) in outcome.grant_events.iter().zip(&audit.current_results) {
        let ExactCurrentResultsReadOutcome::Present { entry, .. } = current else {
            panic!("audit requires accepted current")
        };
        let arkret_models_collaboration::exact_current_results::ExactCurrentResultEntry::CapabilityGrant(current)=entry else {panic!("wrong audit selector")};
        assert_eq!(current.value.status,arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Revoked);
        assert_ne!(current.revision.commit_id, original.commit.commit_id);
    }
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
}

#[tokio::test]
async fn service_authority_material_uses_current_service_method_after_rotation() {
    let fixture = Fixture::new().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let installed = fixture
        .install_package(false, native.package.clone(), &namespace)
        .await;
    let path = format!(
        "/_arkret/self/applets/{}/authority/material",
        installed.package.applet_id
    );
    let body = json!({"effective_scope":ScopeRef::Realm {realm_id:fixture.realm.clone()},"grant_ids":installed.outcome.capability_grant_refs});
    let operation = arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1;
    let (status, before) = fixture
        .service_post(&installed.package, &path, operation, &body, "pre-rotation")
        .await;
    assert_eq!(status, StatusCode::OK, "{before}");
    let rotated = native.rotate();
    let (status, after) = fixture
        .service_post(&rotated, &path, operation, &body, "new-method")
        .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(before, after);
    let (status, error) = fixture
        .service_post(
            &installed.package,
            &path,
            operation,
            &body,
            "removed-method",
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{error}");
    fixture.revoke(&installed).await;
    let (status, audit) = fixture
        .service_post(&rotated, &path, operation, &body, "new-method-inactive")
        .await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    assert_eq!(audit["registration"], before["registration"]);
}

#[tokio::test]
async fn service_authority_material_refuses_missing_original_device_root() {
    let fixture = Fixture::new_with_second_device().await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let installed = fixture
        .install_package(false, native.package.clone(), &namespace)
        .await;
    let path = format!(
        "/_arkret/self/applets/{}/authority/material",
        installed.package.applet_id
    );
    let body = json!({"effective_scope": ScopeRef::Realm { realm_id:fixture.realm.clone() }, "grant_ids":installed.outcome.capability_grant_refs});
    let (status, original) = fixture
        .service_post(
            &installed.package,
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &body,
            "original-device-root",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{original}");
    revoke_original_admin_device(&fixture).await;
    assert_ne!(
        fixture
            .state
            .test_persistence()
            .device_revocations()
            .pcr_device_admission(
                &fixture.pcr.history.account,
                &fixture.pcr.history.founding_device_id,
                chrono::Utc::now()
            )
            .await
            .unwrap(),
        arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    let before = authority_snapshot(&fixture.pool).await;
    let (status, historical) = fixture
        .service_post(
            &installed.package,
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &body,
            "revoked-device-history",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{historical}");
    assert_eq!(
        original, historical,
        "current Device revocation cannot alter accepted historical material"
    );
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let mut conn = fixture.pool.get().await.unwrap();
    // Simulate a lost original accepted root. The reader must never reconstruct
    // or re-sign a root from today's mutable Device projection.
    diesel::sql_query("DELETE FROM account_device_committed_evidence WHERE commit_id=$1")
        .bind::<diesel::sql_types::Text, _>(
            original["registration"]["commit"]["commit_id"]
                .as_str()
                .unwrap(),
        )
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let before = authority_snapshot(&fixture.pool).await;
    let (status, refusal) = fixture
        .service_post(
            &installed.package,
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
            &body,
            "missing-device-root",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refusal}");
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
}

// Only the Device revoke proposal and its immutable accepted decision are
// executed here. Later backup publication/erase steps remain pending; no fake
// Device revocation references or synthetic current projection enter the test.
async fn revoke_original_admin_device(fixture: &Fixture) {
    use arkret_models_collaboration::events_payloads::{
        ControllerBackupTrustAnchor, DeviceAuthorizePayload, UnsignedKeyBackupActiveSeries,
    };
    use arkret_models_crypto::*;
    use coland_storage::*;
    use ed25519_dalek::Signer as _;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let account = fixture.pcr.history.account.clone();
    let device = fixture.pcr.history.founding_device_id.clone();
    let other = fixture
        .other_device
        .as_ref()
        .expect("real accepted revoking Device");
    let authorizer = arkret_wire::DeviceId::new(other.authorization.device_id.clone()).unwrap();
    let sign_as_other = |mut event: Event| {
        event.producer_proof = None;
        coland_test_support::signed_event::sign_fixture_event(
            event,
            fixture.pcr.history.did.as_str(),
            authorizer.as_str(),
            other.signing_seed,
        )
    };
    let source: DeviceAuthorizePayload = serde_json::from_value(
        serde_json::to_value(&fixture.pcr.history.events.last().unwrap().payload).unwrap(),
    )
    .unwrap();
    let old_series =
        arkret_wire::BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7()))
            .unwrap();
    let new_series =
        arkret_wire::BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7()))
            .unwrap();
    let backup = |series: &arkret_wire::BackupSeriesId| {
        let mut backup: KeyBackup = serde_json::from_value(json!({
            "backup_id":format!("ak:backup:{}",uuid::Uuid::now_v7()),"actor_id":ActorId::account(account.clone()),
            "backup_kind":"secret_storage","backup_version":"kb_1","created_at":at,"series_id":series,"series_seq":0,
            "encryption":{"recipient_method":"secret_storage_key","recipient_key_ref":"source-history-fixture-key","aead":{"name":"xchacha20_poly1305","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
            "domain_separation":{"subdomain":"secret_storage"},"contents":[{"item_kind":"recovery_key_share","secret_id":"device-source-history"}],
            "ciphertext":"AAAA","ciphertext_digest":arkret_canonical::sha256_digest([0,0,0]),
            "auth_data":{"device_id":device,"verification_method":fixture.pcr.history.device_verification_method,"signature_algorithm":"Ed25519","signature":"AA","device_authorize_event_id":fixture.pcr.unit.transactions[1].event.event_id}
        })).unwrap();
        let signature = SigningKey::from_bytes(&other.signing_seed)
            .sign(&backup.signing_payload_bytes().unwrap());
        backup.auth_data.signature = arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode(signature.to_bytes()),
        )
        .unwrap();
        backup.validate().unwrap();
        backup
    };
    let old = backup(&old_series);
    let new = backup(&new_series);
    let persistence = fixture.state.test_persistence();
    persistence
        .key_backups()
        .put(
            old.backup_id.to_string(),
            serde_json::to_value(&old).unwrap(),
        )
        .await
        .unwrap();
    let pointer = |series: &arkret_wire::BackupSeriesId, epoch, replaces, head| {
        let unsigned = UnsignedKeyBackupActiveSeries::new(
            ActorId::account(account.clone()),
            BackupKind::SecretStorage,
            series.clone(),
            epoch,
            replaces,
            head,
            at,
            other.verification_method.clone(),
            ControllerBackupTrustAnchor {
                authorize_event_id: other.authorization.authorization_ref.event_id.clone(),
                generation_ref: source.authorized_generation_ref,
            },
        )
        .unwrap();
        let signature = SigningKey::from_bytes(&other.signing_seed)
            .sign(&unsigned.signing_payload_bytes().unwrap());
        let payload = unsigned
            .attach_signature(
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    signature.to_bytes(),
                ))
                .unwrap(),
            )
            .unwrap();
        sign_as_other(fixture.admin_event(
            EventKind::KeyBackupActiveSeries,
            ScopeRef::Realm {
                realm_id: fixture.pcr.unit.transactions[0].event.realm_id.clone(),
            },
            serde_json::to_value(payload).unwrap(),
        ))
    };
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let stream = fixture.pcr.unit.transactions[1].commit.stream_ref.clone();
    let head = store.stream_head(&stream).await.unwrap().unwrap();
    let initial_pointer = pointer(&old_series, 1, vec![], head.commit_id);
    let transaction = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(
            fixture.state.test_persistence(),
        ),
        0,
    )
    .prepare_self_event_transaction(
        &initial_pointer,
        &fixture.state.service_core_id(),
        fixture
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        fixture.state.notary_signing_key().as_ref(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )
    .await
    .unwrap();
    persistence
        .key_backups()
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            queued_at: transaction.commit.committed_at,
            commit: transaction,
        })
        .await
        .unwrap();
    let revoke = sign_as_other(fixture.admin_event(EventKind::DeviceRevoke,ScopeRef::Realm {realm_id:stream.realm_id().clone()},json!({"device_id":device,"revoked_by":authorizer,"revoked_at":at,"reason":"security_rotation"})));
    let transaction = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(
            fixture.state.test_persistence(),
        ),
        0,
    )
    .prepare_self_event_transaction(
        &revoke,
        &fixture.state.service_core_id(),
        fixture
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        fixture.state.notary_signing_key().as_ref(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )
    .await
    .unwrap();
    let covering = transaction.commit.clone();
    let active = pointer(
        &new_series,
        2,
        vec![old_series.clone()],
        covering.commit_id.clone(),
    );
    let plan = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        arkret_wire::TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        account.clone(),
        authorizer,
        at + chrono::Duration::hours(1),
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::EventsSubmitBatchRequestBody {
                events: (vec![revoke.clone()])
                    .into_iter()
                    .map(arkret_wire::EventAdmissionSubmission::new)
                    .collect(),
            },
        )
        .unwrap(),
        Hash::new(arkret_canonical::sha256_digest(
            b"new-fixture-storage-secret",
        ))
        .unwrap(),
        vec![BackupRotationPlan {
            binding: BackupRotationBinding {
                backup_kind: BackupRotationKind::SecretStorage,
                previous_series_id: old_series,
                new_series_id: new_series,
                new_backups: vec![BackupObjectRef {
                    backup_id: new.backup_id.clone(),
                    ciphertext_digest: new.ciphertext_digest.clone(),
                }],
                active_series_event_id: active.event_id.clone(),
                old_backups: vec![BackupObjectRef {
                    backup_id: old.backup_id,
                    ciphertext_digest: old.ciphertext_digest,
                }],
            },
            new_backup_envelopes: vec![new],
            active_series_unit: PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                arkret_wire::EventsSubmitBatchRequestBody {
                    events: (vec![active])
                        .into_iter()
                        .map(arkret_wire::EventAdmissionSubmission::new)
                        .collect(),
                },
            )
            .unwrap(),
        }],
    )
    .unwrap();
    let prepared = SecurityTransactionPreparedPlan::SecurityRotation(plan.prepared_plan.clone());
    let (mut initial, canonical_request) = SecurityTransactionCreateRequest::SecurityRotation(plan)
        .into_initial_resource(prepared, at)
        .unwrap();
    let id = initial.transaction_id.clone();
    persistence
        .security_transactions()
        .create(SecurityTransactionRecord {
            resource: initial.clone(),
            canonical_request: canonical_request.clone(),
        })
        .await
        .unwrap();
    initial.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
    });
    persistence
        .security_transactions()
        .commit_revoke_proposal(RevokeProposalCommitWrite {
            transaction: SecurityTransactionRecord {
                resource: initial,
                canonical_request,
            },
            queued_at: covering.committed_at,
            commit: transaction,
        })
        .await
        .unwrap();
    let mut terminal = persistence
        .security_transactions()
        .get(id.as_str())
        .await
        .unwrap()
        .unwrap();
    let decided_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    terminal
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: fixture.state.service_core_id(),
            },
            accepted_at: decided_at,
        });
    terminal.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: revoke.event_id,
        covering_commit_id: covering.commit_id,
        result: SecurityRotationRevokeCommandDecision::Accepted,
        decided_at,
    });
    persistence
        .security_transactions()
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            step_outcome: Some(SecurityTransactionStepOutcomeRecord {
                transaction_id: id.to_string(),
                step: SecurityTransactionStep::Revoke,
                canonical_request: terminal.canonical_request.clone(),
                response: serde_json::to_value(&terminal.resource).unwrap(),
                participant_outcome: None,
            }),
            transaction: terminal,
        })
        .await
        .unwrap();
}

struct ManagedActorFixture {
    actor_id: arkret_identifiers::DidCoreId,
    initial_resolution: arkret_models_identity::ResolutionCommitment,
    method_history_evidence: arkret_models_identity::ResolutionMethodHistoryEvidence,
    inception_log_entry: Value,
}

fn sign_managed_device_event(
    mut event: Event,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    proof_at: chrono::DateTime<chrono::Utc>,
) -> Event {
    event.producer_proof = None;
    let suite = event.realm_id.digest_suite_code().digest_suite();
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(event, suite).unwrap();
    let signer = Ed25519PayloadSigner::new(
        key.clone(),
        authority.native_did.clone(),
        arkret_wire::DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id))
            .unwrap(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(proof_at),
    )
    .unwrap();
    event.into_event()
}

fn managed_device_metadata(
    authority: &coland_storage::AppletManagedDeviceAuthority,
) -> AppletManagedDeviceMetadata {
    AppletManagedDeviceMetadata {
        account_id: authority.account_id.clone(),
        device_id: authority.device_id.clone(),
        authorization_event_id: authority.selector.authorization_ref.event_id.clone(),
        applet_id: authority.applet_id.clone(),
        effective_scope: authority.scopes.entries()[0].effective_scope.clone(),
        nonce: format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
    }
}

fn managed_device_http_request(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    metadata: &AppletManagedDeviceMetadata,
    operation: arkret_wire::ServiceOperationId,
    signer: &SigningKey,
) -> salvo::test::RequestBuilder {
    managed_device_http_request_body(state, authority, metadata, operation, signer, None)
}

fn managed_device_http_request_body(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    metadata: &AppletManagedDeviceMetadata,
    operation: arkret_wire::ServiceOperationId,
    signer: &SigningKey,
    provided_body: Option<Vec<u8>>,
) -> salvo::test::RequestBuilder {
    managed_device_http_request_at(
        state,
        authority,
        metadata,
        operation,
        signer,
        provided_body,
        None,
    )
}

fn managed_device_http_request_at(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    metadata: &AppletManagedDeviceMetadata,
    operation: arkret_wire::ServiceOperationId,
    signer: &SigningKey,
    provided_body: Option<Vec<u8>>,
    provided_path: Option<&str>,
) -> salvo::test::RequestBuilder {
    managed_device_http_request_with_idempotency_at(
        state,
        authority,
        metadata,
        operation,
        signer,
        provided_body,
        provided_path,
        "same-business-intent",
    )
}

fn managed_device_http_request_with_idempotency_at(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    metadata: &AppletManagedDeviceMetadata,
    operation: arkret_wire::ServiceOperationId,
    signer: &SigningKey,
    provided_body: Option<Vec<u8>>,
    provided_path: Option<&str>,
    idempotency_key: &str,
) -> salvo::test::RequestBuilder {
    let descriptor = operation.descriptor();
    let path = descriptor
        .http_path
        .split('/')
        .map(|part| {
            if part.starts_with('{') {
                authority.selector.authorization_ref.event_id.as_str()
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let path = provided_path.map(str::to_owned).unwrap_or(path);
    let body = provided_body.unwrap_or_else(|| {
        if descriptor.http_method == "GET" || descriptor.http_method == "HEAD" {
            Vec::new()
        } else if descriptor.body_class == Some("binary_stream") {
            vec![0, 255, 1, 2]
        } else {
            b"{}".to_vec()
        }
    });
    let scheme = state
        .config()
        .public_base_url
        .split_once("://")
        .map_or("http", |(scheme, _)| scheme);
    let digest = content_digest_header(&body);
    let metadata = metadata.to_header_value().unwrap();
    let headers = vec![
        ("arkret-operation".to_owned(), operation.as_str().to_owned()),
        ("arkret-managed-device".to_owned(), metadata),
        (
            "destination-service-id".to_owned(),
            state.service_id().to_owned(),
        ),
        ("content-digest".to_owned(), digest.clone()),
        ("idempotency-key".to_owned(), idempotency_key.to_owned()),
    ];
    let parts = SignedRequestParts {
        method: descriptor.http_method.to_owned(),
        target_uri: format!("{scheme}://server{path}"),
        authority: "server".to_owned(),
        path: path.clone(),
        headers: headers.clone(),
        body_digest: Some(digest),
    };
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let kid = format!("did:key:{fingerprint}#{fingerprint}");
    let signature = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::AppletManagedDeviceV1,
        if body.is_empty() {
            &["idempotency-key"]
        } else {
            &["content-digest", "idempotency-key"]
        },
        "sig1",
        &kid,
        chrono::Utc::now().timestamp(),
        signer,
    )
    .unwrap();
    let mut builder = salvo::test::RequestBuilder::new(
        format!("http://server{path}"),
        salvo::http::Method::from_bytes(descriptor.http_method.as_bytes()).unwrap(),
    );
    for (name, value) in headers {
        builder = builder.add_header(
            name.parse::<salvo::http::header::HeaderName>().unwrap(),
            value,
            true,
        );
    }
    builder
        .add_header("Signature-Input", signature.signature_input_header, true)
        .add_header("Signature", signature.signature_header, true)
        .body(body)
}

async fn exercise_managed_device_http_authentication(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    signer: &SigningKey,
) {
    let echo =
        coland_http::test_applet_managed_device_authentication_service(fixture.state.clone());
    let baseline = authority_snapshot(&fixture.pool).await;
    let operations = arkret_wire::ServiceOperationId::ALL
        .iter()
        .copied()
        .filter(|operation| arkret_wire::applet_managed_device_scope_rule(*operation).is_some())
        .collect::<Vec<_>>();
    assert_eq!(operations.len(), 21);
    for operation in operations {
        let metadata = managed_device_metadata(authority);
        let response =
            managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
                .send(&echo)
                .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::OK),
            "authentication component: {operation}"
        );
        let before_replay = authority_snapshot(&fixture.pool).await;
        let response =
            managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
                .send(&echo)
                .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "nonce replay: {operation}"
        );
        assert_eq!(before_replay, authority_snapshot(&fixture.pool).await);
    }
    let operation = arkret_wire::ServiceOperationId::SelfCurrentResultsReadExactV1;
    let metadata = managed_device_metadata(authority);
    let before = authority_snapshot(&fixture.pool).await;
    let requests = [
        managed_device_http_request(
            &fixture.state,
            authority,
            &metadata,
            operation,
            &SigningKey::from_bytes(&[43; 32]),
        ),
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .add_header("Authorization", "Bearer impossible-human-session", true),
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .add_header("DPoP", "not-a-credential", true),
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .add_header(
                "Source-Service-ID",
                authority.source_service_id.as_str(),
                true,
            ),
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .add_header("Content-Encoding", "identity", true),
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .add_header(
                "Arkret-Managed-Device",
                metadata.to_header_value().unwrap(),
                false,
            ),
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .body(b"{\"tampered\":true}".to_vec()),
        managed_device_http_request(
            &fixture.state,
            authority,
            &metadata,
            arkret_wire::ServiceOperationId::SelfRealmReadStreamsV1,
            signer,
        ),
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                true,
            ),
    ];
    for request in requests {
        let response = request.send(&echo).await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(
            before,
            authority_snapshot(&fixture.pool).await,
            "invalid transport cannot consume nonce or business state"
        );
    }
    for metadata in [
        {
            let mut metadata = managed_device_metadata(authority);
            metadata.applet_id =
                arkret_wire::AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
            metadata
        },
        {
            let mut metadata = managed_device_metadata(authority);
            metadata.account_id.station_id = "ak:did_core:web:other.example".parse().unwrap();
            metadata
        },
        {
            let mut metadata = managed_device_metadata(authority);
            metadata.authorization_event_id =
                fixture.pcr.unit.transactions[1].event.event_id.clone();
            metadata
        },
        {
            let mut metadata = managed_device_metadata(authority);
            metadata.effective_scope = ScopeRef::Realm {
                realm_id: RealmId::from_event_id(&fixture.pcr.unit.transactions[1].event.event_id),
            };
            metadata
        },
    ] {
        let response =
            managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
                .send(&echo)
                .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(before, authority_snapshot(&fixture.pool).await);
    }
    let metadata = managed_device_metadata(authority);
    let (first, second) = tokio::join!(
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .send(&echo),
        managed_device_http_request(&fixture.state, authority, &metadata, operation, signer)
            .send(&echo),
    );
    let mut statuses = [first.status_code.unwrap(), second.status_code.unwrap()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::UNAUTHORIZED]);
    let mut after = authority_snapshot(&fixture.pool).await;
    let mut baseline = baseline;
    after.as_object_mut().unwrap().remove("device_nonces");
    baseline.as_object_mut().unwrap().remove("device_nonces");
    assert_eq!(
        baseline, after,
        "authentication creates only private nonce state"
    );
}

async fn authority_snapshot(pool: &PgPool) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Snapshot {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut connection = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object( \
        'events',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM canonical_events r), \
        'commits',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM realm_commits r), \
        'reviews',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM management_review_requests r), \
        'approval_audit',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM event_approval_private_audit r), \
        'profiles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM actor_profile_current_results r), \
        'device_generations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM pcr_device_generation_current_results r), \
        'device_authorizations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM pcr_device_authorization_current_results r), \
        'device_nonces',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_managed_device_nonces r), \
        'grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM capability_grant_current_results r), \
        'quota_counters',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM capability_quota_counters r), \
        'quota_consumptions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM capability_quota_consumptions r), \
        'quota_buckets',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM capability_quota_buckets r), \
        'managed',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_managed_identities r), \
        'installs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_installations r), \
        'claims',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM realm_actor_creations r), \
        'namespace_claims',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_namespace_claims r), \
        'transactions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_transactions r), \
        'completions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_authoring_completions r), \
        'authoring_units',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_authoring_units r), \
        'signer_sources',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM agent_producer_signer_keys r), \
        'authoring_previews',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_authoring_previews r), \
        'idempotency',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM idempotency_keys r), \
        'outbox',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM federation_outbox r), \
        'event_outbox',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM event_federation_outbox r)) AS value")
        .get_result::<Snapshot>(&mut *connection).await.unwrap().value
}

fn install_namespace(install: &Installed) -> &str {
    install
        .package
        .webhook_auth
        .key_ref
        .as_str()
        .strip_prefix("did:webvh:")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(_, rest)| rest.split([':', '#']).next())
        .and_then(|host| host.strip_suffix(".applet.example"))
        .expect("fixture Service DID authority is <namespace>.applet.example")
}

/// `ak.profile.create` is principal-scoped: the managed actor's Profile is
/// committed on, and projected for, its own PCR stream, never the portal.
async fn assert_profile_in_principal_control_realm(
    fixture: &Fixture,
    bundle: &AppletManagedActorAuthoringBundle,
) {
    let pcr_realm_id = arkret_wire::RealmId::from_event_id(&bundle.pcr_genesis_event.event_id);
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&bundle.profile_event.event_id)
        .await
        .unwrap()
        .expect("accepted managed Profile");
    assert_eq!(accepted.event.realm_id, pcr_realm_id);
    assert_eq!(accepted.commit.stream_ref.realm_id(), &pcr_realm_id);
    #[derive(diesel::QueryableByName)]
    struct ProfileRealm {
        #[diesel(sql_type = diesel::sql_types::Text)]
        realm_id: String,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let projected = diesel::sql_query(
        "SELECT realm_id FROM actor_profile_current_results WHERE actor_profile_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(
        arkret_wire::ActorProfileId::from_event_id(&bundle.profile_event.event_id).as_str(),
    )
    .get_result::<ProfileRealm>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(projected.realm_id, pcr_realm_id.as_str());
}

async fn assert_accepted_event(fixture: &Fixture, event: &Event) {
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .expect("accepted canonical Event and covering Commit");
    assert_eq!(accepted.event.event_id, event.event_id);
    assert_eq!(
        serde_json::to_value(accepted.event).unwrap(),
        serde_json::to_value(event).unwrap()
    );
    assert_eq!(accepted.commit.event_ref, event.event_id);
}

#[tokio::test]
async fn service_install_and_separate_bot_unit_have_exact_retry_without_new_writes() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);
    let install = Box::new(Box::pin(fixture.install(false)).await);
    let body: AppletInstallRequestBody = serde_json::from_value(install.body.clone()).unwrap();
    #[derive(diesel::QueryableByName)]
    struct AcceptanceInstant {
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        accepted_at: chrono::DateTime<chrono::Utc>,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let acceptance = diesel::sql_query(
        "SELECT accepted_at FROM applet_authoring_units WHERE response_body->>'applet_id'=$1 AND operation_id='ak.self.applet.command.install'",
    )
    .bind::<diesel::sql_types::Text, _>(install.package.applet_id.as_str())
    .get_result::<AcceptanceInstant>(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        acceptance.accepted_at,
        arkret_canonical::normalize_timestamp_canonical(acceptance.accepted_at)
    );
    let basis = &body.authoring_request_basis;
    for event in
        std::iter::once(&basis.registration_event).chain(basis.capability_grant_events.iter())
    {
        let accepted = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        #[derive(diesel::QueryableByName)]
        struct Source {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            payload: Value,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let source = diesel::sql_query(
            "SELECT producer_source_fact AS payload FROM agent_producer_signer_keys WHERE commit_id=$1 AND producer_source_fact IS NOT NULL",
        ).bind::<diesel::sql_types::Text,_>(accepted.commit.commit_id.as_str())
            .get_result::<Source>(&mut *conn).await.unwrap();
        let fact: arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact =
            serde_json::from_value(source.payload).unwrap();
        let suite = event.realm_id.digest_suite_code().digest_suite();
        fact.validate_commit_binding(
            &arkret_wire::CommittedEventFullView {
                event: accepted.event.clone(),
                commit: accepted.commit.clone(),
            },
            suite,
        )
        .unwrap();
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
            event, &fact, suite,
        )
        .unwrap();
        assert!(fact.accepted_at <= acceptance.accepted_at);
        assert_eq!(accepted.commit.committed_at, acceptance.accepted_at);
    }
    let bot_body: AppletBotProvisionRequestBody =
        serde_json::from_value(install.bot_body.clone()).unwrap();
    for event in [
        &bot_body.managed_actor_bundle.managed_actor_provision_event,
        &bot_body.managed_actor_bundle.pcr_genesis_event,
        &bot_body.managed_actor_bundle.accountability_grant_event,
        &bot_body.managed_actor_bundle.profile_event,
    ] {
        assert_accepted_event(&fixture, event).await;
    }
    assert_profile_in_principal_control_realm(&fixture, &bot_body.managed_actor_bundle).await;
    let authority = coland_http::routing::extensions::applet_bridge::managed_principal_authority(
        &fixture.state,
        install.bot_outcome.bot_actor_id.signing_principal_id(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(authority.applet_id, install.package.applet_id);
    assert!(!authority.fenced);
    let before = authority_snapshot(&fixture.pool).await;
    let (status, replay) = fixture
        .admin_post(
            "/_arkret/self/applets/install",
            arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
            &install.body,
            Some(&install.key),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "exact install retry: {replay}");
    assert_eq!(replay, serde_json::to_value(&install.outcome).unwrap());
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn signed_ghost_unit_rejects_inner_bad_signature_without_partial_acceptance() {
    use arkret_wire::PayloadSigner as _;
    let fixture = Box::new(Box::pin(Fixture::new()).await);
    let install = Box::new(Box::pin(fixture.install(true)).await);
    let body = fixture
        .ghost_body(&install, install_namespace(&install), "remote-a")
        .await;
    let mut bad: GhostActorProvisionRequestBody = serde_json::from_value(body.clone()).unwrap();
    let bad_bundle = bad.managed_actor_bundle.as_mut().unwrap();
    let proof = bad_bundle.profile_event.producer_proof.as_mut().unwrap();
    let header = proof.jws.split_once("..").unwrap().0;
    proof.jws = format!(
        "{header}..{}",
        arkret_canonical::base64url_encode([0_u8; 64])
    );
    bad_bundle.proof.payload_digest = bad_bundle.payload_digest().unwrap();
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&install.package.webhook_auth.key_ref),
        applet_service_did(&install.package),
        install.package.webhook_auth.key_ref.clone(),
    );
    bad_bundle.proof.jws = signer
        .sign_payload(&bad_bundle.proof_binding_bytes().unwrap())
        .unwrap()
        .jws;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .ghost_commit(
            &install,
            &serde_json::to_value(bad).unwrap(),
            "bad-inner-signature",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "bad inner producer signature: {rejection}"
    );
    assert_eq!(
        rejection["type"],
        "https://arkret.org/problems/signature_invalid"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
    let (status, outcome) = fixture.ghost_commit(&install, &body, "valid-ghost").await;
    assert_eq!(status, StatusCode::CREATED, "valid Ghost: {outcome}");
    let typed: GhostActorProvisionRequestBody = serde_json::from_value(body.clone()).unwrap();
    let bundle = typed.managed_actor_bundle.as_ref().unwrap();
    for event in [
        &bundle.managed_actor_provision_event,
        &bundle.pcr_genesis_event,
        &bundle.accountability_grant_event,
        &bundle.profile_event,
    ] {
        assert_accepted_event(&fixture, event).await;
    }
    // The Bot Profile already occupies its own PCR; the Ghost Profile must land
    // in the Ghost's PCR instead of colliding in the shared portal Realm.
    assert_profile_in_principal_control_realm(&fixture, bundle).await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, replay) = fixture.ghost_commit(&install, &body, "valid-ghost").await;
    assert_eq!(status, StatusCode::OK, "Ghost exact retry: {replay}");
    assert_eq!(replay, outcome);
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn real_install_without_ghost_scope_refuses_provision_preview() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);
    let install = Box::new(Box::pin(fixture.install(false)).await);
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture.ghost_preview(&install, "unapproved-ghost").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unapproved Ghost scope: {rejection}"
    );
    assert_eq!(
        rejection["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn valid_service_signed_ghost_outside_declared_namespace_is_rejected() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);
    let install = Box::new(Box::pin(fixture.install(true)).await);
    let body = fixture
        .ghost_body(&install, "another-service", "remote-b")
        .await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .ghost_commit(&install, &body, "outside-namespace")
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "namespace mismatch: {rejection}"
    );
    assert_eq!(
        rejection["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(rejection["reason_code"], "applet_namespace_mismatch");
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn accepted_applet_revoke_fences_original_bot_authority_from_durable_current() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);
    let install = Box::new(Box::pin(fixture.install(false)).await);
    let principal = install.bot_outcome.bot_actor_id.signing_principal_id();
    let before = coland_http::routing::extensions::applet_bridge::managed_principal_authority(
        &fixture.state,
        principal,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!before.fenced);
    assert_eq!(
        before.principal_control_realm_id,
        install.bot_outcome.principal_control_realm_id
    );
    Box::pin(fixture.revoke(&install)).await;
    let after = coland_http::routing::extensions::applet_bridge::managed_principal_authority(
        &fixture.state,
        principal,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(after.fenced);
    assert_eq!(after.provision_event_id, before.provision_event_id);
    assert_eq!(after.pcr_genesis_event_id, before.pcr_genesis_event_id);
    assert_eq!(after.effective_scope, before.effective_scope);
    let grants = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    for grant_id in &install.outcome.capability_grant_refs {
        let current = grants
            .iter()
            .find(|row| &row.grant_id == grant_id)
            .expect("installed Grant current");
        assert_eq!(
            serde_json::to_value(current.value.status).unwrap(),
            "revoked"
        );
    }
}

#[tokio::test]
async fn revoke_all_needs_no_account_authority_and_has_no_delegated_session_mode() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);
    let install = Box::new(Box::pin(fixture.install(false)).await);
    let preview_path = format!(
        "/_arkret/self/applets/{}/revoke/preview",
        install.package.applet_id
    );
    let mut unknown_mode = serde_json::to_value(AppletRevokePreviewRequestBody {
        effective_scope: ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        reason_code: arkret_wire::ReasonCode::from_wire("applet_revoked"),
        revoke_mode: arkret_wire::AppletRevokeMode::RevokeAll,
    })
    .unwrap();
    unknown_mode["revoke_mode"] = json!("revoke_delegated_sessions");
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .admin_post(
            &preview_path,
            arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
            &unknown_mode,
            None,
        )
        .await;
    assert!(
        status.is_client_error(),
        "revoke_delegated_sessions is not a v1 revoke mode: {status} {rejection}"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);

    let outcome = fixture
        .revoke_with_mode(&install, arkret_wire::AppletRevokeMode::RevokeAll)
        .await;
    let local_effects = outcome
        .steps
        .iter()
        .filter_map(|step| match step {
            AppletRevokeStep::LocalEffect(local) => Some(local.effect_kind),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        local_effects,
        vec![AppletRevokeLocalEffectKind::LocalAppletFence]
    );
    let grants = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    for grant_id in &install.outcome.capability_grant_refs {
        let current = grants
            .iter()
            .find(|row| &row.grant_id == grant_id)
            .expect("installed Grant current");
        assert_eq!(
            serde_json::to_value(current.value.status).unwrap(),
            "revoked"
        );
    }
}

#[tokio::test]
async fn revoke_rechecks_previously_signed_ghost_request_before_accepting_any_event() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);
    let install = Box::new(Box::pin(fixture.install(true)).await);
    let body = fixture
        .ghost_body(&install, install_namespace(&install), "pending-remote")
        .await;
    Box::pin(fixture.revoke(&install)).await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .ghost_commit(&install, &body, "signed-before-revoke")
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "stale Applet authority: {rejection}"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
    let (status, rejection) = fixture.ghost_preview(&install, "after-revoke").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "new authoring after revoke: {rejection}"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn service_cannot_relinquish_a_managed_bots_terminal_child() {
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let grant_id = managed_actor_action_grant(
        &fixture,
        &install,
        &install.bot_outcome.bot_actor_id,
        vec!["ak.message.create".to_owned()],
    )
    .await;
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let grant = rows.iter().find(|r| r.grant_id == grant_id).unwrap();
    let event = managed_service_event(
        &fixture,
        &install,
        &install.bot_outcome.bot_actor_id,
        &grant_id,
        EventKind::CapabilityRelinquish,
        json!({"grant_id":grant_id,"expected_revision":grant.revision,"reason":"subject_request"}),
    );
    let before = managed_domain_snapshot(&fixture.pool).await;
    managed_rejected_event(&fixture, &install, &event).await;
    assert_eq!(before, managed_domain_snapshot(&fixture.pool).await);
    let after = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&after.iter().find(|r| r.grant_id == grant_id).unwrap().value)
            .unwrap(),
        serde_json::to_value(&grant.value).unwrap()
    );
    // The authenticated rejected delivery may replay; it never becomes an
    // accepted relinquish and never alters the child or its source parent.
    managed_rejected_event(&fixture, &install, &event).await;
    assert_eq!(before, managed_domain_snapshot(&fixture.pool).await);
}

#[tokio::test]
async fn managed_child_rejects_service_executor_and_noncanonical_binding_changes() {
    use arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind;
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let child_id = managed_actor_action_grant(
        &fixture,
        &install,
        &install.bot_outcome.bot_actor_id,
        vec!["ak.message.create".to_owned()],
    )
    .await;
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let child = &rows.iter().find(|r| r.grant_id == child_id).unwrap().value;
    let [IssuerAuthorityRef::Grant { grant_id: parent }] = child.issuer_authority_refs.as_slice()
    else {
        panic!("exact parent")
    };
    let service = ActorId::service(install.package.service_id.clone());
    for mutation in 0..4 {
        let mut body = CapabilityGrantCreateBody {
            schema: child.schema.clone(),
            realm_id: child.realm_id.clone(),
            issuer_id: child.issuer_id.clone(),
            subject: child.subject.clone(),
            actions: child.actions.clone(),
            resources: child.resources.clone(),
            constraints: child.constraints.clone(),
            issuer_authority_refs: child.issuer_authority_refs.clone(),
            issued_at: chrono::Utc::now(),
        };
        let binding = body
            .constraints
            .iter_mut()
            .find(|c| c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority))
            .unwrap();
        match mutation {
            0 => binding.executed_by=Some(service.clone()),
            1 => binding.effect=arkret_models_collaboration::governance::grant_constraint::GrantConstraintEffect::Deny,
            2 => binding.evaluation_class=None,
            3 => binding.applies_to_actions=vec!["ak.message.create".to_owned()],
            _ => unreachable!(),
        }
        let event = managed_service_event(
            &fixture,
            &install,
            &service,
            parent,
            EventKind::CapabilityGrant,
            serde_json::to_value(CapabilityGrantPayload { grant: body }).unwrap(),
        );
        let before = managed_domain_snapshot(&fixture.pool).await;
        managed_rejected_event(&fixture, &install, &event).await;
        assert_eq!(
            before,
            managed_domain_snapshot(&fixture.pool).await,
            "binding mutation {mutation} wrote domain state"
        );
    }
}

#[tokio::test]
async fn service_original_issuer_can_revoke_terminal_child_after_parent_revocation() {
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let child_id = managed_actor_action_grant(
        &fixture,
        &install,
        &install.bot_outcome.bot_actor_id,
        vec!["ak.message.create".to_owned()],
    )
    .await;
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let child = rows.iter().find(|r| r.grant_id == child_id).unwrap();
    let [
        IssuerAuthorityRef::Grant {
            grant_id: parent_id,
        },
    ] = child.value.issuer_authority_refs.as_slice()
    else {
        panic!("terminal child exact Service parent")
    };
    let parent = rows.iter().find(|r| &r.grant_id == parent_id).unwrap();
    let parent_revoke = fixture.admin_event(
        EventKind::CapabilityRevoke,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        json!({"grant_id":parent_id,"expected_revision":parent.revision,"reason":"parent_closed"}),
    );
    accepted_admin_domain_event(&fixture, parent_revoke).await;
    let service = ActorId::service(install.package.service_id.clone());
    let revoke = managed_service_event(
        &fixture,
        &install,
        &service,
        parent_id,
        EventKind::CapabilityRevoke,
        json!({"grant_id":child_id,"expected_revision":child.revision,"reason":"issuer_request"}),
    );
    assert_managed_accepted(&fixture, &install, &revoke).await;
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    assert_eq!(
        rows.iter().find(|r| r.grant_id == child_id).unwrap().status,
        coland_storage::CapabilityGrantCurrentStatus::Revoked
    );
    assert_eq!(
        rows.iter()
            .find(|r| &r.grant_id == parent_id)
            .unwrap()
            .status,
        coland_storage::CapabilityGrantCurrentStatus::Revoked
    );
}

fn deterministic_managed_actor_seed(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"coland:extensions-smoke:managed-actor:");
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn managed_actor_fixture(
    namespace: &str,
    local_id: &str,
    controller_principal_id: &arkret_identifiers::DidCoreId,
) -> ManagedActorFixture {
    let endpoint: Url = format!("https://{}.applet.example/", safe_did_token(namespace))
        .parse()
        .expect("fixture managed-actor endpoint");
    let local_id = safe_did_token(local_id);
    let root_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:root:{controller_principal_id}",
        safe_did_token(namespace)
    ));
    let next_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:next:{controller_principal_id}",
        safe_did_token(namespace)
    ));
    let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&next_seed)
            .verifying_key()
            .as_bytes(),
    );
    let version_time = chrono::DateTime::parse_from_rfc3339("2026-08-24T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let controller_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:controller:{controller_principal_id}",
        safe_did_token(namespace)
    ));
    let inception = arkret_signatures::webvh::prepare_applet_managed_inception(
        &arkret_signatures::webvh::AppletManagedInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &local_id,
            controller_public_key: &SigningKey::from_bytes(&controller_seed)
                .verifying_key()
                .to_bytes(),
            version_time,
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_key,
        },
    )
    .expect("fixture managed-actor WebVH inception");
    let did = Did::new(inception.did.clone()).expect("fixture managed-actor DID");
    let actor_id = arkret_wire::project_did_to_core_id(&did)
        .expect("fixture managed-actor Core DID projection");
    let method_history_head = arkret_canonical::canonical_sha256(&inception.log_entry)
        .expect("fixture WebVH history head");
    let normalized_document: arkret_models_identity::DidDocument =
        serde_json::from_value(inception.log_entry["state"].clone())
            .expect("fixture WebVH DID document");
    let document_digest = arkret_identity::document_canonical_digest(&normalized_document)
        .expect("fixture WebVH document digest");
    let witness_records = Vec::<Value>::new();
    let witness_proofs_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&witness_records).expect("fixture WebVH witness digest"),
    )
    .unwrap();
    let boundary = arkret_models_identity::ResolutionMethodEvidenceBoundary {
        from_method_history_head: method_history_head.clone(),
        from_version_id: inception.version_id.clone(),
        to_method_history_head: method_history_head.clone(),
        to_version_id: inception.version_id.clone(),
    };
    let method_history_evidence =
        arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            boundary,
            evidence: arkret_models_identity::ResolutionDidBindingEvidenceReceipt {
                kind:
                    arkret_models_identity::ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".to_owned(),
                document_digest,
                method_proofs: vec![arkret_models_identity::ResolutionDidBindingMethodProof {
                    kind: arkret_models_identity::ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: method_history_head.clone(),
                    witnesses: Vec::new(),
                    witness_proofs_digest,
                }],
            },
            log_entries: vec![inception.log_entry.clone()],
            witness_records,
        };
    ManagedActorFixture {
        actor_id,
        initial_resolution: arkret_models_identity::ResolutionCommitment {
            did,
            method_history_head,
            version_id: inception.version_id,
        },
        method_history_evidence,
        inception_log_entry: inception.log_entry,
    }
}

async fn ingest_managed_actor_current_document(state: &AppState, actor: &ManagedActorFixture) {
    let now = chrono::Utc::now();
    let did = actor.initial_resolution.did.to_string();
    let document = actor.inception_log_entry["state"].clone();
    let record = coland_storage::WebvhDocumentRecord {
        did: did.clone(),
        did_document: document,
        key_log_head: Some(actor.initial_resolution.method_history_head.clone()),
        seq: 1,
        method_evidence: serde_json::to_value(&actor.method_history_evidence).unwrap(),
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .append_log_event(coland_storage::WebvhLogRecord {
            event_digest: actor.initial_resolution.method_history_head.clone(),
            did,
            seq: 1,
            operation: actor.inception_log_entry.clone(),
            created_at: now,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .webvh()
        .put_document(record.clone())
        .await
        .unwrap();
    state
        .test_cache_resolved_webvh_record(coland_services::identity::DidDocumentState {
            did: record.did,
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            method_evidence: record.method_evidence,
            fetched_at: record.fetched_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
        })
        .unwrap();
}

// This provider serves an actual signed native WebVH history over TLS.
// Requests resolve afresh, so removing a method cannot be hidden by the
// installation snapshot or the process-local DID cache.
struct NativeAppletService {
    package: AppletPackage,
    history: Arc<Mutex<Vec<Value>>>,
    managed_author: Arc<
        Mutex<
            Option<
                Arc<arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService>,
            >,
        >,
    >,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn native_applet_service_inception(
    package: &AppletPackage,
) -> arkret_signatures::webvh::PreparedInception {
    use rand_chacha::rand_core::SeedableRng as _;
    let did = applet_service_did(package);
    let authority = did
        .as_str()
        .strip_prefix("did:webvh:")
        .unwrap()
        .split(':')
        .nth(1)
        .unwrap()
        .replace("%3A", ":")
        .replace("%3a", ":");
    let endpoint: Url = format!("https://{authority}/").parse().unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([43; 32]);
    arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            did_key_fragment: Some("applet-native-key"),
        },
        &[42; 32],
    )
    .unwrap()
}
fn resign_native_applet_package(package: &mut AppletPackage) {
    let evidence = applet_registration_epoch_evidence(package);
    package.stamp_registration_epoch(&evidence).unwrap();
    package.stamp_package_digest().unwrap();
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[13; 32]).verifying_key().as_bytes(),
    );
    let did = Did::new(format!("did:key:{multibase}")).unwrap();
    let vm = arkret_wire::DidUrl::new(format!("{did}#{multibase}")).unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed([13; 32], did, vm.clone());
    package.sign(&signer, &vm).unwrap();
}
impl NativeAppletService {
    fn new(applet: &str, namespace: &str, station: &arkret_wire::DidCoreId) -> Self {
        use std::io::{Read as _, Write as _};

        use rand_chacha::rand_core::SeedableRng as _;
        let expected = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../server/tests/fixtures/outbox-test-ca.pem")
            .canonicalize()
            .expect("checked-in Applet TLS test CA");
        let configured = std::env::var_os("SSL_CERT_FILE")
            .and_then(|path| std::path::Path::new(&path).canonicalize().ok());
        assert_eq!(
            configured.as_deref(),
            Some(expected.as_path()),
            "native Applet history requires SSL_CERT_FILE={}",
            expected.display(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint: Url = format!("https://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([43; 32]);
        let inception = arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
            &mut rng,
            &arkret_signatures::webvh::ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "service",
                also_known_as: &[],
                version_time: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                did_key_fragment: Some("applet-native-key"),
            },
            &[42; 32],
        )
        .unwrap();
        let history = Arc::new(Mutex::new(vec![inception.log_entry.clone()]));
        let mut package =
            signed_applet_package(applet, namespace, station, Some(endpoint.as_str()));
        package.service_id =
            arkret_wire::project_did_to_core_id(&Did::new(inception.did.clone()).unwrap()).unwrap();
        package.webhook_auth.key_ref =
            arkret_wire::DidUrl::new(inception.did_key_id.clone()).unwrap();
        resign_native_applet_package(&mut package);
        native_applet_service_histories()
            .lock()
            .unwrap()
            .insert(package.service_id.clone(), history.lock().unwrap().clone());
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    include_bytes!("fixtures/outbox-test-cert.der").to_vec(),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        include_bytes!("fixtures/outbox-test-key.der").to_vec(),
                    ),
                ),
            )
            .unwrap(),
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_stop = stop.clone();
        let served = history.clone();
        let managed_author = Arc::new(Mutex::new(
            None::<Arc<arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService>>,
        ));
        let served_author = managed_author.clone();
        let runtime = tokio::runtime::Handle::current();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let mut connections = Vec::new();
            ready_tx.send(()).unwrap();
            while !server_stop
                .as_ref()
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                let stream = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => panic!("native DID provider: {e}"),
                };
                let tls = tls.clone();
                let served = served.clone();
                let served_author = served_author.clone();
                let runtime = runtime.clone();
                // Fresh current resolution may open multiple TLS connections.
                // An idle connection must not block another request's proof.
                connections.push(std::thread::spawn(move || {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(tls.clone()).unwrap(),
                    stream,
                );
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buffer).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..n]);
                }
                let request = String::from_utf8_lossy(&bytes);
                if bytes.is_empty() { return; }
                let path = request.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                let author = served_author.lock().unwrap().clone();
                let local_id = path.strip_prefix("/webvh/").and_then(|p| p.strip_suffix("/did.jsonl").or_else(||p.strip_suffix("/did.json")));
                let published = match (author, local_id) {
                    (Some(author), Some(local_id)) if local_id != "service" => runtime.block_on(author.published_principal(local_id)).unwrap(),
                    _ => None,
                };
                let entries = served.lock().unwrap();
                let body = if let Some((document, history)) = published {
                    if path.ends_with("did.jsonl") { history.iter().map(|e|serde_json::to_string(e).unwrap()+"\n").collect::<String>() }
                    else { serde_json::to_string(&document).unwrap() }
                } else if request
                    .lines()
                    .next()
                    .is_some_and(|l| l.contains("did.jsonl"))
                {
                    entries
                        .iter()
                        .map(|e| serde_json::to_string(e).unwrap() + "\n")
                        .collect::<String>()
                } else {
                    serde_json::to_string(&entries.last().unwrap()["state"]).unwrap()
                };
                drop(entries);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
                }));
            }
            for connection in connections {
                connection.join().unwrap();
            }
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("native DID provider must be serving before installation");
        Self {
            package,
            history,
            managed_author,
            stop,
            thread: Some(thread),
        }
    }
    fn rotate(&self) -> AppletPackage {
        let inception = native_applet_service_inception(&self.package);
        let mut entries = self.history.lock().unwrap();
        let mut document = entries.last().unwrap()["state"].clone();
        let new_vm = format!("{}#applet-native-key-new", inception.did);
        document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .retain(|m| m["id"] != self.package.webhook_auth.key_ref.as_str());
        document["verificationMethod"].as_array_mut().unwrap().push(json!({"id":new_vm,"type":"Multikey","controller":inception.did,"publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(SigningKey::from_bytes(&[44;32]).verifying_key().as_bytes())}));
        document["assertionMethod"] = json!([new_vm]);
        let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[45; 32]).verifying_key().as_bytes(),
        );
        let rotation = arkret_signatures::webvh::prepare_service_rotation(
            &arkret_signatures::webvh::ServiceRotationInput {
                did: &inception.did,
                previous_entries: &entries,
                state: &document,
                current_update_seed: &inception.next_update_key_seed,
                next_update_public_key_multibase: &next,
                version_time: chrono::Utc::now() - chrono::Duration::seconds(1),
            },
        )
        .unwrap();
        entries.push(rotation.log_entry);
        let mut rotated = self.package.clone();
        rotated.webhook_auth.key_ref = arkret_wire::DidUrl::new(new_vm).unwrap();
        native_applet_service_histories()
            .lock()
            .unwrap()
            .insert(rotated.service_id.clone(), entries.clone());
        rotated
    }
}
impl Drop for NativeAppletService {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn content_digest_header(bytes: &[u8]) -> String {
    let raw = Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn applet_service_signing_key(verification_method: &str) -> SigningKey {
    if verification_method.ends_with("#applet-native-key")
        || verification_method.ends_with("#applet-service-key")
    {
        return SigningKey::from_bytes(&[42; 32]);
    }
    if verification_method.ends_with("#applet-native-key-new") {
        return SigningKey::from_bytes(&[44; 32]);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"coland:applet-service-key:");
    hasher.update(verification_method.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn signed_applet_package(
    applet_id: &str,
    namespace: &str,
    _target_station_id: &arkret_identifiers::DidCoreId,
    endpoint: Option<&str>,
) -> AppletPackage {
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[13; 32]).verifying_key().as_bytes(),
    );
    let controller_did = Did::new(format!("did:key:{multibase}")).unwrap();
    let controller_principal_id = arkret_wire::project_did_to_core_id(&controller_did).unwrap();
    // Registration epoch evidence admits only did:webvh / did:key; the Service
    // keeps its own SCID, distinct from every managed actor it provisions.
    let authority = format!("{}.applet.example", safe_did_token(namespace));
    let native = fixture_applet_service_inception(&authority);
    let service_did = Did::new(native.did.clone()).unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&service_did).unwrap();
    let mut package = AppletPackage::new(
        format!("package:{applet_id}"),
        AppletId::new(applet_id.to_owned()).unwrap(),
        service_id.clone(),
        service_did.clone(),
        controller_principal_id.clone(),
        endpoint
            .map(str::to_owned)
            .unwrap_or_else(|| format!("https://{}.applet.example", safe_did_token(namespace))),
        vec!["arkret.portal".to_owned()],
        AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(format!(
                "did:webvh:*:{}.applet.example:webvh:*",
                safe_did_token(namespace)
            ))],
            handles: vec![AppletNamespaceEntry::exclusive(namespace.to_owned())],
            ..Default::default()
        },
    );
    // Exercise canonical .000 serialization before sealing every package.
    package.created_at =
        chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    package.webhook_auth = WebhookAuth::http_message_signature(
        arkret_wire::DidUrl::new(format!("{service_did}#applet-service-key")).unwrap(),
        vec![HttpMessageSignatureAlgorithm::Ed25519],
    );
    let service_document = applet_service_id_document(&package);
    let registration_epoch_evidence =
        arkret_models_integration::applet::AppletRegistrationEpochEvidence::from_did_document(
            &service_document,
            service_method_version_evidence(&package),
        )
        .unwrap();
    package.requested_scopes = vec![
        "ak.message.create".to_owned(),
        "ak.applet.bot.provision".to_owned(),
        "ak.applet.ghost.provision".to_owned(),
    ];
    package.claimed_profiles = vec![
        "ak.profile.applet_bridge.v1".to_owned(),
        "ak.profile.applet_service.v1".to_owned(),
    ];
    package.endpoint_policy = AppletEndpointPolicy {
        endpoints: [
            "/_arkret/edge/applet/transactions",
            "/_arkret/edge/applet/actors/{actor_id}",
            "/_arkret/edge/applet/realms/{realm_id_or_alias}",
        ]
        .into_iter()
        .map(|path| AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: path.to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        })
        .collect(),
        extra: Default::default(),
    };
    package.ghost_policy = AppletGhostPolicy {
        enabled: true,
        accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
        ..Default::default()
    };
    package.receive_events = true;
    package.receive_signals = true;
    package
        .stamp_registration_epoch(&registration_epoch_evidence)
        .unwrap();
    package.stamp_package_digest().unwrap();
    let verification_method = arkret_wire::DidUrl::new(format!("{controller_did}#{multibase}"))
        .expect("fixture verification method is a DID URL");
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [13u8; 32],
        controller_did,
        verification_method.clone(),
    );
    package.sign(&signer, &verification_method).unwrap();
    package
}

fn applet_service_did(package: &AppletPackage) -> Did {
    let did = Did::new(
        package
            .webhook_auth
            .key_ref
            .as_str()
            .split_once('#')
            .expect("fixture signing method has a fragment")
            .0,
    )
    .expect("fixture signing method names a Service DID");
    assert_eq!(
        arkret_wire::project_did_to_core_id(&did).unwrap(),
        package.service_id
    );
    did
}

fn fixture_applet_service_inception(
    authority: &str,
) -> arkret_signatures::webvh::PreparedInception {
    use rand_chacha::rand_core::SeedableRng as _;
    let endpoint: Url = format!("https://{authority}/").parse().unwrap();
    let mut rng =
        rand_chacha::ChaCha20Rng::from_seed(arkret_canonical::sha256_bytes(authority.as_bytes()));
    arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: "2026-01-01T00:00:00Z".parse().unwrap(),
            did_key_fragment: Some("applet-service-key"),
        },
        &[42; 32],
    )
    .unwrap()
}

fn native_applet_service_histories() -> &'static Mutex<BTreeMap<arkret_wire::DidCoreId, Vec<Value>>>
{
    static HISTORIES: std::sync::OnceLock<Mutex<BTreeMap<arkret_wire::DidCoreId, Vec<Value>>>> =
        std::sync::OnceLock::new();
    HISTORIES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn fixture_applet_service_history(
    package: &AppletPackage,
) -> arkret_models_identity::AuthenticatedServiceResolution {
    let did = applet_service_did(package);
    let published = native_applet_service_histories()
        .lock()
        .unwrap()
        .get(&package.service_id)
        .cloned();
    let entries = if let Some(entries) = published {
        entries
    } else if package
        .webhook_auth
        .key_ref
        .as_str()
        .contains("#applet-native-key")
    {
        vec![native_applet_service_inception(package).log_entry.clone()]
    } else {
        let authority = did
            .as_str()
            .strip_prefix("did:webvh:")
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .replace("%3A", ":")
            .replace("%3a", ":");
        let native = fixture_applet_service_inception(&authority);
        assert_eq!(native.did, did.as_str());
        vec![native.log_entry.clone()]
    };
    let document = serde_json::from_value(entries.last().unwrap()["state"].clone()).unwrap();
    arkret_identity::build_authenticated_webvh_service_resolution(
        package.service_id.clone(),
        "applet_service".to_owned(),
        document,
        entries,
        Vec::new(),
        chrono::Utc::now(),
    )
    .unwrap()
}

fn applet_service_id_document(package: &AppletPackage) -> arkret_identity::DidDocument {
    fixture_applet_service_history(package).normalized_did_document
}

async fn ingest_applet_service_id_document(state: &AppState, package: &AppletPackage) {
    let now = chrono::Utc::now();
    let source = fixture_applet_service_history(package);
    let document = source.normalized_did_document.clone();
    let native_live_provider = package
        .webhook_auth
        .key_ref
        .as_str()
        .contains("#applet-native-key");
    let record = coland_storage::WebvhDocumentRecord {
        did: document.id.to_string(),
        did_document: serde_json::to_value(document).unwrap(),
        key_log_head: Some(
            source
                .method_history_evidence
                .boundary()
                .to_method_history_head
                .clone(),
        ),
        seq: 1,
        // Native HTTP scenarios acquire the complete source from their real
        // TLS provider. Only the generic component fixture caches its full proof.
        method_evidence: if native_live_provider {
            serde_json::to_value(service_method_version_evidence(package)).unwrap()
        } else {
            serde_json::to_value(&source.method_history_evidence).unwrap()
        },
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .put_document(record.clone())
        .await
        .unwrap();
    state
        .test_cache_resolved_webvh_record(coland_services::identity::DidDocumentState {
            did: record.did,
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            method_evidence: record.method_evidence,
            fetched_at: record.fetched_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
        })
        .unwrap();
}

/// The pinned `did:webvh` method version of the fixture Service DID.
fn service_method_version_evidence(package: &AppletPackage) -> AppletDidMethodVersionEvidence {
    AppletDidMethodVersionEvidence::versioned(
        "did:webvh",
        Some(
            fixture_applet_service_history(package)
                .method_history_evidence
                .boundary()
                .to_version_id
                .clone(),
        ),
        None,
    )
    .unwrap()
}

fn applet_registration_epoch_evidence(
    package: &AppletPackage,
) -> arkret_models_integration::AppletRegistrationEpochEvidence {
    arkret_models_integration::AppletRegistrationEpochEvidence::from_did_document(
        &applet_service_id_document(package),
        service_method_version_evidence(package),
    )
    .unwrap()
}

fn safe_did_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[derive(Clone)]
struct ManagementAuthorityFixture {
    record: arkret_models_collaboration::account_status::AccountStatusRecord,
    public_key: [u8; 32],
}

async fn spawn_introspection_mock(
    slot: Arc<Mutex<Value>>,
    authority: Arc<Mutex<Option<ManagementAuthorityFixture>>>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("introspection mock binds");
    let address = listener.local_addr().expect("introspection mock address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let slot = slot.clone();
            let authority = authority.clone();
            tokio::spawn(async move {
                let request = read_http_request(&mut stream).await;
                let end = request
                    .windows(4)
                    .position(|bytes| bytes == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let headers = String::from_utf8_lossy(&request[..end]);
                let body = if headers.lines().next()
                    == Some("POST /_arkret/peer/account-status/resolve HTTP/1.1")
                {
                    use arkret_models_collaboration::account_lifecycle::{
                        AccountStatusResolveOutcome, AccountStatusResolveRequestBody,
                    };
                    let query: AccountStatusResolveRequestBody =
                        serde_json::from_slice(&request[end..]).unwrap();
                    query.validate().unwrap();
                    let source = authority
                        .lock()
                        .unwrap()
                        .clone()
                        .expect("explicit signed AA fixture prerequisite");
                    assert_eq!(query.account_id, source.record.account_id);
                    assert_eq!(
                        query.account_authority_id,
                        source.record.account_authority_id
                    );
                    let pairs = headers
                        .lines()
                        .skip(1)
                        .filter_map(|line| line.split_once(':'))
                        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                        .collect::<Vec<_>>();
                    let policy=arkret_signatures::http_signature::SignatureVerificationPolicy::for_scenario(HttpSignatureScenario::ServiceToServiceV1,&["content-digest","source-trust-domain","destination-trust-domain"]).unwrap();
                    arkret_signatures::http_signature::verify_signed_canonical_json_message(
                        "POST",
                        &format!("http://{address}/_arkret/peer/account-status/resolve"),
                        &address.to_string(),
                        "/_arkret/peer/account-status/resolve",
                        pairs
                            .iter()
                            .map(|(name, value)| (name.as_str(), value.as_str())),
                        false,
                        &request[end..],
                        &ed25519_dalek::VerifyingKey::from_bytes(&source.public_key).unwrap(),
                        &policy,
                        chrono::Utc::now().timestamp(),
                    )
                    .unwrap();
                    let answer = AccountStatusResolveOutcome {
                        account_authority_id: query.account_authority_id.clone(),
                        account_id: query.account_id.clone(),
                        records: if query.from_status_seq <= source.record.status_seq {
                            vec![source.record]
                        } else {
                            vec![]
                        },
                        next_status_seq: None,
                        has_more: false,
                    };
                    answer.validate_for_request(&query).unwrap();
                    arkret_canonical::canonical_json_bytes(&answer).unwrap()
                } else {
                    serde_json::to_vec(&*slot.lock().unwrap()).expect("serialize outcome")
                };
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            });
        }
    });
    format!("http://{address}")
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut expected = None;
    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await.expect("read request");
        assert!(read > 0, "introspection request ended early");
        request.extend_from_slice(&chunk[..read]);
        if expected.is_none()
            && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let headers = String::from_utf8_lossy(&request[..index]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            expected = Some(index + 4 + length);
        }
        if expected.is_some_and(|total| request.len() >= total) {
            return request;
        }
    }
}

pub(crate) struct Fixture {
    pub(crate) state: AppState,
    pub(crate) pool: PgPool,
    pcr: PcrGenesisFixture,
    realm: RealmId,
    authority_event_ref: Option<EventId>,
    token: String,
    holder_key: SigningKey,
    other_device: Option<coland_test_support::pcr_genesis::AcceptedDevice>,
    management_authority: Arc<Mutex<Option<ManagementAuthorityFixture>>>,
}

impl Fixture {
    async fn revoke(&self, install: &Installed) -> AppletRevokeOutcome {
        Box::pin(self.revoke_with_mode(install, arkret_wire::AppletRevokeMode::RevokeRuntimeOnly))
            .await
    }

    fn revoke_with_mode<'a>(
        &'a self,
        install: &'a Installed,
        revoke_mode: arkret_wire::AppletRevokeMode,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AppletRevokeOutcome> + Send + 'a>> {
        Box::pin(async move {
            let reason = arkret_wire::ReasonCode::from_wire("applet_revoked");
            let preview_body = serde_json::to_value(AppletRevokePreviewRequestBody {
                effective_scope: ScopeRef::Realm {
                    realm_id: self.realm.clone(),
                },
                reason_code: reason.clone(),
                revoke_mode,
            })
            .unwrap();
            let path = format!(
                "/_arkret/self/applets/{}/revoke/preview",
                install.package.applet_id
            );

            let (status, preview) = self
                .admin_post(
                    &path,
                    arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
                    &preview_body,
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "revoke preview: {preview}");

            let preview: AppletRevokePreviewOutcome = serde_json::from_value(preview).unwrap();
            let revoke_plan_digest =
                Hash::new(arkret_canonical::canonical_sha256(&preview.revoke_plan).unwrap())
                    .unwrap();
            let events = preview
                .revoke_plan
                .capability_revocations
                .iter()
                .map(|intent| arkret_wire::EventAdmissionSubmission {
                    event: self.admin_event(
                        EventKind::CapabilityRevoke,
                        ScopeRef::Realm {
                            realm_id: self.realm.clone(),
                        },
                        serde_json::to_value(
                            arkret_models_collaboration::events_payloads::CapabilityRevokePayload {
                                grant_id: intent.grant_id.clone(),
                                expected_revision: intent.expected_revision.clone(),
                                reason: Some(intent.reason_code.as_str().to_owned()),
                            },
                        )
                        .unwrap(),
                    ),
                    approval_signatures: None,
                })
                .collect();
            let members=preview.revoke_plan.membership_removals.iter().map(|intent| arkret_wire::EventAdmissionSubmission {
            event:self.admin_event(EventKind::MemberState,ScopeRef::Realm {realm_id:self.realm.clone()},json!({"member_id":intent.member_id,"membership":intent.membership,"reason":intent.reason_code})), approval_signatures:None,
        }).collect();
            let body = serde_json::to_value(AppletRevokeRequestBody {
                revoke_plan_digest,
                effective_scope: preview.revoke_plan.effective_scope,
                reason_code: reason,
                revoke_mode,
                capability_revoke_events: events,
                membership_state_events: members,
            })
            .unwrap();
            let path = format!("/_arkret/self/applets/{}/revoke", install.package.applet_id);

            let (status, outcome) = self
                .admin_post(
                    &path,
                    arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
                    &body,
                    Some(&format!("revoke-{}", uuid::Uuid::now_v7())),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "accepted Applet revoke: {outcome}");
            let outcome: AppletRevokeOutcome = serde_json::from_value(outcome).unwrap();
            assert_eq!(
                outcome.status,
                AppletRevokeSagaStatus::Complete,
                "revoke outcome: {outcome:?}"
            );
            outcome
        })
    }

    pub(crate) async fn new() -> Self {
        Self::new_inner(false).await
    }
    async fn new_with_second_device() -> Self {
        Self::new_inner(true).await
    }
    async fn new_inner(with_second_device: bool) -> Self {
        Self::new_inner_with_public_base_url(with_second_device, None).await
    }
    async fn new_inner_with_public_base_url(
        with_second_device: bool,
        public_base_url: Option<String>,
    ) -> Self {
        let public_fixture = public_base_url.is_some();
        if public_fixture {
            eprintln!("[managed forward] origin fixture entered");
        }
        let _ = tracing_subscriber::fmt()
            .with_env_filter("warn,coland_storage_postgres::applet_content_delivery=debug,coland_http::routing::identity::applet_managed_device=debug")
            .with_test_writer()
            .try_init();
        let slot = Arc::new(Mutex::new(Value::Null));
        let management_authority = Arc::new(Mutex::new(None));
        let origin = spawn_introspection_mock(slot.clone(), management_authority.clone()).await;
        let mut config = AppConfig {
            development_mode: true,
            embedded_webvh_registration_bearer: Some("applet-fixture-registration".to_owned()),
            session_grant_introspection_url: Some(format!(
                "{origin}/_coauth/internal/session-grants/introspect"
            )),
            account_authority_url: Some(origin),
            // The fixture Applet Service is a did:webvh; registration epoch
            // evidence admits no did:web Service.
            did_resolver_allow_methods: vec![
                "webvh".to_owned(),
                "web".to_owned(),
                "key".to_owned(),
                "uuid".to_owned(),
            ],
            ..coland_test_support::app_config()
        };
        if let Some(public_base_url) = public_base_url {
            config.public_base_url = public_base_url;
        }
        config.account_authority_trust_domain = Some(config.trust_domain.clone());
        config.register_test_internal_authority_channel("applet-http-standard-grant".to_owned());
        let (state, pool) = coland_test_support::app_state_with_pool(config);
        if public_fixture {
            eprintln!("[managed forward] origin Station initialized");
        }
        let mut pcr = PcrGenesisFixture::new(state.service_did());
        Box::pin(pcr.admit(&state)).await.unwrap();
        if public_fixture {
            eprintln!("[managed forward] origin Human PCR accepted");
        }
        let other_device = if with_second_device {
            Some(
                pcr.admit_accepted_device(state.test_persistence().as_ref(), [89; 32])
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        state
            .test_persistence()
            .accounts()
            .put(&coland_storage::AccountRecord {
                pk: coland_storage::AccountPk(0),
                principal_id: pcr.history.account.principal_id.clone(),
                station_id: pcr.history.account.station_id.clone(),
                localpart: String::new(),
                display_name: Some("Applet admin".to_owned()),
                bio: None,
                avatar_blob_ref: None,
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("production account directory prerequisite after accepted PCR");
        let holder_key = SigningKey::from_bytes(&[88; 32]);
        let token = format!("applet-standard.{}", uuid::Uuid::now_v7());
        let jwk =
            arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&holder_key.verifying_key());
        let jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&jwk).unwrap();
        let session_public_key =
            arkret_models_identity::session_credential::CanonicalSessionPublicJwk::new(
                serde_json::to_string(&json!({
                    "crv":"Ed25519", "kty":"OKP",
                    "x": arkret_canonical::base64url_encode(holder_key.verifying_key().to_bytes()),
                }))
                .unwrap(),
            )
            .expect("canonical public holder JWK");
        assert_eq!(session_public_key.thumbprint_sha256().unwrap(), jkt);
        let grant = arkret_models_collaboration::session_grants::SessionGrantValidationMetadata {
            id: arkret_identifiers::SessionGrantId::from_issuance_digest(
                Sha256::digest(token.as_bytes()).into(),
            ),
            issuer_id: arkret_wire::DidCoreId::new("ak:did_core:web:coauth.example").unwrap(),
            account_id: pcr.history.account.clone(),
            device_id: Some(pcr.history.founding_device_id.clone()),
            audience_id: state.service_core_id(),
            scopes: vec![
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
                arkret_wire::ServiceOperationId::SELF_SIGNER_KEYS_READ_RESOLVE_V1,
                arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
                arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,
                arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(30),
            revoked_at: None,
            revocation_ref: format!("ak:session:{}", uuid::Uuid::now_v7()),
            session_public_key,
            cnf_jkt: jkt,
            credential_class:
                arkret_models_identity::session_credential::SessionGrantCredentialClass::Standard,
            holder_binding:
                arkret_models_identity::session_credential::SessionGrantHolderBinding::HumanDevice {
                    device_binding: pcr.history.founding_device_id.to_string(),
                },
            device_binding: Some(
                arkret_models_identity::session_credential::SessionGrantDeviceBinding {
                    device_id: pcr.history.founding_device_id.clone(),
                    authorization_event_id: pcr.history.events[1].event_id.clone(),
                    model_generation_ref: 1,
                },
            ),
            scope_details: None,
        };
        grant
            .validate()
            .expect("actual accepted founding-device StandardGrant metadata");
        let introspection = arkret_models_collaboration::session_grants::SessionGrantValidationOutcome {
            active: true,
            status: arkret_models_identity::admin_grant::SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(grant),
        };
        let wire = serde_json::to_value(&introspection).unwrap();
        serde_json::from_value::<
            arkret_models_collaboration::session_grants::SessionGrantValidationOutcome,
        >(wire.clone())
        .expect("typed introspection response round-trip")
        .validate()
        .expect("valid serialized introspection metadata");
        *slot.lock().unwrap() = wire;
        let realm = pcr.unit.transactions[0].event.realm_id.clone();
        let mut fixture = Box::new(Self {
            state,
            pool,
            pcr,
            realm,
            authority_event_ref: None,
            token,
            holder_key,
            other_device,
            management_authority,
        });
        let profile = fixture.admin_event(EventKind::ProfileCreate,ScopeRef::Realm {realm_id:fixture.pcr.unit.transactions[0].event.realm_id.clone()},
            json!({"object":{"principal_id":fixture.pcr.history.account.principal_id,"actor_kind":"user","display_name":"Applet admin"}}));
        if public_fixture {
            eprintln!("[managed forward] submitting origin Human Profile");
        }
        let (status, body) = fixture
            .admin_post(
                "/_arkret/self/account/profile",
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
                &json!({"profile_event":{"event":profile}}),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "Human Profile: {body}");
        if public_fixture {
            eprintln!("[managed forward] origin Human Profile accepted");
        }
        ordinary_realm::case_future(|| fixture.new_realm()).await;
        if public_fixture {
            eprintln!("[managed forward] origin Realm accepted");
        }
        *fixture
    }

    async fn new_circle_scope(&self) -> ScopeRef {
        let create = self.admin_event(EventKind::CircleCreate, ScopeRef::Realm { realm_id: self.realm.clone() }, json!({"object":{
            "schema":"ak.schema.circle.v1","realm_id":self.realm,"title":"Applet scope","display":{"short_name":format!("Applet-{}",&uuid::Uuid::now_v7().simple().to_string()[24..]),"color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join","state":"active","created_by":ActorId::account(self.pcr.history.account.clone()),"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
        }}));
        let circle_id = arkret_wire::CircleId::from_event_id(&create.event_id);
        accepted_admin_domain_event(self, create).await;
        ScopeRef::Circle {
            realm_id: self.realm.clone(),
            circle_id,
        }
    }

    async fn new_realm(&mut self) {
        self.new_realm_with_history("since_join").await;
    }

    async fn new_realm_with_history(&mut self, history_access: &str) {
        let mut unit = Box::new(ordinary_realm::bootstrap_unit_with_history_for_account(
            &uuid::Uuid::now_v7().to_string(),
            "public",
            history_access,
            &self.pcr.history.account,
            &self.state.service_did(),
        ));
        self.realm = unit.transactions[0].event.realm_id.clone();
        let source = PgAuthorityCommitStore {
            pool: self.pool.clone(),
        };
        let mut previous_commit = None;
        for tx in &mut unit.transactions {
            tx.event = self.sign_admin(tx.event.clone());
            tx.commit.event_ref = tx.event.event_id.clone();
            tx.producer_signer_fact = source
                .prepare_account_device_signer_fact(&tx.event, tx.commit.committed_at)
                .await
                .unwrap()
                .map(Into::into);
            assert!(tx.producer_signer_fact.is_some());
            tx.commit.producer_signer_fact_digest = tx
                .producer_signer_fact
                .as_ref()
                .map(|fact| fact.digest().unwrap());
            tx.commit.previous_commit_ref = previous_commit;
            self.seal_commit(&mut tx.commit);
            previous_commit = Some(tx.commit.commit_id.clone());
        }
        for (submission, tx) in unit.submission.events.iter_mut().zip(&unit.transactions) {
            submission.event = tx.event.clone();
        }
        unit.exact_request_body=arkret_canonical::canonical_json_bytes(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone())).unwrap();
        PgAuthorityCommitStore {
            pool: self.pool.clone(),
        }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
        self.authority_event_ref = Some(unit.transactions[0].event.event_id.clone());
    }

    fn seal_commit(&self, commit: &mut arkret_wire::RealmCommit) {
        commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(
                &arkret_canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap(),
            )
            .unwrap(),
        ));
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::unsigned_value(commit, &["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            self.state
                .service_verification_method("notary-key")
                .unwrap(),
            commit.committed_at,
            self.state.notary_signing_key().as_ref(),
        )
        .unwrap();
        commit.verify_commit_id_matches_content().unwrap();
    }

    fn sign_admin(&self, mut event: Event) -> Event {
        // Replace the bootstrap fixture's structural proof only after finalizing
        // the complete Event content with the real device signer.
        event.producer_proof = None;
        coland_test_support::signed_event::sign_fixture_event(
            event,
            self.pcr.history.did.as_str(),
            self.pcr.history.founding_device_id.as_str(),
            self.pcr.history.founding_device_signing_seed,
        )
    }
    fn admin_event(&self, kind: EventKind, scope: ScopeRef, payload: Value) -> Event {
        self.admin_event_at(kind, scope, payload, chrono::Utc::now())
    }
    fn admin_event_at(
        &self,
        kind: EventKind,
        scope: ScopeRef,
        payload: Value,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Event {
        let mut event = arkret_wire::test_support::raw_event_at(
            kind.as_str(),
            scope,
            self.pcr.history.account.principal_id.clone(),
            self.state.service_core_id(),
            payload,
            at,
        )
        .unwrap();
        if matches!(kind, EventKind::CircleCreate | EventKind::StrandCreate) {
            event.payload.get_mut("object").unwrap()["created_at"] = serde_json::Value::String(
                arkret_canonical::format_timestamp_canonical(event.created_at),
            );
        }
        self.sign_admin(event)
    }
    fn admin_post<'a>(
        &'a self,
        path: &'a str,
        operation: &'a str,
        body: &'a Value,
        idempotency: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (StatusCode, Value)> + Send + 'a>> {
        Box::pin(async move {
            let htu = format!(
                "{}{}",
                self.state.config().public_base_url.trim_end_matches('/'),
                path
            );
            let dpop = arkret_signatures::dpop::build_dpop_proof(
                &arkret_signatures::dpop::DpopProofRequest::new("POST", htu)
                    .access_token(self.token.clone()),
                &self.holder_key,
            )
            .unwrap();
            let mut request = TestClient::post(format!("http://server{path}"))
                .add_header("authorization", format!("DPoP {}", self.token), true)
                .add_header("dpop", dpop.header_value, true)
                .add_header("Arkret-Operation", operation, true)
                .add_header("content-type", "application/json", true)
                .body(arkret_canonical::canonical_json_bytes(body).unwrap());
            if let Some(key) = idempotency {
                request = request.add_header("Idempotency-Key", key, true);
            }
            let mut response = request.send(&service(self.state.clone())).await;
            let status = response.status_code.unwrap();
            (status, response.take_json().await.unwrap())
        })
    }

    async fn service_post(
        &self,
        package: &AppletPackage,
        path: &str,
        operation: &str,
        body: &Value,
        key: &str,
    ) -> (StatusCode, Value) {
        self.service_post_at(
            package,
            path,
            operation,
            body,
            key,
            chrono::Utc::now().timestamp(),
        )
        .await
    }
    async fn service_post_at(
        &self,
        package: &AppletPackage,
        path: &str,
        operation: &str,
        body: &Value,
        key: &str,
        created: i64,
    ) -> (StatusCode, Value) {
        let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
        let digest = content_digest_header(&bytes);
        let scheme = self
            .state
            .config()
            .public_base_url
            .split_once("://")
            .map_or("http", |(scheme, _)| scheme);
        let source_service_id = package.service_id.to_string();
        let destination_service_id = self.state.service_id().to_owned();
        let signed_request = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: format!("{scheme}://server{path}"),
            authority: "server".to_owned(),
            path: path.to_owned(),
            headers: vec![
                ("arkret-operation".to_owned(), operation.to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
                ("content-digest".to_owned(), digest.clone()),
                ("source-service-id".to_owned(), source_service_id.clone()),
                (
                    "destination-service-id".to_owned(),
                    destination_service_id.clone(),
                ),
                ("idempotency-key".to_owned(), key.to_owned()),
            ],
            body_digest: Some(digest.clone()),
        };
        let signature = sign_http_message_for_scenario(
            &signed_request,
            if operation == arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1
                || operation == arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1
                || operation
                    == arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1
                || operation
                    == arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1
                || operation
                    == arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1
            {
                HttpSignatureScenario::ServiceToServiceV1
            } else {
                HttpSignatureScenario::AppletTransactionV1
            },
            if operation == arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1
                || operation == arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1
                || operation
                    == arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1
                || operation
                    == arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1
                || operation
                    == arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1
            {
                &["content-digest", "idempotency-key"]
            } else {
                &[]
            },
            "sig1",
            &package.webhook_auth.key_ref,
            created,
            &applet_service_signing_key(&package.webhook_auth.key_ref),
        )
        .unwrap();
        let mut response = TestClient::post(format!("http://server{path}"))
            .add_header("Arkret-Operation", operation, true)
            .add_header("content-type", "application/json", true)
            .add_header("Content-Digest", digest, true)
            .add_header("Source-Service-ID", source_service_id, true)
            .add_header("Destination-Service-ID", destination_service_id, true)
            .add_header("Idempotency-Key", key, true)
            .add_header("Signature-Input", signature.signature_input_header, true)
            .add_header("Signature", signature.signature_header, true)
            .body(bytes)
            .send(&service(self.state.clone()))
            .await;
        (
            response.status_code.unwrap(),
            response.take_json().await.unwrap(),
        )
    }
}

pub(crate) struct Installed {
    pub(crate) package: AppletPackage,
    pub(crate) outcome: AppletInstallOutcome,
    pub(crate) bot_outcome: AppletBotProvisionOutcome,
    bot_body: Value,
    body: Value,
    key: String,
}

impl Fixture {
    fn managed_bundle(
        &self,
        package: &AppletPackage,
        request: &AppletManagedActorAuthoringRequest,
        actor: &ManagedActorFixture,
        registration: EventId,
    ) -> AppletManagedActorAuthoringBundle {
        let signer = Ed25519PayloadSigner::new(
            applet_service_signing_key(&package.webhook_auth.key_ref),
            applet_service_did(package),
            package.webhook_auth.key_ref.clone(),
        );
        arkret::author_applet_managed_actor_bundle(
            request,
            arkret::AppletManagedActorBundleAuthoringInput {
                actor_id: actor.actor_id.clone(),
                initial_resolution: actor.initial_resolution.clone(),
                method_history_evidence: actor.method_history_evidence.clone(),
                registration_ref: registration,
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                genesis_salt: arkret_wire::GenesisSalt::generate().unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:applet.example")
                    .unwrap(),
                security_class: arkret_wire::SecurityClass::HighAssurance,
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
                bot_display_name: "Installed Applet Bot".to_owned(),
            },
            &signer,
        )
        .unwrap()
    }

    pub(crate) async fn install(&self, ghost: bool) -> Installed {
        Box::pin(self.install_at_endpoint(ghost, None)).await
    }
    pub(crate) async fn install_at_endpoint(
        &self,
        ghost: bool,
        endpoint: Option<&str>,
    ) -> Installed {
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let id = format!("ak:applet:{}", uuid::Uuid::now_v7());
        let package =
            signed_applet_package(&id, &namespace, &self.state.service_core_id(), endpoint);
        self.install_package(ghost, package, &namespace).await
    }
    async fn install_package(
        &self,
        ghost: bool,
        package: AppletPackage,
        namespace: &str,
    ) -> Installed {
        self.install_package_in_scope(
            ghost,
            package,
            namespace,
            ScopeRef::Realm {
                realm_id: self.realm.clone(),
            },
        )
        .await
    }
    async fn install_package_in_scope(
        &self,
        ghost: bool,
        package: AppletPackage,
        namespace: &str,
        scope: ScopeRef,
    ) -> Installed {
        self.install_package_with_ghost_quota(ghost, package, namespace, scope, None)
            .await
    }

    async fn install_package_with_ghost_quota(
        &self,
        ghost: bool,
        package: AppletPackage,
        namespace: &str,
        scope: ScopeRef,
        ghost_quota: Option<GrantConstraint>,
    ) -> Installed {
        let extras = ghost_quota
            .map(|constraint| {
                BTreeMap::from([("ak.applet.ghost.provision".to_owned(), vec![constraint])])
            })
            .unwrap_or_default();
        let (package, install_outcome, body, key) = self
            .install_service_with_constraints(ghost, package, scope.clone(), extras)
            .await;
        let (bot_outcome, bot_body) = self
            .provision_bot_in_scope(
                &package,
                namespace,
                install_outcome.registration_event_ref.clone(),
                scope,
            )
            .await;
        Installed {
            package,
            outcome: install_outcome,
            bot_outcome,
            bot_body,
            body,
            key,
        }
    }

    async fn prepare_install_service_with_constraints(
        &self,
        ghost: bool,
        package: AppletPackage,
        scope: ScopeRef,
        creation_constraints: BTreeMap<String, Vec<GrantConstraint>>,
    ) -> (AppletPackage, Value) {
        ingest_applet_service_id_document(&self.state, &package).await;
        let evidence = applet_registration_epoch_evidence(&package);
        let registration = self.admin_event(
            EventKind::AppletRegistration,
            scope.clone(),
            serde_json::to_value(package.to_registration(&evidence).unwrap()).unwrap(),
        );
        let actions = if ghost {
            vec![
                "ak.message.create",
                "ak.applet.bot.provision",
                "ak.applet.ghost.provision",
            ]
        } else {
            vec!["ak.message.create", "ak.applet.bot.provision"]
        };
        let grants = actions
            .iter()
            .map(|action| {
                let grant = CapabilityGrantCreateBody {
                    schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                    realm_id: Some(self.realm.clone()),
                    issuer_id: ActorId::account(self.pcr.history.account.clone()),
                    subject: CapabilitySubject::Actor(ActorId::service(package.service_id.clone())),
                    actions: vec![(*action).to_owned()],
                    resources: vec![match &scope {
                        ScopeRef::Realm { realm_id } => {
                            arkret_wire::WireResourceSelector::realm(realm_id.clone())
                        }
                        ScopeRef::Circle {
                            realm_id,
                            circle_id,
                        } => {
                            let mut resource = arkret_wire::WireResourceSelector::circle(
                                realm_id.clone(),
                                circle_id.clone(),
                            );
                            resource.match_scope = Some(arkret_wire::ResourceMatchScope::Exact);
                            resource
                        }
                        _ => panic!("fixture only supports Realm/Circle"),
                    }],
                    constraints: {
                        let mut constraints = vec![GrantConstraint::applet_authority(
                            package.applet_id.clone(),
                            ActorId::service(package.service_id.clone()),
                            package.registration_epoch.clone(),
                        )];
                        if let Some(extra) = creation_constraints.get(*action) {
                            constraints.extend(extra.iter().cloned());
                        }
                        constraints
                    },
                    issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                        realm_id: self.realm.clone(),
                        authority_event_ref: self
                            .authority_event_ref
                            .as_ref()
                            .expect("accepted Realm genesis authority")
                            .clone(),
                        authority_generation: 0,
                    }],
                    issued_at: chrono::Utc::now(),
                };
                self.admin_event(
                    EventKind::CapabilityGrant,
                    scope.clone(),
                    serde_json::to_value(CapabilityGrantPayload { grant }).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let basis:AppletInstallAuthoringRequestBasis=serde_json::from_value(json!({
            "schema":AppletInstallAuthoringRequestBasis::SCHEMA,"purpose":"install_service","target_station_id":self.state.service_core_id(),
            "install_actor_id":registration.actor_id,"applet_id":package.applet_id,"service_id":package.service_id,"package_digest":package.package_digest,
            "effective_scope":scope,"approval_request":{"approve_actions":actions,
                "ghost_actor_mode":if ghost {"policy_declared"} else {"disallowed"},"delegated_native_actors_allowed":false,"e2ee_join_allowed":package.e2ee_policy.mls_join_requested == Some(true),"widget_allowed":false},
            "actor_policy":{"ghost_actor_mode":"policy_declared"},"e2ee_policy":{"mls_join_allowed":package.e2ee_policy.mls_join_requested == Some(true)},"widget_policy":{"widget_allowed":false},
            "registration_event":registration,"capability_grant_events":grants,
        })).unwrap();
        let preview_body = serde_json::to_value(AppletInstallPreviewRequestBody {
            applet_package: package.clone(),
            authoring_request_basis: basis.clone(),
        })
        .unwrap();
        let (status, preview) = self
            .admin_post(
                "/_arkret/self/applets/install/preview",
                arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
                &preview_body,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "install preview: {preview}");
        assert!(
            preview.get("authoring_request").is_none(),
            "Service install never authors a managed identity"
        );
        let plan: AppletInstallPlan = serde_json::from_value(preview["plan"].clone()).unwrap();
        let body = serde_json::to_value(AppletInstallRequestBody {
            applet_package: package.clone(),
            authoring_request_basis: basis,
            plan_digest: plan.plan_digest,
        })
        .unwrap();
        (package, body)
    }

    async fn install_service_with_constraints(
        &self,
        ghost: bool,
        package: AppletPackage,
        scope: ScopeRef,
        creation_constraints: BTreeMap<String, Vec<GrantConstraint>>,
    ) -> (AppletPackage, AppletInstallOutcome, Value, String) {
        let (package, body) = Box::pin(self.prepare_install_service_with_constraints(
            ghost,
            package,
            scope,
            creation_constraints,
        ))
        .await;
        let key = format!("install-{}", uuid::Uuid::now_v7());
        let service_before = authority_snapshot(&self.pool).await;
        let (status, outcome) = self
            .admin_post(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &body,
                Some(&key),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "install commit: {outcome}");
        let install_outcome: AppletInstallOutcome = serde_json::from_value(outcome).unwrap();
        let service_after = authority_snapshot(&self.pool).await;
        for key in [
            "profiles",
            "device_generations",
            "device_authorizations",
            "completions",
            "outbox",
        ] {
            assert_eq!(
                service_before[key], service_after[key],
                "Service-only install changed {key}"
            );
        }

        assert!(
            serde_json::to_value(&install_outcome)
                .unwrap()
                .get("bot_actor_id")
                .is_none()
        );
        (package, install_outcome, body, key)
    }

    async fn provision_bot(
        &self,
        package: &AppletPackage,
        namespace: &str,
        registration_ref: EventId,
    ) -> (AppletBotProvisionOutcome, Value) {
        self.provision_bot_in_scope(
            package,
            namespace,
            registration_ref,
            ScopeRef::Realm {
                realm_id: self.realm.clone(),
            },
        )
        .await
    }
    async fn bot_body_in_scope(
        &self,
        package: &AppletPackage,
        namespace: &str,
        registration_ref: EventId,
        scope: ScopeRef,
    ) -> Value {
        let path = format!(
            "/_arkret/self/applets/{}/bots/provision/preview",
            package.applet_id
        );
        let (status, preview) = self.service_post(package, &path, arkret_wire::ServiceOperationId::SELF_APPLET_BOT_COMMAND_PREVIEW_V1,
            &json!({"effective_scope":scope,"request_id":format!("bot-{}",uuid::Uuid::now_v7()),"display_name":"Installed Applet Bot"}), &format!("bot-preview-{}",uuid::Uuid::now_v7())).await;
        assert_eq!(status, StatusCode::OK, "Bot preview: {preview}");
        let request: AppletManagedActorAuthoringRequest =
            serde_json::from_value(preview["authoring_request"].clone()).unwrap();
        let bot = managed_actor_fixture(
            namespace,
            &format!("bot-{}", uuid::Uuid::now_v7().simple()),
            &package.service_id,
        );
        ingest_managed_actor_current_document(&self.state, &bot).await;
        let bundle = self.managed_bundle(package, &request, &bot, registration_ref);
        let bot_body = serde_json::to_value(AppletBotProvisionRequestBody {
            authoring_request: request,
            managed_actor_bundle: bundle,
            approval_signatures: vec![],
        })
        .unwrap();
        bot_body
    }

    async fn provision_bot_in_scope(
        &self,
        package: &AppletPackage,
        namespace: &str,
        registration_ref: EventId,
        scope: ScopeRef,
    ) -> (AppletBotProvisionOutcome, Value) {
        let bot_body = self
            .bot_body_in_scope(package, namespace, registration_ref, scope)
            .await;
        let path = format!("/_arkret/self/applets/{}/bots/provision", package.applet_id);
        let (status, bot_outcome) = self
            .service_post(
                package,
                &path,
                arkret_wire::ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
                &bot_body,
                &format!("bot-provision-{}", uuid::Uuid::now_v7()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "Bot provision: {bot_outcome}");
        (serde_json::from_value(bot_outcome).unwrap(), bot_body)
    }

    async fn ghost_preview(&self, install: &Installed, external: &str) -> (StatusCode, Value) {
        let path = format!(
            "/_arkret/self/applets/{}/ghosts/provision/preview",
            install.package.applet_id
        );
        self.service_post(&install.package,&path,arkret_wire::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PREVIEW_V1,
            &json!({"effective_scope":install.body["authoring_request_basis"]["effective_scope"],"external_ref":{"protocol":"slack","instance_id":"team","external_id":external},"display_name":"Remote user"}),&format!("preview-{external}-{}",uuid::Uuid::now_v7())).await
    }
    async fn ghost_body(&self, install: &Installed, namespace: &str, external: &str) -> Value {
        let (status, preview) = self.ghost_preview(install, external).await;
        assert_eq!(status, StatusCode::OK, "ghost preview: {preview}");
        let request: AppletManagedActorAuthoringRequest =
            serde_json::from_value(preview["authoring_request"].clone()).unwrap();
        if let Some(existing) = request
            .basis
            .ghost()
            .unwrap()
            .existing_managed_actor
            .clone()
        {
            return serde_json::to_value(GhostActorProvisionRequestBody {
                authoring_request: request,
                managed_actor_bundle: None,
                existing_managed_actor: Some(existing),
                approval_signatures: vec![],
            })
            .unwrap();
        }
        let actor = managed_actor_fixture(namespace, external, &install.package.service_id);
        ingest_managed_actor_current_document(&self.state, &actor).await;
        let bundle = self.managed_bundle(
            &install.package,
            &request,
            &actor,
            install.outcome.registration_event_ref.clone(),
        );
        serde_json::to_value(GhostActorProvisionRequestBody {
            authoring_request: request,
            managed_actor_bundle: Some(bundle),
            existing_managed_actor: None,
            approval_signatures: vec![],
        })
        .unwrap()
    }
    async fn ghost_commit(
        &self,
        install: &Installed,
        body: &Value,
        key: &str,
    ) -> (StatusCode, Value) {
        self.service_post(
            &install.package,
            &format!(
                "/_arkret/self/applets/{}/ghosts/provision",
                install.package.applet_id
            ),
            arkret_wire::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1,
            body,
            key,
        )
        .await
    }
}

async fn admin_domain_request(
    fixture: &Fixture,
    event: Event,
) -> coland_storage::EventCommitRequest {
    let producer = event
        .account_device_producer()
        .unwrap()
        .expect("admin Event has a Human Device producer");
    // Explicit directory issuance is a fixture prerequisite. Local
    // producer validation prepares its root without retaining it.
    let query = arkret_models_crypto::KeysQueryRequestBody {
        device_keys: vec![arkret_models_crypto::QueryAccountDeviceSelector {
            account_id: producer.account_id.clone(),
            device_ids: vec![producer.device_id.clone()],
        }],
        timeout_ms: None,
    };
    let (status, result) = fixture
        .admin_post(
            "/_arkret/self/keys/query",
            arkret_wire::ServiceOperationId::SELF_KEYS_READ_LOOKUP_V1,
            &serde_json::to_value(query).unwrap(),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "explicit Device directory issuance: {result}"
    );
    let result: arkret_models_crypto::KeysQueryOutcome = serde_json::from_value(result).unwrap();
    let row = result
        .device_keys
        .iter()
        .find(|entry| entry.account_id == producer.account_id)
        .and_then(|entry| entry.device_keys.get(&producer.device_id))
        .expect("complete current Device directory row");
    let original = fixture
        .state
        .test_persistence()
        .account_device_signer_evidence()
        .get(
            &producer.account_id,
            &producer.device_id,
            &row.signer_evidence_ref,
        )
        .await
        .unwrap()
        .expect("explicitly issued original Device evidence retained");
    original
        .validate_binding(&producer.account_id, &producer.device_id)
        .unwrap();
    assert_eq!(
        original.signer_evidence_ref().unwrap(),
        row.signer_evidence_ref
    );
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let stream =
        arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .unwrap();
    let stream_head = store.stream_head(&stream).await.unwrap();
    let head = match stream_head.as_ref() {
        Some(head) => head.clone(),
        None => store
            .stream_head(&arkret_wire::CommitStreamRef::Realm {
                realm_id: fixture.realm.clone(),
            })
            .await
            .unwrap()
            .unwrap(),
    };
    let accepted = store
        .committed_event_by_commit_id(&head.commit_id)
        .await
        .unwrap()
        .unwrap();
    let previous = coland_storage::AuthorityCommitTransaction {
        expected_authority: store
            .current_authority(&fixture.realm)
            .await
            .unwrap()
            .unwrap(),
        event: accepted.event,
        commit: accepted.commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: vec![],
        recipient_queue_capacity: 0,
    };
    let mut request = ordinary_realm::request_for_event(
        &previous,
        event.clone(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    request.authority_commit.commit.stream_ref = stream;
    request.authority_commit.commit.stream_position = stream_head
        .as_ref()
        .map_or(0, |head| head.stream_position + 1);
    request.authority_commit.commit.previous_commit_ref = stream_head.map(|head| head.commit_id);
    let mut request = ordinary_realm::source_request(&fixture.pool, request).await;
    fixture.seal_commit(&mut request.authority_commit.commit);
    if let Some(fact) = request
        .authority_commit
        .producer_signer_fact
        .as_ref()
        .and_then(|fact| fact.as_account_device())
    {
        let selector = coland_storage::DeviceRevocationGateSelector {
            principal_id: producer.account_id.principal_id,
            station_id: producer.account_id.station_id,
            device_id: producer.device_id.to_string(),
            authorization_ref: fact.key.authorization_ref.clone(),
        };
        assert_eq!(
            original
                .device_projection_attestation
                .attestation
                .device_authorize_event_id,
            selector.authorization_ref.event_id
        );
        request.self_producer_guard = Some(
            coland_storage::SelfProducerCommitGuard::HumanDeviceEvidence {
                selector,
                evidence: Box::new(original),
            },
        );
    }
    request
}

// Registration replacement uses the same closed native aggregate as install.
// HTTP's ordinary duplicate-install guard remains in force; no isolated
// registration Event or fabricated Commit is accepted for this fixture.
async fn replace_installation_closed_unit(
    fixture: &Fixture,
    prior: &Installed,
    package: AppletPackage,
) -> AppletInstallOutcome {
    use coland_storage::{AppletStore as _, PersistenceError, SelfProducerCommitGuard};
    let mut body: AppletInstallRequestBody = serde_json::from_value(prior.body.clone()).unwrap();
    body.applet_package = package.clone();
    body.authoring_request_basis.package_digest = package.package_digest.clone().unwrap();
    let basis = &mut body.authoring_request_basis;
    basis.registration_event = fixture.admin_event(
        EventKind::AppletRegistration,
        basis.effective_scope.clone(),
        serde_json::to_value(
            package
                .to_registration(&applet_registration_epoch_evidence(&package))
                .unwrap(),
        )
        .unwrap(),
    );
    for event in &mut basis.capability_grant_events {
        let mut payload: CapabilityGrantPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
        for constraint in &mut payload.grant.constraints {
            if constraint.applet_id.as_ref() == Some(&package.applet_id) {
                constraint.registration_epoch = Some(package.registration_epoch.clone());
            }
        }
        payload.grant.issued_at = chrono::Utc::now();
        *event = fixture.admin_event(
            EventKind::CapabilityGrant,
            basis.effective_scope.clone(),
            serde_json::to_value(payload).unwrap(),
        );
    }
    let preview_body = serde_json::to_value(AppletInstallPreviewRequestBody {
        applet_package: package.clone(),
        authoring_request_basis: basis.clone(),
    })
    .unwrap();
    let (status, preview) = fixture
        .admin_post(
            "/_arkret/self/applets/install/preview",
            arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
            &preview_body,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let plan: AppletInstallPlan = serde_json::from_value(preview["plan"].clone()).unwrap();
    body.plan_digest = plan.plan_digest.clone();
    let store = coland_storage_postgres::PgAppletStore {
        pool: fixture.pool.clone(),
    };
    let identity = store
        .get_identity(package.applet_id.as_str(), fixture.state.service_id())
        .await
        .unwrap()
        .unwrap();
    let scope =
        coland_storage::applet_effective_scope_key(&body.authoring_request_basis.effective_scope)
            .unwrap();
    let old = store
        .get(package.applet_id.as_str(), &scope)
        .await
        .unwrap()
        .unwrap();
    let mut guards = vec![];
    for event in std::iter::once(&body.authoring_request_basis.registration_event)
        .chain(&body.authoring_request_basis.capability_grant_events)
    {
        guards.push(
            admin_domain_request(fixture, event.clone())
                .await
                .self_producer_guard
                .unwrap(),
        );
    }
    let SelfProducerCommitGuard::HumanDeviceEvidence { evidence, .. } = &guards[0] else {
        panic!("original regular Device root")
    };
    let service_resolution = evidence.service_resolution.clone();
    let key = fixture.state.notary_signing_key();
    let vm = fixture
        .state
        .service_verification_method("notary-key")
        .unwrap();
    let app = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(
            fixture.state.test_persistence(),
        ),
        0,
    );
    let signing_key = key.clone();
    let signing_method = vm.clone();
    let author: coland_storage::AppletCommitAuthor =
        Arc::new(move |event, authority, head, at, fact, core| {
            let commit = app
                .sign_event_commit_at_authority_cut(
                    event,
                    authority,
                    head,
                    signing_method.clone(),
                    signing_key.as_ref(),
                    at,
                    fact,
                )
                .map_err(|e| PersistenceError::Conflict(e.to_string()))?;
            let root = core.map(|core| arkret_models_identity::AccountDeviceSignerEvidence {
                device_projection_attestation:
                    arkret_signatures::device_projection::sign_device_projection_attestation(
                        core.clone(),
                        signing_method.clone(),
                        signing_key.as_ref(),
                    )
                    .unwrap(),
                service_resolution: service_resolution.clone(),
            });
            Ok((commit, root))
        });
    let attester: coland_storage::AppletResolutionAttester = Arc::new(move |core| {
        arkret_signatures::service_resolution::sign_principal_resolution_projection_attestation(
            core,
            vm.clone(),
            key.as_ref(),
        )
        .map_err(|e| PersistenceError::Conflict(e.to_string()))
    });
    let actor = body.authoring_request_basis.install_actor_id.clone();
    let digest = arkret_canonical::canonical_sha256(&body).unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let idempotency_key = format!("closed-replacement-{}", uuid::Uuid::now_v7());
    let input = coland_storage::AppletAuthoringUnitWrite {
        candidate: coland_storage::AppletAuthoringCandidate {
            request: coland_storage::AppletAdmissionRequest::Install(Box::new(body.clone())),
            package: package.clone(),
            recomputed_install_plan: Some(plan),
            service_did_document: applet_service_id_document(&package),
            controller_did_document: arkret_identity::DidResolver::resolve_did(
                &arkret_identity::DidKeyResolver::new(),
                &Did::new(
                    package
                        .proof
                        .as_ref()
                        .unwrap()
                        .verification_method
                        .as_str()
                        .split('#')
                        .next()
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap()
            .document,
            station_verification_method: fixture
                .state
                .service_verification_method("notary-key")
                .unwrap(),
            station_public_key: *fixture
                .state
                .notary_signing_key()
                .verifying_key()
                .as_bytes(),
            admin_actor_id: actor.clone(),
            admin_producer_guards: guards,
            request_digest: Hash::new(digest.clone()).unwrap(),
            canonical_request_hash: Hash::new(digest.clone()).unwrap(),
            prior_managed_refs: vec![],
            prior_service_signer_evidence: None,
            accepted_at: at,
        },
        creation_service_resolution: None,
        expected_identity: Some(identity.clone()),
        expected_installation: Some(old.clone()),
        preview_subject_key: String::new(),
        operation_id: "ak.self.applet.command.install".to_owned(),
        idempotency_key: idempotency_key.clone(),
        operation_approvals: None,
    };
    let mut outcome = prior.outcome.clone();
    outcome.install_id = coland_storage::ids::generate("install");
    outcome.registration_event_ref = body
        .authoring_request_basis
        .registration_event
        .event_id
        .clone();
    outcome.registration_epoch = package.registration_epoch.clone();
    outcome.capability_grant_refs = body
        .authoring_request_basis
        .capability_grant_events
        .iter()
        .map(|e| arkret_wire::GrantId::from_event_id(&e.event_id))
        .collect();
    let response = serde_json::to_value(&outcome).unwrap();
    let finalizer: coland_storage::AppletUnitFinalizer = Arc::new(move |_| {
        let mut record = old.clone();
        record["package"] = serde_json::to_value(&package).unwrap();
        record["registration_event"] =
            serde_json::to_value(&body.authoring_request_basis.registration_event).unwrap();
        record["capability_grant_events"] =
            serde_json::to_value(&body.authoring_request_basis.capability_grant_events).unwrap();
        record["install_response"] = response.clone();
        record["install_id"] = response["install_id"].clone();
        record["idempotency_key"] = json!(idempotency_key);
        record["install_body_digest"] = json!(digest);
        record["registered_at"] = json!(at);
        record["install_execution"]["idempotency_key"] = json!(idempotency_key);
        record["install_execution"]["body_hash"] = json!(digest);
        record["install_execution"]["submitted_plan_digest"] = json!(body.plan_digest);
        let events = std::iter::once(&body.authoring_request_basis.registration_event)
            .chain(body.authoring_request_basis.capability_grant_events.iter())
            .collect::<Vec<_>>();
        record["install_execution"]["produced_event_refs"] = json!(
            events
                .iter()
                .map(|event| &event.event_id)
                .collect::<Vec<_>>()
        );
        record["install_execution"]["steps"] =
            json!(events.iter().enumerate().map(|(index, event)| {
            let mut step = json!({
                "step_index": index,
                "target_event_kind": event.kind.as_str(),
                "canonical_event_body_hash": arkret_canonical::canonical_sha256(event).unwrap(),
                "status": "accepted",
                "planned_event_ref": event.event_id,
                "event_ref": event.event_id,
            });
            if event.kind == EventKind::CapabilityGrant {
                step["grant_binding"] = json!({
                    "applet_id": package.applet_id,
                    "grant_id": arkret_wire::GrantId::from_event_id(&event.event_id),
                    "executed_by": ActorId::service(package.service_id.clone()),
                    "registration_epoch": package.registration_epoch,
                });
            }
            step
        }).collect::<Vec<_>>());
        Ok(coland_storage::AppletUnitFinalization {
            applet_record: coland_storage::AppletRecordCommit {
                applet_id: package.applet_id.clone(),
                identity: coland_storage::AppletIdentityCommit {
                    target_station_id: body.authoring_request_basis.target_station_id.clone(),
                    expected_record: Some(identity.clone()),
                    record: identity.clone(),
                },
                expected_record: Some(old.clone()),
                record,
            },
            idempotency_record: coland_storage::IdempotencyRecord {
                authenticated_actor: actor.clone(),
                operation_id: "ak.self.applet.command.install".to_owned(),
                idempotency_key: idempotency_key.clone(),
                request_hash: digest.clone(),
                response_status: 201,
                response_body: response.clone(),
                created_at: at,
                expires_at: at + chrono::Duration::days(1),
            },
            response_body: response.clone(),
        })
    });
    let accepted = store
        .admit_authoring_unit(input, author, attester, finalizer)
        .await
        .unwrap();
    serde_json::from_value(accepted.response_body).unwrap()
}

async fn accepted_admin_domain_event(fixture: &Fixture, event: Event) {
    use coland_storage::EventCommitUnitOfWork as _;
    let request = admin_domain_request(fixture, event.clone()).await;
    coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone())
        .commit_event(request)
        .await
        .unwrap();
    assert_accepted_event(fixture, &event).await;
}

fn managed_actor_action_grant<'a>(
    fixture: &'a Fixture,
    install: &'a Installed,
    actor: &'a ActorId,
    actions: Vec<String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = arkret_wire::GrantId> + Send + 'a>> {
    Box::pin(async move {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraintEffect, GrantConstraintKind, ManagedActorRole,
        };
        let service = ActorId::service(install.package.service_id.clone());
        let managed =
            actor != &service && actor.signing_principal_id() != &install.package.service_id;
        let mut control = GrantConstraint::new(
            GrantConstraintKind::AuthorityControl,
            GrantConstraintEffect::Allow,
        );
        control.authority_regrant_allowed = Some(false);
        control.max_authority_depth = Some(0);
        control.allowed_managed_actor_roles = vec![ManagedActorRole::Bot, ManagedActorRole::Ghost];
        let binding = GrantConstraint::applet_authority(
            install.package.applet_id.clone(),
            service.clone(),
            install.package.registration_epoch.clone(),
        );
        let parent = fixture.admin_event(
            EventKind::CapabilityGrant,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            serde_json::to_value(CapabilityGrantPayload {
                grant: CapabilityGrantCreateBody {
                    schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                    realm_id: Some(fixture.realm.clone()),
                    issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
                    subject: CapabilitySubject::Actor(if managed {
                        service.clone()
                    } else {
                        actor.clone()
                    }),
                    actions: actions.clone(),
                    resources: vec![arkret_wire::WireResourceSelector::realm(
                        fixture.realm.clone(),
                    )],
                    constraints: vec![binding.clone(), control],
                    issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                        realm_id: fixture.realm.clone(),
                        authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
                        authority_generation: 0,
                    }],
                    issued_at: chrono::Utc::now(),
                },
            })
            .unwrap(),
        );
        let parent_id = arkret_wire::GrantId::from_event_id(&parent.event_id);
        accepted_admin_domain_event(fixture, parent).await;
        if !managed {
            return parent_id;
        }
        let mut terminal = GrantConstraint::new(
            GrantConstraintKind::AuthorityControl,
            GrantConstraintEffect::Allow,
        );
        terminal.authority_regrant_allowed = Some(false);
        terminal.max_authority_depth = Some(0);
        let child = managed_service_event(
            fixture,
            install,
            &service,
            &parent_id,
            EventKind::CapabilityGrant,
            serde_json::to_value(CapabilityGrantPayload {
                grant: CapabilityGrantCreateBody {
                    schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                    realm_id: Some(fixture.realm.clone()),
                    issuer_id: service.clone(),
                    subject: CapabilitySubject::Actor(actor.clone()),
                    actions,
                    resources: vec![arkret_wire::WireResourceSelector::realm(
                        fixture.realm.clone(),
                    )],
                    constraints: vec![
                        GrantConstraint::applet_authority(
                            install.package.applet_id.clone(),
                            actor.clone(),
                            install.package.registration_epoch.clone(),
                        ),
                        terminal,
                    ],
                    issuer_authority_refs: vec![IssuerAuthorityRef::Grant {
                        grant_id: parent_id.clone(),
                    }],
                    issued_at: chrono::Utc::now(),
                },
            })
            .unwrap(),
        );
        let id = arkret_wire::GrantId::from_event_id(&child.event_id);
        assert_managed_accepted(fixture, install, &child).await;
        id
    })
}

fn managed_service_event(
    fixture: &Fixture,
    install: &Installed,
    actor: &ActorId,
    grant: &arkret_wire::GrantId,
    kind: EventKind,
    payload: Value,
) -> Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        actor.clone(),
        payload,
        chrono::Utc::now(),
    )
    .unwrap();
    event.producer_proof = None;
    let service = ActorId::service(install.package.service_id.clone());
    event.executed_by = (actor != &service).then_some(service);
    event.applet_id = Some(install.package.applet_id.clone());
    event.authorization_ref = Some(grant.clone().into());
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&install.package.webhook_auth.key_ref),
        applet_service_did(&install.package),
        install.package.webhook_auth.key_ref.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new(),
    )
    .unwrap();
    authored.into_event()
}

async fn managed_http_event(
    fixture: &Fixture,
    install: &Installed,
    event: &Event,
) -> (StatusCode, Value) {
    let body = serde_json::to_value(AppletEventTransactionRequestBody {
        applet_id: install.package.applet_id.clone(),
        source_id: install.package.service_id.clone(),
        events: vec![event.clone()],
        committed_events: vec![],
        signals: vec![],
    })
    .unwrap();
    fixture
        .service_post(
            &install.package,
            "/_arkret/edge/applet/transactions",
            arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            &body,
            &format!("managed-{}", uuid::Uuid::now_v7()),
        )
        .await
}

async fn assert_managed_accepted(fixture: &Fixture, install: &Installed, event: &Event) {
    let (status, value) = managed_http_event(fixture, install, event).await;
    assert_eq!(status, StatusCode::OK, "managed transaction: {value}");
    let outcome: AppletTransactionOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(
        outcome.status(),
        AppletTransactionStatus::Accepted,
        "{outcome:?}"
    );
    assert_eq!(outcome.committed_event_refs()[0].event_id, event.event_id);
    assert_accepted_event(fixture, event).await;
}

async fn managed_rejected_event(fixture: &Fixture, install: &Installed, event: &Event) -> Value {
    let (status, value) = managed_http_event(fixture, install, event).await;
    assert_eq!(status, StatusCode::OK, "authenticated delivery: {value}");
    let outcome: AppletTransactionOutcome = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(outcome.status(), AppletTransactionStatus::Rejected);
    assert!(outcome.committed_event_refs().is_empty());
    assert_eq!(outcome.rejections().len(), 1);
    assert_eq!(
        outcome.rejections()[0].event_id.as_ref(),
        Some(&event.event_id)
    );
    value
}

async fn managed_domain_snapshot(pool: &PgPool) -> Value {
    // Transport delivery replays persist rejected outcomes independently of
    // the Event unit. Compare the authority facts and domain current writes.
    let mut value = authority_snapshot(pool).await;
    value.as_object_mut().unwrap().remove("transactions");
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut conn = pool.get().await.unwrap();
    let current = diesel::sql_query("SELECT jsonb_build_object( \
        'members',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM member_state_current_results r), \
        'messages',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM message_revision_current_results r), \
        'strands',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM strand_current_results r)) AS value")
        .get_result::<Row>(&mut *conn).await.unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("domain_current".to_owned(), current.value);
    value
}

async fn assert_service_historical_fact(
    fixture: &Fixture,
    install: &Installed,
    event: &Event,
) -> arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact {
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let accepted = store
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let fact = store
        .producer_signer_fact(event, &accepted.commit)
        .await
        .unwrap()
        .unwrap();
    let arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(
        service,
    ) = &fact
    else {
        panic!("ordinary Applet requires a Service fact")
    };
    assert_eq!(&service.actor, event.actual_signer());
    assert_eq!(service.key.applet_id, install.package.applet_id);
    assert_eq!(
        service.key.registration_epoch,
        install.package.registration_epoch
    );
    assert_eq!(
        service.key.registration_ref.event_id,
        install.outcome.registration_event_ref
    );
    assert_eq!(service.key.effective_scope, event.scope_ref);
    let suite = event.realm_id.digest_suite_code().digest_suite();
    fact.validate_commit_binding(
        &arkret_wire::CommittedEventFullView {
            event: event.clone(),
            commit: accepted.commit.clone(),
        },
        suite,
    )
    .unwrap();
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        event, &fact, suite,
    )
    .unwrap();
    let selector = arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
        sender: arkret_models_identity::HistoricalSignerKeyQuerySender::Service {
            actor: service.actor.clone(),
            verification_method: service.verification_method.clone(),
            committed_event_ref: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: accepted.commit.commit_id,
                stream_ref: accepted.commit.stream_ref,
                stream_position: accepted.commit.stream_position,
            },
        },
    };
    let result = store
        .historical_producer_signer_key(&fixture.realm, &selector)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.service_key(), Some(&service.key));
    let body = serde_json::to_value(arkret_models_identity::SignerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        realm_id: fixture.realm.clone(),
        recipient_account_id: fixture.pcr.history.account.clone(),
        queries: vec![selector.clone()],
    })
    .unwrap();
    let (status, outcome) = fixture
        .admin_post(
            "/_arkret/self/signer-keys/query",
            arkret_wire::ServiceOperationId::SELF_SIGNER_KEYS_READ_RESOLVE_V1,
            &body,
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary reader Service source: {outcome}"
    );
    let outcome: arkret_models_identity::SignerKeysQueryOutcome =
        serde_json::from_value(outcome).unwrap();
    assert_eq!(outcome.results, vec![result.clone()]);
    let encoded = serde_json::to_value(&result).unwrap();
    assert!(encoded.get("device_id").is_none());
    assert!(encoded.get("private_completion").is_none());
    let mut wrong = service.clone();
    wrong.key.authorization_ref.event_id = EventId::from_digest(suite, [193; 32]);
    assert!(wrong.validate_event_binding(event, suite).is_err());
    fact
}

#[tokio::test]
async fn native_service_bridge_error_requires_exact_installed_grant_and_revoke_fence() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);

    let install = Box::new(Box::pin(fixture.install(false)).await);
    let service = ActorId::service(install.package.service_id.clone());
    let authority_subject = ActorId::account(arkret_wire::AccountId::new(
        install.package.service_id.clone(),
        fixture.state.service_core_id(),
    ));

    let grant = managed_actor_action_grant(
        &fixture,
        &install,
        &service,
        vec!["ak.applet.bridge_error".to_owned()],
    )
    .await;

    let bot_grant = managed_actor_action_grant(
        &fixture,
        &install,
        &install.bot_outcome.bot_actor_id,
        vec!["ak.message.create".to_owned()],
    )
    .await;

    let payload = json!({
        "applet_id": install.package.applet_id,
        "realm_id": fixture.realm,
        "failed_transaction_ref": install.outcome.registration_event_ref,
        "error_class": "external_network",
        "error_code": "external_unavailable",
        "retriable": true,
        "visibility_scope": "realm_members",
    });
    let make_event = |actor: &ActorId, grant, payload| {
        managed_service_event(
            &fixture,
            &install,
            actor,
            grant,
            EventKind::AppletBridgeError,
            payload,
        )
    };
    let mut foreign_payload = payload.clone();
    foreign_payload["applet_id"] = json!(format!("ak:applet:{}", uuid::Uuid::now_v7()));
    for event in [
        make_event(&service, &bot_grant, payload.clone()),
        make_event(&authority_subject, &grant, payload.clone()),
        make_event(&service, &grant, foreign_payload),
    ] {
        let before = managed_domain_snapshot(&fixture.pool).await;

        Box::pin(managed_rejected_event(&fixture, &install, &event)).await;
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
    }
    let event = make_event(&service, &grant, payload.clone());
    assert!(event.executed_by.is_none());

    Box::pin(assert_managed_accepted(&fixture, &install, &event)).await;

    let historical = Box::pin(assert_service_historical_fact(&fixture, &install, &event)).await;
    let original_event = event.clone();
    let accepted = managed_domain_snapshot(&fixture.pool).await;
    Box::pin(assert_managed_accepted(&fixture, &install, &event)).await;
    assert_eq!(managed_domain_snapshot(&fixture.pool).await, accepted);

    Box::pin(fixture.revoke(&install)).await;

    assert_eq!(
        Box::pin(assert_service_historical_fact(
            &fixture,
            &install,
            &original_event
        ))
        .await,
        historical
    );
    let mut revoked_payload = payload;
    revoked_payload["error_code"] = json!("external_unavailable_after_revoke");
    let event = make_event(&service, &grant, revoked_payload);
    let before = managed_domain_snapshot(&fixture.pool).await;
    let (status, refusal) = managed_http_event(&fixture, &install, &event).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "revoked installation: {refusal}"
    );
    assert_eq!(
        refusal["type"],
        "https://arkret.org/problems/applet_registration_unauthorized"
    );
    assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn service_cannot_borrow_bot_or_ghost_children_for_join_message_or_leave() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);

    let install = Box::new(Box::pin(fixture.install(true)).await);

    let ghost_body = fixture
        .ghost_body(&install, install_namespace(&install), "member-ghost")
        .await;

    let (status, ghost) = fixture
        .ghost_commit(&install, &ghost_body, "member-ghost-provision")
        .await;
    assert_eq!(status, StatusCode::CREATED, "managed Ghost: {ghost}");
    let ghost: GhostActorProvisionOutcome = serde_json::from_value(ghost).unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let strand_event = fixture.admin_event(
        EventKind::StrandCreate,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":fixture.realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Managed actual message"},"state":"active",
            "created_by":ActorId::account(fixture.pcr.history.account.clone()),"created_at":at}}),
    );
    let strand = arkret_wire::StrandId::from_event_id(&strand_event.event_id);

    Box::pin(accepted_admin_domain_event(&fixture, strand_event)).await;
    for actor in [
        install.bot_outcome.bot_actor_id.clone(),
        ghost.ghost_actor_id.clone(),
    ] {
        let message_grant = Box::pin(managed_actor_action_grant(
            &fixture,
            &install,
            &actor,
            vec!["ak.message.create".to_owned()],
        ))
        .await;
        let content = json!({"strand_id":strand,"track_name":"discussion",
            "content":{"kind":"ak.content.text","format":"plain","body":"actual managed message"}});
        let not_joined = managed_service_event(
            &fixture,
            &install,
            &actor,
            &message_grant,
            EventKind::MessageCreate,
            content.clone(),
        );
        let before = managed_domain_snapshot(&fixture.pool).await;
        let rejection = Box::pin(managed_rejected_event(&fixture, &install, &not_joined)).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&not_joined.event_id)
                .await
                .unwrap()
                .is_none(),
            "unjoined: {rejection}"
        );
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
        let wrong_action = managed_service_event(
            &fixture,
            &install,
            &actor,
            &message_grant,
            EventKind::MemberState,
            json!({"realm_id":fixture.realm,"member_id":actor,"membership":"join"}),
        );
        let rejection = Box::pin(managed_rejected_event(&fixture, &install, &wrong_action)).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&wrong_action.event_id)
                .await
                .unwrap()
                .is_none(),
            "wrong action: {rejection}"
        );
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);

        let member_grant = Box::pin(managed_actor_action_grant(
            &fixture,
            &install,
            &actor,
            vec!["ak.realm.admin".to_owned()],
        ))
        .await;
        let other = if actor == install.bot_outcome.bot_actor_id {
            ghost.ghost_actor_id.clone()
        } else {
            install.bot_outcome.bot_actor_id.clone()
        };
        let forced_join = managed_service_event(
            &fixture,
            &install,
            &actor,
            &member_grant,
            EventKind::MemberState,
            json!({"realm_id":fixture.realm,"member_id":other,"membership":"join"}),
        );
        let before = managed_domain_snapshot(&fixture.pool).await;
        let rejection = Box::pin(managed_rejected_event(&fixture, &install, &forced_join)).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&forced_join.event_id)
                .await
                .unwrap()
                .is_none(),
            "admin cannot force leave to join: {rejection}"
        );
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
        let join = managed_service_event(
            &fixture,
            &install,
            &actor,
            &member_grant,
            EventKind::MemberState,
            json!({"realm_id":fixture.realm,"member_id":actor,"membership":"join"}),
        );

        let before = managed_domain_snapshot(&fixture.pool).await;
        managed_rejected_event(&fixture, &install, &join).await;
        assert_eq!(before, managed_domain_snapshot(&fixture.pool).await);
        // Even the Service's genuine parent is not this Account's own
        // membership consent. It must be exercised as its actual Service.
        let rows = fixture
            .state
            .test_persistence()
            .capability_grant_current_results()
            .snapshot_for_realm(&fixture.realm)
            .await
            .unwrap();
        let child = rows.iter().find(|r| r.grant_id == member_grant).unwrap();
        let IssuerAuthorityRef::Grant { grant_id: parent } = &child.value.issuer_authority_refs[0]
        else {
            panic!("missing Service source parent")
        };
        let parent_join = managed_service_event(
            &fixture,
            &install,
            &actor,
            parent,
            EventKind::MemberState,
            json!({"realm_id":fixture.realm,"member_id":actor,"membership":"join"}),
        );
        managed_rejected_event(&fixture, &install, &parent_join).await;
        assert_eq!(before, managed_domain_snapshot(&fixture.pool).await);
        for event in [
            managed_service_event(
                &fixture,
                &install,
                &actor,
                &message_grant,
                EventKind::MessageCreate,
                content,
            ),
            managed_service_event(
                &fixture,
                &install,
                &actor,
                &member_grant,
                EventKind::MemberState,
                json!({"realm_id":fixture.realm,"member_id":actor,"membership":"leave"}),
            ),
        ] {
            managed_rejected_event(&fixture, &install, &event).await;
            assert_eq!(before, managed_domain_snapshot(&fixture.pool).await);
        }
        assert!(
            !fixture
                .state
                .test_persistence()
                .authority_commits()
                .local_current_member_joined(
                    &fixture.realm,
                    &actor,
                    &fixture.state.service_core_id()
                )
                .await
                .unwrap()
        );
    }
}

/// `common-fields.md` §4.5: `leave -> join` is written by the target itself or
/// by the exact target's Invite acceptance. A managed Bot or Ghost accepts an
/// Invite addressed to it through its Applet Service; the acceptance is
/// `subject_only`, and the cited grant of the actor only binds the exact
/// install (`applet-integration.md` §8, §9.1).
#[tokio::test]
async fn service_cannot_accept_invites_as_managed_bot_or_ghost() {
    let fixture = Box::new(Box::pin(Fixture::new()).await);
    let install = Box::new(Box::pin(fixture.install(true)).await);
    let ghost_body = fixture
        .ghost_body(&install, install_namespace(&install), "invited-ghost")
        .await;
    let (status, ghost) = fixture
        .ghost_commit(&install, &ghost_body, "invited-ghost-provision")
        .await;
    assert_eq!(status, StatusCode::CREATED, "managed Ghost: {ghost}");
    let ghost: GhostActorProvisionOutcome = serde_json::from_value(ghost).unwrap();
    let realm_scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    for (actor, other) in [
        (
            install.bot_outcome.bot_actor_id.clone(),
            ghost.ghost_actor_id.clone(),
        ),
        (
            ghost.ghost_actor_id.clone(),
            install.bot_outcome.bot_actor_id.clone(),
        ),
    ] {
        let invitee = actor.as_account_id().unwrap().clone();
        let invite = fixture.admin_event(
            EventKind::InviteCreate,
            realm_scope.clone(),
            json!({
                "invitee_account_id": invitee,
                "introduction_evidence_digest": format!("sha256:{}", "4".repeat(64)),
                "expires_at": arkret_canonical::format_timestamp_canonical(
                    chrono::Utc::now() + chrono::Duration::days(1)
                ),
            }),
        );
        let invite_id = arkret_wire::InviteId::from_event_id(&invite.event_id);
        accepted_admin_domain_event(&fixture, invite).await;
        let grant = managed_actor_action_grant(
            &fixture,
            &install,
            &actor,
            vec!["ak.message.create".to_owned()],
        )
        .await;
        let other_grant = managed_actor_action_grant(
            &fixture,
            &install,
            &other,
            vec!["ak.message.create".to_owned()],
        )
        .await;

        // Only the directed invitee may accept, even through the same Service.
        let foreign = managed_service_event(
            &fixture,
            &install,
            &other,
            &other_grant,
            EventKind::InviteAccept,
            json!({"invite_id": invite_id, "previous_state": "pending", "invitee_account_id": invitee}),
        );
        let before = managed_domain_snapshot(&fixture.pool).await;
        let rejection = Box::pin(managed_rejected_event(&fixture, &install, &foreign)).await;
        assert_eq!(
            managed_domain_snapshot(&fixture.pool).await,
            before,
            "foreign acceptance: {rejection}"
        );

        // The acceptance must cite an install-bound grant of the actor itself.
        let borrowed_grant = managed_service_event(
            &fixture,
            &install,
            &actor,
            &other_grant,
            EventKind::InviteAccept,
            json!({"invite_id": invite_id, "previous_state": "pending", "invitee_account_id": invitee}),
        );
        let rejection = Box::pin(managed_rejected_event(&fixture, &install, &borrowed_grant)).await;
        assert_eq!(
            managed_domain_snapshot(&fixture.pool).await,
            before,
            "borrowed grant: {rejection}"
        );

        let accept = managed_service_event(
            &fixture,
            &install,
            &actor,
            &grant,
            EventKind::InviteAccept,
            json!({"invite_id": invite_id, "previous_state": "pending", "invitee_account_id": invitee}),
        );
        managed_rejected_event(&fixture, &install, &accept).await;
        assert_eq!(before, managed_domain_snapshot(&fixture.pool).await);
        assert!(
            !fixture
                .state
                .test_persistence()
                .authority_commits()
                .local_current_member_joined(
                    &fixture.realm,
                    &actor,
                    &fixture.state.service_core_id()
                )
                .await
                .unwrap()
        );
    }
}

#[path = "applet_widget_inventory/cases.rs"]
mod widget_inventory_cases;

fn creation_review_vote(
    fixture: &Fixture,
    request: &arkret_models_integration::management_review::ManagementReviewRequestBody,
) -> arkret_wire::ApprovalSignature {
    creation_operation_vote(
        fixture,
        &request.target,
        arkret_wire::ApprovalContext::Management {
            request_id: request.request_id.clone(),
            management_operation: request.management_operation,
            effective_scope: request.effective_scope.clone(),
        },
    )
}

fn creation_operation_vote(
    fixture: &Fixture,
    target: &arkret_models_integration::management_review::ManagementReviewTarget,
    context: arkret_wire::ApprovalContext,
) -> arkret_wire::ApprovalSignature {
    creation_operation_vote_at(
        fixture,
        target,
        context,
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )
}

fn creation_operation_vote_at(
    fixture: &Fixture,
    target: &arkret_models_integration::management_review::ManagementReviewTarget,
    context: arkret_wire::ApprovalContext,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::ApprovalSignature {
    use arkret_models_integration::management_review::ManagementReviewTarget;
    use arkret_wire::*;
    let (scope, service, operation, action) = match target {
        ManagementReviewTarget::BotCreation { request_body, .. } => {
            let basis = request_body.authoring_request.basis.bot().unwrap();
            (
                &basis.effective_scope,
                &basis.service_id,
                ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
                CapabilityActionId::AppletBotProvision,
            )
        }
        ManagementReviewTarget::GhostCreation { request_body, .. } => {
            let basis = request_body.authoring_request.basis.ghost().unwrap();
            (
                &basis.effective_scope,
                &basis.service_id,
                ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1,
                CapabilityActionId::AppletGhostProvision,
            )
        }
        ManagementReviewTarget::Event { event } => (
            &event.scope_ref,
            event.actor_id.signing_principal_id(),
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            if matches!(
                event.kind,
                EventKind::ProfileCreate | EventKind::ProfileUpdate
            ) {
                CapabilityActionId::AppletPublish
            } else if event.kind == EventKind::MessageCreate {
                CapabilityActionId::MessageCreate
            } else {
                CapabilityActionId::AppletJoin
            },
        ),
    };
    let arkret_models_identity::principal_registration_anchor::PrincipalRegistrationAnchor::WebvhRegistration {log_entries,..}=&fixture.pcr.history.registration_anchor;
    let entries = log_entries
        .iter()
        .map(|entry| serde_json::to_value(entry).unwrap())
        .collect::<Vec<_>>();
    let history =
        arkret_identity::verify_did_webvh_v1_chain(&fixture.pcr.history.did, &entries).unwrap();
    let selected = coland_services::identity::select_did_webvh_state_at(
        &fixture.pcr.history.did,
        &history,
        at,
    )
    .unwrap();
    let multibase = selected.update_keys.as_slice().first().unwrap();
    let key = SigningKey::from_bytes(&[70; 32]);
    assert_eq!(
        &arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes()),
        multibase
    );
    let method = DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: context,
            approval_target: match target {
                ManagementReviewTarget::Event { event } => ApprovalTarget::Event {
                    event_id: event.event_id.clone(),
                },
                _ => ApprovalTarget::Operation,
            },
            request_canonical_digest: target.canonical_target_digest().unwrap(),
            operation: operation.into(),
            action,
            realm_id: scope.realm_id().clone(),
            initiating_actor_id: match target {
                ManagementReviewTarget::Event { event } => event.actual_signer().clone(),
                _ => ActorId::service(service.clone()),
            },
            approver_did: fixture.pcr.history.did.clone(),
            approved_at: at,
            nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: method.clone(),
            jws: String::new(),
        },
    };
    signature.proof.jws =
        arkret_signatures::Ed25519DetachedJwsSigner::from_seed([70; 32], method.as_str())
            .sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(
                    &signature,
                )
                .unwrap(),
            );
    signature
}

impl Fixture {
    fn enable_management_authority(&self) {
        let record = arkret_signatures::account_status::sign_account_status_record(
            arkret_models_collaboration::account_status::UnsignedAccountStatusRecord {
                schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
                account_authority_id: self.state.service_core_id(),
                account_id: self.pcr.history.account.clone(),
                principal_control_realm_id: self.pcr.unit.transactions[0].event.realm_id.clone(),
                binding_version: 1,
                status_seq: 1,
                previous_account_status_record_id: None,
                status: arkret_models_collaboration::objects::account_status::AccountStatus::Active,
                reason_code: None,
                reason: None,
                issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
                expires_at: None,
            },
            self.state
                .service_verification_method("notary-key")
                .unwrap(),
            self.state.notary_signing_key().as_ref(),
        )
        .unwrap();
        arkret_signatures::account_status::verify_account_status_record(
            &record,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: self.state.notary_verifying_key().as_bytes().to_vec(),
            },
        )
        .unwrap();
        *self.management_authority.lock().unwrap() = Some(ManagementAuthorityFixture {
            record,
            public_key: *self.state.notary_verifying_key().as_bytes(),
        });
    }
}

fn business_without_reviews(mut snapshot: Value) -> Value {
    snapshot.as_object_mut().unwrap().remove("reviews");
    snapshot.as_object_mut().unwrap().remove("approval_audit");
    snapshot
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creation_reviews_use_original_targets_and_consume_with_real_bot_ghost_and_mapping_outcomes()
 {
    tokio::spawn(ordinary_realm::case_future(creation_review_atomic_scenario))
        .await
        .unwrap();
}

struct CreationReviewAtomicContext {
    fixture: Box<Fixture>,
    _native: NativeAppletService,
    namespace: String,
    first: Box<Installed>,
    second: Box<Installed>,
    policy: Event,
    policy_id: String,
    cases: Vec<(bool, Value, ScopeRef, bool)>,
}

async fn creation_review_atomic_scenario() {
    let mut context = creation_approval_phase(creation_review_atomic_setup).await;
    for (index, (second, body, scope, is_bot)) in
        std::mem::take(&mut context.cases).into_iter().enumerate()
    {
        let install = if second {
            context.second.as_ref()
        } else {
            context.first.as_ref()
        };
        creation_approval_phase(|| {
            creation_review_atomic_case(
                &context.fixture,
                install,
                &context.policy_id,
                index,
                body,
                scope,
                is_bot,
            )
        })
        .await;
    }
    creation_approval_phase(|| creation_review_atomic_lifecycle(&context)).await;
}

async fn creation_review_atomic_setup() -> Box<CreationReviewAtomicContext> {
    let fixture = Box::new(creation_approval_phase(Fixture::new).await);
    fixture.enable_management_authority();
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let first = Box::new(
        creation_approval_phase(|| {
            fixture.install_package(true, native.package.clone(), &namespace)
        })
        .await,
    );
    let circle = creation_approval_phase(|| fixture.new_circle_scope()).await;
    let second = Box::new(
        creation_approval_phase(|| {
            fixture.install_package_in_scope(
                true,
                native.package.clone(),
                &namespace,
                circle.clone(),
            )
        })
        .await,
    );
    let original_ghost = fixture.ghost_body(&first, &namespace, "review-reuse").await;
    assert_eq!(
        fixture
            .ghost_commit(&first, &original_ghost, "before-review-original")
            .await
            .0,
        StatusCode::CREATED
    );
    let administrator = ActorId::account(fixture.pcr.history.account.clone());
    let policy_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let policy=fixture.admin_event(EventKind::PolicySet,ScopeRef::Realm {realm_id:fixture.realm.clone()},json!({"policy_id":policy_id,"expected_revision":null,
        "value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":fixture.realm,"policy_kind":"applet","default_effect":"allow",
        "created_by":administrator,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "rules":[{"rule_id":"original_creation","kind":"applet","effect":"require_review","applet_target":{"kind":"all"},"applet_operations":["create_bot","map_ghost"],
        "review_requirement":{"approver_actor_ids":[administrator],"threshold":1,"max_age_seconds":3600}}]}}));
    Box::pin(accepted_admin_domain_event(&fixture, policy.clone())).await;
    let bot = fixture
        .bot_body_in_scope(
            &first.package,
            &namespace,
            first.outcome.registration_event_ref.clone(),
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
        )
        .await;
    let fresh_ghost = fixture.ghost_body(&first, &namespace, "review-fresh").await;
    let reused = fixture
        .ghost_body(&second, &namespace, "review-reuse")
        .await;
    assert!(reused.get("managed_actor_bundle").is_none());
    let cases = vec![
        (
            false,
            bot,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            true,
        ),
        (
            false,
            fresh_ghost,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            false,
        ),
        (true, reused, circle, false),
    ];
    Box::new(CreationReviewAtomicContext {
        fixture,
        _native: native,
        namespace,
        first,
        second,
        policy,
        policy_id,
        cases,
    })
}

async fn creation_review_atomic_case(
    fixture: &Fixture,
    install: &Installed,
    policy_id: &str,
    index: usize,
    mut body: Value,
    scope: ScopeRef,
    is_bot: bool,
) {
    use arkret_models_integration::management_review::*;
    use arkret_wire::{ManagementOperation, ServiceOperationId};
    let path = format!(
        "/_arkret/self/applets/{}/{}s/provision",
        install.package.applet_id,
        if is_bot { "bot" } else { "ghost" }
    );
    let operation = if is_bot {
        ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1
    } else {
        ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1
    };
    let before = authority_snapshot(&fixture.pool).await;
    let (status, error) = fixture
        .service_post(
            &install.package,
            &path,
            operation,
            &body,
            &format!("unapproved-{index}"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unapproved creation {error}");
    assert!(error.to_string().contains("approval_required"), "{error}");
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let target = if is_bot {
        ManagementReviewTarget::BotCreation {
            applet_id: install.package.applet_id.clone(),
            request_body: Box::new(serde_json::from_value(body.clone()).unwrap()),
        }
    } else {
        ManagementReviewTarget::GhostCreation {
            applet_id: install.package.applet_id.clone(),
            request_body: Box::new(serde_json::from_value(body.clone()).unwrap()),
        }
    };
    let request = ManagementReviewRequestBody {
        request_id: format!("creation-review-{index}-{}", uuid::Uuid::now_v7()),
        effective_scope: scope,
        management_operation: if is_bot {
            ManagementOperation::CreateBot
        } else {
            ManagementOperation::MapGhost
        },
        requester_actor_id: ActorId::service(install.package.service_id.clone()),
        target,
    };
    let (status, pending) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(request),
            &format!("review-{index}"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "pending creation {pending}");
    assert_eq!(pending["status"], "pending");
    assert_eq!(
        pending["target_digest"],
        json!(request.target.canonical_target_digest().unwrap())
    );
    let deadline: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(pending["expires_at"].clone()).unwrap();
    let original_deadline: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(body["authoring_request"]["expires_at"].clone()).unwrap();
    assert!(deadline <= original_deadline);
    assert_eq!(
        business_without_reviews(before),
        business_without_reviews(authority_snapshot(&fixture.pool).await)
    );
    let stable = authority_snapshot(&fixture.pool).await;
    let created: chrono::DateTime<chrono::Utc> = serde_json::from_value(
        stable["reviews"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["request_id"] == request.request_id)
            .unwrap()["created_at"]
            .clone(),
    )
    .unwrap();
    assert_eq!(
        created,
        arkret_canonical::normalize_timestamp_canonical(created)
    );
    let (status, retry) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(request),
            "same-private-intent",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{retry}");
    assert_eq!(pending, retry);
    assert_eq!(stable, authority_snapshot(&fixture.pool).await);
    if index == 0 {
        #[derive(diesel::QueryableByName)]
        struct PolicyRow {
            #[diesel(sql_type=diesel::sql_types::Jsonb)]
            value: Value,
        }
        let original = {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("DELETE FROM policy_current_results p WHERE policy_id=$1 RETURNING to_jsonb(p) AS value")
            .bind::<diesel::sql_types::Text,_>(&policy_id).get_result::<PolicyRow>(&mut conn).await.unwrap().value
        };
        let incomplete = authority_snapshot(&fixture.pool).await;
        let (status, error) = fixture
            .service_post(
                &install.package,
                "/_arkret/self/management-reviews/status",
                ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,
                &json!({"request_id":request.request_id}),
                "missing-policy-current",
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{error}");
        assert!(
            error.to_string().contains("revision_unavailable"),
            "incomplete current is unavailable: {error}"
        );
        assert_eq!(
            incomplete,
            authority_snapshot(&fixture.pool).await,
            "unknown must not terminalize the original pending ledger"
        );
        {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("INSERT INTO policy_current_results SELECT (jsonb_populate_record(NULL::policy_current_results,$1)).*")
            .bind::<diesel::sql_types::Jsonb,_>(original).execute(&mut conn).await.unwrap();
        }
        assert_eq!(stable, authority_snapshot(&fixture.pool).await);
    }
    let mut collision = request.clone();
    collision.request_id.push_str("-other");
    let (status, error) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(collision),
            "same-candidate-new-id",
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(stable, authority_snapshot(&fixture.pool).await);
    let mut changed = json!(request);
    let original = changed["target"]["request_body"]["authoring_request"]["proof"]["jws"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut changed_proof = original[..original.len() - 1].to_owned();
    changed_proof.push(if original.ends_with('A') { 'Q' } else { 'A' });
    changed["target"]["request_body"]["authoring_request"]["proof"]["jws"] = json!(changed_proof);
    let (status, error) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &changed,
            "same-id-new-candidate",
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(stable, authority_snapshot(&fixture.pool).await);
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let vote = creation_review_vote(&fixture, &request);
    let decision = json!({"request_id":request.request_id,"expected_status":"pending","decision":"approve","approval_signatures":[vote]});
    let (status, error) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/decisions",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,
            &decision,
            "service-may-not-approve",
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
    assert_eq!(stable, authority_snapshot(&fixture.pool).await);
    let (status, approved) = fixture
        .admin_post(
            "/_arkret/self/management-reviews/decisions",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,
            &decision,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "approved creation {approved}");
    assert_eq!(approved["status"], "approved");
    let approved_snapshot = authority_snapshot(&fixture.pool).await;
    assert_eq!(
        business_without_reviews(stable),
        business_without_reviews(approved_snapshot.clone())
    );
    body["approval_signatures"] = json!([vote]);
    let fail_key = format!("review-fail-{index}-{}", uuid::Uuid::now_v7());
    let constraint = format!("review_failure_{}", uuid::Uuid::now_v7().simple());
    {
        use std::io::Write as _;
        writeln!(
            std::io::stderr(),
            "creation review fault injection: constraint={constraint} key={fail_key}"
        )
        .unwrap();
    }
    {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(format!("ALTER TABLE applet_authoring_units ADD CONSTRAINT {constraint} CHECK (idempotency_key <> '{fail_key}') NOT VALID")).execute(&mut conn).await.unwrap();
    }
    let (status, error) = fixture
        .service_post(&install.package, &path, operation, &body, &fail_key)
        .await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(format!(
            "ALTER TABLE applet_authoring_units DROP CONSTRAINT {constraint}"
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    }
    assert!(
        status.is_server_error(),
        "injected final durable-outcome failure: {status} {error}"
    );
    assert_eq!(
        approved_snapshot,
        authority_snapshot(&fixture.pool).await,
        "failed aggregate must roll back creation, ledger, nonce and quota"
    );
    let (status, accepted) = fixture
        .service_post(&install.package, &path, operation, &body, &fail_key)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "accepted reviewed creation {accepted}"
    );
    let after = authority_snapshot(&fixture.pool).await;
    let row = after["reviews"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["request_id"] == request.request_id)
        .unwrap();
    assert_eq!(row["status"], "consumed");
    assert!(row["accepted_commit_id"].is_null());
    assert_eq!(row["accepted_operation_outcome"]["response_body"], accepted);
    assert_eq!(
        row["accepted_operation_outcome"]["committed_event_refs"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let audit = after["approval_audit"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["nonce"] == vote.input.nonce)
        .unwrap();
    assert!(audit["event_id"].is_null());
    assert!(audit["accepted_commit_id"].is_null());
    assert_eq!(
        audit["operation_outcome"],
        row["accepted_operation_outcome"]
    );
    if index == 2 {
        for key in ["events", "commits", "completions", "outbox"] {
            assert_eq!(
                approved_snapshot[key], after[key],
                "mapping must not manufacture {key}"
            );
        }
    }
    let (status, retry) = fixture
        .service_post(&install.package, &path, operation, &body, &fail_key)
        .await;
    assert_eq!(status, StatusCode::OK, "{retry}");
    assert_eq!(retry, accepted);
    assert_eq!(after, authority_snapshot(&fixture.pool).await);
    let (status, consumed) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/status",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,
            &json!({"request_id":request.request_id}),
            "consumed-status",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{consumed}");
    assert_eq!(consumed["status"], "consumed");
    assert_eq!(after, authority_snapshot(&fixture.pool).await);
}

async fn creation_review_atomic_lifecycle(context: &CreationReviewAtomicContext) {
    use arkret_models_integration::management_review::*;
    use arkret_wire::{ManagementOperation, ServiceOperationId};
    let fixture = &context.fixture;
    let first = &context.first;
    let namespace = &context.namespace;
    let policy = &context.policy;

    let body = fixture
        .bot_body_in_scope(
            &first.package,
            &namespace,
            first.outcome.registration_event_ref.clone(),
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
        )
        .await;
    let mut request = ManagementReviewRequestBody {
        request_id: format!("superseded-{}", uuid::Uuid::now_v7()),
        effective_scope: ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        management_operation: ManagementOperation::CreateBot,
        requester_actor_id: ActorId::service(first.package.service_id.clone()),
        target: ManagementReviewTarget::BotCreation {
            applet_id: first.package.applet_id.clone(),
            request_body: Box::new(serde_json::from_value(body.clone()).unwrap()),
        },
    };
    let (status, pending) = fixture
        .service_post(
            &first.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(request),
            "before-policy-update",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let vote = creation_review_vote(&fixture, &request);
    let (status,approved)=fixture.admin_post("/_arkret/self/management-reviews/decisions",ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,&json!({"request_id":request.request_id,"expected_status":"pending","decision":"approve","approval_signatures":[vote]}),None).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let policy = change_creation_review_age(&fixture, &policy, 20).await;
    let (status, superseded) = fixture
        .service_post(
            &first.package,
            "/_arkret/self/management-reviews/status",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,
            &json!({"request_id":request.request_id}),
            "after-policy-update",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{superseded}");
    assert_eq!(superseded["status"], "superseded");
    let stable = authority_snapshot(&fixture.pool).await;
    let mut attached = body.clone();
    attached["approval_signatures"] = json!([vote]);
    let path = format!(
        "/_arkret/self/applets/{}/bots/provision",
        first.package.applet_id
    );
    let (status, error) = fixture
        .service_post(
            &first.package,
            &path,
            ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
            &attached,
            "old-approved-target",
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
    assert_eq!(stable, authority_snapshot(&fixture.pool).await);
    request.request_id.push_str("-new");
    let (status, pending) = fixture
        .service_post(
            &first.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(request),
            "replacement-private-request",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let stable = authority_snapshot(&fixture.pool).await;
    let (status,error)=fixture.admin_post("/_arkret/self/management-reviews/decisions",ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,&json!({"request_id":request.request_id,"expected_status":"pending","decision":"approve","approval_signatures":[vote]}),None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "old request vote must not transfer: {error}"
    );
    assert_eq!(stable, authority_snapshot(&fixture.pool).await);
    let (status,cancelled)=fixture.service_post(&first.package,"/_arkret/self/management-reviews/decisions",ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,&json!({"request_id":request.request_id,"expected_status":"pending","decision":"cancel"}),"cancel-own").await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["status"], "cancelled");
    let _policy = change_creation_review_age(&fixture, &policy, 1).await;
    request.request_id.push_str("-expiring");
    let (status, pending) = fixture
        .service_post(
            &first.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(request),
            "short-policy-lifetime",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let before = business_without_reviews(authority_snapshot(&fixture.pool).await);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (status, expired) = fixture
        .service_post(
            &first.package,
            "/_arkret/self/management-reviews/status",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,
            &json!({"request_id":request.request_id}),
            "expired-status",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{expired}");
    assert_eq!(expired["status"], "expired");
    assert_eq!(
        before,
        business_without_reviews(authority_snapshot(&fixture.pool).await)
    );
}

async fn change_creation_review_age(fixture: &Fixture, previous: &Event, max_age: u64) -> Event {
    #[derive(diesel::QueryableByName)]
    struct Current {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let policy_id = previous.payload.get("policy_id").unwrap().as_str().unwrap();
    let current = {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("SELECT jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position) AS value FROM policy_current_results WHERE policy_id=$1")
        .bind::<diesel::sql_types::Text,_>(policy_id).get_result::<Current>(&mut conn).await.unwrap().value
    };
    let mut payload = json!(&previous.payload);
    payload["expected_revision"] = current;
    payload["value"]["rules"][0]["review_requirement"]["max_age_seconds"] = json!(max_age);
    let event = fixture.admin_event(
        EventKind::PolicySet,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        payload,
    );
    accepted_admin_domain_event(fixture, event.clone()).await;
    event
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_bot_and_ghost_profiles_cannot_publish_even_with_valid_service_and_bundle_signatures()
 {
    use arkret_wire::PayloadSigner as _;
    let fixture = Box::pin(Fixture::new()).await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let installed =
        Box::pin(fixture.install_package(true, native.package.clone(), &namespace)).await;
    let bot = fixture
        .bot_body_in_scope(
            &installed.package,
            &namespace,
            installed.outcome.registration_event_ref.clone(),
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
        )
        .await;
    let ghost = fixture
        .ghost_body(&installed, &namespace, "initial-public")
        .await;
    for (is_bot, mut body) in [(true, bot), (false, ghost)] {
        let mut bundle: AppletManagedActorAuthoringBundle =
            serde_json::from_value(body["managed_actor_bundle"].clone()).unwrap();
        bundle.profile_event.payload.get_mut("object").unwrap()["profile_fields"]["applet_interaction"] =
            json!({"effective_scope":{"kind":"realm","realm_id":fixture.realm},"mode":"public"});
        bundle.profile_event.producer_proof = None;
        let signer = Ed25519PayloadSigner::new(
            applet_service_signing_key(&installed.package.webhook_auth.key_ref),
            applet_service_did(&installed.package),
            installed.package.webhook_auth.key_ref.clone(),
        );
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            bundle.profile_event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &signer,
            arkret_signatures::SignEventOptions::new(),
        )
        .unwrap();
        bundle.profile_event = authored.into_event();
        bundle.proof.payload_digest = bundle.payload_digest().unwrap();
        bundle.proof.jws = signer
            .sign_payload(&bundle.proof_binding_bytes().unwrap())
            .unwrap()
            .jws;
        body["managed_actor_bundle"] = json!(bundle);
        let before = authority_snapshot(&fixture.pool).await;
        let path = format!(
            "/_arkret/self/applets/{}/{}s/provision",
            installed.package.applet_id,
            if is_bot { "bot" } else { "ghost" }
        );
        let (status, error) = fixture
            .service_post(
                &installed.package,
                &path,
                if is_bot {
                    arkret_wire::ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1
                } else {
                    arkret_wire::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1
                },
                &body,
                "initial-public-refusal",
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{error}");
        assert!(
            error
                .to_string()
                .contains("initial managed Profile cannot publish"),
            "must reach the production initial Profile gate: {error}"
        );
        assert_eq!(before, authority_snapshot(&fixture.pool).await);
        let mut private: AppletManagedActorAuthoringBundle =
            serde_json::from_value(body["managed_actor_bundle"].clone()).unwrap();
        let scope = private.profile_event.scope_ref.clone();
        private.profile_event.payload.get_mut("object").unwrap()["profile_fields"]["applet_interaction"] =
            json!({"effective_scope":scope,"mode":"private"});
        private.profile_event.payload.get_mut("object").unwrap()["profile_fields"]["bio"] =
            json!("Legitimate display fields coexist with reserved identity members");
        private.profile_event.producer_proof = None;
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            private.profile_event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &signer,
            arkret_signatures::SignEventOptions::new(),
        )
        .unwrap();
        private.profile_event = authored.into_event();
        private.proof.payload_digest = private.payload_digest().unwrap();
        private.proof.jws = signer
            .sign_payload(&private.proof_binding_bytes().unwrap())
            .unwrap()
            .jws;
        body["managed_actor_bundle"] = json!(private);
        let (status, accepted) = fixture
            .service_post(
                &installed.package,
                &path,
                if is_bot {
                    arkret_wire::ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1
                } else {
                    arkret_wire::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1
                },
                &body,
                "initial-private-with-display",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "valid private/display members: {accepted}"
        );
        assert_accepted_event(&fixture, &private.profile_event).await;
        assert_profile_in_principal_control_realm(&fixture, &private).await;
    }
}

async fn creation_body_for_service(
    fixture: &Fixture,
    package: &AppletPackage,
    installed: &AppletInstallOutcome,
    scope: &ScopeRef,
    namespace: &str,
    label: &str,
    is_bot: bool,
) -> Value {
    if is_bot {
        return fixture
            .bot_body_in_scope(
                package,
                namespace,
                installed.registration_event_ref.clone(),
                scope.clone(),
            )
            .await;
    }
    let (status,preview)=fixture.service_post(
        package,&format!("/_arkret/self/applets/{}/ghosts/provision/preview",package.applet_id),
        arkret_wire::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PREVIEW_V1,
        &json!({"effective_scope":scope,"external_ref":{"protocol":"slack","instance_id":"team","external_id":label},"display_name":"Reviewed remote user"}),
        &format!("action-preview-{label}-{}",uuid::Uuid::now_v7()),
    ).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let request: AppletManagedActorAuthoringRequest =
        serde_json::from_value(preview["authoring_request"].clone()).unwrap();
    if let Some(existing) = request
        .basis
        .ghost()
        .unwrap()
        .existing_managed_actor
        .clone()
    {
        return serde_json::to_value(GhostActorProvisionRequestBody {
            authoring_request: request,
            managed_actor_bundle: None,
            existing_managed_actor: Some(existing),
            approval_signatures: Vec::new(),
        })
        .unwrap();
    }
    let actor = managed_actor_fixture(namespace, label, &package.service_id);
    ingest_managed_actor_current_document(&fixture.state, &actor).await;
    let bundle = fixture.managed_bundle(
        package,
        &request,
        &actor,
        installed.registration_event_ref.clone(),
    );
    serde_json::to_value(GhostActorProvisionRequestBody {
        authoring_request: request,
        managed_actor_bundle: Some(bundle),
        existing_managed_actor: None,
        approval_signatures: Vec::new(),
    })
    .unwrap()
}

fn operation_target(
    package: &AppletPackage,
    body: &Value,
    is_bot: bool,
) -> arkret_models_integration::management_review::ManagementReviewTarget {
    use arkret_models_integration::management_review::ManagementReviewTarget;
    if is_bot {
        ManagementReviewTarget::BotCreation {
            applet_id: package.applet_id.clone(),
            request_body: Box::new(serde_json::from_value(body.clone()).unwrap()),
        }
    } else {
        ManagementReviewTarget::GhostCreation {
            applet_id: package.applet_id.clone(),
            request_body: Box::new(serde_json::from_value(body.clone()).unwrap()),
        }
    }
}

async fn grant_creation_vote_administrator(
    fixture: &Fixture,
    scope: &ScopeRef,
) -> arkret_wire::GrantId {
    let grant = CapabilityGrantCreateBody {
        schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
        realm_id: Some(fixture.realm.clone()),
        issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
        subject: CapabilitySubject::Actor(ActorId::account(fixture.pcr.history.account.clone())),
        actions: vec!["ak.realm.admin".into()],
        resources: vec![match scope {
            ScopeRef::Realm { realm_id } => {
                arkret_wire::WireResourceSelector::realm(realm_id.clone())
            }
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => arkret_wire::WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
            _ => unreachable!(),
        }],
        constraints: Vec::new(),
        issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
            realm_id: fixture.realm.clone(),
            authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
            authority_generation: 0,
        }],
    };
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        serde_json::to_value(CapabilityGrantPayload { grant }).unwrap(),
    );
    let id = arkret_wire::GrantId::from_event_id(&event.event_id);
    accepted_admin_domain_event(fixture, event).await;
    id
}

async fn creation_governance_quorum(fixture: &Fixture, action: &str, id: &str, quorum: u64) {
    let payload = arkret_models_collaboration::events_payloads::PolicyActionStatePayload {
        policy_id: None,
        action_id: Some(arkret_wire::RealmPolicyActionId::new(id).unwrap()),
        value: arkret_models_collaboration::events_payloads::PolicyActionDocument {
            action: arkret_wire::PolicyActionName::new(action).unwrap(),
            approval_required: true,
            approval_quorum: quorum,
            policy_scope: fixture.realm.to_string(),
        },
    };
    let event = fixture.admin_event(
        EventKind::PolicyAction,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        serde_json::to_value(payload).unwrap(),
    );
    accepted_admin_domain_event(fixture, event).await;
}

fn assert_creation_approval_missing(status: StatusCode, error: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
    let problem: arkret_wire::problem_details::Problem =
        serde_json::from_value(error.clone()).unwrap();
    assert_eq!(
        problem.problem_type,
        arkret_wire::problem_details::Problem::from_code("claim_required", "").problem_type
    );
    assert_eq!(
        problem.extensions.get("reason_code"),
        Some(&json!("approval_required"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creation_action_approvals_bind_bot_ghost_and_reuse_without_a_management_ledger() {
    tokio::spawn(Box::pin(creation_action_approval_scenario()))
        .await
        .unwrap();
}

// Keep the scenario driver small beneath the real HTTP admission poll stack.
// Construct and await each owned phase without enlarging the default stack.
#[inline(never)]
fn creation_approval_phase<F: std::future::Future>(
    make: impl FnOnce() -> F,
) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

struct CreationActionApprovalContext {
    fixture: Box<Fixture>,
    _native: NativeAppletService,
    namespace: String,
    is_bot: bool,
    action: &'static str,
    operation: &'static str,
    scope: ScopeRef,
    approval: GrantConstraint,
    package: AppletPackage,
    installed: AppletInstallOutcome,
    governance_id: &'static str,
    path: String,
    body: Value,
    target: arkret_models_integration::management_review::ManagementReviewTarget,
    grant_id: arkret_wire::GrantId,
}

async fn creation_action_approval_scenario() {
    for is_bot in [true, false] {
        let mut context = creation_approval_phase(|| creation_action_approval_setup(is_bot)).await;
        let administrator_grant =
            creation_approval_phase(|| creation_action_approval_qualification(&mut context)).await;
        let vote =
            creation_approval_phase(|| creation_action_approval_consumption(&mut context)).await;
        creation_approval_phase(|| {
            creation_action_approval_replay_and_mapping(&mut context, &vote)
        })
        .await;
        creation_approval_phase(|| {
            creation_action_approval_admin_revocation(&mut context, &administrator_grant)
        })
        .await;
    }
}

async fn creation_action_approval_setup(is_bot: bool) -> Box<CreationActionApprovalContext> {
    use arkret_wire::{GrantId, ServiceOperationId};
    let fixture = Box::new(creation_approval_phase(Fixture::new).await);
    fixture.enable_management_authority();
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let action = if is_bot {
        "ak.applet.bot.provision"
    } else {
        "ak.applet.ghost.provision"
    };
    let operation = if is_bot {
        ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1
    } else {
        ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1
    };
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let approval:GrantConstraint=serde_json::from_value(json!({"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"require_review","approval_required":true,"approval_mode":"before_commit","approval_actor_ids":[fixture.pcr.history.account.principal_id],"approval_threshold":1,"timeout":"PT2S"})).unwrap();
    let (package, installed, ..) = fixture
        .install_service_with_constraints(
            true,
            native.package.clone(),
            scope.clone(),
            BTreeMap::from([(action.to_owned(), vec![approval.clone()])]),
        )
        .await;
    let governance_id = if is_bot {
        "create_bot_approval"
    } else {
        "map_ghost_approval"
    };
    creation_governance_quorum(&fixture, action, governance_id, 2).await;
    let path = format!(
        "/_arkret/self/applets/{}/{}s/provision",
        package.applet_id,
        if is_bot { "bot" } else { "ghost" }
    );
    let body = creation_body_for_service(
        &fixture,
        &package,
        &installed,
        &scope,
        &namespace,
        "action-original",
        is_bot,
    )
    .await;
    let target = operation_target(&package, &body, is_bot);
    let grant_id: GrantId = body["authoring_request"]["basis"]["authorization_ref"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    Box::new(CreationActionApprovalContext {
        fixture,
        _native: native,
        namespace,
        is_bot,
        action,
        operation,
        scope,
        approval,
        package,
        installed,
        governance_id,
        path,
        body,
        target,
        grant_id,
    })
}

async fn creation_action_approval_qualification(
    context: &mut CreationActionApprovalContext,
) -> arkret_wire::GrantId {
    let fixture = context.fixture.as_ref();
    let action = context.action;
    let operation = context.operation;
    let scope = &context.scope;
    let package = &context.package;
    let governance_id = context.governance_id;
    let path = &context.path;
    let body = &mut context.body;
    let target = &context.target;
    let grant_id = &context.grant_id;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, error) = fixture
        .service_post(package, path, operation, body, "action-unapproved")
        .await;
    assert_creation_approval_missing(status, &error);
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let realm_vote = creation_operation_vote(
        fixture,
        target,
        arkret_wire::ApprovalContext::RealmGovernance {},
    );
    body["approval_signatures"] = json!([realm_vote]);
    let (status, error) = fixture
        .service_post(
            package,
            path,
            operation,
            body,
            "governance-is-not-grant-approval",
        )
        .await;
    assert_creation_approval_missing(status, &error);
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let grant_vote = creation_operation_vote(
        fixture,
        target,
        arkret_wire::ApprovalContext::Grant {
            grant_id: grant_id.clone(),
        },
    );
    body["approval_signatures"] = json!([grant_vote, realm_vote]);
    let (status, error) = fixture
        .service_post(
            package,
            path,
            operation,
            body,
            "root-owner-without-explicit-admin",
        )
        .await;
    assert_creation_approval_missing(status, &error);
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let wrong_scope = fixture.new_circle_scope().await;
    grant_creation_vote_administrator(fixture, &wrong_scope).await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, error) = fixture
        .service_post(
            package,
            path,
            operation,
            body,
            "admin-in-other-scope-cannot-approve",
        )
        .await;
    assert_creation_approval_missing(status, &error);
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let administrator_grant = grant_creation_vote_administrator(fixture, scope).await;
    let grant_vote = creation_operation_vote(
        fixture,
        target,
        arkret_wire::ApprovalContext::Grant {
            grant_id: grant_id.clone(),
        },
    );
    let realm_vote = creation_operation_vote(
        fixture,
        target,
        arkret_wire::ApprovalContext::RealmGovernance {},
    );
    body["approval_signatures"] = json!([grant_vote, realm_vote]);
    let before = authority_snapshot(&fixture.pool).await;
    let (status, error) = fixture
        .service_post(
            package,
            path,
            operation,
            body,
            "one-principal-cannot-meet-two-votes",
        )
        .await;
    assert_creation_approval_missing(status, &error);
    assert!(
        error.to_string().contains("effective_approval_quorum=2"),
        "{error}"
    );
    assert!(error.to_string().contains("counted_approvals=1"), "{error}");
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    creation_governance_quorum(fixture, action, governance_id, 1).await;
    administrator_grant
}

async fn creation_action_approval_consumption(
    context: &mut CreationActionApprovalContext,
) -> arkret_wire::ApprovalSignature {
    let fixture = context.fixture.as_ref();
    let operation = context.operation;
    let package = &context.package;
    let path = &context.path;
    let body = &mut context.body;
    let target = &context.target;
    let grant_id = &context.grant_id;
    let before = authority_snapshot(&fixture.pool).await;
    let expired_vote = creation_operation_vote(
        fixture,
        target,
        arkret_wire::ApprovalContext::Grant {
            grant_id: grant_id.clone(),
        },
    );
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    body["approval_signatures"] = json!([expired_vote]);
    let (status, error) = fixture
        .service_post(package, path, operation, body, "expired-creation-approval")
        .await;
    assert_creation_approval_missing(status, &error);
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let future = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
        + chrono::TimeDelta::milliseconds(arkret_wire::hlc::HARD_FUTURE_SKEW_MS / 2);
    let vote = creation_operation_vote_at(
        fixture,
        target,
        arkret_wire::ApprovalContext::Grant {
            grant_id: grant_id.clone(),
        },
        future,
    );
    body["approval_signatures"] = json!([expired_vote, vote]);
    let (status, accepted) = fixture
        .service_post(
            package,
            path,
            operation,
            body,
            "one-original-vote-two-independent-requirements",
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");
    let after = authority_snapshot(&fixture.pool).await;
    assert_eq!(
        after["reviews"], before["reviews"],
        "action approval never fabricates a private management request"
    );
    let audit = after["approval_audit"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["nonce"] == vote.input.nonce)
        .unwrap();
    assert!(
        !after["approval_audit"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["nonce"] == expired_vote.input.nonce),
        "expired grant evidence cannot be consumed through the governance layer"
    );
    assert!(audit["event_id"].is_null());
    assert!(audit["accepted_commit_id"].is_null());
    assert_eq!(audit["operation_outcome"]["response_body"], accepted);
    assert_eq!(
        audit["accepted_basis"]["qualifications"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let (status, retry) = fixture
        .service_post(
            package,
            path,
            operation,
            body,
            "one-original-vote-two-independent-requirements",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{retry}");
    assert_eq!(accepted, retry);
    assert_eq!(after, authority_snapshot(&fixture.pool).await);
    vote
}

async fn creation_action_approval_replay_and_mapping(
    context: &mut CreationActionApprovalContext,
    vote: &arkret_wire::ApprovalSignature,
) {
    let fixture = context.fixture.as_ref();
    let namespace = &context.namespace;
    let action = context.action;
    let operation = context.operation;
    let scope = &context.scope;
    let approval = context.approval.clone();
    let package = &context.package;
    let installed = &context.installed;
    let path = &context.path;
    let grant_id = &context.grant_id;
    let is_bot = context.is_bot;
    let mut other = creation_body_for_service(
        fixture,
        package,
        installed,
        scope,
        namespace,
        "action-other",
        is_bot,
    )
    .await;
    let mut replay = creation_operation_vote(
        fixture,
        &operation_target(package, &other, is_bot),
        arkret_wire::ApprovalContext::Grant {
            grant_id: grant_id.clone(),
        },
    );
    replay.input.nonce = vote.input.nonce.clone();
    replay.proof.jws = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        [70; 32],
        replay.proof.verification_method.as_str(),
    )
    .sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&replay).unwrap(),
    );
    other["approval_signatures"] = json!([replay]);
    let stable = authority_snapshot(&fixture.pool).await;
    let (status, error) = fixture
        .service_post(
            package,
            path,
            operation,
            &other,
            "same-nonce-new-signed-target",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::from_u16(arkret_wire::ErrorCode::FailedPrecondition.http_status()).unwrap(),
        "{error}"
    );
    let problem: arkret_wire::problem_details::Problem = serde_json::from_value(error).unwrap();
    assert_eq!(
        problem.extensions.get("reason_code"),
        Some(&json!("approval_nonce_reused"))
    );
    assert_eq!(stable, authority_snapshot(&fixture.pool).await);
    if !is_bot {
        let circle = fixture.new_circle_scope().await;
        let (_, second, ..) = fixture
            .install_service_with_constraints(
                true,
                package.clone(),
                circle.clone(),
                BTreeMap::from([(action.to_owned(), vec![approval])]),
            )
            .await;
        let mut mapping = creation_body_for_service(
            fixture,
            package,
            &second,
            &circle,
            namespace,
            "action-original",
            false,
        )
        .await;
        assert!(mapping.get("managed_actor_bundle").is_none());
        let mapping_id: arkret_wire::GrantId =
            mapping["authoring_request"]["basis"]["authorization_ref"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
        let mapping_target = operation_target(package, &mapping, false);
        let mapping_vote = creation_operation_vote(
            fixture,
            &mapping_target,
            arkret_wire::ApprovalContext::Grant {
                grant_id: mapping_id,
            },
        );
        let root_vote = creation_operation_vote(
            fixture,
            &mapping_target,
            arkret_wire::ApprovalContext::Grant {
                grant_id: grant_id.clone(),
            },
        );
        mapping["approval_signatures"] = json!([mapping_vote, root_vote]);
        let before_mapping = authority_snapshot(&fixture.pool).await;
        let (status, outcome) = fixture
            .service_post(
                package,
                path,
                operation,
                &mapping,
                "reviewed-native-ghost-mapping",
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{outcome}");
        let after_mapping = authority_snapshot(&fixture.pool).await;
        for key in ["events", "commits", "completions", "outbox"] {
            assert_eq!(
                before_mapping[key], after_mapping[key],
                "mapping changed {key}"
            );
        }
        assert_eq!(after_mapping["reviews"], before_mapping["reviews"]);
    }
}

async fn creation_action_approval_admin_revocation(
    context: &mut CreationActionApprovalContext,
    administrator_grant: &arkret_wire::GrantId,
) {
    let fixture = context.fixture.as_ref();
    let namespace = &context.namespace;
    let operation = context.operation;
    let scope = &context.scope;
    let package = &context.package;
    let installed = &context.installed;
    let path = &context.path;
    let body = &mut context.body;
    let is_bot = context.is_bot;
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let current = rows
        .iter()
        .find(|row| row.grant_id == *administrator_grant)
        .unwrap();
    let revoke = fixture.admin_event(
        EventKind::CapabilityRevoke,
        scope.clone(),
        json!({"grant_id":administrator_grant,"expected_revision":current.revision,"reason":"approval_administrator_closed"}),
    );
    accepted_admin_domain_event(fixture, revoke).await;
    let mut blocked = creation_body_for_service(
        fixture,
        package,
        installed,
        scope,
        namespace,
        "admin-revoked",
        is_bot,
    )
    .await;
    let blocked_target = operation_target(package, &blocked, is_bot);
    let blocked_vote = creation_operation_vote(
        fixture,
        &blocked_target,
        arkret_wire::ApprovalContext::Grant {
            grant_id: body["authoring_request"]["basis"]["authorization_ref"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        },
    );
    blocked["approval_signatures"] = json!([blocked_vote]);
    let before = authority_snapshot(&fixture.pool).await;
    let (status, error) = fixture
        .service_post(
            package,
            path,
            operation,
            &blocked,
            "revoked-admin-cannot-approve",
        )
        .await;
    assert_creation_approval_missing(status, &error);
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
}

async fn approve_creation_management(
    fixture: &Fixture,
    package: &AppletPackage,
    target: arkret_models_integration::management_review::ManagementReviewTarget,
    scope: ScopeRef,
) -> arkret_wire::ApprovalSignature {
    use arkret_models_integration::management_review::*;
    let request = ManagementReviewRequestBody {
        request_id: format!("combined-creation-{}", uuid::Uuid::now_v7()),
        effective_scope: scope,
        management_operation: arkret_wire::ManagementOperation::CreateBot,
        requester_actor_id: ActorId::service(package.service_id.clone()),
        target,
    };
    let (status, pending) = fixture
        .service_post(
            package,
            "/_arkret/self/management-reviews/requests",
            arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(request),
            &format!("combined-request-{}", uuid::Uuid::now_v7()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["status"], "pending");
    let vote = creation_review_vote(fixture, &request);
    let (status,approved)=fixture.admin_post("/_arkret/self/management-reviews/decisions",arkret_wire::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,&json!({"request_id":request.request_id,"expected_status":"pending","decision":"approve","approval_signatures":[vote]}),None).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["status"], "approved");
    vote
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_grant_and_governance_creation_approvals_share_one_rollback_and_quota_cut() {
    tokio::spawn(Box::pin(combined_creation_approval_scenario()))
        .await
        .unwrap();
}

async fn combined_creation_approval_scenario() {
    use arkret_wire::{ApprovalContext, GrantId, ServiceOperationId};
    let fixture = Box::pin(Fixture::new()).await;
    fixture.enable_management_authority();
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let required:GrantConstraint=serde_json::from_value(json!({"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"require_review","approval_required":true,"approval_mode":"before_commit","approval_actor_ids":[fixture.pcr.history.account.principal_id],"approval_threshold":1,"timeout":"PT5M"})).unwrap();
    let quota:GrantConstraint=serde_json::from_value(json!({"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operations":1,"period":"P1D","constraint_scope":"per_realm"})).unwrap();
    let (package, installed, ..) = fixture
        .install_service_with_constraints(
            false,
            native.package.clone(),
            scope.clone(),
            BTreeMap::from([("ak.applet.bot.provision".to_owned(), vec![required, quota])]),
        )
        .await;
    grant_creation_vote_administrator(&fixture, &scope).await;
    creation_governance_quorum(&fixture, "ak.applet.bot.provision", "combined_creation", 1).await;
    let policy_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let administrator = ActorId::account(fixture.pcr.history.account.clone());
    let policy=fixture.admin_event(EventKind::PolicySet,scope.clone(),json!({"policy_id":policy_id,"expected_revision":null,"value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":fixture.realm,"policy_kind":"applet","default_effect":"allow","created_by":administrator,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),"rules":[{"rule_id":"combined_creation","kind":"applet","effect":"require_review","applet_target":{"kind":"all"},"applet_operations":["create_bot"],"review_requirement":{"approver_actor_ids":[administrator],"threshold":1,"max_age_seconds":3600}}]}}));
    accepted_admin_domain_event(&fixture, policy).await;
    let path = format!("/_arkret/self/applets/{}/bots/provision", package.applet_id);
    let mut body = creation_body_for_service(
        &fixture, &package, &installed, &scope, &namespace, "combined", true,
    )
    .await;
    let target = operation_target(&package, &body, true);
    let management =
        approve_creation_management(&fixture, &package, target.clone(), scope.clone()).await;
    let grant_id: GrantId = body["authoring_request"]["basis"]["authorization_ref"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let grant = creation_operation_vote(&fixture, &target, ApprovalContext::Grant { grant_id });
    let governance =
        creation_operation_vote(&fixture, &target, ApprovalContext::RealmGovernance {});
    let before = authority_snapshot(&fixture.pool).await;
    for (key, votes) in [
        (
            "management-cannot-substitute-action",
            vec![management.clone()],
        ),
        ("grant-cannot-substitute-management", vec![grant.clone()]),
        (
            "governance-cannot-substitute-grant",
            vec![management.clone(), governance],
        ),
    ] {
        body["approval_signatures"] = json!(votes);
        let (status, error) = fixture
            .service_post(
                &package,
                &path,
                ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
                &body,
                key,
            )
            .await;
        assert_creation_approval_missing(status, &error);
        assert_eq!(before, authority_snapshot(&fixture.pool).await);
    }
    body["approval_signatures"] = json!([management, grant]);
    let fail_key = format!("review-fail-0-{}", uuid::Uuid::now_v7());
    let constraint = format!("review_failure_{}", uuid::Uuid::now_v7().simple());
    {
        use std::io::Write as _;
        writeln!(
            std::io::stderr(),
            "creation review fault injection: constraint={constraint} key={fail_key}"
        )
        .unwrap();
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(format!("ALTER TABLE applet_authoring_units ADD CONSTRAINT {constraint} CHECK (idempotency_key <> '{fail_key}') NOT VALID")).execute(&mut conn).await.unwrap();
    }
    let (status, error) = fixture
        .service_post(
            &package,
            &path,
            ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
            &body,
            &fail_key,
        )
        .await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(format!(
            "ALTER TABLE applet_authoring_units DROP CONSTRAINT {constraint}"
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    }
    assert!(status.is_server_error(), "{status} {error}");
    assert_eq!(
        before,
        authority_snapshot(&fixture.pool).await,
        "all approval layers and quota must roll back with the real final outcome failure"
    );
    let (status, accepted) = fixture
        .service_post(
            &package,
            &path,
            ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
            &body,
            &fail_key,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");
    let after = authority_snapshot(&fixture.pool).await;
    assert_eq!(after["approval_audit"].as_array().unwrap().len(), 2);
    assert_eq!(after["quota_counters"].as_array().unwrap().len(), 1);
    assert_eq!(after["quota_counters"][0]["consumed"], 1);
    assert_eq!(after["reviews"][0]["status"], "consumed");
    assert_eq!(
        after["reviews"][0]["accepted_operation_outcome"]["response_body"],
        accepted
    );
    let (status, retry) = fixture
        .service_post(
            &package,
            &path,
            ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
            &body,
            &fail_key,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{retry}");
    assert_eq!(accepted, retry);
    assert_eq!(after, authority_snapshot(&fixture.pool).await);
    let mut another = creation_body_for_service(
        &fixture,
        &package,
        &installed,
        &scope,
        &namespace,
        "quota-full",
        true,
    )
    .await;
    let another_target = operation_target(&package, &another, true);
    let management =
        approve_creation_management(&fixture, &package, another_target.clone(), scope).await;
    let grant_id: GrantId = another["authoring_request"]["basis"]["authorization_ref"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let grant = creation_operation_vote(
        &fixture,
        &another_target,
        ApprovalContext::Grant { grant_id },
    );
    another["approval_signatures"] = json!([management, grant]);
    let stable = authority_snapshot(&fixture.pool).await;
    let (status, error) = fixture
        .service_post(
            &package,
            &path,
            ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
            &another,
            "quota-full-approved-creation",
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{error}");
    assert_eq!(stable, authority_snapshot(&fixture.pool).await);
}

#[path = "applet_admission/native_device.rs"]
mod native_device;

#[path = "applet_admission/managed_runtime.rs"]
mod managed_runtime;
