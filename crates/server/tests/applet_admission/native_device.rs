//! Real native Device join through the mounted self/events route and private ledger.
use arkret_models_integration::management_review::*;
use arkret_wire::{DeviceId, ManagementOperation, ServiceOperationId};
use coland_storage::DeviceRevocationStore as _;

use super::*;

async fn authorize(
    fixture: &Fixture,
    install: &Installed,
    bundle: &Value,
    namespace: &str,
    key: &SigningKey,
    device_id: DeviceId,
    allow_join: bool,
) -> coland_storage::AppletManagedDeviceAuthority {
    use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
    use ed25519_dalek::Signer as _;
    let provision = &bundle["managed_actor_provision_event"]["payload"];
    let actor: ActorId = serde_json::from_value(provision["actor_id"].clone()).unwrap();
    let did = provision["initial_resolution"]["did"].as_str().unwrap();
    let local = did.rsplit(':').next().unwrap();
    let seed = deterministic_managed_actor_seed(&format!(
        "{}:{local}:controller:{}",
        safe_did_token(namespace),
        install.package.service_id
    ));
    let controller = SigningKey::from_bytes(&seed);
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let actions = if allow_join {
        json!(["ak.applet.join", "ak.event.read"])
    } else {
        json!(["ak.event.read"])
    };
    let mut payload:DeviceAuthorizePayload=serde_json::from_value(json!({
        "device_id":device_id,"device_public_key_did":format!("did:key:{}",arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())),
        "hpke_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[119;32]),"algorithms":["Ed25519"],"device_key_algorithm":"Ed25519",
        "authorized_by":actor.signing_principal_id(),"scopes":[{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":actions}],
        "not_before":now-chrono::Duration::seconds(1),"expires_at":now+chrono::Duration::hours(1),"authorization_binding_kind":"applet_managed_delegation","authorized_generation_ref":1,"device_signature":"AA","applet_id":install.package.applet_id
    })).unwrap();
    payload.device_signature = serde_json::from_value(json!(arkret_canonical::base64url_encode(
        key.sign(
            &payload
                .device_possession_signature_input(actor.as_account_id().unwrap())
                .unwrap()
        )
        .to_bytes()
    )))
    .unwrap();
    let realm = RealmId::from_event_id(
        &serde_json::from_value(bundle["pcr_genesis_event"]["event_id"].clone()).unwrap(),
    );
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::DeviceAuthorize.as_str(),
        ScopeRef::Realm { realm_id: realm },
        actor.clone(),
        json!(payload),
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
        controller,
        Did::new(did).unwrap(),
        arkret_wire::DidUrl::new(format!("{did}#managed-controller")).unwrap(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new(),
    )
    .unwrap();
    let body = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(authored.into_event()),
    );
    let (status, outcome) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/events",
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(body),
            &format!("native-device-{}", uuid::Uuid::now_v7()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "authorize: {outcome}");
    coland_storage_postgres::PgDeviceRevocationStore {
        pool: fixture.pool.clone(),
    }
    .applet_managed_device_authority(
        actor.as_account_id().unwrap(),
        &device_id,
        chrono::Utc::now(),
    )
    .await
    .unwrap()
    .unwrap()
}

fn join_event(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    grant: &arkret_wire::GrantId,
) -> Event {
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let actor = ActorId::account(authority.account_id.clone());
    let mut draft = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::MemberState.as_str(),
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        actor.clone(),
        json!({"member_id":actor,"membership":"join"}),
        now,
    )
    .unwrap();
    draft.applet_id = Some(install.package.applet_id.clone());
    draft.authorization_ref = Some(grant.clone().into());
    sign_managed_device_event(draft, authority, key, now)
}

async fn post(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    event: &Event,
    votes: Vec<arkret_wire::ApprovalSignature>,
) -> (StatusCode, Value) {
    let submission = arkret_wire::EventAdmissionSubmission {
        event: event.clone(),
        approval_signatures: (!votes.is_empty()).then_some(votes),
    };
    let body = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        submission,
    );
    let mut response = managed_device_http_request_body(
        &fixture.state,
        authority,
        &managed_device_metadata(authority),
        ServiceOperationId::SelfEventsCommandSubmitV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),
    )
    .send(&service(fixture.state.clone()))
    .await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}

async fn business(fixture: &Fixture) -> Value {
    let mut snapshot = authority_snapshot(&fixture.pool).await;
    snapshot.as_object_mut().unwrap().remove("device_nonces");
    snapshot
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_join_use_real_native_device_installation_source_and_exact_replay() {
    tokio::spawn(Box::pin(async {
        let fixture=Box::pin(Fixture::new()).await;
        let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());
        let native=NativeAppletService::new(&format!("ak:applet:{}",uuid::Uuid::now_v7()),&namespace,&fixture.state.service_core_id());
        let install=Box::pin(fixture.install_package(true,native.package.clone(),&namespace)).await;
        let ghost=fixture.ghost_body(&install,&namespace,"native-join").await;
        assert_eq!(fixture.ghost_commit(&install,&ghost,"native-ghost").await.0,StatusCode::CREATED);
        let mut originals=Vec::new();
        let unrelated=managed_actor_action_grant(&fixture,&install,&ActorId::service(install.package.service_id.clone()),vec!["ak.message.create".into()]).await;
        for bundle in [install.bot_body["managed_actor_bundle"].clone(),ghost["managed_actor_bundle"].clone()] {
            let actor:ActorId=serde_json::from_value(bundle["managed_actor_provision_event"]["payload"]["actor_id"].clone()).unwrap();
            let installation_grant=install.bot_outcome.authorization_ref.clone();
            let key=SigningKey::from_bytes(&[121;32]);
            let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
            let narrow=authorize(&fixture,&install,&bundle,&namespace,&key,device.clone(),false).await;
            let event=join_event(&fixture,&install,&narrow,&key,&installation_grant);
            let before=business(&fixture).await;
            let (status,error)=post(&fixture,&narrow,&key,&event,vec![]).await;
            assert!(!status.is_success(),"scope/action ceiling: {error}");assert_eq!(before,business(&fixture).await);
            let authority=authorize(&fixture,&install,&bundle,&namespace,&key,device.clone(),true).await;
            let event=join_event(&fixture,&install,&authority,&key,&installation_grant);
            let unrelated_ref=join_event(&fixture,&install,&authority,&key,&unrelated);
            let mut other_subject=event.clone();other_subject.payload.insert("member_id".into(),json!(ActorId::account(fixture.pcr.history.account.clone())));
            let other_subject=sign_managed_device_event(other_subject,&authority,&key,event.created_at);
            for wrong in [unrelated_ref,other_subject] {
                let before=business(&fixture).await;let (status,error)=post(&fixture,&authority,&key,&wrong,vec![]).await;
                assert!(!status.is_success(),"wrong installation or subject: {error}");assert_eq!(before,business(&fixture).await);
            }
            let service_key=applet_service_signing_key(&install.package.webhook_auth.key_ref);
            let wrong=sign_managed_device_event(event.clone(),&authority,&service_key,event.created_at);
            let before=business(&fixture).await;
            assert!(!post(&fixture,&authority,&key,&wrong,vec![]).await.0.is_success());assert_eq!(before,business(&fixture).await);
            let (status,accepted)=post(&fixture,&authority,&key,&event,vec![]).await;
            assert_eq!(status,StatusCode::OK,"native join: {accepted}");
            assert_accepted_event(&fixture,&event).await;
            assert!(fixture.state.test_persistence().authority_commits().local_current_member_joined(&fixture.realm,&actor,&fixture.state.service_core_id()).await.unwrap());
            let record=fixture.state.test_persistence().authority_commits().committed_event(&event.event_id).await.unwrap().unwrap();
            let fact=fixture.state.test_persistence().authority_commits().account_device_signer_fact(&event,&record.commit).await.unwrap().unwrap();
            assert_eq!(fact.actor,actor);assert_eq!(fact.key.authorization_ref,authority.selector.authorization_ref);
            arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(&event,&fact,fixture.realm.digest_suite_code().digest_suite()).unwrap();
            let before=business(&fixture).await;
            let (status,replay)=post(&fixture,&authority,&key,&event,vec![]).await;assert_eq!(status,StatusCode::OK,"{replay}");assert_eq!(before,business(&fixture).await);
            let replacement_key=SigningKey::from_bytes(&[122;32]);
            let replacement=authorize(&fixture,&install,&bundle,&namespace,&replacement_key,device,true).await;
            let before=business(&fixture).await;
            let (status,replay)=post(&fixture,&replacement,&replacement_key,&event,vec![]).await;assert_eq!(status,StatusCode::OK,"replacement replay: {replay}");assert_eq!(before,business(&fixture).await);
            let fact_after=fixture.state.test_persistence().authority_commits().account_device_signer_fact(&event,&record.commit).await.unwrap().unwrap();assert_eq!(fact,fact_after);
            originals.push((event,replacement,replacement_key));
        }
        fixture.revoke(&install).await;
        for (original,authority,key) in originals {
            let before=business(&fixture).await;
            let fresh=join_event(&fixture,&install,&authority,&key,&install.bot_outcome.authorization_ref);
            let (status,error)=post(&fixture,&authority,&key,&fresh,vec![]).await;assert!(!status.is_success(),"revoked install new join: {error}");assert_eq!(before,business(&fixture).await);
            let (status,replay)=post(&fixture,&authority,&key,&original,vec![]).await;assert_eq!(status,StatusCode::OK,"accepted original after revoke: {replay}");assert_eq!(before,business(&fixture).await);
        }
    })).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_join_review_binds_service_requester_device_original_and_atomic_consumption() {
    tokio::spawn(Box::pin(async {
        let fixture=Box::pin(Fixture::new()).await;fixture.enable_management_authority();
        let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());
        let native=NativeAppletService::new(&format!("ak:applet:{}",uuid::Uuid::now_v7()),&namespace,&fixture.state.service_core_id());
        let install=Box::pin(fixture.install_package(true,native.package.clone(),&namespace)).await;
        let actor=install.bot_outcome.bot_actor_id.clone();
        let installation_grant=install.bot_outcome.authorization_ref.clone();
        let key=SigningKey::from_bytes(&[123;32]);let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
        let authority=authorize(&fixture,&install,&install.bot_body["managed_actor_bundle"],&namespace,&key,device,true).await;
        let event=join_event(&fixture,&install,&authority,&key,&installation_grant);
        let admin=ActorId::account(fixture.pcr.history.account.clone());let policy_id=format!("ak:policy:{}",uuid::Uuid::now_v7());
        let policy=fixture.admin_event(EventKind::PolicySet,event.scope_ref.clone(),json!({"policy_id":policy_id,"expected_revision":null,"value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":fixture.realm,"policy_kind":"applet","default_effect":"allow","created_by":admin,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),"rules":[{"rule_id":"native_join","kind":"applet","effect":"require_review","applet_target":{"kind":"installation","applet_id":install.package.applet_id,"effective_scope":event.scope_ref},"applet_operations":["join"],"review_requirement":{"approver_actor_ids":[admin],"threshold":1,"max_age_seconds":3600}}]}}));
        accepted_admin_domain_event(&fixture,policy).await;
        let before=business(&fixture).await;let (status,error)=post(&fixture,&authority,&key,&event,vec![]).await;assert!(!status.is_success(),"{error}");assert!(error.to_string().contains("approval_required"),"{error}");assert_eq!(before,business(&fixture).await);
        let request=ManagementReviewRequestBody {request_id:format!("native-review-{}",uuid::Uuid::now_v7()),effective_scope:event.scope_ref.clone(),management_operation:ManagementOperation::Join,requester_actor_id:ActorId::service(install.package.service_id.clone()),target:ManagementReviewTarget::Event {event:Box::new(event.clone())}};
        let (status,pending)=fixture.service_post(&install.package,"/_arkret/self/management-reviews/requests",ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,&json!(request),"native-review-request").await;assert_eq!(status,StatusCode::OK,"pending native: {pending}");assert_eq!(pending["status"],"pending");
        let vote=creation_review_vote(&fixture,&request);
        let decision=json!({"request_id":request.request_id,"expected_status":"pending","decision":"approve","approval_signatures":[vote]});
        let (status,approved)=fixture.admin_post("/_arkret/self/management-reviews/decisions",ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,&decision,None).await;assert_eq!(status,StatusCode::OK,"native approve: {approved}");assert_eq!(approved["status"],"approved");
        let before=business(&fixture).await;
        let unrecorded=creation_review_vote(&fixture,&request);
        let (status,hidden)=post(&fixture,&authority,&key,&event,vec![unrecorded]).await;
        assert_eq!(status,StatusCode::NOT_FOUND,"unrecorded approval cannot prepare private ledger: {hidden}");assert_eq!(before,business(&fixture).await);
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("CREATE FUNCTION fail_native_membership() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'native membership fault'; END $$").execute(&mut conn).await.unwrap();diesel::sql_query("CREATE TRIGGER fail_native_membership BEFORE INSERT ON member_state_current_results FOR EACH ROW EXECUTE FUNCTION fail_native_membership()").execute(&mut conn).await.unwrap();}
        let (status,error)=post(&fixture,&authority,&key,&event,vec![vote.clone()]).await;
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("DROP TRIGGER fail_native_membership ON member_state_current_results").execute(&mut conn).await.unwrap();diesel::sql_query("DROP FUNCTION fail_native_membership()").execute(&mut conn).await.unwrap();}
        assert!(status.is_server_error(),"injected native failure: {error}");assert_eq!(before,business(&fixture).await);
        let (status,outcome)=post(&fixture,&authority,&key,&event,vec![vote.clone()]).await;assert_eq!(status,StatusCode::OK,"native reviewed join: {outcome}");
        let after=business(&fixture).await;let row=after["reviews"].as_array().unwrap().iter().find(|r|r["request_id"]==request.request_id).unwrap();assert_eq!(row["status"],"consumed");assert!(!row["accepted_commit_id"].is_null());
        let (status,replay)=post(&fixture,&authority,&key,&event,vec![vote]).await;assert_eq!(status,StatusCode::OK,"{replay}");assert_eq!(after,business(&fixture).await);

        let ghost=fixture.ghost_body(&install,&namespace,"native-review-grant-current").await;
        assert_eq!(fixture.ghost_commit(&install,&ghost,"native-pending-ghost").await.0,StatusCode::CREATED);
        let ghost_key=SigningKey::from_bytes(&[124;32]);let ghost_device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
        let ghost_authority=authorize(&fixture,&install,&ghost["managed_actor_bundle"],&namespace,&ghost_key,ghost_device,true).await;
        let ghost_event=join_event(&fixture,&install,&ghost_authority,&ghost_key,&installation_grant);
        let pending_request=ManagementReviewRequestBody {request_id:format!("native-revoked-source-{}",uuid::Uuid::now_v7()),effective_scope:ghost_event.scope_ref.clone(),management_operation:ManagementOperation::Join,requester_actor_id:request.requester_actor_id.clone(),target:ManagementReviewTarget::Event {event:Box::new(ghost_event)}};
        let (status,pending)=fixture.service_post(&install.package,"/_arkret/self/management-reviews/requests",ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,&json!(pending_request),"native-pending-source").await;assert_eq!(status,StatusCode::OK,"{pending}");assert_eq!(pending["status"],"pending");
        let complete=business(&fixture).await;
        let original_projection=complete["grants"].as_array().unwrap().iter().find(|row|row["grant_id"]==installation_grant.as_str()).unwrap().clone();
        {let mut conn=fixture.pool.get().await.unwrap();let deleted=diesel::sql_query("DELETE FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2").bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(installation_grant.as_str()).execute(&mut conn).await.unwrap();assert_eq!(deleted,1);}
        let incomplete=business(&fixture).await;
        let (status,unknown)=fixture.service_post(&install.package,"/_arkret/self/management-reviews/status",ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,&json!({"request_id":pending_request.request_id}),"native-missing-source-current").await;
        assert_eq!(status,StatusCode::CONFLICT,"{unknown}");assert!(unknown.to_string().contains("revision_unavailable"),"{unknown}");assert_eq!(incomplete,business(&fixture).await);
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("INSERT INTO capability_grant_current_results SELECT r.* FROM jsonb_populate_recordset(NULL::capability_grant_current_results,$1) r").bind::<diesel::sql_types::Jsonb,_>(json!([original_projection])).execute(&mut conn).await.unwrap();}
        assert_eq!(complete,business(&fixture).await);
        let grants=fixture.state.test_persistence().capability_grant_current_results().snapshot_for_realm(&fixture.realm).await.unwrap();
        let grant=grants.iter().find(|grant|grant.grant_id==installation_grant).unwrap();
        let revoke=fixture.admin_event(EventKind::CapabilityRevoke,event.scope_ref.clone(),json!({"grant_id":installation_grant,"expected_revision":grant.revision,"reason":"native_installation_source_closed"}));
        accepted_admin_domain_event(&fixture,revoke).await;
        let before=business(&fixture).await;
        let (status,superseded)=fixture.service_post(&install.package,"/_arkret/self/management-reviews/status",ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,&json!({"request_id":pending_request.request_id}),"native-source-status").await;
        assert_eq!(status,StatusCode::OK,"{superseded}");assert_eq!(superseded["status"],"superseded");assert_eq!(business_without_reviews(before),business_without_reviews(business(&fixture).await));
        let (status,consumed)=fixture.service_post(&install.package,"/_arkret/self/management-reviews/status",ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,&json!({"request_id":request.request_id}),"native-original-consumed-status").await;assert_eq!(status,StatusCode::OK,"{consumed}");assert_eq!(consumed["status"],"consumed");
    })).await.unwrap();
}
