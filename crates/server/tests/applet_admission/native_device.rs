//! Real native Device join through the mounted self/events route and private ledger.
#[path = "native_device/e2ee.rs"]
mod e2ee;
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
    let actions = if allow_join {
        json!(["ak.applet.join", "ak.event.read"])
    } else {
        json!(["ak.event.read"])
    };
    authorize_scopes(
        fixture,
        install,
        bundle,
        namespace,
        key,
        device_id,
        json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":actions}]),
    )
    .await
}

async fn authorize_scopes(
    fixture: &Fixture,
    install: &Installed,
    bundle: &Value,
    namespace: &str,
    key: &SigningKey,
    device_id: DeviceId,
    scopes: Value,
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
    let mut payload:DeviceAuthorizePayload=serde_json::from_value(json!({
        "device_id":device_id,"device_public_key_did":format!("did:key:{}",arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())),
        "hpke_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[119;32]),"algorithms":["Ed25519"],"device_key_algorithm":"Ed25519",
        "authorized_by":actor.signing_principal_id(),"scopes":scopes,
        "not_before":arkret_canonical::format_timestamp_canonical(now-chrono::Duration::seconds(1)),"expires_at":arkret_canonical::format_timestamp_canonical(now+chrono::Duration::hours(1)),"authorization_binding_kind":"applet_managed_delegation","authorized_generation_ref":1,"device_signature":"AA","applet_id":install.package.applet_id
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

#[inline(never)]
fn business(
    fixture: &Fixture,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Value> + Send + '_>> {
    Box::pin(async move {
        let mut snapshot = Box::pin(managed_domain_snapshot(&fixture.pool)).await;
        snapshot.as_object_mut().unwrap().remove("device_nonces");
        snapshot
    })
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

fn profile_create(
    fixture: &Fixture,
    install: &Installed,
    bundle: &Value,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    mode: &str,
) -> Event {
    let mut object = bundle["profile_event"]["payload"]["object"].clone();
    object["profile_fields"]["applet_interaction"] =
        json!({"effective_scope":{"kind":"realm","realm_id":fixture.realm},"mode":mode});
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::ProfileCreate.as_str(),
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        ActorId::account(authority.account_id.clone()),
        json!({"object":object}),
        now,
    )
    .unwrap();
    event.applet_id = Some(install.package.applet_id.clone());
    event.authorization_ref = Some(install.bot_outcome.authorization_ref.clone().into());
    sign_managed_device_event(event, authority, key, now)
}
fn profile_update(
    original: &Event,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    patch: Value,
) -> Event {
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut event=arkret_wire::test_support::raw_event_for_actor_at(EventKind::ProfileUpdate.as_str(),original.scope_ref.clone(),original.actor_id.clone(),json!({"target_ref":arkret_wire::ActorProfileId::from_event_id(&original.event_id),"patch":patch}),now).unwrap();
    event.applet_id = original.applet_id.clone();
    event.authorization_ref = original.authorization_ref.clone();
    sign_managed_device_event(event, authority, key, now)
}
async fn publish_policy(fixture: &Fixture, install: &Installed, effect: &str) -> Event {
    let id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let mut rule = json!({"rule_id":"native_publish","kind":"applet","effect":effect,"applet_target":{"kind":"installation","applet_id":install.package.applet_id,"effective_scope":{"kind":"realm","realm_id":fixture.realm}},"applet_operations":["publish"]});
    if effect == "require_review" {
        rule["review_requirement"] =
            json!({"approver_actor_ids":[admin],"threshold":1,"max_age_seconds":3600});
    }
    let event=fixture.admin_event(EventKind::PolicySet,ScopeRef::Realm{realm_id:fixture.realm.clone()},json!({"policy_id":id,"expected_revision":null,"value":{"schema":"ak.schema.policy.v1","id":id,"realm_id":fixture.realm,"policy_kind":"applet","default_effect":"allow","created_by":admin,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),"rules":[rule]}}));
    accepted_admin_domain_event(fixture, event.clone()).await;
    event
}
async fn approved_profile(
    fixture: &Fixture,
    install: &Installed,
    event: &Event,
) -> (ManagementReviewRequestBody, arkret_wire::ApprovalSignature) {
    let request = ManagementReviewRequestBody {
        request_id: format!("publish-{}", uuid::Uuid::now_v7()),
        effective_scope: event.scope_ref.clone(),
        management_operation: ManagementOperation::Publish,
        requester_actor_id: ActorId::service(install.package.service_id.clone()),
        target: ManagementReviewTarget::Event {
            event: Box::new(event.clone()),
        },
    };
    let (status, pending) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(request),
            &format!("request-{}", uuid::Uuid::now_v7()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "publish pending: {pending}");
    assert_eq!(pending["status"], "pending");
    let vote = creation_review_vote(fixture, &request);
    let (status,approved)=fixture.admin_post("/_arkret/self/management-reviews/decisions",ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,&json!({"request_id":request.request_id,"expected_status":"pending","decision":"approve","approval_signatures":[vote]}),None).await;
    assert_eq!(status, StatusCode::OK, "publish approved: {approved}");
    assert_eq!(approved["status"], "approved");
    (request, vote)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_profiles_keep_full_subject_scope_and_reserved_identity() {
    tokio::spawn(Box::pin(async {
        let fixture=Box::pin(Fixture::new()).await;
        let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());
        let native=NativeAppletService::new(&format!("ak:applet:{}",uuid::Uuid::now_v7()),&namespace,&fixture.state.service_core_id());
        let install=Box::pin(fixture.install_package(true,native.package.clone(),&namespace)).await;
        let ghost=fixture.ghost_body(&install,&namespace,"scope-profile").await;assert_eq!(fixture.ghost_commit(&install,&ghost,"scope-profile-ghost").await.0,StatusCode::CREATED);
        let mut profiles=Vec::new();
        for bundle in [install.bot_body["managed_actor_bundle"].clone(),ghost["managed_actor_bundle"].clone()] {
            let key=SigningKey::from_bytes(&[125;32]);let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
            let narrow=authorize(&fixture,&install,&bundle,&namespace,&key,device.clone(),true).await;
            let join=join_event(&fixture,&install,&narrow,&key,&install.bot_outcome.authorization_ref);
            let (status,out)=post(&fixture,&narrow,&key,&join,vec![]).await;assert_eq!(status,StatusCode::OK,"{out}");
            let denied=profile_create(&fixture,&install,&bundle,&narrow,&key,"public");let before=business(&fixture).await;
            assert!(!post(&fixture,&narrow,&key,&denied,vec![]).await.0.is_success());assert_eq!(before,business(&fixture).await);
            let authority=authorize_scopes(&fixture,&install,&bundle,&namespace,&key,device,json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.applet.publish","ak.event.read"]}])).await;
            let original=profile_create(&fixture,&install,&bundle,&authority,&key,"public");
            for (field,value) in [("managed_by_applet",json!("ak:applet:00000000-0000-4000-8000-000000000999")),("applet_interaction",json!({"effective_scope":{"kind":"realm","realm_id":authority.pcr_realm_id},"mode":"public"}))] {
                let mut wrong=original.clone();wrong.payload.get_mut("object").unwrap()["profile_fields"][field]=value;
                let wrong=sign_managed_device_event(wrong,&authority,&key,original.created_at);let before=business(&fixture).await;
                assert!(!post(&fixture,&authority,&key,&wrong,vec![]).await.0.is_success());assert_eq!(before,business(&fixture).await);
            }
            let (status,out)=post(&fixture,&authority,&key,&original,vec![]).await;assert_eq!(status,StatusCode::OK,"scope create: {out}");assert_accepted_event(&fixture,&original).await;
            let update=profile_update(&original,&authority,&key,json!({"display_name":"Native scope profile"}));
            let (status,out)=post(&fixture,&authority,&key,&update,vec![]).await;assert_eq!(status,StatusCode::OK,"scope update: {out}");
            let before=business(&fixture).await;assert_eq!(post(&fixture,&authority,&key,&original,vec![]).await.0,StatusCode::OK);assert_eq!(before,business(&fixture).await);
            for patch in [json!({"accountable_principal_ids":[]}),json!({"profile_fields.managed_by_applet":null})] {
                let wrong=profile_update(&original,&authority,&key,patch);let before=business(&fixture).await;
                assert!(!post(&fixture,&authority,&key,&wrong,vec![]).await.0.is_success());assert_eq!(before,business(&fixture).await);
            }
            profiles.push((original,authority,key));
        }
        let material=fixture.state.test_persistence().authority_commits().realm_state_snapshot_material_for_account(&fixture.realm,&fixture.pcr.history.account).await.unwrap().unwrap();
        let rows=material.current_state_entries.iter().filter_map(|row|{let arkret_wire::TypedCurrentRow::Value{selector:arkret_wire::CurrentSelector::ActorProfile{actor_profile_id},value,..}=row else{return None};Some((actor_profile_id,value))}).collect::<Vec<_>>();assert_eq!(rows.len(),2);
        for (original,authority,key) in &profiles {
            let id=arkret_wire::ActorProfileId::from_event_id(&original.event_id);let row=rows.iter().find(|(found,_)|**found==id).unwrap();assert_eq!(row.1["principal_id"],json!(authority.account_id.principal_id));assert!(row.1.get("resolution").is_none());
            let before=business(&fixture).await;
            let missing=before["profiles"].as_array().unwrap().iter().find(|p|p["actor_profile_id"]==id.as_str()).unwrap().clone();
            {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("DELETE FROM actor_profile_current_results WHERE actor_profile_id=$1").bind::<diesel::sql_types::Text,_>(id.as_str()).execute(&mut conn).await.unwrap();}
            let incomplete=business(&fixture).await;let next=profile_update(original,authority,key,json!({"display_name":"Unavailable current"}));let (status,error)=post(&fixture,authority,key,&next,vec![]).await;assert_eq!(status,StatusCode::CONFLICT,"{error}");assert!(error.to_string().contains("revision_unavailable"),"{error}");assert_eq!(incomplete,business(&fixture).await);
            {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("INSERT INTO actor_profile_current_results SELECT r.* FROM jsonb_populate_recordset(NULL::actor_profile_current_results,$1) r").bind::<diesel::sql_types::Jsonb,_>(json!([missing])).execute(&mut conn).await.unwrap();}assert_eq!(before,business(&fixture).await);
        }
        publish_policy(&fixture,&install,"deny").await;
        for (original,authority,key) in &profiles {
            let public=profile_update(original,authority,key,json!({"display_name":"Still public"}));let before=business(&fixture).await;assert!(!post(&fixture,authority,key,&public,vec![]).await.0.is_success());assert_eq!(before,business(&fixture).await);
            let private=profile_update(original,authority,key,json!({"profile_fields.applet_interaction.mode":"private"}));let (status,out)=post(&fixture,authority,key,&private,vec![]).await;assert_eq!(status,StatusCode::OK,"private transition: {out}");
            let reopen=profile_update(original,authority,key,json!({"profile_fields.applet_interaction.mode":"public"}));let before=business(&fixture).await;assert!(!post(&fixture,authority,key,&reopen,vec![]).await.0.is_success());assert_eq!(before,business(&fixture).await);
        }
    })).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_public_profile_review_consumes_exact_postimage_and_rolls_back() {
    tokio::spawn(Box::pin(async {
        let fixture=Box::pin(Fixture::new()).await;fixture.enable_management_authority();
        let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());let native=NativeAppletService::new(&format!("ak:applet:{}",uuid::Uuid::now_v7()),&namespace,&fixture.state.service_core_id());
        let install=Box::pin(fixture.install_package(true,native.package.clone(),&namespace)).await;
        let key=SigningKey::from_bytes(&[126;32]);let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
        let authority=authorize_scopes(&fixture,&install,&install.bot_body["managed_actor_bundle"],&namespace,&key,device,json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.applet.publish","ak.event.read"]}])).await;
        let join=join_event(&fixture,&install,&authority,&key,&install.bot_outcome.authorization_ref);let (status,out)=post(&fixture,&authority,&key,&join,vec![]).await;assert_eq!(status,StatusCode::OK,"{out}");
        publish_policy(&fixture,&install,"require_review").await;
        let original=profile_create(&fixture,&install,&install.bot_body["managed_actor_bundle"],&authority,&key,"public");
        let before=business(&fixture).await;let (status,error)=post(&fixture,&authority,&key,&original,vec![]).await;assert!(!status.is_success(),"{error}");assert!(error.to_string().contains("approval_required"),"{error}");assert_eq!(before,business(&fixture).await);
        let (request,vote)=approved_profile(&fixture,&install,&original).await;
        let before=business(&fixture).await;
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("CREATE FUNCTION fail_native_profile() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'native profile fault'; END $$").execute(&mut conn).await.unwrap();diesel::sql_query("CREATE TRIGGER fail_native_profile BEFORE INSERT ON actor_profile_current_results FOR EACH ROW EXECUTE FUNCTION fail_native_profile()").execute(&mut conn).await.unwrap();}
        let (status,error)=post(&fixture,&authority,&key,&original,vec![vote.clone()]).await;
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("DROP TRIGGER fail_native_profile ON actor_profile_current_results").execute(&mut conn).await.unwrap();diesel::sql_query("DROP FUNCTION fail_native_profile()").execute(&mut conn).await.unwrap();}
        assert!(status.is_server_error(),"{error}");assert_eq!(before,business(&fixture).await);
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("CREATE FUNCTION fail_native_profile_source() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'native profile retained source fault'; END $$").execute(&mut conn).await.unwrap();diesel::sql_query("CREATE TRIGGER fail_native_profile_source BEFORE INSERT ON agent_producer_signer_keys FOR EACH ROW EXECUTE FUNCTION fail_native_profile_source()").execute(&mut conn).await.unwrap();}
        let (status,error)=post(&fixture,&authority,&key,&original,vec![vote.clone()]).await;
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("DROP TRIGGER fail_native_profile_source ON agent_producer_signer_keys").execute(&mut conn).await.unwrap();diesel::sql_query("DROP FUNCTION fail_native_profile_source()").execute(&mut conn).await.unwrap();}
        assert!(status.is_server_error(),"failure after ledger and nonce consumption: {error}");assert_eq!(before,business(&fixture).await);
        let (status,out)=post(&fixture,&authority,&key,&original,vec![vote.clone()]).await;assert_eq!(status,StatusCode::OK,"reviewed profile: {out}");let after=business(&fixture).await;assert_eq!(after["reviews"].as_array().unwrap().iter().find(|r|r["request_id"]==request.request_id).unwrap()["status"],"consumed");
        assert_eq!(post(&fixture,&authority,&key,&original,vec![vote]).await.0,StatusCode::OK);assert_eq!(after,business(&fixture).await);
        // Any patch whose materialized postimage stays public needs a new review.
        for patch in [json!({"display_name":"Reviewed display"}),json!({"profile_fields.applet_interaction":{"effective_scope":original.scope_ref,"mode":"public"}}),json!({"profile_fields.applet_interaction.mode":"public"})] {
            let next=profile_update(&original,&authority,&key,patch);let before=business(&fixture).await;let (status,error)=post(&fixture,&authority,&key,&next,vec![]).await;assert!(!status.is_success(),"{error}");assert!(error.to_string().contains("approval_required"),"{error}");assert_eq!(before,business(&fixture).await);
        }
        let pending=profile_update(&original,&authority,&key,json!({"display_name":"Stale postimage"}));let (stale,vote)=approved_profile(&fixture,&install,&pending).await;
        let private=profile_update(&original,&authority,&key,json!({"profile_fields.applet_interaction.mode":"private"}));assert_eq!(post(&fixture,&authority,&key,&private,vec![]).await.0,StatusCode::OK);
        let before=business(&fixture).await;let (status,error)=post(&fixture,&authority,&key,&pending,vec![vote]).await;assert!(!status.is_success(),"stale Profile revision: {error}");assert_eq!(business_without_reviews(before),business_without_reviews(business(&fixture).await));
        let (status,out)=fixture.service_post(&install.package,"/_arkret/self/management-reviews/status",ServiceOperationId::SELF_MANAGEMENT_REVIEW_READ_STATUS_V1,&json!({"request_id":stale.request_id}),"stale-publish-status").await;assert_eq!(status,StatusCode::OK,"{out}");assert_eq!(out["status"],"superseded");
        let reopening=profile_update(&original,&authority,&key,json!({"profile_fields.applet_interaction.mode":"public"}));let (_,vote)=approved_profile(&fixture,&install,&reopening).await;let (status,out)=post(&fixture,&authority,&key,&reopening,vec![vote]).await;assert_eq!(status,StatusCode::OK,"reviewed reopen: {out}");
    })).await.unwrap();
}

#[inline(never)]
fn native_business_parent<'a>(
    fixture: &'a Fixture,
    install: &'a Installed,
    extra: Vec<GrantConstraint>,
    actions: Vec<String>,
    source: Option<arkret_wire::GrantId>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = arkret_wire::GrantId> + Send + 'a>> {
    native_business_parent_in_scope(
        fixture,
        install,
        extra,
        actions,
        source,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
    )
}
#[inline(never)]
fn native_business_parent_in_scope<'a>(
    fixture: &'a Fixture,
    install: &'a Installed,
    extra: Vec<GrantConstraint>,
    actions: Vec<String>,
    source: Option<arkret_wire::GrantId>,
    scope: ScopeRef,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = arkret_wire::GrantId> + Send + 'a>> {
    Box::pin(async move {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraintEffect, GrantConstraintKind, ManagedActorRole,
        };
        let service = ActorId::service(install.package.service_id.clone());
        let mut control = GrantConstraint::new(
            GrantConstraintKind::AuthorityControl,
            GrantConstraintEffect::Allow,
        );
        control.authority_regrant_allowed = Some(source.is_some());
        control.max_authority_depth = Some(if source.is_some() { 1 } else { 0 });
        control.allowed_managed_actor_roles = vec![ManagedActorRole::Bot, ManagedActorRole::Ghost];
        let mut constraints = vec![
            GrantConstraint::applet_authority(
                install.package.applet_id.clone(),
                service.clone(),
                install.package.registration_epoch.clone(),
            ),
            control,
        ];
        constraints.extend(extra);
        let event = fixture.admin_event(
            EventKind::CapabilityGrant,
            scope.clone(),
            json!(CapabilityGrantPayload {
                grant: CapabilityGrantCreateBody {
                    schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                    realm_id: Some(fixture.realm.clone()),
                    issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
                    subject: CapabilitySubject::Actor(service),
                    actions,
                    resources: vec![match &scope {
                        ScopeRef::Circle {
                            realm_id,
                            circle_id,
                        } => {
                            let mut selector = arkret_wire::WireResourceSelector::circle(
                                realm_id.clone(),
                                circle_id.clone(),
                            );
                            selector.match_scope = Some(arkret_wire::ResourceMatchScope::Exact);
                            selector
                        }
                        _ => arkret_wire::WireResourceSelector::realm(fixture.realm.clone()),
                    }],
                    constraints,
                    issuer_authority_refs: match source {
                        Some(grant_id) => vec![IssuerAuthorityRef::Grant { grant_id }],
                        None => vec![IssuerAuthorityRef::RealmRoot {
                            realm_id: fixture.realm.clone(),
                            authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
                            authority_generation: 0
                        }],
                    },
                    issued_at: chrono::Utc::now()
                }
            }),
        );
        let id = arkret_wire::GrantId::from_event_id(&event.event_id);
        accepted_admin_domain_event(fixture, event).await;
        id
    })
}
async fn native_message_parent(
    fixture: &Fixture,
    install: &Installed,
    extra: Vec<GrantConstraint>,
) -> arkret_wire::GrantId {
    native_business_parent(
        fixture,
        install,
        extra,
        vec!["ak.message.create".into()],
        None,
    )
    .await
}
#[inline(never)]
fn native_business_child_with_constraints<'a>(
    fixture: &'a Fixture,
    install: &'a Installed,
    actor: &'a ActorId,
    parents: &'a [arkret_wire::GrantId],
    extra: Vec<GrantConstraint>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = arkret_wire::GrantId> + Send + 'a>> {
    Box::pin(async move {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraintKind, GrantConstraintSubkind,
        };
        let parent_id = &parents[0];
        let rows = fixture
            .state
            .test_persistence()
            .capability_grant_current_results()
            .snapshot_for_realm(&fixture.realm)
            .await
            .unwrap();
        let parent = &rows
            .iter()
            .find(|r| &r.grant_id == parent_id)
            .unwrap()
            .value;
        let mut constraints = parent.constraints.clone();
        for constraint in &mut constraints {
            if constraint.constraint_kind == GrantConstraintKind::AuthorityControl {
                if constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
                    constraint.executed_by = Some(actor.clone());
                } else if constraint.constraint_subkind.is_none() {
                    constraint.authority_regrant_allowed = Some(false);
                    constraint.max_authority_depth = Some(0);
                    constraint.allowed_managed_actor_roles.clear();
                }
            }
        }
        constraints.extend(extra);
        let service = ActorId::service(install.package.service_id.clone());
        let mut event = managed_service_event(
            fixture,
            install,
            &service,
            parent_id,
            EventKind::CapabilityGrant,
            json!(CapabilityGrantPayload {
                grant: CapabilityGrantCreateBody {
                    schema: parent.schema.clone(),
                    realm_id: parent.realm_id.clone(),
                    issuer_id: service.clone(),
                    subject: CapabilitySubject::Actor(actor.clone()),
                    actions: parents
                        .iter()
                        .flat_map(|id| rows
                            .iter()
                            .find(|r| &r.grant_id == id)
                            .unwrap()
                            .value
                            .actions
                            .clone())
                        .collect(),
                    resources: parent.resources.clone(),
                    constraints,
                    issuer_authority_refs: parents
                        .iter()
                        .map(|id| IssuerAuthorityRef::Grant {
                            grant_id: id.clone()
                        })
                        .collect(),
                    issued_at: chrono::Utc::now()
                }
            }),
        );
        if let Some(circle) = parent.resources[0].circle_id.as_ref() {
            event.scope_ref = ScopeRef::Circle {
                realm_id: fixture.realm.clone(),
                circle_id: circle.clone(),
            };
            event.producer_proof = None;
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
            event = authored.into_event();
        }
        let id = arkret_wire::GrantId::from_event_id(&event.event_id);
        assert_managed_accepted(fixture, install, &event).await;
        id
    })
}
async fn native_business_child(
    fixture: &Fixture,
    install: &Installed,
    actor: &ActorId,
    parents: &[arkret_wire::GrantId],
) -> arkret_wire::GrantId {
    native_business_child_with_constraints(fixture, install, actor, parents, vec![]).await
}
async fn native_message_child(
    fixture: &Fixture,
    install: &Installed,
    actor: &ActorId,
    parent_id: &arkret_wire::GrantId,
) -> arkret_wire::GrantId {
    native_business_child(fixture, install, actor, std::slice::from_ref(parent_id)).await
}
fn native_message(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    grant: &arkret_wire::GrantId,
    strand: &arkret_wire::StrandId,
    body: &str,
) -> Event {
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut event=arkret_wire::test_support::raw_event_for_actor_at(EventKind::MessageCreate.as_str(),ScopeRef::Realm{realm_id:fixture.realm.clone()},ActorId::account(authority.account_id.clone()),json!({"strand_id":strand,"track_name":"discussion","content":{"kind":"ak.content.text","format":"plain","body":body}}),now).unwrap();
    event.applet_id = Some(install.package.applet_id.clone());
    event.authorization_ref = Some(grant.clone().into());
    sign_managed_device_event(event, authority, key, now)
}
async fn native_strand(fixture: &Fixture) -> arkret_wire::StrandId {
    let event=fixture.admin_event(EventKind::StrandCreate,ScopeRef::Realm{realm_id:fixture.realm.clone()},json!({"object":{"schema":"ak.schema.strand.v1","realm_id":fixture.realm,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Native Device messages"},"state":"active","created_by":ActorId::account(fixture.pcr.history.account.clone()),"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
    let id = arkret_wire::StrandId::from_event_id(&event.event_id);
    accepted_admin_domain_event(fixture, event).await;
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_messages_use_actual_device_and_share_service_parent_quota_atomically() {
    tokio::spawn(Box::pin(async {
        let fixture=Box::pin(Fixture::new()).await;let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());let native=NativeAppletService::new(&format!("ak:applet:{}",uuid::Uuid::now_v7()),&namespace,&fixture.state.service_core_id());
        let install=Box::pin(fixture.install_package(true,native.package.clone(),&namespace)).await;let ghost=fixture.ghost_body(&install,&namespace,"native-message").await;assert_eq!(fixture.ghost_commit(&install,&ghost,"native-message-ghost").await.0,StatusCode::CREATED);
        let strand=native_strand(&fixture).await;
        let quota:GrantConstraint=serde_json::from_value(json!({"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operations":1,"period":"P1D","constraint_scope":"per_realm"})).unwrap();
        let parent=native_message_parent(&fixture,&install,vec![quota]).await;
        let mut actors=Vec::new();
        for bundle in [install.bot_body["managed_actor_bundle"].clone(),ghost["managed_actor_bundle"].clone()] {
            let actor:ActorId=serde_json::from_value(bundle["managed_actor_provision_event"]["payload"]["actor_id"].clone()).unwrap();let before=business(&fixture).await;
            let child=native_message_child(&fixture,&install,&actor,&parent).await;let after=business(&fixture).await;
            for table in ["quota_counters","quota_buckets","quota_consumptions"] {assert_eq!(before[table],after[table],"issuing a terminal child cannot spend business quota");}
            let key=SigningKey::from_bytes(&[127;32]);let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();
            let authority=authorize_scopes(&fixture,&install,&bundle,&namespace,&key,device,json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read","ak.message.create"]}])).await;
            let unjoined=native_message(&fixture,&install,&authority,&key,&child,&strand,"not yet joined");let before=business(&fixture).await;let (status,error)=post(&fixture,&authority,&key,&unjoined,vec![]).await;assert!(!status.is_success(),"{error}");assert_eq!(before,business(&fixture).await);
            let join=join_event(&fixture,&install,&authority,&key,&install.bot_outcome.authorization_ref);let (status,out)=post(&fixture,&authority,&key,&join,vec![]).await;assert_eq!(status,StatusCode::OK,"{out}");actors.push((authority,key,child));
        }
        let (authority,key,child)=&actors[0];
        for grant in [&parent,&actors[1].2,&install.bot_outcome.authorization_ref] {
            let wrong=native_message(&fixture,&install,authority,key,grant,&strand,"wrong authority source");let before=business(&fixture).await;let (status,error)=post(&fixture,authority,key,&wrong,vec![]).await;assert!(!status.is_success(),"{error}");assert_eq!(before,business(&fixture).await);
        }
        let unknown=arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[0x78;32]));let wrong=native_message(&fixture,&install,authority,key,child,&unknown,"missing actual Strand");let before=business(&fixture).await;assert!(!post(&fixture,authority,key,&wrong,vec![]).await.0.is_success());assert_eq!(before,business(&fixture).await);
        let event=native_message(&fixture,&install,authority,key,child,&strand,"actual native Bot message");
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("CREATE FUNCTION fail_native_message() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'native message current fault'; END $$").execute(&mut conn).await.unwrap();diesel::sql_query("CREATE TRIGGER fail_native_message BEFORE INSERT ON message_revision_current_results FOR EACH ROW EXECUTE FUNCTION fail_native_message()").execute(&mut conn).await.unwrap();}
        let (status,error)=post(&fixture,authority,key,&event,vec![]).await;
        {let mut conn=fixture.pool.get().await.unwrap();diesel::sql_query("DROP TRIGGER fail_native_message ON message_revision_current_results").execute(&mut conn).await.unwrap();diesel::sql_query("DROP FUNCTION fail_native_message()").execute(&mut conn).await.unwrap();}
        assert!(status.is_server_error(),"{error}");assert_eq!(before,business(&fixture).await);
        let (status,out)=post(&fixture,authority,key,&event,vec![]).await;assert_eq!(status,StatusCode::OK,"native Message: {out}");assert_accepted_event(&fixture,&event).await;
        let after=business(&fixture).await;let source=after["quota_counters"].as_array().unwrap().iter().find(|r|r["grant_id"]==parent.as_str()).unwrap();assert_eq!(source["consumed"],1);assert_eq!(after["domain_current"]["messages"].as_array().unwrap().len(),1);
        let record=fixture.state.test_persistence().authority_commits().committed_event(&event.event_id).await.unwrap().unwrap();let fact=fixture.state.test_persistence().authority_commits().account_device_signer_fact(&event,&record.commit).await.unwrap().unwrap();assert_eq!(fact.actor,ActorId::account(authority.account_id.clone()));arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(&event,&fact,fixture.realm.digest_suite_code().digest_suite()).unwrap();
        let (status,out)=post(&fixture,authority,key,&event,vec![]).await;assert_eq!(status,StatusCode::OK,"{out}");assert_eq!(after,business(&fixture).await);
        let (ghost_authority,ghost_key,ghost_child)=&actors[1];let second=native_message(&fixture,&install,ghost_authority,ghost_key,ghost_child,&strand,"same parent shared quota");let (status,error)=post(&fixture,ghost_authority,ghost_key,&second,vec![]).await;assert_eq!(status,StatusCode::TOO_MANY_REQUESTS,"{error}");assert!(error.to_string().contains("rate_limited"),"{error}");assert_eq!(after,business(&fixture).await);
        let rows=fixture.state.test_persistence().capability_grant_current_results().snapshot_for_realm(&fixture.realm).await.unwrap();let current=rows.iter().find(|r|r.grant_id==parent).unwrap();let revoke=fixture.admin_event(EventKind::CapabilityRevoke,event.scope_ref.clone(),json!({"grant_id":parent,"expected_revision":current.revision,"reason":"native source closed"}));accepted_admin_domain_event(&fixture,revoke).await;
        let before=business(&fixture).await;let fresh=native_message(&fixture,&install,authority,key,child,&strand,"closed parent");assert!(!post(&fixture,authority,key,&fresh,vec![]).await.0.is_success());assert_eq!(before,business(&fixture).await);assert_eq!(post(&fixture,authority,key,&event,vec![]).await.0,StatusCode::OK);assert_eq!(before,business(&fixture).await);
    })).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_message_service_and_terminal_grant_reviews_remain_independent() {
    tokio::spawn(Box::pin(async {
        let fixture=Box::pin(Fixture::new()).await;fixture.enable_management_authority();let namespace=format!("bridge.{}",uuid::Uuid::now_v7().simple());let native=NativeAppletService::new(&format!("ak:applet:{}",uuid::Uuid::now_v7()),&namespace,&fixture.state.service_core_id());
        let install=Box::pin(fixture.install_package(true,native.package.clone(),&namespace)).await;let strand=native_strand(&fixture).await;
        let voter=ActorId::account(fixture.pcr.history.account.clone());
        let permission=fixture.admin_event(EventKind::CapabilityGrant,ScopeRef::Realm{realm_id:fixture.realm.clone()},json!(CapabilityGrantPayload{grant:CapabilityGrantCreateBody{schema:arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),realm_id:Some(fixture.realm.clone()),issuer_id:voter.clone(),subject:CapabilitySubject::Actor(voter),actions:vec!["ak.message.create".into()],resources:vec![arkret_wire::WireResourceSelector::realm(fixture.realm.clone())],constraints:vec![],issuer_authority_refs:vec![IssuerAuthorityRef::RealmRoot{realm_id:fixture.realm.clone(),authority_event_ref:fixture.authority_event_ref.clone().unwrap(),authority_generation:0}],issued_at:chrono::Utc::now()}}));
        accepted_admin_domain_event(&fixture,permission).await;
        let required:GrantConstraint=serde_json::from_value(json!({"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"require_review","approval_required":true,"approval_mode":"before_commit","approval_actor_ids":[fixture.pcr.history.account.principal_id],"approval_threshold":1,"timeout":"PT5M"})).unwrap();
        let parent=native_message_parent(&fixture,&install,vec![required]).await;let child=native_message_child(&fixture,&install,&install.bot_outcome.bot_actor_id,&parent).await;
        let key=SigningKey::from_bytes(&[128;32]);let device=DeviceId::new(format!("ak:device:{}",uuid::Uuid::now_v7())).unwrap();let authority=authorize_scopes(&fixture,&install,&install.bot_body["managed_actor_bundle"],&namespace,&key,device,json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read","ak.message.create"]}])).await;
        let join=join_event(&fixture,&install,&authority,&key,&install.bot_outcome.authorization_ref);let (status,out)=post(&fixture,&authority,&key,&join,vec![]).await;assert_eq!(status,StatusCode::OK,"{out}");
        let event=native_message(&fixture,&install,&authority,&key,&child,&strand,"two real grant reviews");let target=ManagementReviewTarget::Event{event:Box::new(event.clone())};
        let parent_vote=creation_operation_vote(&fixture,&target,arkret_wire::ApprovalContext::Grant{grant_id:parent});let child_vote=creation_operation_vote(&fixture,&target,arkret_wire::ApprovalContext::Grant{grant_id:child});
        for votes in [vec![],vec![parent_vote.clone()],vec![child_vote.clone()]] {
            let before=business(&fixture).await;let (status,error)=post(&fixture,&authority,&key,&event,votes).await;assert!(!status.is_success(),"{error}");assert!(error.to_string().contains("approval_required"),"{error}");assert_eq!(before,business(&fixture).await);
        }
        let votes=vec![parent_vote,child_vote];let (status,out)=post(&fixture,&authority,&key,&event,votes.clone()).await;assert_eq!(status,StatusCode::OK,"independent source and terminal approvals: {out}");let after=business(&fixture).await;assert_eq!(post(&fixture,&authority,&key,&event,votes).await.0,StatusCode::OK);assert_eq!(after,business(&fixture).await);
    })).await.unwrap();
}

#[inline(never)]
fn native_phase<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}
struct NativeSourcesContext {
    native: NativeAppletService,
    namespace: String,
    ghost_bundle: Value,
    fixture: Box<Fixture>,
    install: Box<Installed>,
    ghost_actor: ActorId,
    strand: arkret_wire::StrandId,
    ancestor: arkret_wire::GrantId,
    messages: arkret_wire::GrantId,
    reading: arkret_wire::GrantId,
    sibling: arkret_wire::GrantId,
    actors: Vec<(
        coland_storage::AppletManagedDeviceAuthority,
        SigningKey,
        arkret_wire::GrantId,
    )>,
}
async fn native_sources_setup() -> Box<NativeSourcesContext> {
    native_sources_setup_for_history(None).await
}

async fn native_sources_setup_for_history(history: Option<&str>) -> Box<NativeSourcesContext> {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind,
    };

    let mut fixture = Box::new(native_phase(Fixture::new).await);
    if let Some(history) = history {
        native_phase(|| fixture.new_realm_with_history(history)).await;
    }
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        &namespace,
        &fixture.state.service_core_id(),
    );
    let install = Box::new(
        native_phase(|| fixture.install_package(true, native.package.clone(), &namespace)).await,
    );
    let ghost = fixture
        .ghost_body(&install, &namespace, "multi-parent-ghost")
        .await;
    assert_eq!(
        fixture
            .ghost_commit(&install, &ghost, "multi-parent-ghost")
            .await
            .0,
        StatusCode::CREATED
    );
    let strand = native_strand(&fixture).await;
    let quota:GrantConstraint=serde_json::from_value(json!({"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operations":2,"period":"P1D","constraint_scope":"per_actor"})).unwrap();
    let mut control = GrantConstraint::new(
        GrantConstraintKind::AuthorityControl,
        GrantConstraintEffect::Allow,
    );
    control.authority_regrant_allowed = Some(true);
    control.max_authority_depth = Some(2);
    control.allowed_managed_actor_roles = vec![
        arkret_models_collaboration::governance::grant_constraint::ManagedActorRole::Bot,
        arkret_models_collaboration::governance::grant_constraint::ManagedActorRole::Ghost,
    ];
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let original = fixture.admin_event(
        EventKind::CapabilityGrant,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        json!(CapabilityGrantPayload {
            grant: CapabilityGrantCreateBody {
                schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                realm_id: Some(fixture.realm.clone()),
                issuer_id: admin.clone(),
                subject: CapabilitySubject::Actor(admin),
                actions: vec!["ak.message.create".into(), "ak.event.read".into()],
                resources: vec![arkret_wire::WireResourceSelector::realm(
                    fixture.realm.clone()
                )],
                constraints: vec![control, quota.clone()],
                issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                    realm_id: fixture.realm.clone(),
                    authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
                    authority_generation: 0
                }],
                issued_at: chrono::Utc::now()
            }
        }),
    );
    let ancestor = arkret_wire::GrantId::from_event_id(&original.event_id);
    accepted_admin_domain_event(&fixture, original).await;
    let messages = native_business_parent(
        &fixture,
        &install,
        vec![quota.clone()],
        vec!["ak.message.create".into()],
        Some(ancestor.clone()),
    )
    .await;
    let reading = native_business_parent(
        &fixture,
        &install,
        vec![quota.clone()],
        vec!["ak.event.read".into()],
        Some(ancestor.clone()),
    )
    .await;
    let sibling = native_business_parent(
        &fixture,
        &install,
        vec![quota],
        vec!["ak.message.create".into()],
        Some(ancestor.clone()),
    )
    .await;
    let ghost_actor: ActorId = serde_json::from_value(
        ghost["managed_actor_bundle"]["managed_actor_provision_event"]["payload"]["actor_id"]
            .clone(),
    )
    .unwrap();
    let before = business(&fixture).await;
    let ghost_child = native_business_child(
        &fixture,
        &install,
        &ghost_actor,
        &[messages.clone(), reading.clone()],
    )
    .await;
    let bot_child = native_message_child(
        &fixture,
        &install,
        &install.bot_outcome.bot_actor_id,
        &sibling,
    )
    .await;
    let after = business(&fixture).await;
    for table in ["quota_counters", "quota_buckets", "quota_consumptions"] {
        assert_eq!(
            before[table], after[table],
            "issuance must not exercise ancestor business quota"
        );
    }
    let mut actors = Vec::new();
    for (bundle, child, seed) in [
        (&ghost["managed_actor_bundle"], ghost_child, 131),
        (&install.bot_body["managed_actor_bundle"], bot_child, 132),
    ] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        let authority=authorize_scopes(&fixture,&install,bundle,&namespace,&key,device,json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read","ak.message.create"]}])).await;
        let join = join_event(
            &fixture,
            &install,
            &authority,
            &key,
            &install.bot_outcome.authorization_ref,
        );
        let (status, out) = post(&fixture, &authority, &key, &join, vec![]).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        actors.push((authority, key, child));
    }

    Box::new(NativeSourcesContext {
        native,
        namespace,
        ghost_bundle: ghost["managed_actor_bundle"].clone(),
        fixture,
        install,
        ghost_actor,
        strand,
        ancestor,
        messages,
        reading,
        sibling,
        actors,
    })
}
async fn native_sources_exercise(context: Box<NativeSourcesContext>) {
    let (authority, key, child) = &context.actors[0];
    let first = native_message(
        &context.fixture,
        &context.install,
        authority,
        key,
        child,
        &context.strand,
        "real Ghost with split action sources",
    );
    native_phase(|| native_sources_refusals(&context, &first)).await;
    let used = native_phase(|| native_sources_commits(&context, &first)).await;
    native_phase(|| native_sources_exhaustion(&context, &first, &used)).await;
}

async fn native_sources_refusals(context: &NativeSourcesContext, first: &Event) {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind,
    };
    let fixture = &context.fixture;
    let install = &context.install;
    let ghost_actor = context.ghost_actor.clone();
    let messages = context.messages.clone();
    let strand = &context.strand;
    let actors = &context.actors;
    let (authority, key, _) = &actors[0];
    let mut deny = GrantConstraint::new(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Deny,
    );
    deny.denied_strand_ids = vec![strand.to_string()];
    let independent_ancestor = native_unmetered_ancestor(&fixture).await;
    let global_service = native_business_parent(
        &fixture,
        &install,
        vec![deny.clone()],
        vec!["ak.message.create".into()],
        Some(independent_ancestor.clone()),
    )
    .await;
    let before = business(&fixture).await;
    let (status, error) = post(&fixture, authority, key, &first, vec![]).await;
    assert!(!status.is_success(), "{error}");
    assert!(error.to_string().contains("capability_denied"), "{error}");
    assert_eq!(before, business(&fixture).await);
    #[derive(diesel::QueryableByName)]
    struct SavedCurrent {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let saved = {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("DELETE FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2 RETURNING to_jsonb(capability_grant_current_results) AS value")
        .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(independent_ancestor.as_str()).get_result::<SavedCurrent>(&mut conn).await.unwrap()
    };
    let damaged = business(&fixture).await;
    let (status, error) = post(&fixture, authority, key, &first, vec![]).await;
    let unchanged = business(&fixture).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO capability_grant_current_results SELECT * FROM jsonb_populate_record(NULL::capability_grant_current_results,$1)")
        .bind::<diesel::sql_types::Jsonb,_>(saved.value).execute(&mut conn).await.unwrap();
    }
    assert!(
        !status.is_success(),
        "missing global-refusal source cannot disappear: {error}"
    );
    assert_eq!(damaged, unchanged);
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let current = rows.iter().find(|r| r.grant_id == global_service).unwrap();
    accepted_admin_domain_event(&fixture,fixture.admin_event(EventKind::CapabilityRevoke,first.scope_ref.clone(),json!({"grant_id":global_service,"expected_revision":current.revision,"reason":"remove independent Service deny"}))).await;
    let global_account = native_business_child_with_constraints(
        &fixture,
        &install,
        &ghost_actor,
        std::slice::from_ref(&messages),
        vec![deny],
    )
    .await;
    let before = business(&fixture).await;
    let (status, error) = post(&fixture, authority, key, &first, vec![]).await;
    assert!(!status.is_success(), "{error}");
    assert!(error.to_string().contains("capability_denied"), "{error}");
    assert_eq!(before, business(&fixture).await);
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let current = rows.iter().find(|r| r.grant_id == global_account).unwrap();
    let close = managed_service_event(
        &fixture,
        &install,
        &ActorId::service(install.package.service_id.clone()),
        &messages,
        EventKind::CapabilityRevoke,
        json!({"grant_id":global_account,"expected_revision":current.revision,"reason":"remove independent Account deny"}),
    );
    assert_managed_accepted(&fixture, &install, &close).await;
}

async fn native_sources_commits(context: &NativeSourcesContext, first: &Event) -> Value {
    let fixture = &context.fixture;
    let install = &context.install;
    let ghost_actor = context.ghost_actor.clone();
    let strand = &context.strand;
    let ancestor = context.ancestor.clone();
    let messages = context.messages.clone();
    let reading = context.reading.clone();
    let sibling = context.sibling.clone();
    let actors = &context.actors;
    let (authority, key, child) = &actors[0];
    let (status, out) = post(&fixture, authority, key, &first, vec![]).await;
    assert_eq!(status, StatusCode::OK, "real Ghost multi-parent: {out}");
    let record = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&first.event_id)
        .await
        .unwrap()
        .unwrap();
    let fact = fixture
        .state
        .test_persistence()
        .authority_commits()
        .account_device_signer_fact(&first, &record.commit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fact.actor, ghost_actor);
    arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(&first,&fact,fixture.realm.digest_suite_code().digest_suite()).unwrap();
    let accepted = business(&fixture).await;
    assert_eq!(
        post(&fixture, authority, key, &first, vec![]).await.0,
        StatusCode::OK
    );
    assert_eq!(accepted, business(&fixture).await);
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let read = rows.iter().find(|r| r.grant_id == reading).unwrap();
    accepted_admin_domain_event(&fixture,fixture.admin_event(EventKind::CapabilityRevoke,first.scope_ref.clone(),json!({"grant_id":reading,"expected_revision":read.revision,"reason":"close only reading source"}))).await;
    let next = native_message(
        &fixture,
        &install,
        authority,
        key,
        child,
        &strand,
        "unrelated revoked read parent cannot close message authority",
    );
    let (status, out) = post(&fixture, authority, key, &next, vec![]).await;
    assert_eq!(status, StatusCode::OK, "action-local current source: {out}");
    let used = business(&fixture).await;
    let rows = used["quota_counters"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|r| r["grant_id"] == ancestor.as_str() && r["consumed"] == 2)
    );
    assert!(
        rows.iter()
            .any(|r| r["grant_id"] == messages.as_str() && r["consumed"] == 2)
    );
    assert!(
        !rows
            .iter()
            .any(|r| r["grant_id"] == reading.as_str() || r["grant_id"] == sibling.as_str())
    );
    used
}

async fn native_sources_exhaustion(context: &NativeSourcesContext, first: &Event, used: &Value) {
    let fixture = &context.fixture;
    let install = &context.install;
    let strand = &context.strand;
    let ancestor = context.ancestor.clone();
    let actors = &context.actors;
    let (authority, key, _) = &actors[0];
    let (bot, bot_key, bot_child) = &actors[1];
    let refused = native_message(
        &fixture,
        &install,
        bot,
        bot_key,
        bot_child,
        &strand,
        "separate parent still shares original ancestor budget",
    );
    let (status, error) = post(&fixture, bot, bot_key, &refused, vec![]).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{error}");
    assert_eq!(*used, business(&fixture).await);
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let current = rows.iter().find(|r| r.grant_id == ancestor).unwrap();
    accepted_admin_domain_event(&fixture,fixture.admin_event(EventKind::CapabilityRevoke,first.scope_ref.clone(),json!({"grant_id":ancestor,"expected_revision":current.revision,"reason":"close original ancestor"}))).await;
    let before = business(&fixture).await;
    let closed = native_message(
        &fixture,
        &install,
        bot,
        bot_key,
        bot_child,
        &strand,
        "ancestor closed",
    );
    assert!(
        !post(&fixture, bot, bot_key, &closed, vec![])
            .await
            .0
            .is_success()
    );
    assert_eq!(before, business(&fixture).await);
    assert_eq!(
        post(&fixture, authority, key, &first, vec![]).await.0,
        StatusCode::OK
    );
    assert_eq!(before, business(&fixture).await);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_ghost_multi_parent_messages_keep_action_local_sources_and_shared_ancestor_quota() {
    tokio::spawn(native_phase(|| async {
        let context = native_phase(native_sources_setup).await;
        native_phase(|| native_sources_exercise(context)).await;
    }))
    .await
    .unwrap();
}

async fn native_get(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    event: &EventId,
) -> salvo::Response {
    let path = format!("/_arkret/self/committed-events/{event}");
    managed_device_http_request_at(
        &fixture.state,
        authority,
        &managed_device_metadata(authority),
        ServiceOperationId::SelfCommittedEventResourceGetV1,
        key,
        None,
        Some(&path),
    )
    .send(&service(fixture.state.clone()))
    .await
}
async fn native_signer_query(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    selectors: &[arkret_models_identity::SignerKeyQuerySelector],
) -> salvo::Response {
    let body = arkret_models_identity::SignerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        realm_id: fixture.realm.clone(),
        recipient_account_id: authority.account_id.clone(),
        queries: selectors.to_vec(),
    };
    managed_device_http_request_body(
        &fixture.state,
        authority,
        &managed_device_metadata(authority),
        ServiceOperationId::SelfSignerKeysReadResolveV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await
}
async fn native_historical_selector(
    fixture: &Fixture,
    event: &Event,
) -> arkret_models_identity::SignerKeyQuerySelector {
    let persistence = fixture.state.test_persistence();
    let store = persistence.authority_commits();
    let record = store
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let fact = store
        .producer_signer_fact(event, &record.commit)
        .await
        .unwrap()
        .unwrap();
    let committed_event_ref = arkret_wire::CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: record.commit.commit_id,
        stream_ref: record.commit.stream_ref,
        stream_position: record.commit.stream_position,
    };
    let sender = match fact {
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::AccountDevice(fact) =>
            arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                actor: fact.actor, device_id: fact.device_id, verification_method: fact.verification_method, committed_event_ref,
            },
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(fact) =>
            arkret_models_identity::HistoricalSignerKeyQuerySender::Service {
                actor: fact.actor, verification_method: fact.verification_method, committed_event_ref,
            },
    };
    arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent { sender }
}
async fn native_current_revoke(fixture: &Fixture, grant: &arkret_wire::GrantId) {
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let row = rows.iter().find(|r| &r.grant_id == grant).unwrap();
    let event=fixture.admin_event(EventKind::CapabilityRevoke,ScopeRef::Realm{realm_id:fixture.realm.clone()},json!({"grant_id":grant,"expected_revision":row.revision,"reason":"native read source closed"}));
    accepted_admin_domain_event(fixture, event).await;
}
async fn native_read_exercise(context: Box<NativeSourcesContext>) {
    let NativeSourcesContext {
        native: _native,
        fixture,
        install,
        namespace,
        ghost_bundle,
        strand,
        reading,
        messages,
        sibling,
        mut actors,
        ..
    } = *context;
    let mut historical_events = Vec::new();
    for (authority, key, child) in &actors {
        let event = native_message(
            &fixture,
            &install,
            authority,
            key,
            child,
            &strand,
            "original native signer before replacement",
        );
        let (status, outcome) =
            native_phase(|| post(&fixture, authority, key, &event, vec![])).await;
        assert_eq!(status, StatusCode::OK, "{outcome}");
        historical_events.push(event);
    }
    let service_subject = ActorId::account(actors[0].0.account_id.clone());
    let service_child =
        native_phase(|| native_message_child(&fixture, &install, &service_subject, &messages))
            .await;
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let child_row = rows
        .iter()
        .find(|row| row.grant_id == service_child)
        .unwrap();
    let service_original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event_by_commit_id(&child_row.revision.commit_id)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        service_original.event.actual_signer(),
        ActorId::Service { .. }
    ));
    historical_events.push(service_original.event);
    native_phase(|| native_current_revoke(&fixture, &reading)).await;
    for (index, (_, _, child)) in actors.iter().enumerate() {
        let rows = fixture
            .state
            .test_persistence()
            .capability_grant_current_results()
            .snapshot_for_realm(&fixture.realm)
            .await
            .unwrap();
        let current = rows.iter().find(|r| &r.grant_id == child).unwrap();
        let parent = if index == 0 { &messages } else { &sibling };
        let close = managed_service_event(
            &fixture,
            &install,
            &ActorId::service(install.package.service_id.clone()),
            parent,
            EventKind::CapabilityRevoke,
            json!({"grant_id":child,"expected_revision":current.revision,"reason":"member reads need no terminal read child"}),
        );
        native_phase(|| assert_managed_accepted(&fixture, &install, &close)).await;
    }
    let event=fixture.admin_event(EventKind::MessageCreate,ScopeRef::Realm{realm_id:fixture.realm.clone()},json!({"strand_id":strand,"track_name":"discussion","content":{"kind":"ak.content.text","format":"plain","body":"actual member content for independent native readers"}}));
    native_phase(|| accepted_admin_domain_event(&fixture, event.clone())).await;
    historical_events.push(event.clone());
    let mut selectors = Vec::new();
    for original in &historical_events {
        selectors.push(native_historical_selector(&fixture, original).await);
    }
    let mut original_answers = Vec::new();
    for selector in &selectors {
        original_answers.push(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .historical_producer_signer_key(&fixture.realm, selector)
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let read_parent = native_business_parent(
        &fixture,
        &install,
        vec![],
        vec!["ak.event.read".into()],
        None,
    )
    .await;
    let before = business(&fixture).await;
    for (authority, key, _) in &actors {
        let mut response =
            native_phase(|| native_get(&fixture, authority, key, &event.event_id)).await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        let problem = response.take_json::<Value>().await.unwrap();
        assert!(problem.get("event").is_none());
    }
    for (authority, key, _) in &actors {
        let mut response =
            native_phase(|| native_signer_query(&fixture, authority, key, &selectors)).await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        let _: Value = response.take_json().await.unwrap();
    }
    assert_eq!(before, business(&fixture).await);
    for (index, (authority, key, _)) in actors.iter_mut().enumerate() {
        let old = authority.clone();
        let bundle = if index == 0 {
            &ghost_bundle
        } else {
            &install.bot_body["managed_actor_bundle"]
        };
        *authority=native_phase(||authorize_scopes(&fixture,&install,bundle,&namespace,key,old.device_id.clone(),json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read","ak.message.create","ak.object.read_content"]}]))).await;
        let before = business(&fixture).await;
        let mut expired = native_phase(|| native_get(&fixture, &old, key, &event.event_id)).await;
        assert_eq!(expired.status_code, Some(StatusCode::UNAUTHORIZED));
        let _: Value = expired.take_json().await.unwrap();
        assert_eq!(before, business(&fixture).await);
        let mut response =
            native_phase(|| native_get(&fixture, authority, key, &event.event_id)).await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        let _: Value = response.take_json().await.unwrap();
    }
    let content_parent = native_business_parent(
        &fixture,
        &install,
        vec![],
        vec!["ak.object.read_content".into()],
        None,
    )
    .await;
    let before = business(&fixture).await;
    for (authority, key, _) in &actors {
        let mut response =
            native_phase(|| native_get(&fixture, authority, key, &event.event_id)).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let row: arkret_wire::CommittedEventView = response.take_json().await.unwrap();
        assert_eq!(row.reducer_input().unwrap(), &event);
        let unknown = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0xfa; 32]);
        let private = authority.selector.authorization_ref.event_id.clone();
        let mut hidden = Vec::new();
        for id in [unknown, private] {
            let mut response = native_phase(|| native_get(&fixture, authority, key, &id)).await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
            let p: Value = response.take_json().await.unwrap();
            hidden.push((p["type"].clone(), p["title"].clone(), p["detail"].clone()));
        }
        assert_eq!(hidden[0], hidden[1]);
    }
    assert_eq!(before, business(&fixture).await);
    for (authority, key, _) in &actors {
        let mut response =
            native_phase(|| native_signer_query(&fixture, authority, key, &selectors)).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let result: arkret_models_identity::SignerKeysQueryOutcome =
            response.take_json().await.unwrap();
        assert_eq!(result.results.len(), historical_events.len());
        assert_eq!(
            result.results, original_answers,
            "replacement must preserve the original historical authorization instance"
        );
        for ((selector, original), answer) in selectors
            .iter()
            .zip(&historical_events)
            .zip(&result.results)
        {
            assert_eq!(answer.selector(), selector);
            assert!(answer.key().is_some() || answer.service_key().is_some());
            let record = fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&original.event_id)
                .await
                .unwrap()
                .unwrap();
            let fact = fixture
                .state
                .test_persistence()
                .authority_commits()
                .producer_signer_fact(original, &record.commit)
                .await
                .unwrap()
                .unwrap();
            arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
                original, &fact, fixture.realm.digest_suite_code().digest_suite(),
            ).unwrap();
        }
        let arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
            sender:
                arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                    actor,
                    device_id,
                    verification_method,
                    committed_event_ref,
                },
        } = &selectors[0]
        else {
            unreachable!()
        };
        let mut wrong = committed_event_ref.clone();
        wrong.stream_position += 1;
        let probes = vec![
            arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
                sender: arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                    actor: actor.clone(),
                    device_id: device_id.clone(),
                    verification_method: verification_method.clone(),
                    committed_event_ref: wrong,
                },
            },
            arkret_models_identity::SignerKeyQuerySelector::CurrentAdmission {
                sender: arkret_models_identity::CurrentSignerKeyQuerySender::AccountDevice {
                    actor: actor.clone(),
                    device_id: device_id.clone(),
                    verification_method: verification_method.clone(),
                },
            },
        ];
        let mut response =
            native_phase(|| native_signer_query(&fixture, authority, key, &probes)).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let hidden: arkret_models_identity::SignerKeysQueryOutcome =
            response.take_json().await.unwrap();
        assert!(hidden.results.iter().all(|a| matches!(
            a,
            arkret_models_identity::SignerKeyQueryOutcome::Unavailable { .. }
        )));
    }
    for (authority, key, _) in &actors {
        let private_body = arkret_models_identity::SignerKeysQueryRequestBody {
            request_id: arkret_wire::RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            realm_id: authority.pcr_realm_id.clone(),
            recipient_account_id: authority.account_id.clone(),
            queries: vec![
                arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
                    sender: arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                        actor: ActorId::account(authority.account_id.clone()),
                        device_id: authority.device_id.clone(),
                        verification_method: arkret_wire::DidUrl::new(format!(
                            "{}#{}",
                            authority.native_did, authority.device_id
                        ))
                        .unwrap(),
                        committed_event_ref: authority.selector.authorization_ref.clone(),
                    },
                },
            ],
        };
        private_body.validate().unwrap();
        let mut response = managed_device_http_request_body(
            &fixture.state,
            authority,
            &managed_device_metadata(authority),
            ServiceOperationId::SelfSignerKeysReadResolveV1,
            key,
            Some(arkret_canonical::canonical_json_bytes(&private_body).unwrap()),
        )
        .add_header("content-type", "application/json", true)
        .send(&service(fixture.state.clone()))
        .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        let _: Value = response.take_json().await.unwrap();
    }
    assert_eq!(before, business(&fixture).await);
    let (authority, key, _) = &actors[0];
    let mut response =
        native_phase(|| native_signer_query(&fixture, authority, key, &selectors)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let mut close = native_phase(|| native_current_revoke(&fixture, &read_parent));
    native_wait_for_blocked_revoke(&fixture, &mut close).await;
    let result: arkret_models_identity::SignerKeysQueryOutcome =
        response.take_json().await.unwrap();
    assert_eq!(result.results.len(), selectors.len());
    close.await;
    let before = business(&fixture).await;
    for (authority, key, _) in &actors {
        let mut response =
            native_phase(|| native_get(&fixture, authority, key, &event.event_id)).await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        let _: Value = response.take_json().await.unwrap();
    }
    assert_eq!(before, business(&fixture).await);
    let mut response =
        native_phase(|| native_signer_query(&fixture, authority, key, &selectors)).await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    let _: Value = response.take_json().await.unwrap();
    assert_eq!(before, business(&fixture).await);
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind,
    };
    let mut temporal =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    temporal.expires_at = Some(arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(3),
    ));
    let _short = native_business_parent(
        &fixture,
        &install,
        vec![temporal],
        vec!["ak.event.read".into()],
        None,
    )
    .await;
    let mut response = native_phase(|| native_get(&fixture, authority, key, &event.event_id)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let before = business(&fixture).await;
    tokio::time::sleep(std::time::Duration::from_millis(3200)).await;
    assert!(
        response.take_json::<Value>().await.is_err(),
        "expired source cannot hand off prepared bytes"
    );
    assert_eq!(before, business(&fixture).await);
    // Each response is independently prepared while its source is active.
    // A retained delivery cut must not be followed by an awaited request
    // requiring the same PCR nonce writer before the first body is drained.
    let mut temporal =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    temporal.expires_at = Some(arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(3),
    ));
    let _signer_short = native_business_parent(
        &fixture,
        &install,
        vec![temporal],
        vec!["ak.event.read".into()],
        None,
    )
    .await;
    let mut signer_response =
        native_phase(|| native_signer_query(&fixture, authority, key, &selectors)).await;
    assert_eq!(signer_response.status_code, Some(StatusCode::OK));
    let before = business(&fixture).await;
    tokio::time::sleep(std::time::Duration::from_millis(3200)).await;
    assert!(
        signer_response.take_json::<Value>().await.is_err(),
        "expired sources cannot hand off prepared historical facts"
    );
    assert_eq!(before, business(&fixture).await);
    assert_ne!(content_parent, read_parent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_member_event_and_signer_reads_require_actual_sources_through_handoff() {
    tokio::spawn(native_phase(|| async {
        let context = native_phase(native_sources_setup).await;
        native_phase(|| native_read_exercise(context)).await;
    }))
    .await
    .unwrap();
}

async fn native_unmetered_ancestor(fixture: &Fixture) -> arkret_wire::GrantId {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind, ManagedActorRole,
    };
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let mut control = GrantConstraint::new(
        GrantConstraintKind::AuthorityControl,
        GrantConstraintEffect::Allow,
    );
    control.authority_regrant_allowed = Some(true);
    control.max_authority_depth = Some(3);
    control.allowed_managed_actor_roles = vec![ManagedActorRole::Bot, ManagedActorRole::Ghost];
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        json!(CapabilityGrantPayload {
            grant: CapabilityGrantCreateBody {
                schema: arkret_wire::SchemaId::CAPABILITY_V1.into(),
                realm_id: Some(fixture.realm.clone()),
                issuer_id: actor.clone(),
                subject: CapabilitySubject::Actor(actor),
                actions: vec!["ak.message.create".into()],
                resources: vec![arkret_wire::WireResourceSelector::realm(
                    fixture.realm.clone()
                )],
                constraints: vec![control],
                issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                    realm_id: fixture.realm.clone(),
                    authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
                    authority_generation: 0
                }],
                issued_at: chrono::Utc::now()
            }
        }),
    );
    let id = arkret_wire::GrantId::from_event_id(&event.event_id);
    accepted_admin_domain_event(fixture, event).await;
    id
}

async fn native_wait_for_blocked_revoke<F: std::future::Future<Output = ()> + Send>(
    fixture: &Fixture,
    closing: &mut std::pin::Pin<Box<F>>,
) {
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        present: bool,
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        tokio::select! {_=&mut *closing=>panic!("source revoke committed before held content handoff"),_=tokio::time::sleep(std::time::Duration::from_millis(10))=>{}}
        let waiting = {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%realm_authorities%' AND cardinality(pg_blocking_pids(pid))>0) AS present")
                .get_result::<Waiting>(&mut conn).await.unwrap().present
        };
        if waiting {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the actual source writer did not reach its held authority lock"
        );
    }
}

async fn native_scan(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    request: &arkret_wire::StreamScanRequest,
) -> salvo::Response {
    managed_device_http_request_body(
        &fixture.state,
        authority,
        &managed_device_metadata(authority),
        ServiceOperationId::SelfCommittedEventReadScanV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(request).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await
}

async fn native_scan_exercise(context: Box<NativeSourcesContext>) {
    let NativeSourcesContext {
        native: _native,
        namespace,
        ghost_bundle,
        fixture,
        install,
        strand,
        mut actors,
        ..
    } = *context;
    let original = fixture.admin_event(EventKind::MessageCreate,
        ScopeRef::Realm {realm_id: fixture.realm.clone()},
        json!({"strand_id":strand,"track_name":"discussion","content":{"kind":"ak.content.text","format":"plain","body":"native scan content, not an Applet Service delivery"}}));
    native_phase(|| accepted_admin_domain_event(&fixture, original.clone())).await;
    let read_parent = native_business_parent(
        &fixture,
        &install,
        vec![],
        vec!["ak.event.read".into()],
        None,
    )
    .await;
    let request = arkret_wire::StreamScanRequest {
        realm_id: fixture.realm.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 1000,
    };
    let before = business(&fixture).await;
    for (authority, key, _) in &actors {
        let mut response = native_phase(|| native_scan(&fixture, authority, key, &request)).await;
        assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
        let _: Value = response.take_json().await.unwrap();
    }
    assert_eq!(before, business(&fixture).await);
    // Preserve the actual accepted signed Commit. Temporarily remove only
    // its original-pair projection; this is not a new or seeded anchor.
    #[derive(diesel::QueryableByName)]
    struct OriginalPair {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        event_pk: i64,
    }
    let opaque_selector = native_historical_selector(&fixture, &original).await;
    let opaque_selectors = [opaque_selector];
    let original_pair = {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("WITH prior AS (SELECT event_pk FROM realm_commits WHERE realm_id=$1 AND commit_json->>'event_ref'=$2 FOR UPDATE) UPDATE realm_commits c SET event_pk=NULL FROM prior WHERE c.realm_id=$1 AND c.commit_json->>'event_ref'=$2 RETURNING prior.event_pk")
            .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(original.event_id.as_str()).get_result::<OriginalPair>(&mut conn).await.unwrap()
    };
    let before_opaque = business(&fixture).await;
    let mut opaque_results = Vec::new();
    let mut signer_results = Vec::new();
    for (authority, key, _) in &actors {
        let mut response = native_phase(|| native_scan(&fixture, authority, key, &request)).await;
        opaque_results.push((
            response.status_code,
            response
                .take_json::<Value>()
                .await
                .map_err(|error| error.to_string()),
        ));
        let mut response =
            native_phase(|| native_signer_query(&fixture, authority, key, &opaque_selectors)).await;
        signer_results.push((
            response.status_code,
            response
                .take_json::<Value>()
                .await
                .map_err(|error| error.to_string()),
        ));
    }
    let after_opaque = business(&fixture).await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        let restored=diesel::sql_query("UPDATE realm_commits SET event_pk=$1 WHERE realm_id=$2 AND commit_json->>'event_ref'=$3 AND event_pk IS NULL")
            .bind::<diesel::sql_types::BigInt,_>(original_pair.event_pk).bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(original.event_id.as_str()).execute(&mut conn).await.unwrap();
        assert_eq!(restored, 1);
    }
    assert_eq!(before_opaque, after_opaque);
    for (status, body) in opaque_results {
        assert_eq!(
            status,
            Some(StatusCode::FORBIDDEN),
            "unproved current Policy cannot become an empty or opaque allow: {body:?}"
        );
        assert!(body.unwrap().get("committed_events").is_none());
    }
    for (status, body) in signer_results {
        assert_eq!(status, Some(StatusCode::OK), "opaque signer: {body:?}");
        let result: arkret_models_identity::SignerKeysQueryOutcome =
            serde_json::from_value(body.unwrap()).unwrap();
        assert!(matches!(
            &result.results[0],
            arkret_models_identity::SignerKeyQueryOutcome::Unavailable { .. }
        ));
    }
    for (index, (authority, key, _)) in actors.iter_mut().enumerate() {
        let bundle = if index == 0 {
            &ghost_bundle
        } else {
            &install.bot_body["managed_actor_bundle"]
        };
        *authority=native_phase(||authorize_scopes(&fixture,&install,bundle,&namespace,key,authority.device_id.clone(),json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read","ak.message.create","ak.object.read_content"]}]))).await;
        let before = business(&fixture).await;
        let mut response = native_phase(|| native_scan(&fixture, authority, key, &request)).await;
        assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
        let _: Value = response.take_json().await.unwrap();
        assert_eq!(before, business(&fixture).await);
    }
    let _content_parent = native_business_parent(
        &fixture,
        &install,
        vec![],
        vec!["ak.object.read_content".into()],
        None,
    )
    .await;
    let private_scope = native_phase(|| fixture.new_circle_scope()).await;
    let private_head = fixture
        .state
        .test_persistence()
        .authority_commits()
        .stream_head(&request.stream_ref)
        .await
        .unwrap()
        .unwrap();
    let private = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event_by_commit_id(&private_head.commit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(private.event.kind, EventKind::CircleCreate);
    assert_eq!(
        private_scope.circle_id(),
        Some(&arkret_wire::CircleId::from_event_id(
            &private.event.event_id
        ))
    );
    let full_private = arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
        commit: private.commit.clone(),
        event: private.event.clone(),
    });
    let realm_scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let realm_private = full_private
        .clone()
        .into_effective_scope(&realm_scope)
        .unwrap()
        .unwrap();
    assert!(matches!(
        realm_private,
        arkret_wire::CommittedEventView::Withheld(_)
    ));
    assert_eq!(realm_private.commit(), &private.commit);
    assert!(
        serde_json::to_value(&realm_private)
            .unwrap()
            .get("event")
            .is_none()
    );
    assert_eq!(
        full_private
            .clone()
            .into_effective_scope(&private_scope)
            .unwrap()
            .unwrap(),
        full_private
    );
    assert!(
        realm_private
            .into_effective_scope(&private_scope)
            .unwrap()
            .is_none(),
        "scope narrowing must never promote a withheld original"
    );
    let private_selector = native_historical_selector(&fixture, &private.event).await;
    let private_selectors = [private_selector];
    let before = business(&fixture).await;
    let mut last_position = None;
    for (authority, key, _) in &actors {
        let mut response = native_phase(|| native_scan(&fixture, authority, key, &request)).await;
        let status = response.status_code;
        if status != Some(StatusCode::OK) {
            panic!(
                "native scan {status:?}: {}",
                response.take_string().await.unwrap()
            );
        }
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let whole: arkret_wire::StreamScanOutcome = response.take_json().await.unwrap();
        whole.validate_for_request(&request).unwrap();
        assert!(!whole.truncated && !whole.committed_events.is_empty());
        assert!(
            whole
                .committed_events
                .iter()
                .any(|v| v.reducer_input() == Some(&original))
        );
        let withheld = whole
            .committed_events
            .iter()
            .find(|v| v.commit().event_ref == private.event.event_id)
            .unwrap();
        assert!(matches!(
            withheld,
            arkret_wire::CommittedEventView::Withheld(_)
        ));
        assert!(
            serde_json::to_value(withheld)
                .unwrap()
                .get("event")
                .is_none()
        );
        let mut private_response =
            native_phase(|| native_signer_query(&fixture, authority, key, &private_selectors))
                .await;
        assert_eq!(private_response.status_code, Some(StatusCode::OK));
        let private_result: arkret_models_identity::SignerKeysQueryOutcome =
            private_response.take_json().await.unwrap();
        assert!(matches!(
            &private_result.results[0],
            arkret_models_identity::SignerKeyQueryOutcome::Unavailable { .. }
        ));
        let genesis = whole
            .committed_events
            .iter()
            .find_map(|v| {
                v.reducer_input()
                    .filter(|event| event.kind == EventKind::RealmCreate)
            })
            .unwrap();
        assert_eq!(genesis.scope_ref, ScopeRef::RealmGenesis);
        assert_eq!(whole.readable_floor.as_ref().unwrap().oldest_position, 0);
        let mut genesis_response =
            native_phase(|| native_get(&fixture, authority, key, &genesis.event_id)).await;
        assert_eq!(genesis_response.status_code, Some(StatusCode::OK));
        let genesis_view: arkret_wire::CommittedEventView =
            genesis_response.take_json().await.unwrap();
        assert_eq!(genesis_view.reducer_input(), Some(genesis));
        let genesis_selector = native_historical_selector(&fixture, genesis).await;
        let genesis_selectors = [genesis_selector];
        let mut signer_response =
            native_phase(|| native_signer_query(&fixture, authority, key, &genesis_selectors))
                .await;
        assert_eq!(signer_response.status_code, Some(StatusCode::OK));
        let signer_result: arkret_models_identity::SignerKeysQueryOutcome =
            signer_response.take_json().await.unwrap();
        assert!(signer_result.results[0].key().is_some());
        let mut after = None;
        let mut paged = Vec::new();
        loop {
            let small = arkret_wire::StreamScanRequest {
                direction: arkret_wire::StreamScanDirection::After(after),
                limit: 2,
                ..request.clone()
            };
            let mut response = native_phase(|| native_scan(&fixture, authority, key, &small)).await;
            assert_eq!(response.status_code, Some(StatusCode::OK));
            let page: arkret_wire::StreamScanOutcome = response.take_json().await.unwrap();
            page.validate_for_request(&small).unwrap();
            after = page
                .committed_events
                .last()
                .map(|v| v.commit().stream_position)
                .or(after);
            paged.extend(page.committed_events);
            if !page.truncated {
                break;
            }
            assert!(
                paged.len() <= 1000,
                "the actual stream must make bounded progress"
            );
        }
        assert_eq!(
            paged, whole.committed_events,
            "native pagination cannot skip, duplicate or merge positions"
        );
        last_position = after;
        let empty = arkret_wire::StreamScanRequest {
            direction: arkret_wire::StreamScanDirection::After(after),
            ..request.clone()
        };
        let mut response = native_phase(|| native_scan(&fixture, authority, key, &empty)).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let empty_page: arkret_wire::StreamScanOutcome = response.take_json().await.unwrap();
        assert!(empty_page.committed_events.is_empty() && !empty_page.truncated);
        assert_eq!(empty_page.readable_floor, whole.readable_floor);
        let backward = arkret_wire::StreamScanRequest {
            direction: arkret_wire::StreamScanDirection::Before(None),
            ..request.clone()
        };
        let mut response = native_phase(|| native_scan(&fixture, authority, key, &backward)).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let backward_page: arkret_wire::StreamScanOutcome = response.take_json().await.unwrap();
        backward_page.validate_for_request(&backward).unwrap();
        assert_eq!(
            backward_page.committed_events,
            whole.committed_events.into_iter().rev().collect::<Vec<_>>()
        );
        let probes = [
            arkret_wire::StreamScanRequest {
                realm_id: authority.pcr_realm_id.clone(),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: authority.pcr_realm_id.clone(),
                },
                ..request.clone()
            },
            arkret_wire::StreamScanRequest {
                stream_ref: arkret_wire::CommitStreamRef::Circle {
                    realm_id: fixture.realm.clone(),
                    circle_id: arkret_wire::CircleId::from_event_id(&original.event_id),
                },
                ..request.clone()
            },
        ];
        for probe in probes {
            let mut response = native_phase(|| native_scan(&fixture, authority, key, &probe)).await;
            assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
            let problem: Value = response.take_json().await.unwrap();
            assert!(problem.get("committed_events").is_none());
        }
    }
    assert_eq!(before, business(&fixture).await);
    let (authority, key, _) = &actors[0];
    let empty = arkret_wire::StreamScanRequest {
        direction: arkret_wire::StreamScanDirection::After(last_position),
        ..request.clone()
    };
    let mut held = native_phase(|| native_scan(&fixture, authority, key, &empty)).await;
    assert_eq!(held.status_code, Some(StatusCode::OK));
    let mut close = native_phase(|| native_current_revoke(&fixture, &read_parent));
    native_wait_for_blocked_revoke(&fixture, &mut close).await;
    let page: arkret_wire::StreamScanOutcome = held.take_json().await.unwrap();
    assert!(page.committed_events.is_empty());
    close.await;
    let before = business(&fixture).await;
    let mut response = native_phase(|| native_scan(&fixture, authority, key, &empty)).await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let _: Value = response.take_json().await.unwrap();
    assert_eq!(before, business(&fixture).await);
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind,
    };
    let mut temporal =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    temporal.expires_at = Some(arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(3),
    ));
    let _short = native_business_parent(
        &fixture,
        &install,
        vec![temporal],
        vec!["ak.event.read".into()],
        None,
    )
    .await;
    let head = fixture
        .state
        .test_persistence()
        .authority_commits()
        .stream_head(&request.stream_ref)
        .await
        .unwrap()
        .unwrap();
    let empty = arkret_wire::StreamScanRequest {
        direction: arkret_wire::StreamScanDirection::After(Some(head.stream_position)),
        ..empty
    };
    let mut response = native_phase(|| native_scan(&fixture, authority, key, &empty)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let before = business(&fixture).await;
    tokio::time::sleep(std::time::Duration::from_millis(3200)).await;
    assert!(
        response.take_json::<Value>().await.is_err(),
        "expired read sources cannot deliver an empty page or its floor"
    );
    assert_eq!(before, business(&fixture).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_stream_scans_keep_actual_scope_pages_floors_and_final_delivery_current() {
    tokio::spawn(native_phase(|| async {
        let context = native_phase(|| {
            native_sources_setup_for_history(Some("all_history_for_current_members"))
        })
        .await;
        native_phase(|| native_scan_exercise(context)).await;
    }))
    .await
    .unwrap();
}

fn native_circle_event(
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    child: &arkret_wire::GrantId,
    membership: &str,
    parent: Option<Value>,
    expected: Value,
) -> Event {
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let actor = ActorId::account(authority.account_id.clone());
    let mut payload = json!({"circle_id":scope.circle_id().unwrap(),"member_id":actor,"membership":membership,"expected_membership":expected});
    if let Some(parent) = parent {
        payload["parent_membership_revision"] = parent;
    }
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::CircleMemberState.as_str(),
        scope.clone(),
        actor,
        payload,
        now,
    )
    .unwrap();
    event.applet_id = Some(install.package.applet_id.clone());
    event.authorization_ref = Some(child.clone().into());
    sign_managed_device_event(event, authority, key, now)
}

async fn native_circle_snapshot(fixture: &Fixture) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut value = business(fixture).await;
    let mut conn = fixture.pool.get().await.unwrap();
    let rows = diesel::sql_query("SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY circle_id,member_id),'[]'::jsonb) AS value FROM circle_member_state_current_results m").get_result::<Row>(&mut conn).await.unwrap();
    value["circle_members"] = rows.value;
    value
}

async fn native_circle_request(
    fixture: &Fixture,
    install: &Installed,
    request: &ManagementReviewRequestBody,
) -> (StatusCode, Value) {
    fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SelfManagementReviewCommandRequestV1.as_str(),
            &json!(request),
            &format!("circle-request-{}", uuid::Uuid::now_v7()),
        )
        .await
}

async fn native_circle_approve(
    fixture: &Fixture,
    install: &Installed,
    event: &Event,
) -> (ManagementReviewRequestBody, arkret_wire::ApprovalSignature) {
    let request = ManagementReviewRequestBody {
        request_id: format!("native-circle-{}", uuid::Uuid::now_v7()),
        effective_scope: event.scope_ref.clone(),
        management_operation: ManagementOperation::Join,
        requester_actor_id: ActorId::service(install.package.service_id.clone()),
        target: ManagementReviewTarget::Event {
            event: Box::new(event.clone()),
        },
    };
    let before = native_circle_snapshot(fixture).await;
    let (status, pending) = fixture
        .service_post(
            &install.package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SelfManagementReviewCommandRequestV1.as_str(),
            &json!(request),
            &format!("circle-request-{}", uuid::Uuid::now_v7()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "native Circle pending: {pending}");
    assert_eq!(pending["status"], "pending");
    let requested = native_circle_snapshot(fixture).await;
    for field in [
        "quota_counters",
        "quota_buckets",
        "quota_consumptions",
        "approval_audit",
        "events",
        "commits",
        "circle_members",
    ] {
        assert_eq!(
            before[field], requested[field],
            "request must not spend {field}"
        );
    }
    let vote = creation_review_vote(fixture, &request);
    let (status, approved) = fixture.admin_post("/_arkret/self/management-reviews/decisions",ServiceOperationId::SelfManagementReviewCommandDecideV1.as_str(),&json!({"request_id":request.request_id,"expected_status":"pending","decision":"approve","approval_signatures":[vote]}),None).await;
    assert_eq!(status, StatusCode::OK, "native Circle approval: {approved}");
    assert_eq!(approved["status"], "approved");
    (request, vote)
}

fn native_circle_governance_vote(
    fixture: &Fixture,
    event: &Event,
    action: arkret_wire::CapabilityActionId,
) -> arkret_wire::ApprovalSignature {
    let mut vote = creation_operation_vote(
        fixture,
        &ManagementReviewTarget::Event {
            event: Box::new(event.clone()),
        },
        arkret_wire::ApprovalContext::RealmGovernance {},
    );
    vote.input.action = action;
    vote.proof.jws = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        [70; 32],
        vote.proof.verification_method.as_str(),
    )
    .sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote).unwrap(),
    );
    vote
}

async fn native_circle_exercise(context: Box<NativeSourcesContext>) {
    let NativeSourcesContext {
        native: _native,
        namespace,
        ghost_bundle,
        fixture,
        install,
        mut actors,
        ..
    } = *context;
    fixture.enable_management_authority();
    let scope = native_phase(|| fixture.new_circle_scope()).await;
    let circle_id = scope.circle_id().unwrap().clone();
    // Keep the existing Realm installation and both original Realm Devices active.
    native_phase(|| {
        fixture.install_service_with_constraints(
            true,
            install.package.clone(),
            scope.clone(),
            BTreeMap::new(),
        )
    })
    .await;
    let realm_reads = native_business_parent(
        &fixture,
        &install,
        vec![],
        vec!["ak.event.read".into(), "ak.object.read_content".into()],
        None,
    )
    .await;
    let circle_reads = native_business_parent_in_scope(
        &fixture,
        &install,
        vec![],
        vec!["ak.event.read".into(), "ak.object.read_content".into()],
        None,
        scope.clone(),
    )
    .await;
    let quota: GrantConstraint = serde_json::from_value(json!({"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operations":3,"period":"P1D","constraint_scope":"per_actor"})).unwrap();
    native_phase(|| {
        creation_governance_quorum(&fixture, "ak.applet.join", "circle_applet_join", 1)
    })
    .await;
    native_phase(|| {
        creation_governance_quorum(&fixture, "ak.circle.member.add", "circle_domain_join", 1)
    })
    .await;
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let approval_permission = fixture.admin_event(
        EventKind::CapabilityGrant,
        scope.clone(),
        json!(CapabilityGrantPayload {
            grant: CapabilityGrantCreateBody {
                schema: arkret_wire::SchemaId::CAPABILITY_V1.into(),
                realm_id: Some(fixture.realm.clone()),
                issuer_id: admin.clone(),
                subject: CapabilitySubject::Actor(admin.clone()),
                actions: vec!["ak.applet.join".into(), "ak.circle.member.add".into()],
                resources: vec![arkret_wire::WireResourceSelector::circle(
                    fixture.realm.clone(),
                    circle_id.clone()
                )],
                constraints: vec![],
                issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                    realm_id: fixture.realm.clone(),
                    authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
                    authority_generation: 0,
                }],
                issued_at: chrono::Utc::now(),
            }
        }),
    );
    native_phase(|| accepted_admin_domain_event(&fixture, approval_permission)).await;

    let policy_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let policy = fixture.admin_event(EventKind::PolicySet,scope.clone(),json!({"policy_id":policy_id,"expected_revision":null,"value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":fixture.realm,"policy_kind":"applet","default_effect":"allow","created_by":admin,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),"rules":[{"rule_id":"circle_join","kind":"applet","effect":"require_review","applet_target":{"kind":"installation","applet_id":install.package.applet_id,"effective_scope":scope},"applet_operations":["join"],"review_requirement":{"approver_actor_ids":[admin],"threshold":1,"max_age_seconds":3600}}]}}));
    native_phase(|| accepted_admin_domain_event(&fixture, policy)).await;
    let create = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&EventId::from_token_bytes(circle_id.token_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap()
        .event;
    let selector = native_historical_selector(&fixture, &create).await;
    let scan = arkret_wire::StreamScanRequest {
        realm_id: fixture.realm.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Circle {
            realm_id: fixture.realm.clone(),
            circle_id: circle_id.clone(),
        },
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 1000,
    };
    for (index, (realm_device, realm_key, _)) in actors.iter_mut().enumerate() {
        let bundle = if index == 0 {
            &ghost_bundle
        } else {
            &install.bot_body["managed_actor_bundle"]
        };
        *realm_device = native_phase(|| authorize_scopes(&fixture,&install,bundle,&namespace,realm_key,realm_device.device_id.clone(),json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.event.read","ak.message.create","ak.object.read_content"]}]))).await;
        let actor = ActorId::account(realm_device.account_id.clone());
        let parent = native_business_parent_in_scope(
            &fixture,
            &install,
            vec![quota.clone()],
            vec!["ak.circle.member.add".into()],
            None,
            scope.clone(),
        )
        .await;
        let child =
            native_business_child(&fixture, &install, &actor, std::slice::from_ref(&parent)).await;
        let sibling_parent = native_business_parent_in_scope(
            &fixture,
            &install,
            vec![],
            vec!["ak.circle.member.add".into()],
            None,
            scope.clone(),
        )
        .await;
        let sibling_child = native_business_child(
            &fixture,
            &install,
            &actor,
            std::slice::from_ref(&sibling_parent),
        )
        .await;
        let parent_revision =
            ordinary_realm::parent_membership_revision(&fixture.pool, &fixture.realm, &actor).await;
        let key = SigningKey::from_bytes(&[160 + index as u8; 32]);
        let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        let narrow = native_phase(|| authorize_scopes(&fixture,&install,bundle,&namespace,&key,device.clone(),json!([{"effective_scope":scope,"actions":["ak.applet.join","ak.event.read","ak.object.read_content"]}]))).await;
        let original = native_circle_event(
            &install,
            &narrow,
            &key,
            &scope,
            &child,
            "join",
            Some(parent_revision.clone()),
            Value::Null,
        );
        let before = native_circle_snapshot(&fixture).await;
        let (status, error) =
            native_phase(|| post(&fixture, &narrow, &key, &original, vec![])).await;
        assert!(
            !status.is_success(),
            "missing original Circle action: {error}"
        );
        assert_eq!(before, native_circle_snapshot(&fixture).await);
        let authority = native_phase(|| authorize_scopes(&fixture,&install,bundle,&namespace,&key,device,json!([{"effective_scope":scope,"actions":["ak.applet.join","ak.circle.member.add","ak.event.read","ak.object.read_content"]}]))).await;
        let original = native_circle_event(
            &install,
            &authority,
            &key,
            &scope,
            &child,
            "join",
            Some(parent_revision.clone()),
            Value::Null,
        );
        let before = native_circle_snapshot(&fixture).await;
        let (status, error) =
            native_phase(|| post(&fixture, &authority, &key, &original, vec![])).await;
        assert!(
            !status.is_success() && error.to_string().contains("approval_required"),
            "missing independent review: {error}"
        );
        assert_eq!(before, native_circle_snapshot(&fixture).await);
        let mut stale_parent = parent_revision.clone();
        stale_parent["stream_position"] =
            json!(parent_revision["stream_position"].as_u64().unwrap() + 1);
        let stale = native_circle_event(
            &install,
            &authority,
            &key,
            &scope,
            &child,
            "join",
            Some(stale_parent),
            Value::Null,
        );
        let (status, error) =
            native_phase(|| post(&fixture, &authority, &key, &stale, vec![])).await;
        assert!(!status.is_success(), "stale parent must not join: {error}");
        assert_eq!(before, native_circle_snapshot(&fixture).await);
        let stale_request = ManagementReviewRequestBody {
            request_id: format!("stale-circle-{}", uuid::Uuid::now_v7()),
            effective_scope: scope.clone(),
            management_operation: ManagementOperation::Join,
            requester_actor_id: ActorId::service(install.package.service_id.clone()),
            target: ManagementReviewTarget::Event {
                event: Box::new(stale),
            },
        };
        let (status, error) =
            native_phase(|| native_circle_request(&fixture, &install, &stale_request)).await;
        assert!(
            !status.is_success() && error.to_string().contains("failed_precondition"),
            "stale signed parent cannot open a pending Circle review: {error}"
        );
        assert_eq!(before, native_circle_snapshot(&fixture).await);
        let wrong_reference = native_circle_event(
            &install,
            &authority,
            &key,
            &scope,
            &install.bot_outcome.authorization_ref,
            "join",
            Some(parent_revision.clone()),
            Value::Null,
        );
        let (status, error) =
            native_phase(|| post(&fixture, &authority, &key, &wrong_reference, vec![])).await;
        assert!(
            !status.is_success() && !error.to_string().contains("approval_required"),
            "an installation ref cannot replace the real Circle child: {error}"
        );
        assert_eq!(before, native_circle_snapshot(&fixture).await);
        let (request, vote) =
            native_phase(|| native_circle_approve(&fixture, &install, &original)).await;
        let join_governance = native_circle_governance_vote(
            &fixture,
            &original,
            arkret_wire::CapabilityActionId::AppletJoin,
        );
        let domain_governance = native_circle_governance_vote(
            &fixture,
            &original,
            arkret_wire::CapabilityActionId::CircleMemberAdd,
        );
        let votes = vec![
            vote.clone(),
            join_governance.clone(),
            domain_governance.clone(),
        ];
        let before = native_circle_snapshot(&fixture).await;
        for partial in [
            vec![vote.clone()],
            vec![vote.clone(), join_governance.clone()],
            vec![vote.clone(), domain_governance.clone()],
            vec![join_governance, domain_governance],
        ] {
            let (status, error) =
                native_phase(|| post(&fixture, &authority, &key, &original, partial)).await;
            assert!(
                !status.is_success() && error.to_string().contains("approval_required"),
                "management, Applet join governance and actual Circle governance are independent: {error}"
            );
            assert_eq!(before, native_circle_snapshot(&fixture).await);
        }
        #[derive(diesel::QueryableByName)]
        struct SavedSource {
            #[diesel(sql_type=diesel::sql_types::Jsonb)]
            value: Value,
        }
        let saved_source = {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("DELETE FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2 RETURNING to_jsonb(capability_grant_current_results) AS value")
                .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(sibling_parent.as_str()).get_result::<SavedSource>(&mut conn).await.unwrap().value
        };
        let (status, error) =
            native_phase(|| post(&fixture, &authority, &key, &original, votes.clone())).await;
        {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("INSERT INTO capability_grant_current_results SELECT * FROM jsonb_populate_record(NULL::capability_grant_current_results,$1)").bind::<diesel::sql_types::Jsonb,_>(saved_source).execute(&mut conn).await.unwrap();
        }
        assert!(
            !status.is_success() && error.to_string().contains("revision_unavailable"),
            "an unproved independent Account source cannot disappear behind the selected child: {error}"
        );
        assert_eq!(before, native_circle_snapshot(&fixture).await);
        {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("CREATE FUNCTION fail_native_circle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'native Circle fault'; END $$").execute(&mut conn).await.unwrap();
            diesel::sql_query("CREATE TRIGGER fail_native_circle BEFORE INSERT ON circle_member_state_current_results FOR EACH ROW EXECUTE FUNCTION fail_native_circle()").execute(&mut conn).await.unwrap();
        }
        let (status, error) =
            native_phase(|| post(&fixture, &authority, &key, &original, votes.clone())).await;
        {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query(
                "DROP TRIGGER fail_native_circle ON circle_member_state_current_results",
            )
            .execute(&mut conn)
            .await
            .unwrap();
            diesel::sql_query("DROP FUNCTION fail_native_circle()")
                .execute(&mut conn)
                .await
                .unwrap();
        }
        assert!(
            status.is_server_error(),
            "real Circle writer rollback: {error}"
        );
        assert_eq!(before, native_circle_snapshot(&fixture).await);
        let (status, accepted) =
            native_phase(|| post(&fixture, &authority, &key, &original, votes.clone())).await;
        assert_eq!(status, StatusCode::OK, "native Circle accepted: {accepted}");
        let after = native_circle_snapshot(&fixture).await;
        for grant in [&parent, &child] {
            let counter = after["quota_counters"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["grant_id"] == grant.as_str())
                .unwrap();
            assert_eq!(
                counter["consumed"], 1,
                "the selected child and original Service holder each spend once"
            );
        }
        assert!(
            !after["quota_counters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["grant_id"] == sibling_parent.as_str()
                    || row["grant_id"] == sibling_child.as_str())
        );
        let row = after["reviews"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["request_id"] == request.request_id)
            .unwrap();
        assert_eq!(row["status"], "consumed");
        let (status, replay) =
            native_phase(|| post(&fixture, &authority, &key, &original, votes.clone())).await;
        assert_eq!(status, StatusCode::OK, "native Circle replay: {replay}");
        assert_eq!(accepted["commit"], replay["commit"]);
        assert_eq!(replay["status"], "duplicate");
        assert_eq!(after, native_circle_snapshot(&fixture).await);
        // Same Account, two real Devices: exact Circle proof is not Realm proof.
        let mut response =
            native_phase(|| native_get(&fixture, &authority, &key, &create.event_id)).await;
        let status = response.status_code;
        let value = response.take_json::<Value>().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "Circle original: {value}");
        let full: arkret_wire::CommittedEventView = serde_json::from_value(value).unwrap();
        assert_eq!(full.reducer_input(), Some(&create));
        let join_selector = native_historical_selector(&fixture, &original).await;
        let expected_join_key = fixture
            .state
            .test_persistence()
            .authority_commits()
            .historical_producer_signer_key(&fixture.realm, &join_selector)
            .await
            .unwrap()
            .unwrap();
        let mut joined_key_response = native_phase(|| {
            native_signer_query(
                &fixture,
                &authority,
                &key,
                std::slice::from_ref(&join_selector),
            )
        })
        .await;
        assert_eq!(joined_key_response.status_code, Some(StatusCode::OK));
        let joined_key: arkret_models_identity::SignerKeysQueryOutcome =
            joined_key_response.take_json().await.unwrap();
        assert_eq!(joined_key.results[0], expected_join_key);

        let mut response =
            native_phase(|| native_get(&fixture, realm_device, realm_key, &create.event_id)).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let withheld: arkret_wire::CommittedEventView = response.take_json().await.unwrap();
        assert!(matches!(
            withheld,
            arkret_wire::CommittedEventView::Withheld(_)
        ));
        assert_eq!(withheld.commit(), full.commit());
        let mut response = native_phase(|| {
            native_signer_query(&fixture, &authority, &key, std::slice::from_ref(&selector))
        })
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let fact: arkret_models_identity::SignerKeysQueryOutcome =
            response.take_json().await.unwrap();
        assert!(!matches!(
            fact.results[0],
            arkret_models_identity::SignerKeyQueryOutcome::Unavailable { .. }
        ));
        let mut response = native_phase(|| {
            native_signer_query(
                &fixture,
                realm_device,
                realm_key,
                std::slice::from_ref(&selector),
            )
        })
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let fact: arkret_models_identity::SignerKeysQueryOutcome =
            response.take_json().await.unwrap();
        assert!(matches!(
            fact.results[0],
            arkret_models_identity::SignerKeyQueryOutcome::Unavailable { .. }
        ));
        let mut response = native_phase(|| native_scan(&fixture, &authority, &key, &scan)).await;
        let status = response.status_code;
        let value = response.take_json::<Value>().await.unwrap();
        assert_eq!(
            status,
            Some(StatusCode::OK),
            "Circle independent stream: {value}"
        );
        let page: arkret_wire::StreamScanOutcome = serde_json::from_value(value).unwrap();
        page.validate_for_request(&scan).unwrap();
        assert!(
            page.committed_events
                .iter()
                .any(|v| v.reducer_input() == Some(&original))
        );
        assert!(
            page.committed_events
                .iter()
                .all(|v| v.commit().stream_ref == scan.stream_ref)
        );
        // A missing projection after a real accepted join must never prove absence.
        #[derive(diesel::QueryableByName)]
        struct Saved {
            #[diesel(sql_type=diesel::sql_types::Jsonb)]
            value: Value,
        }
        let saved = {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("DELETE FROM circle_member_state_current_results WHERE realm_id=$1 AND circle_id=$2 AND member_id=$3 RETURNING to_jsonb(circle_member_state_current_results) AS value")
                .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(circle_id.as_str()).bind::<diesel::sql_types::Text,_>(actor.to_string()).get_result::<Saved>(&mut conn).await.unwrap().value
        };
        let duplicate = native_circle_event(
            &install,
            &authority,
            &key,
            &scope,
            &child,
            "join",
            Some(parent_revision.clone()),
            Value::Null,
        );
        let pending = ManagementReviewRequestBody {
            request_id: format!("missing-circle-{}", uuid::Uuid::now_v7()),
            effective_scope: scope.clone(),
            management_operation: ManagementOperation::Join,
            requester_actor_id: ActorId::service(install.package.service_id.clone()),
            target: ManagementReviewTarget::Event {
                event: Box::new(duplicate),
            },
        };
        let (status, error) =
            native_phase(|| native_circle_request(&fixture, &install, &pending)).await;
        {
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("INSERT INTO circle_member_state_current_results SELECT * FROM jsonb_populate_record(NULL::circle_member_state_current_results,$1)").bind::<diesel::sql_types::Jsonb,_>(saved).execute(&mut conn).await.unwrap();
        }
        assert!(
            !status.is_success() && error.to_string().contains("revision_unavailable"),
            "lost Circle current is not first join: {error}"
        );
        assert_eq!(after, native_circle_snapshot(&fixture).await);
        let leave = native_circle_event(
            &install,
            &authority,
            &key,
            &scope,
            &child,
            "leave",
            None,
            json!("join"),
        );
        let (status, out) = native_phase(|| {
            post(
                &fixture,
                &authority,
                &key,
                &leave,
                vec![native_circle_governance_vote(
                    &fixture,
                    &leave,
                    arkret_wire::CapabilityActionId::CircleMemberAdd,
                )],
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "leave uses domain action, not join review: {out}"
        );
        let rejoin = native_circle_event(
            &install,
            &authority,
            &key,
            &scope,
            &child,
            "join",
            Some(parent_revision),
            json!("leave"),
        );
        let (_, vote) = native_phase(|| native_circle_approve(&fixture, &install, &rejoin)).await;
        let (status, out) = native_phase(|| {
            post(
                &fixture,
                &authority,
                &key,
                &rejoin,
                vec![
                    vote,
                    native_circle_governance_vote(
                        &fixture,
                        &rejoin,
                        arkret_wire::CapabilityActionId::AppletJoin,
                    ),
                    native_circle_governance_vote(
                        &fixture,
                        &rejoin,
                        arkret_wire::CapabilityActionId::CircleMemberAdd,
                    ),
                ],
            )
        })
        .await;
        assert_eq!(status, StatusCode::OK, "reviewed Circle rejoin: {out}");
        let exhausted = native_circle_event(
            &install,
            &authority,
            &key,
            &scope,
            &child,
            "leave",
            None,
            json!("join"),
        );
        let before = native_circle_snapshot(&fixture).await;
        let (status, error) =
            native_phase(|| post(&fixture, &authority, &key, &exhausted, vec![])).await;
        assert!(
            !status.is_success() && error.to_string().contains("rate_limited"),
            "original quota is spent once for join, leave and rejoin: {error}"
        );
        assert_eq!(before, native_circle_snapshot(&fixture).await);
    }
    let _ = (realm_reads, circle_reads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_circle_join_review_and_original_reads_keep_two_device_scopes_separate() {
    tokio::spawn(Box::pin(async {
        let context = native_phase(native_sources_setup).await;
        native_phase(|| native_circle_exercise(context)).await;
    }))
    .await
    .unwrap();
}
