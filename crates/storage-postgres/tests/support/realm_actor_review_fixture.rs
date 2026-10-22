// Included in realm_native_fixture. Actual current RealmActor approvals, never the
// retired Account/PCR aggregate. Transport nonces are independent from business audit.
use arkret_wire::DeviceId;

fn realm_review_vote(
    fixture: &Fixture,
    event: &Event,
    context: arkret_wire::ApprovalContext,
    action: arkret_wire::CapabilityActionId,
) -> arkret_wire::ApprovalSignature {
    use arkret_wire::*;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let key = SigningKey::from_bytes(&[70; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let method = DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
    let mut vote = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: context,
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(arkret_canonical::canonical_sha256(event).unwrap())
                .unwrap(),
            operation: ServiceOperationId::SelfEventsCommandSubmitV1
                .as_str()
                .into(),
            action,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actual_signer().clone(),
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
    vote.proof.jws =
        arkret_signatures::Ed25519DetachedJwsSigner::from_seed([70; 32], method.as_str())
            .sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)
                    .unwrap(),
            );
    vote
}

async fn realm_review_open_and_approve(
    fixture: &Fixture,
    package: &AppletPackage,
    event: &Event,
    effective_scope: ScopeRef,
    operation: arkret_wire::ManagementOperation,
    action: arkret_wire::CapabilityActionId,
) -> (
    arkret_models_integration::ManagementReviewRequestBody,
    arkret_wire::ApprovalSignature,
) {
    use arkret_models_integration::{ManagementReviewRequestBody, ManagementReviewTarget};
    use arkret_wire::{ApprovalContext, ServiceOperationId};
    let request = ManagementReviewRequestBody {
        configuration_ref: None,
        request_id: format!("realm-native-review-{}", uuid::Uuid::now_v7()),
        effective_scope,
        management_operation: operation,
        requester_actor_id: ActorId::service(package.service_id.clone()),
        target: ManagementReviewTarget::Event {
            event: Box::new(event.clone()),
        },
    };
    request.validate().unwrap();
    let (status, pending) = fixture
        .service_post(
            package,
            "/_arkret/self/management-reviews/requests",
            ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_REQUEST_V1,
            &json!(request),
            &format!("review-request-{}", uuid::Uuid::now_v7()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Service review request: {pending}"
    );
    assert_eq!(pending["status"], "pending");
    let material = fixture
        .state
        .test_persistence()
        .agents()
        .management_review_material(&request.requester_actor_id, &request.request_id, &[])
        .await
        .unwrap();
    assert_eq!(
        material
            .request
            .target
            .canonical_target_digest()
            .unwrap()
            .as_str(),
        arkret_canonical::canonical_sha256(event).unwrap()
    );
    assert_eq!(json!(material.request.target), json!(request.target));
    let vote = realm_review_vote(
        fixture,
        event,
        ApprovalContext::Management {
            request_id: request.request_id.clone(),
            management_operation: operation,
            effective_scope: request.effective_scope.clone(),
        },
        action,
    );
    let (status, approved) = fixture.admin_post(
        "/_arkret/self/management-reviews/decisions",
        ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,
        &json!({"request_id":request.request_id,"expected_status":"pending","decision":"approve","approval_signatures":[vote.clone()]}),
        Some(request.request_id.as_str()),
    ).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Account approval: {approved}"
    );
    assert_eq!(approved["status"], "approved");
    (request, vote)
}

async fn realm_review_footprint(fixture: &Fixture) -> Value {
    use diesel::sql_types::Jsonb;
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    let mut before = native_business_footprint(fixture).await;
    let mut conn = fixture.pool.get().await.unwrap();
    for table in [
        "event_approval_private_audit",
        "applet_installations",
        "capability_grant_current_results",
        "agent_producer_signer_keys",
    ] {
        let row = diesel::sql_query(format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"
        )).get_result::<Row>(&mut conn).await.unwrap();
        before
            .as_object_mut()
            .unwrap()
            .insert(table.to_owned(), row.value);
    }
    before
}

fn realm_review_submission(
    event: &Event,
    votes: &[arkret_wire::ApprovalSignature],
) -> arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest {
    let mut submission = arkret_wire::EventAdmissionSubmission::new(event.clone());
    if !votes.is_empty() {
        submission.approval_signatures = Some(votes.to_vec());
    }
    arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(submission)
}

struct RealmReviewFixture {
    factory: AppletAuthoringFactory,
    _native: NativeService,
    _governor: NetworkStation,
    package: AppletPackage,
    installation: Value,
    registration: Event,
}

async fn realm_review_setup(pool: PgPool) -> Box<RealmReviewFixture> {
    let (fixture, governor) = boxed_step(|| network_fixture(pool)).await;
    let factory = AppletAuthoringFactory {
        fixture,
        packages: Default::default(),
        scopes: Default::default(),
    };
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut native = NativeService::new(&id, &factory.fixture.state.service_core_id());
    native
        .package
        .requested_scopes
        .push("ak.applet.publish".into());
    native.package.requested_scopes.sort();
    let method = native
        .package
        .proof
        .as_ref()
        .unwrap()
        .verification_method
        .clone();
    let did = arkret_identity::verification_method_did(method.as_str()).unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed([13; 32], did, method.clone());
    native
        .package
        .stamp_registration_epoch(&applet_registration_epoch_evidence(&native.package))
        .unwrap();
    native.package.stamp_package_digest().unwrap();
    native.package.sign(&signer, &method).unwrap();
    factory
        .packages
        .lock()
        .await
        .insert(id.to_string(), native.package.clone());
    let install = boxed_step(|| factory.prepare_install(&id, "realm-review-current")).await;
    let outcome = boxed_step(|| commit_install_http(&factory.fixture, &install)).await;
    let store = PgAppletStore {
        pool: factory.fixture.pool.clone(),
    };
    let installation = store
        .get(
            id.as_str(),
            &coland_storage::applet_effective_scope_key(&install.effective_scope).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let registration: Event =
        serde_json::from_value(installation["registration_event"].clone()).unwrap();
    assert_eq!(registration.event_id, outcome.registration_event_ref);
    let package = serde_json::from_value(installation["package"].clone()).unwrap();
    Box::new(RealmReviewFixture {
        factory,
        _native: native,
        _governor: governor,
        package,
        installation,
        registration,
    })
}

fn realm_review_install_grant(context: &RealmReviewFixture, action: &str) -> Event {
    serde_json::from_value(
        context.installation["capability_grant_events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| {
                event["payload"]["grant"]["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item == action)
            })
            .unwrap()
            .clone(),
    )
    .unwrap()
}

async fn realm_review_admin_event(
    fixture: &Fixture,
    event: Event,
) -> coland_storage::CommittedEventRecord {
    let request = realm_review_submission(&event, &[]);
    let (status, result) = fixture
        .admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(request),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual review prerequisite: {result}"
    );
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.event, event);
    original
}

async fn realm_review_voter_permission(fixture: &Fixture) -> arkret_wire::GrantId {
    let account = ActorId::account(fixture.pcr.history.account.clone());
    let event = fixture.admin_event(EventKind::CapabilityGrant, ScopeRef::Realm { realm_id: fixture.realm.clone() }, json!({"grant": {
        "schema":"ak.schema.capability.v1","realm_id":fixture.realm,"issuer_id":account,"subject":account,
        "actions":["ak.realm.admin","ak.message.create"],"resources":[{"kind":"realm","realm_id":fixture.realm,"match_scope":"realm_wide"}],"constraints":[],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,"authority_event_ref":fixture.authority_event_ref,"authority_generation":0}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }}));
    let id = arkret_wire::GrantId::from_event_id(&event.event_id);
    boxed_step(|| realm_review_admin_event(fixture, event)).await;
    id
}

async fn realm_review_policy(fixture: &Fixture, operations: &[&str]) {
    let id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let account = ActorId::account(fixture.pcr.history.account.clone());
    let event = fixture.admin_event(EventKind::PolicySet, ScopeRef::Realm { realm_id:fixture.realm.clone() }, json!({
        "policy_id":id,"expected_revision":null,"value":{"schema":"ak.schema.policy.v1","id":id,"realm_id":fixture.realm,
        "policy_kind":"applet","default_effect":"allow","created_by":account,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "rules":[{"rule_id":"current_realm_review","kind":"applet","effect":"require_review","applet_target":{"kind":"all"},"applet_operations":operations,
            "review_requirement":{"approver_actor_ids":[account],"threshold":1,"max_age_seconds":3600}}]}
    }));
    boxed_step(|| realm_review_admin_event(fixture, event)).await;
}

async fn realm_review_governance(fixture: &Fixture, action: &str) {
    use arkret_models_collaboration::events_payloads::{
        PolicyActionDocument, PolicyActionStatePayload,
    };
    let payload = PolicyActionStatePayload {
        policy_id: None,
        action_id: Some(
            arkret_wire::RealmPolicyActionId::new(format!(
                "review_{}",
                uuid::Uuid::now_v7().simple()
            ))
            .unwrap(),
        ),
        value: PolicyActionDocument {
            action: arkret_wire::PolicyActionName::new(action).unwrap(),
            approval_required: true,
            approval_quorum: 1,
            policy_scope: fixture.realm.to_string(),
        },
    };
    let event = fixture.admin_event(
        EventKind::PolicyAction,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        json!(payload),
    );
    boxed_step(|| realm_review_admin_event(fixture, event)).await;
}

fn realm_review_required(fixture: &Fixture) -> GrantConstraint {
    serde_json::from_value(json!({"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"require_review","approval_required":true,
        "approval_mode":"before_commit","approval_actor_ids":[fixture.pcr.history.account.principal_id],"approval_threshold":1,"timeout":"PT5M"})).unwrap()
}

async fn realm_review_creation_grant(
    context: &RealmReviewFixture,
    action: &str,
    with_review: bool,
) -> arkret_wire::GrantId {
    let original = realm_review_install_grant(context, action);
    let mut payload: CapabilityGrantPayload =
        serde_json::from_value(json!(original.payload)).unwrap();
    payload.grant.constraints.push(serde_json::from_value(json!({"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operations":1,"period":"P1D","constraint_scope":"per_realm"})).unwrap());
    if with_review {
        payload
            .grant
            .constraints
            .push(realm_review_required(&context.factory.fixture));
    }
    payload.grant.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let event = context.factory.fixture.admin_event(
        EventKind::CapabilityGrant,
        original.scope_ref,
        json!(payload),
    );
    let id = arkret_wire::GrantId::from_event_id(&event.event_id);
    boxed_step(|| realm_review_admin_event(&context.factory.fixture, event)).await;
    id
}

fn realm_review_candidate(
    context: &RealmReviewFixture,
    grant: &arkret_wire::GrantId,
    bot: bool,
) -> (RealmActorCreatePayload, Ed25519PayloadSigner) {
    authority_admission_candidate(
        &context.package,
        &context.factory.fixture,
        &context.registration.event_id,
        grant,
        bot,
    )
}

fn realm_review_create_event(
    candidate: &RealmActorCreatePayload,
    signer: &Ed25519PayloadSigner,
) -> Event {
    arkret::author_realm_actor_create(
        candidate.clone(),
        arkret_canonical::DigestSuite::Sha256,
        candidate.control_signature.created_at,
        signer,
    )
    .unwrap()
}

fn realm_review_resign_service_original(context: &RealmReviewFixture, mut event: Event) -> Event {
    event.producer_proof = None;
    let at = event.created_at;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&context.package.webhook_auth.key_ref),
        applet_service_did(&context.package),
        context.package.webhook_auth.key_ref.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let event = authored.into_event();
    let proof = event.producer_proof.as_ref().unwrap();
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(&event)
        .unwrap();
    let key = applet_service_signing_key(&context.package.webhook_auth.key_ref);
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    event
}

async fn realm_review_service_submit(
    context: &RealmReviewFixture,
    event: &Event,
    votes: &[arkret_wire::ApprovalSignature],
) -> (StatusCode, Value) {
    context
        .factory
        .fixture
        .service_post(
            &context.package,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(realm_review_submission(event, votes)),
            &format!("review-submit-{}", uuid::Uuid::now_v7()),
        )
        .await
}

fn realm_review_assert_required(status: StatusCode, problem: &Value) {
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "current review refusal: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/claim_required"
    );
    assert_eq!(problem["reason_code"], "approval_required");
}

async fn realm_review_assert_consumed(
    fixture: &Fixture,
    request: &arkret_models_integration::ManagementReviewRequestBody,
    event: &Event,
) {
    let material = fixture
        .state
        .test_persistence()
        .agents()
        .management_review_material(&request.requester_actor_id, &request.request_id, &[])
        .await
        .unwrap();
    assert_eq!(json!(material.request.target), json!(request.target));
    assert_eq!(
        material.outcome.status,
        arkret_models_integration::ManagementReviewStatus::Consumed
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, *event);
}

async fn realm_review_creation_case(pool: PgPool, bot: bool) {
    use arkret_wire::{ApprovalContext, CapabilityActionId as Action, ManagementOperation};
    let context = boxed_step(|| realm_review_setup(pool)).await;
    let fixture = &context.factory.fixture;
    boxed_step(|| realm_review_voter_permission(fixture)).await;
    let action = if bot {
        Action::AppletBotProvision
    } else {
        Action::AppletGhostProvision
    };
    let operation = if bot {
        ManagementOperation::CreateBot
    } else {
        ManagementOperation::MapGhost
    };
    let grant = boxed_step(|| realm_review_creation_grant(&context, action.as_str(), true)).await;
    let (candidate, signer) = realm_review_candidate(&context, &grant, bot);
    let event = realm_review_create_event(&candidate, &signer);
    // Keep a genuinely valid Service signature while corrupting only the
    // candidate's independent control possession. No retired bundle is built.
    let mut corrupt = event.clone();
    corrupt.payload.get_mut("control_signature").unwrap()["sig"] =
        json!(arkret_canonical::base64url_encode([0_u8; 64]));
    let corrupt = realm_review_resign_service_original(&context, corrupt);
    let bad_candidate: RealmActorCreatePayload =
        serde_json::from_value(json!(corrupt.payload)).unwrap();
    assert!(
        arkret_identity::verify_realm_actor_initial_resolution(&bad_candidate, corrupt.created_at)
            .is_err()
    );
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, problem) =
        boxed_step(|| realm_review_service_submit(&context, &corrupt, &[])).await;
    assert!(
        status.is_client_error(),
        "a valid Service signature cannot repair invalid native control possession: {problem}"
    );
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, before);
    let reviewed_operations = [if bot { "create_bot" } else { "map_ghost" }];
    boxed_step(|| realm_review_policy(fixture, &reviewed_operations)).await;
    boxed_step(|| realm_review_governance(fixture, action.as_str())).await;
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| realm_review_service_submit(&context, &event, &[])).await;
    realm_review_assert_required(status, &problem);
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, before);
    let (request, management) = boxed_step(|| {
        realm_review_open_and_approve(
            fixture,
            &context.package,
            &event,
            candidate.creation_scope.clone(),
            operation,
            action,
        )
    })
    .await;
    let grant_vote = realm_review_vote(
        fixture,
        &event,
        ApprovalContext::Grant {
            grant_id: grant.clone(),
        },
        action,
    );
    let governance =
        realm_review_vote(fixture, &event, ApprovalContext::RealmGovernance {}, action);
    let approved = boxed_step(|| realm_review_footprint(fixture)).await;
    let mut changed = event.clone();
    changed.created_at += chrono::Duration::milliseconds(1);
    let changed = realm_review_resign_service_original(&context, changed);
    assert_ne!(changed.event_id, event.event_id);
    let changed_votes = vec![management.clone(), grant_vote.clone()];
    let (status, problem) =
        boxed_step(|| realm_review_service_submit(&context, &changed, &changed_votes)).await;
    assert!(
        status.is_client_error(),
        "approval for a prior exact signed Event must not approve another valid Service original: {problem}"
    );
    assert_eq!(
        boxed_step(|| realm_review_footprint(fixture)).await,
        approved
    );
    for votes in [
        vec![management.clone()],
        vec![grant_vote.clone()],
        vec![management.clone(), governance],
    ] {
        let (status, problem) =
            boxed_step(|| realm_review_service_submit(&context, &event, &votes)).await;
        realm_review_assert_required(status, &problem);
        assert_eq!(
            boxed_step(|| realm_review_footprint(fixture)).await,
            approved,
            "one approval domain must not replace another"
        );
    }
    let votes = vec![management, grant_vote];
    use diesel_async::SimpleAsyncConnection as _;
    for table in [
        "realm_actor_private_signer_facts",
        "applet_authoring_completions",
    ] {
        {
            let mut conn = fixture.pool.get().await.unwrap();
            conn.batch_execute(&format!("CREATE FUNCTION test_realm_review_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'actual approved RealmActor writer failure'; END $$; CREATE TRIGGER test_realm_review_failure BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION test_realm_review_failure();")).await.unwrap();
        }
        let (status, problem) =
            boxed_step(|| realm_review_service_submit(&context, &event, &votes)).await;
        {
            let mut conn = fixture.pool.get().await.unwrap();
            conn.batch_execute(&format!("DROP TRIGGER test_realm_review_failure ON {table}; DROP FUNCTION test_realm_review_failure();")).await.unwrap();
        }
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "approved writer {table}: {problem}"
        );
        assert_eq!(
            boxed_step(|| realm_review_footprint(fixture)).await,
            approved,
            "review/audit nonce/quota/current/Commit must all roll back"
        );
    }
    let (status, result) =
        boxed_step(|| realm_review_service_submit(&context, &event, &votes)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "complete current creation approval: {result}"
    );
    boxed_step(|| realm_review_assert_consumed(fixture, &request, &event)).await;
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let after = boxed_step(|| realm_review_footprint(fixture)).await;
    assert!(
        after["capability_quota_counters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["grant_id"] == json!(grant) && row["consumed"] == 1),
        "only the accepted creation spends the one-operation quota"
    );
    let (status, result) =
        boxed_step(|| realm_review_service_submit(&context, &event, &votes)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact approved create retry: {result}"
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit,
        accepted.commit
    );
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, after);
}

pub(super) async fn run_reviews(pool: PgPool) {
    boxed_step(|| realm_review_creation_case(pool.clone(), true)).await;
    {
        let database =
            boxed_step(coland_storage_postgres::test_database::TestDatabase::lease).await;
        boxed_step(|| realm_review_creation_case(database.pool(), false)).await;
    }
    {
        let database =
            boxed_step(coland_storage_postgres::test_database::TestDatabase::lease).await;
        boxed_step(|| realm_review_governance_only_creation(database.pool())).await;
    }
    {
        let database =
            boxed_step(coland_storage_postgres::test_database::TestDatabase::lease).await;
        boxed_step(|| realm_review_join_case(database.pool())).await;
    }
    {
        let database =
            boxed_step(coland_storage_postgres::test_database::TestDatabase::lease).await;
        boxed_step(|| realm_review_profile_case(database.pool())).await;
    }
    {
        let database =
            boxed_step(coland_storage_postgres::test_database::TestDatabase::lease).await;
        boxed_step(|| realm_review_message_case(database.pool())).await;
    }
}

async fn realm_review_governance_only_creation(pool: PgPool) {
    use arkret_wire::{ApprovalContext, CapabilityActionId};
    let context = boxed_step(|| realm_review_setup(pool)).await;
    let fixture = &context.factory.fixture;
    let grant =
        boxed_step(|| realm_review_creation_grant(&context, "ak.applet.bot.provision", true)).await;
    let (candidate, signer) = realm_review_candidate(&context, &grant, true);
    let event = realm_review_create_event(&candidate, &signer);
    boxed_step(|| realm_review_governance(fixture, "ak.applet.bot.provision")).await;
    let governance = realm_review_vote(
        fixture,
        &event,
        ApprovalContext::RealmGovernance {},
        CapabilityActionId::AppletBotProvision,
    );
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    for votes in [vec![], vec![governance]] {
        let (status, problem) =
            boxed_step(|| realm_review_service_submit(&context, &event, &votes)).await;
        realm_review_assert_required(status, &problem);
        assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, before);
    }
    // A qualifying grant-context vote may also satisfy the governance
    // tightening requirement on that exact dependency; no Management ledger
    // or extra administrator interaction is invented for an allow Policy.
    let votes = vec![realm_review_vote(
        fixture,
        &event,
        ApprovalContext::Grant { grant_id: grant },
        CapabilityActionId::AppletBotProvision,
    )];
    // Realm ownership, membership, and the Service's accepted provision grant
    // do not constitute the explicit current RealmAdmin approver authority.
    // Keep the candidate, signature action, vote nonce and target unchanged.
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, problem) =
        boxed_step(|| realm_review_service_submit(&context, &event, &votes)).await;
    realm_review_assert_required(status, &problem);
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, before);
    let permission = boxed_step(|| realm_review_voter_permission(fixture)).await;
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, result) =
        boxed_step(|| realm_review_service_submit(&context, &event, &votes)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "grant approval without a management ledger: {result}"
    );
    let after = boxed_step(|| realm_review_footprint(fixture)).await;
    assert_eq!(
        after["management_review_requests"],
        before["management_review_requests"]
    );
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.event, event);
    let (status, result) =
        boxed_step(|| realm_review_service_submit(&context, &event, &votes)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same approved original without management ledger: {result}"
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit,
        original.commit
    );
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, after);

    // A fresh original has its own unused creation quota. Removing only the
    // approver's authority must make its already signed vote ineligible, and
    // restoring real RealmAdmin must admit that same original and vote.
    let grant =
        boxed_step(|| realm_review_creation_grant(&context, "ak.applet.bot.provision", true)).await;
    let (candidate, signer) = realm_review_candidate(&context, &grant, true);
    let fresh = realm_review_create_event(&candidate, &signer);
    assert_ne!(fresh.actor_id, event.actor_id);
    assert_ne!(fresh.payload["request_id"], event.payload["request_id"]);
    let votes = vec![realm_review_vote(
        fixture,
        &fresh,
        ApprovalContext::Grant { grant_id: grant },
        CapabilityActionId::AppletBotProvision,
    )];
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let current = rows.iter().find(|row| row.grant_id == permission).unwrap();
    let revoke = fixture.admin_event(
        EventKind::CapabilityRevoke,
        ScopeRef::Realm { realm_id: fixture.realm.clone() },
        json!({"grant_id":permission,"expected_revision":current.revision,"reason":"current approver qualification withdrawn"}),
    );
    boxed_step(|| realm_review_admin_event(fixture, revoke)).await;
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, problem) =
        boxed_step(|| realm_review_service_submit(&context, &fresh, &votes)).await;
    realm_review_assert_required(status, &problem);
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, before);
    boxed_step(|| realm_review_voter_permission(fixture)).await;
    let (status, result) =
        boxed_step(|| realm_review_service_submit(&context, &fresh, &votes)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same original and vote after restoring current RealmAdmin: {result}"
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&fresh.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        fresh
    );
}

async fn realm_review_current_actor(
    context: &RealmReviewFixture,
) -> (
    RealmActorCreatePayload,
    coland_storage::CommittedEventRecord,
    DeviceId,
) {
    let grant =
        boxed_step(|| realm_review_creation_grant(context, "ak.applet.ghost.provision", false))
            .await;
    let (candidate, signer) = realm_review_candidate(context, &grant, false);
    let event = realm_review_create_event(&candidate, &signer);
    let (status, outcome) = boxed_step(|| realm_review_service_submit(context, &event, &[])).await;
    assert_eq!(status, StatusCode::OK, "actual review subject: {outcome}");
    let original = context
        .factory
        .fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.event, event);
    let device = boxed_step(|| {
        authorize_device_with_actions(
            &context.factory.fixture,
            &candidate,
            &original.commit,
            79,
            &["ak.applet.join", "ak.event.read", "ak.message.create"],
        )
    })
    .await;
    (candidate, original, device)
}

fn realm_review_signed_event(
    context: &RealmReviewFixture,
    candidate: &RealmActorCreatePayload,
    device: Option<&DeviceId>,
    kind: EventKind,
    scope: ScopeRef,
    payload: Value,
    grant: Option<&arkret_wire::GrantId>,
) -> Event {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        scope,
        candidate.actor_id.clone(),
        payload,
        at,
    )
    .unwrap();
    event.applet_id = Some(context.package.applet_id.clone());
    event.authorization_ref = grant.cloned().map(Into::into);
    let method = match device {
        Some(device) => {
            DidUrl::new(format!("{}#{}", candidate.initial_resolution.did, device)).unwrap()
        }
        None => candidate.control_method_kid.clone(),
    };
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(if device.is_some() {
            &[79; 32]
        } else {
            &[33; 32]
        }),
        candidate.initial_resolution.did.clone(),
        method,
    );
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    authored.into_event()
}

fn realm_review_join_event(
    context: &RealmReviewFixture,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
) -> Event {
    let source = realm_review_install_grant(context, "ak.applet.join");
    let grant = arkret_wire::GrantId::from_event_id(&source.event_id);
    realm_review_signed_event(
        context,
        candidate,
        Some(device),
        EventKind::MemberState,
        candidate.creation_scope.clone(),
        json!({"member_id":candidate.actor_id,"membership":"join"}),
        Some(&grant),
    )
}

async fn realm_review_device_submit(
    context: &RealmReviewFixture,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
    event: &Event,
    votes: Vec<arkret_wire::ApprovalSignature>,
) -> (StatusCode, Value) {
    let fixture = &context.factory.fixture;
    let authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, device, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let metadata = arkret_models_integration::AppletManagedDeviceMetadata {
        actor_id: candidate.actor_id.clone(),
        device_id: device.clone(),
        authorization_event_id: authority.authorization_ref.event_id,
        applet_id: candidate.applet_id.clone(),
        effective_scope: event.scope_ref.clone(),
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    managed_device_post(
        fixture,
        &metadata,
        &DidUrl::new(format!("did:key:{fingerprint}#{fingerprint}")).unwrap(),
        "/_arkret/self/events",
        arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
        &json!(realm_review_submission(event, &votes)),
        &[79; 32],
    )
    .await
}

async fn realm_review_join_case(pool: PgPool) {
    use arkret_wire::{ApprovalContext, CapabilityActionId, ManagementOperation};
    let context = boxed_step(|| realm_review_setup(pool)).await;
    let fixture = &context.factory.fixture;
    let (candidate, _, device) = boxed_step(|| realm_review_current_actor(&context)).await;
    let event = realm_review_join_event(&context, &candidate, &device);
    boxed_step(|| realm_review_policy(fixture, &["join"])).await;
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, problem) =
        boxed_step(|| realm_review_device_submit(&context, &candidate, &device, &event, vec![]))
            .await;
    realm_review_assert_required(status, &problem);
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, before);
    let (request, vote) = boxed_step(|| {
        realm_review_open_and_approve(
            fixture,
            &context.package,
            &event,
            candidate.creation_scope.clone(),
            ManagementOperation::Join,
            CapabilityActionId::AppletJoin,
        )
    })
    .await;
    let approved = boxed_step(|| realm_review_footprint(fixture)).await;
    let unrecorded = realm_review_vote(
        fixture,
        &event,
        ApprovalContext::Management {
            request_id: request.request_id.clone(),
            management_operation: ManagementOperation::Join,
            effective_scope: candidate.creation_scope.clone(),
        },
        CapabilityActionId::AppletJoin,
    );
    let (status, problem) = boxed_step(|| {
        realm_review_device_submit(&context, &candidate, &device, &event, vec![unrecorded])
    })
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a correctly signed unrecorded vote must not expose the private ledger: {problem}"
    );
    assert_eq!(
        boxed_step(|| realm_review_footprint(fixture)).await,
        approved
    );
    use diesel_async::SimpleAsyncConnection as _;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute("CREATE FUNCTION test_realm_join_review_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'reviewed native membership writer failure'; END $$; CREATE TRIGGER test_realm_join_review_failure BEFORE INSERT ON member_state_current_results FOR EACH ROW EXECUTE FUNCTION test_realm_join_review_failure();").await.unwrap();
    }
    let (status, problem) = boxed_step(|| {
        realm_review_device_submit(&context, &candidate, &device, &event, vec![vote.clone()])
    })
    .await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute("DROP TRIGGER test_realm_join_review_failure ON member_state_current_results; DROP FUNCTION test_realm_join_review_failure();").await.unwrap();
    }
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "reviewed native membership writer: {problem}"
    );
    assert_eq!(
        boxed_step(|| realm_review_footprint(fixture)).await,
        approved
    );
    let (status, result) = boxed_step(|| {
        realm_review_device_submit(&context, &candidate, &device, &event, vec![vote.clone()])
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual approved Device join: {result}"
    );
    boxed_step(|| realm_review_assert_consumed(fixture, &request, &event)).await;
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let after = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, result) = boxed_step(|| {
        realm_review_device_submit(&context, &candidate, &device, &event, vec![vote])
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact reviewed join retry: {result}"
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit,
        accepted.commit
    );
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, after);
}

fn realm_review_profile_update(
    context: &RealmReviewFixture,
    candidate: &RealmActorCreatePayload,
    original: &coland_storage::CommittedEventRecord,
    profile_id: &arkret_wire::ActorProfileId,
    patch: Value,
) -> Event {
    realm_review_signed_event(
        context,
        candidate,
        None,
        EventKind::ProfileUpdate,
        ScopeRef::RealmControl {
            realm_id: context.factory.fixture.realm.clone(),
        },
        json!({"target_ref":profile_id,"patch":patch,"expected_revision":{"commit_id":original.commit.commit_id,"stream_position":original.commit.stream_position}}),
        None,
    )
}

async fn realm_review_control_submit(
    context: &RealmReviewFixture,
    candidate: &RealmActorCreatePayload,
    creation: &coland_storage::CommittedEventRecord,
    event: &Event,
    votes: Vec<arkret_wire::ApprovalSignature>,
) -> (StatusCode, Value) {
    realm_profile_post(
        &context.factory.fixture,
        candidate,
        &creation.commit,
        &realm_review_submission(event, &votes),
    )
    .await
}

async fn realm_review_profile_case(pool: PgPool) {
    use arkret_wire::{CapabilityActionId, ManagementOperation};
    let context = boxed_step(|| realm_review_setup(pool)).await;
    let fixture = &context.factory.fixture;
    let (candidate, creation, device) = boxed_step(|| realm_review_current_actor(&context)).await;
    let join = realm_review_join_event(&context, &candidate, &device);
    let (status, result) =
        boxed_step(|| realm_review_device_submit(&context, &candidate, &device, &join, vec![]))
            .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Profile subject membership: {result}"
    );
    // realm-actors §3 binds this private control Profile to the complete
    // subject, and managed-governance §5 restricts the reserved intent to a
    // business scope in that subject's Realm. These are genuine current
    // control signatures; no Service, Account Profile, or public transition
    // approval is involved in either negative.
    let foreign_realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [192; 32],
    ));
    assert_ne!(foreign_realm, fixture.realm);
    let wrong_subject = ActorId::realm(arkret_wire::RealmActorId::new(
        foreign_realm.clone(),
        candidate.actor_id.signing_principal_id().clone(),
    ));
    assert_eq!(
        wrong_subject.signing_principal_id(),
        candidate.actor_id.signing_principal_id(),
        "same native principal must not erase the subject's Realm component"
    );
    assert_ne!(wrong_subject, candidate.actor_id);
    let mut wrong_profile = vec![json!({"object":{
        "actor_id":wrong_subject,"actor_kind":"integration","display_name":"Wrong complete subject"
    }})];
    for scope in [
        ScopeRef::Realm {
            realm_id: foreign_realm,
        },
        ScopeRef::RealmControl {
            realm_id: fixture.realm.clone(),
        },
    ] {
        let reserved = arkret_models_identity::AppletInteractionIntent {
            effective_scope: scope,
            mode: arkret_models_identity::AppletInteractionMode::Private,
        };
        // It is a structurally valid SDK reserved member, so the production
        // subject/business-scope validator is the boundary being exercised.
        let _: arkret_models_identity::AppletInteractionIntent =
            serde_json::from_value(json!(reserved)).unwrap();
        wrong_profile.push(json!({"object":{
            "actor_id":candidate.actor_id,"actor_kind":"integration","display_name":"Wrong reserved intent scope",
            "profile_fields":{"applet_interaction":reserved}
        }}));
    }
    for payload in wrong_profile {
        let event = realm_review_signed_event(
            &context,
            &candidate,
            None,
            EventKind::ProfileCreate,
            ScopeRef::RealmControl {
                realm_id: fixture.realm.clone(),
            },
            payload,
            None,
        );
        assert_eq!(event.actor_id, candidate.actor_id);
        let before = boxed_step(|| realm_review_footprint(fixture)).await;
        let (status, problem) = boxed_step(|| {
            realm_review_control_submit(&context, &candidate, &creation, &event, vec![])
        })
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "control Profile complete subject / reserved scope: {problem}"
        );
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/failed_precondition"
        );
        assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, before);
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
    }
    let private = realm_review_signed_event(
        &context,
        &candidate,
        None,
        EventKind::ProfileCreate,
        ScopeRef::RealmControl {
            realm_id: fixture.realm.clone(),
        },
        json!({"object":{"actor_id":candidate.actor_id,"actor_kind":"integration","display_name":"Current private Profile"}}),
        None,
    );
    let profile_id = arkret_wire::ActorProfileId::from_event_id(&private.event_id);
    let (status, result) = boxed_step(|| {
        realm_review_control_submit(&context, &candidate, &creation, &private, vec![])
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual control-signed private Profile: {result}"
    );
    let current = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&private.event_id)
        .await
        .unwrap()
        .unwrap();
    boxed_step(|| realm_review_policy(fixture, &["publish"])).await;
    let make_public = |current: &coland_storage::CommittedEventRecord| {
        realm_review_profile_update(
            &context,
            &candidate,
            current,
            &profile_id,
            json!({"profile_fields.applet_interaction":{"effective_scope":candidate.creation_scope,"mode":"public"}}),
        )
    };
    let stale = make_public(&current);
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, problem) =
        boxed_step(|| realm_review_control_submit(&context, &candidate, &creation, &stale, vec![]))
            .await;
    realm_review_assert_required(status, &problem);
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, before);
    let (_, stale_vote) = boxed_step(|| {
        realm_review_open_and_approve(
            fixture,
            &context.package,
            &stale,
            candidate.creation_scope.clone(),
            ManagementOperation::Publish,
            CapabilityActionId::AppletPublish,
        )
    })
    .await;
    let updated = realm_review_profile_update(
        &context,
        &candidate,
        &current,
        &profile_id,
        json!({"display_name":"Private metadata may change without publish approval"}),
    );
    let (status, result) = boxed_step(|| {
        realm_review_control_submit(&context, &candidate, &creation, &updated, vec![])
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "private maintenance remains valid: {result}"
    );
    let updated_current = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&updated.event_id)
        .await
        .unwrap()
        .unwrap();
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, problem) = boxed_step(|| {
        realm_review_control_submit(&context, &candidate, &creation, &stale, vec![stale_vote])
    })
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "stale reviewed Profile must preserve exact postimage revision: {problem}"
    );
    let mut after = boxed_step(|| realm_review_footprint(fixture)).await;
    let mut business_before = before;
    business_before
        .as_object_mut()
        .unwrap()
        .remove("management_review_requests");
    after
        .as_object_mut()
        .unwrap()
        .remove("management_review_requests");
    assert_eq!(
        business_before, after,
        "stale review cannot mutate Profile/Commit/approval nonce"
    );
    let public = make_public(&updated_current);
    let (request, vote) = boxed_step(|| {
        realm_review_open_and_approve(
            fixture,
            &context.package,
            &public,
            candidate.creation_scope.clone(),
            ManagementOperation::Publish,
            CapabilityActionId::AppletPublish,
        )
    })
    .await;
    let approved = boxed_step(|| realm_review_footprint(fixture)).await;
    use diesel_async::SimpleAsyncConnection as _;
    for table in [
        "realm_actor_current_results",
        "realm_actor_private_signer_facts",
    ] {
        {
            let mut conn = fixture.pool.get().await.unwrap();
            conn.batch_execute(&format!("CREATE FUNCTION test_realm_publish_review_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'reviewed control Profile writer failure'; END $$; CREATE TRIGGER test_realm_publish_review_failure BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION test_realm_publish_review_failure();")).await.unwrap();
        }
        let (status, problem) = boxed_step(|| {
            realm_review_control_submit(
                &context,
                &candidate,
                &creation,
                &public,
                vec![vote.clone()],
            )
        })
        .await;
        {
            let mut conn = fixture.pool.get().await.unwrap();
            conn.batch_execute(&format!("DROP TRIGGER test_realm_publish_review_failure ON {table}; DROP FUNCTION test_realm_publish_review_failure();")).await.unwrap();
        }
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "reviewed publish {table}: {problem}"
        );
        assert_eq!(
            boxed_step(|| realm_review_footprint(fixture)).await,
            approved,
            "publish/source failure must roll back review and its nonce"
        );
    }
    let (status, result) = boxed_step(|| {
        realm_review_control_submit(&context, &candidate, &creation, &public, vec![vote.clone()])
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual reviewed public transition: {result}"
    );
    boxed_step(|| realm_review_assert_consumed(fixture, &request, &public)).await;
    let after = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, result) = boxed_step(|| {
        realm_review_control_submit(&context, &candidate, &creation, &public, vec![vote])
    })
    .await;
    assert_eq!(status, StatusCode::OK, "exact publish original: {result}");
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, after);
    let public_current = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&public.event_id)
        .await
        .unwrap()
        .unwrap();
    let display = realm_review_profile_update(
        &context,
        &candidate,
        &public_current,
        &profile_id,
        json!({"display_name":"Same public scope is ordinary Profile maintenance"}),
    );
    let (status, result) = boxed_step(|| {
        realm_review_control_submit(&context, &candidate, &creation, &display, vec![])
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same public scope display must not invent a new publish transition: {result}"
    );
}

fn realm_review_service_event(
    context: &RealmReviewFixture,
    kind: EventKind,
    payload: Value,
    grant: &arkret_wire::GrantId,
) -> Event {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        ScopeRef::Realm {
            realm_id: context.factory.fixture.realm.clone(),
        },
        ActorId::service(context.package.service_id.clone()),
        payload,
        at,
    )
    .unwrap();
    event.applet_id = Some(context.package.applet_id.clone());
    event.authorization_ref = Some(grant.clone().into());
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&context.package.webhook_auth.key_ref),
        applet_service_did(&context.package),
        context.package.webhook_auth.key_ref.clone(),
    );
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    authored.into_event()
}

async fn realm_review_message_grants(
    context: &RealmReviewFixture,
    candidate: &RealmActorCreatePayload,
) -> (arkret_wire::GrantId, arkret_wire::GrantId) {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind, ManagedActorRole,
    };
    let fixture = &context.factory.fixture;
    let service = ActorId::service(context.package.service_id.clone());
    let mut control = GrantConstraint::new(
        GrantConstraintKind::AuthorityControl,
        GrantConstraintEffect::Allow,
    );
    control.authority_regrant_allowed = Some(false);
    control.max_authority_depth = Some(0);
    control.allowed_managed_actor_roles = vec![ManagedActorRole::Bot, ManagedActorRole::Ghost];
    let quota: GrantConstraint=serde_json::from_value(json!({"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operations":1,"period":"P1D","constraint_scope":"per_realm"})).unwrap();
    let parent = CapabilityGrantCreateBody {
        schema: arkret_wire::SchemaId::CAPABILITY_V1.into(),
        realm_id: Some(fixture.realm.clone()),
        issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
        subject: CapabilitySubject::Actor(service.clone()),
        actions: vec!["ak.message.create".into()],
        resources: vec![arkret_wire::WireResourceSelector::realm(
            fixture.realm.clone(),
        )],
        constraints: vec![
            GrantConstraint::applet_authority(
                context.package.applet_id.clone(),
                service.clone(),
                context.package.registration_epoch.clone(),
            ),
            control,
            realm_review_required(fixture),
            quota,
        ],
        issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
            realm_id: fixture.realm.clone(),
            authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
            authority_generation: 0,
        }],
        issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    };
    let parent_event = fixture.admin_event(
        EventKind::CapabilityGrant,
        candidate.creation_scope.clone(),
        json!(CapabilityGrantPayload {
            grant: parent.clone()
        }),
    );
    let parent_id = arkret_wire::GrantId::from_event_id(&parent_event.event_id);
    boxed_step(|| realm_review_admin_event(fixture, parent_event)).await;
    let mut child = parent;
    child.issuer_id = service;
    child.subject = CapabilitySubject::Actor(candidate.actor_id.clone());
    child.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
        grant_id: parent_id.clone(),
    }];
    child.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    for constraint in &mut child.constraints {
        if constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
            constraint.executed_by = Some(candidate.actor_id.clone());
        } else if constraint.constraint_kind == GrantConstraintKind::AuthorityControl {
            constraint.allowed_managed_actor_roles.clear();
        }
    }
    let event = realm_review_service_event(
        context,
        EventKind::CapabilityGrant,
        json!(CapabilityGrantPayload { grant: child }),
        &parent_id,
    );
    let child_id = arkret_wire::GrantId::from_event_id(&event.event_id);
    let request = AppletEventTransactionRequestBody {
        applet_id: context.package.applet_id.clone(),
        source_id: context.package.service_id.clone(),
        events: vec![event.clone()],
        committed_events: vec![],
        signals: vec![],
    };
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    let (status, result) = fixture
        .service_post(
            &context.package,
            "/_arkret/edge/applet/transactions",
            arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            &json!(request),
            "current-reviewed-message-terminal-child",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual approval-constrained terminal child: {result}"
    );
    let result: AppletTransactionOutcome = serde_json::from_value(result).unwrap();
    assert_eq!(result.status(), AppletTransactionStatus::Accepted);
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        event
    );
    let after = boxed_step(|| realm_review_footprint(fixture)).await;
    for table in [
        "capability_quota_counters",
        "capability_quota_buckets",
        "capability_quota_consumptions",
        "event_approval_private_audit",
    ] {
        assert_eq!(
            before[table], after[table],
            "issuing terminal authority must not spend its future Message approval or quota"
        );
    }
    (parent_id, child_id)
}

async fn realm_review_message_case(pool: PgPool) {
    use arkret_wire::{ApprovalContext, CapabilityActionId};
    let context = boxed_step(|| realm_review_setup(pool)).await;
    let fixture = &context.factory.fixture;
    let (candidate, _, device) = boxed_step(|| realm_review_current_actor(&context)).await;
    boxed_step(|| realm_review_voter_permission(fixture)).await;
    let join = realm_review_join_event(&context, &candidate, &device);
    let (status, result) =
        boxed_step(|| realm_review_device_submit(&context, &candidate, &device, &join, vec![]))
            .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Message subject membership: {result}"
    );
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let mut strand=fixture.admin_event(EventKind::StrandCreate,candidate.creation_scope.clone(),json!({"object":{
        "schema":"ak.schema.strand.v1","realm_id":fixture.realm,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Independent current grant approvals"},"state":"active","created_by":admin,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }}));
    strand.payload.get_mut("object").unwrap()["created_at"] = json!(
        arkret_canonical::format_timestamp_canonical(strand.created_at)
    );
    strand = fixture.sign_admin(strand);
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.event_id);
    boxed_step(|| realm_review_admin_event(fixture, strand)).await;
    let (parent, child) = boxed_step(|| realm_review_message_grants(&context, &candidate)).await;
    let event = realm_review_signed_event(
        &context,
        &candidate,
        Some(&device),
        EventKind::MessageCreate,
        candidate.creation_scope.clone(),
        json!(arkret::MessageCreatePayload::with_content(
            strand_id,
            "discussion",
            arkret::ContentBlock::text(
                "One actual Device, two independent grant approval contexts"
            )
        )),
        Some(&child),
    );
    let parent_vote = realm_review_vote(
        fixture,
        &event,
        ApprovalContext::Grant { grant_id: parent },
        CapabilityActionId::MessageCreate,
    );
    let child_vote = realm_review_vote(
        fixture,
        &event,
        ApprovalContext::Grant { grant_id: child },
        CapabilityActionId::MessageCreate,
    );
    let before = boxed_step(|| realm_review_footprint(fixture)).await;
    for votes in [vec![], vec![parent_vote.clone()], vec![child_vote.clone()]] {
        let (status, problem) = boxed_step(|| {
            realm_review_device_submit(&context, &candidate, &device, &event, votes.clone())
        })
        .await;
        realm_review_assert_required(status, &problem);
        assert_eq!(
            boxed_step(|| realm_review_footprint(fixture)).await,
            before,
            "one grant context cannot satisfy its independent source or child context"
        );
    }
    let votes = vec![parent_vote, child_vote];
    use diesel_async::SimpleAsyncConnection as _;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute("CREATE FUNCTION test_realm_message_review_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'approved native Message signer source writer failure'; END $$; CREATE TRIGGER test_realm_message_review_failure BEFORE INSERT ON agent_producer_signer_keys FOR EACH ROW EXECUTE FUNCTION test_realm_message_review_failure();").await.unwrap();
    }
    let (status, problem) = boxed_step(|| {
        realm_review_device_submit(&context, &candidate, &device, &event, votes.clone())
    })
    .await;
    {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute("DROP TRIGGER test_realm_message_review_failure ON agent_producer_signer_keys; DROP FUNCTION test_realm_message_review_failure();").await.unwrap();
    }
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "approved Message source writer: {problem}"
    );
    assert_eq!(
        boxed_step(|| realm_review_footprint(fixture)).await,
        before,
        "Message rollback cannot burn grant votes, nonces or shared quota"
    );
    let (status, result) = boxed_step(|| {
        realm_review_device_submit(&context, &candidate, &device, &event, votes.clone())
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual independently approved native Message: {result}"
    );
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.event, event);
    let after = boxed_step(|| realm_review_footprint(fixture)).await;
    assert_eq!(
        after["event_approval_private_audit"]
            .as_array()
            .unwrap()
            .len(),
        before["event_approval_private_audit"]
            .as_array()
            .unwrap()
            .len()
            + 2
    );
    let (status, result) = boxed_step(|| {
        realm_review_device_submit(&context, &candidate, &device, &event, votes.clone())
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact approved Message retry: {result}"
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit,
        original.commit
    );
    assert_eq!(boxed_step(|| realm_review_footprint(fixture)).await, after);
}
