fn mount_completion_receiver(native: &NativeService, edge: Arc<arkret_bridge_runtime::ArkretEdge>) {
    assert!(
        native.completion_handler.lock().unwrap().is_none(),
        "real receiver must not be intercepted by a callback"
    );
    let router = arkret_bridge_runtime::web::managed_applet_host_router(edge).unwrap();
    *native.managed_router.lock().unwrap() = Some(Arc::new(salvo::Service::new(router)));
}

fn completion_journal_rows(path: &std::path::Path, prefix: &str) -> Vec<(String, String)> {
    use arkret_bridge_runtime::AuthoringStore as _;
    let store = arkret_bridge_runtime::FileAuthoringStore::new(path.to_owned()).unwrap();
    let mut rows = store.entries_with_prefix(prefix).unwrap();
    rows.sort();
    rows
}

async fn post_original_completion(
    fixture: &Fixture,
    task: &coland_storage::AppletAuthoringCompletion,
    bytes: &[u8],
    created: i64,
) -> (StatusCode, Value, String) {
    let path = "/_arkret/edge/applet/transactions";
    let target = format!("{}{path}", task.endpoint.trim_end_matches('/'));
    let url = url::Url::parse(&target).unwrap();
    let digest = content_digest_header(bytes);
    let parts = SignedRequestParts {
        method: "POST".into(),
        target_uri: target.clone(),
        authority: url[url::Position::BeforeHost..url::Position::AfterPort].into(),
        path: path.into(),
        headers: vec![
            (
                "arkret-operation".into(),
                arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1.into(),
            ),
            ("content-type".into(), "application/json".into()),
            ("content-digest".into(), digest.clone()),
            ("source-service-id".into(), task.source_id.to_string()),
            (
                "destination-service-id".into(),
                task.destination_id.to_string(),
            ),
            ("idempotency-key".into(), task.idempotency_key.clone()),
        ],
        body_digest: Some(digest),
    };
    let signature = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::AppletTransactionV1,
        &[],
        "sig1",
        fixture
            .state
            .service_verification_method("notary-key")
            .unwrap()
            .as_str(),
        created,
        fixture.state.notary_signing_key().as_ref(),
    )
    .unwrap();
    let mut request = native_http_client(std::time::Duration::from_secs(30)).post(target);
    for (name, value) in parts.headers {
        request = request.header(name, value);
    }
    let response = request
        .header("signature-input", signature.signature_input_header)
        .header("signature", signature.signature_header)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    (status, response.json().await.unwrap(), content_type)
}

fn completion_wire_bytes(task: &coland_storage::AppletAuthoringCompletion) -> Vec<u8> {
    let body = arkret_models_integration::AppletTransactionRequestBody::Authoring(Box::new(
        arkret_models_integration::AppletAuthoringTransactionRequestBody {
            applet_id: task.applet_id.clone(),
            source_id: task.source_id.clone(),
            authoring_context: task
                .context
                .clone()
                .expect("actual application signed material"),
        },
    ));
    body.validate().unwrap();
    arkret_canonical::canonical_json_bytes(&body).unwrap()
}

async fn actual_completion_receiver<F>(
    fixture: &Fixture,
    native: &NativeService,
    actor: &ActorId,
    creation: &arkret_wire::RealmCommit,
    path: &std::path::Path,
    make_edge: &F,
) where
    F: Fn() -> Arc<arkret_bridge_runtime::ArkretEdge>,
{
    let original = completion_journal_rows(path, "managed-authoring/original/");
    let roots = completion_journal_rows(path, "managed-authoring/original-roots/");
    assert_eq!(original.len(), 1);
    assert_eq!(roots.len(), 1);
    let task = fixture
        .state
        .test_persistence()
        .applets()
        .pending_authoring_completions(128)
        .await
        .unwrap()
        .into_iter()
        .find(|task| &task.actor_id == actor)
        .unwrap();
    assert_eq!(task.creation_ref.event_id, creation.event_ref);
    assert_eq!(task.creation_ref.commit_id, creation.commit_id);
    assert_eq!(task.destination_id, native.package.service_id);
    let method = fixture
        .state
        .service_verification_method("notary-key")
        .unwrap();
    let prepared = super::completion_application(&fixture.state)
        .prepare_applet_authoring_completion(
            &task,
            &fixture.state.service_core_id(),
            &method,
            fixture.state.notary_signing_key().as_ref(),
        )
        .await
        .unwrap();
    let bytes = completion_wire_bytes(&prepared);
    let expected = json!(
        arkret_models_integration::AppletTransactionResponseBody::Accepted {
            committed_event_refs: vec![],
            rejections: vec![],
            retry_after_ms: None,
        }
    );
    let edge = make_edge();
    mount_completion_receiver(native, edge.clone());
    let first_created = chrono::Utc::now().timestamp() - 1;
    let (status, outcome, mime) =
        boxed_step(|| post_original_completion(fixture, &prepared, &bytes, first_created)).await;
    assert_eq!(status, StatusCode::OK, "real Bridge receiver: {outcome}");
    assert_eq!(outcome, expected);
    assert!(mime.starts_with("application/json"));
    let first_receipts = completion_journal_rows(path, "managed-authoring/delivery/");
    assert_eq!(
        first_receipts.len(),
        1,
        "actual receiver must durably retain its delivery receipt"
    );
    let first_audit = completion_journal_rows(path, "managed-authoring/delivery-audit/");
    assert_eq!(first_audit.len(), 1);
    let (status, outcome, _) = boxed_step(|| {
        post_original_completion(fixture, &prepared, &bytes, chrono::Utc::now().timestamp())
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fresh transport same body/key: {outcome}"
    );
    assert_eq!(outcome, expected);
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/delivery/"),
        first_receipts
    );
    let audit = completion_journal_rows(path, "managed-authoring/delivery-audit/");
    assert_eq!(audit.len(), 2);
    let records = audit
        .iter()
        .map(|(_, raw)| {
            serde_json::from_str::<arkret::AppletDeliveryAuthenticationRecord>(raw).unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        records[0].stable_digest().unwrap(),
        records[1].stable_digest().unwrap()
    );
    assert_ne!(
        arkret_canonical::canonical_json_bytes(&records[0]).unwrap(),
        arkret_canonical::canonical_json_bytes(&records[1]).unwrap()
    );
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/original/"),
        original
    );
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/original-roots/"),
        roots
    );
    // A new router has an empty volatile claim cache. Only the normal file
    // journal may recover the original and its accepted delivery receipt.
    *native.managed_router.lock().unwrap() = None;
    drop(edge);
    let edge = make_edge();
    mount_completion_receiver(native, edge.clone());
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, outcome, _) = boxed_step(|| {
        post_original_completion(fixture, &prepared, &bytes, chrono::Utc::now().timestamp())
    })
    .await;
    assert_eq!(status, StatusCode::OK, "cold receipt recovery: {outcome}");
    assert_eq!(outcome, expected);
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/delivery/"),
        first_receipts
    );
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/delivery-audit/").len(),
        3
    );
    let expiry = prepared.context.as_ref().unwrap().material.expires_at;
    let remaining = (expiry - chrono::Utc::now()).to_std().unwrap_or_default();
    tokio::time::sleep(remaining + std::time::Duration::from_millis(100)).await;
    assert!(chrono::Utc::now() >= expiry);
    let before_refusal = completion_journal_rows(path, "managed-authoring/");
    let business = boxed_step(|| native_business_footprint(fixture)).await;
    let (status, problem, mime) = boxed_step(|| {
        post_original_completion(fixture, &prepared, &bytes, chrono::Utc::now().timestamp())
    })
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "fresh HTTP cannot replay expired material through cache: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/http_signature_invalid"
    );
    assert_eq!(problem["status"], 401);
    assert!(
        mime.starts_with("application/problem+json"),
        "actual Problem MIME: {mime}"
    );
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/"),
        before_refusal
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        business
    );
    let refreshed = super::completion_application(&fixture.state)
        .prepare_applet_authoring_completion(
            &prepared,
            &fixture.state.service_core_id(),
            &method,
            fixture.state.notary_signing_key().as_ref(),
        )
        .await
        .unwrap();
    assert_ne!(refreshed.idempotency_key, prepared.idempotency_key);
    assert_eq!(refreshed.creation_ref, prepared.creation_ref);
    assert_eq!(
        json!(refreshed.context.as_ref().unwrap().material.material),
        json!(prepared.context.as_ref().unwrap().material.material)
    );
    assert_ne!(
        refreshed.context.as_ref().unwrap().material.request_nonce,
        prepared.context.as_ref().unwrap().material.request_nonce
    );
    let refreshed_bytes = completion_wire_bytes(&refreshed);
    let (status, outcome, _) = boxed_step(|| {
        post_original_completion(
            fixture,
            &refreshed,
            &refreshed_bytes,
            chrono::Utc::now().timestamp(),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fresh verified material after expired cached receipt: {outcome}"
    );
    assert_eq!(outcome, expected);
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/delivery/").len(),
        2
    );
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/original/"),
        original
    );
    assert_eq!(
        completion_journal_rows(path, "managed-authoring/original-roots/"),
        roots
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&creation.event_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&accepted.commit, creation);
    *native.managed_router.lock().unwrap() = None;
    drop(edge);
}
