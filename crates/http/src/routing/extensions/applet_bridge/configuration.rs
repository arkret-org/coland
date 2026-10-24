//! Account ingress and the governing Station's private configuration execution.
use arkret_models_integration::{
    AppletConfigurationAdmissionStatus as Admission, AppletConfigurationCommand as Command,
    AppletConfigurationExecutionIntent as Intent,
    AppletConfigurationExecutionRequestBody as Execution,
    AppletConfigurationPeerRequestBody as PeerRequest,
    AppletConfigurationRequestBody as ConfigurationRequest,
    AppletConfigurationResponseBody as Outcome, AppletConfigurationSignature, AppletEndpointAuth,
    AppletEndpointMethod,
};
use arkret_wire::{AccountId, ActorId, AppletId, CommittedEventRef, ServiceOperationId};
use coland_http::error::AppError;
use coland_storage::{AppletConfigurationIngress as Ingress, AppletConfigurationIngressSource};
use salvo::prelude::*;

use crate::state::AppState;

const MAX_BYTES: usize = 262_144;

fn unavailable(error: impl std::fmt::Debug) -> AppError {
    tracing::warn!(?error, "Applet configuration remains recoverable");
    crate::app_error!(
        TemporarilyUnavailable,
        "Applet configuration is unavailable"
    )
}

fn service_error(error: coland_services::ServiceError) -> AppError {
    use arkret_wire::ErrorCode;
    use coland_services::ServiceError;
    if error.conflict_code() == Some(coland_storage::ConflictCode::ApprovalRequired) {
        return AppError::from_rejection(ErrorCode::ClaimRequired, error.to_string())
            .with_reason_code(arkret_wire::ReasonCode::APPROVAL_REQUIRED);
    }
    let code = match &error {
        ServiceError::NotFound(_) => ErrorCode::NotFound,
        ServiceError::SchemaViolation(_) => ErrorCode::SchemaViolation,
        ServiceError::UnsupportedEventKind(_) => ErrorCode::UnsupportedEventKind,
        ServiceError::Conflict(_) => error
            .conflict_code()
            .and_then(|code| ErrorCode::from_wire(code.as_str()))
            .unwrap_or(ErrorCode::FailedPrecondition),
        ServiceError::Database(_) | ServiceError::Internal(_) => ErrorCode::InternalError,
    };
    AppError::from_rejection(code, error.to_string())
}

async fn body<T: serde::de::DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    let bytes = req.payload().await.map_err(unavailable)?;
    if bytes.len() > MAX_BYTES {
        return Err(AppError::schema_violation(
            "configuration exceeds 262144 bytes",
        ));
    }
    arkret_canonical::canonical::validate_canonical_bytes(bytes)
        .map_err(|_| AppError::json_invalid("configuration body must be canonical"))?;
    serde_json::from_slice(bytes).map_err(|error| AppError::schema_violation(error.to_string()))
}

fn applet(req: &Request) -> Result<AppletId, AppError> {
    super::record::applet_id_param(req)?
        .parse()
        .map_err(|_| AppError::param_invalid("invalid Applet identity"))
}

#[handler]
pub(super) async fn peer_submit(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let result = async {
        crate::routing::events::peer::validate_peer_request(state, req, true).await?;
        if req
            .headers()
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.trim().is_empty())
        {
            return Err(AppError::schema_violation(
                "configuration command requires Idempotency-Key",
            ));
        }
        let applet = applet(req)?;
        let request: PeerRequest = body(req).await?;
        request
            .validate()
            .map_err(|e| AppError::schema_violation(e.to_string()))?;
        let source = crate::routing::events::peer::source_id_from_request(req)?;
        if source != request.requester_account_id.station_id.as_str() {
            return Err(AppError::capability_denied(
                "configuration source is not the Account Station",
            ));
        }
        let header = |name: &str| -> Result<String, AppError> {
            req.headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| AppError::unauthenticated("missing signed peer material"))
        };
        let key = req
            .extensions()
            .get::<crate::routing::federation::VerifiedPeerKeyDigest>()
            .ok_or_else(|| AppError::unauthenticated("verified peer key is unavailable"))?
            .0;
        let ingress = Ingress {
            requester_account_id: request.requester_account_id,
            request: request.request,
            source: AppletConfigurationIngressSource::Peer(Box::new(
                coland_storage::AppletConfigurationPeerSource {
                    source_service_id: source.parse().map_err(unavailable)?,
                    signature_input: header("signature-input")?,
                    signature: header("signature")?,
                    content_digest: header("content-digest")?,
                    verified_key_digest: key,
                    method: req.method().as_str().to_owned(),
                    target_uri: crate::routing::federation::signature_target_uri(req, state),
                    authority: crate::routing::federation::signature_authority(req, state),
                    signed_headers: [
                        "source-service-id",
                        "destination-service-id",
                        "source-trust-domain",
                        "destination-trust-domain",
                        "content-digest",
                        "destination-service-endpoint-digest",
                        "idempotency-key",
                        "content-type",
                        "arkret-operation",
                    ]
                    .into_iter()
                    .filter_map(|name| {
                        req.headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .map(|value| (name.to_owned(), value.to_owned()))
                    })
                    .collect(),
                },
            )),
        };
        govern(state, &applet, &ingress).await
    }
    .await;
    crate::routing::authority_commit::no_store(res);
    match result {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) => error.write(req, depot, res).await,
    }
}

#[handler]
pub(super) async fn self_submit(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some((session, account)) = crate::routing::self_current_reads::authenticated_reader(
        state,
        req,
        res,
        ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1,
    )
    .await
    else {
        return;
    };
    let result = Box::pin(async {
        if account.station_id != state.service_core_id() {
            return Err(AppError::capability_denied("configuration must enter through the Account Station"));
        }
        let applet = applet(req)?;
        let request: ConfigurationRequest = body(req).await?;
        request.validate().map_err(|e| AppError::schema_violation(e.to_string()))?;
        let outcome = route(state, &applet, &account, request).await?;
        let token = coland_http::util::dpop_token(req);
        crate::routing::identity::auth::revalidate_current_read_session(state, &session, token)
            .await.map_err(|_| AppError::unauthenticated("configuration session is no longer current"))?;
        let device = if let Some(device) = session.human_device_id() {
            Some(crate::routing::identity::device_generation::active_device_revocation_gate_selector(
                state, &session.actor, device,
            ).await.map_err(unavailable)?)
        } else { None };
        let input = coland_storage::AccountContentDeliveryInput {
            watch_delivery_device: device,
            watch_local_session: if session.session_grant.is_none() {
                session.account_pk.map(|pk| (session.token_hash.clone(), pk))
            } else { None },
            ..Default::default()
        };
        let guard = crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
        coland_http::result::guarded_json_ok(outcome, guard).map_err(unavailable)
    }).await;
    crate::routing::authority_commit::no_store(res);
    match result {
        Ok(outcome) => salvo::Scribe::render(outcome, res),
        Err(error) => error.write(req, depot, res).await,
    }
}

async fn route(
    state: &AppState,
    applet: &AppletId,
    account: &AccountId,
    request: ConfigurationRequest,
) -> Result<Outcome, AppError> {
    let realm = request.intent.effective_scope.realm_id();
    let observed = state
        .authority_commits()
        .current_authority(realm)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("governance absent"))?;
    if observed.service_id == state.service_core_id() {
        return govern(
            state,
            applet,
            &Ingress {
                requester_account_id: account.clone(),
                request,
                source: AppletConfigurationIngressSource::LocalSession,
            },
        )
        .await;
    }
    use arkret_models_collaboration::governance::realm_join_intake::{
        AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind,
    };
    let hint = RealmJoinCandidate {
        service_kind: RealmJoinCandidateServiceKind::Station,
        service_id: observed.service_id.clone(),
        endpoint_url: None,
        source: AuthorityLocatorSource::Cache,
    };
    use base64::Engine as _;
    let nonce = arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
    )
    .map_err(unavailable)?;
    let located =
        crate::routing::realm_join::resolve_verified_authority(state, realm, &[hint], &nonce)
            .await
            .map_err(unavailable)?;
    let authority = located.current_authority();
    if authority.generation < observed.generation
        || (authority.generation == observed.generation && authority != observed)
    {
        return Err(unavailable("governance locator rolled back"));
    }
    state
        .authority_commits()
        .record_remote_authority(&authority, &state.service_core_id())
        .await
        .map_err(unavailable)?;
    let peer = PeerRequest {
        requester_account_id: account.clone(),
        request,
    };
    let bytes = arkret_canonical::canonical_json_bytes(&peer).map_err(unavailable)?;
    let key = arkret_canonical::canonical_sha256(&peer).map_err(unavailable)?;
    let response = crate::routing::federation::outbox::signed_peer_command(
        state,
        authority.service_id.as_str(),
        &format!("/_arkret/peer/applets/{applet}/configuration"),
        &bytes,
        &key,
        MAX_BYTES,
    )
    .await
    .map_err(unavailable)?;
    if response.status != 200 {
        let problem: arkret_wire::Problem =
            serde_json::from_slice(&response.body).map_err(unavailable)?;
        if problem.status != response.status {
            return Err(unavailable("governor error status differs"));
        }
        return Err(AppError::from_frozen_problem(problem));
    }
    let outcome: Outcome = serde_json::from_slice(&response.body).map_err(unavailable)?;
    if outcome.request_id != peer.request.intent.request_id
        || outcome.source_response_body.as_ref().is_some_and(|source| {
            source.request_id != outcome.request_id || source.intent_digest != outcome.intent_digest
        })
    {
        return Err(unavailable("configuration response correlation differs"));
    }
    Ok(outcome)
}

async fn govern(
    state: &AppState,
    applet: &AppletId,
    ingress: &Ingress,
) -> Result<Outcome, AppError> {
    let request = &ingress.request;
    let realm = request.intent.effective_scope.realm_id();
    let governor = state.service_core_id();
    let authority = state
        .authority_commits()
        .current_authority(realm)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("governance absent"))?;
    if authority.service_id != governor {
        return Err(
            AppError::conflict("configuration targets a different governor")
                .with_wire_code("failed_precondition"),
        );
    }
    let actor = ActorId::account(ingress.requester_account_id.clone());
    let current = crate::approval_admission::observe_management_accounts(
        state,
        std::collections::BTreeSet::from([ingress.requester_account_id.clone()]),
    )
    .await
    .map_err(service_error)?;
    let original = state
        .event_queries()
        .configuration_intent(&governor, applet, &actor, &request.intent, &current)
        .await
        .map_err(service_error)?;
    let record = super::record::applet_record(
        state,
        applet.as_str(),
        request.intent.service_id.as_str(),
        &request.intent.effective_scope,
    )
    .await?
    .ok_or_else(|| AppError::not_found("Applet installation absent"))?;
    let intent = if let Some(original) = original {
        original
    } else {
        let registration = state
            .authority_commits()
            .committed_event(&record.registration_event.event_id)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("registration original absent"))?;
        Intent {
            request_id: request.intent.request_id.clone(),
            applet_id: applet.clone(),
            service_id: record.package.service_id.clone(),
            governance_station_id: governor.clone(),
            governance_generation: authority.generation,
            effective_scope: request.intent.effective_scope.clone(),
            registration_ref: CommittedEventRef {
                event_id: registration.event.event_id,
                commit_id: registration.commit.commit_id,
                stream_ref: registration.commit.stream_ref,
                stream_position: registration.commit.stream_position,
            },
            registration_epoch: record.package.registration_epoch.clone(),
            originating_actor_id: actor,
            selection: request.intent.selection.clone(),
        }
    };
    let outcome = state
        .event_queries()
        .applet_configuration(&governor, &intent, request.command, &current, ingress)
        .await
        .map_err(service_error)?;
    if matches!(
        outcome.admission_status,
        Admission::Accepted | Admission::Denied
    ) {
        return Ok(outcome);
    }
    if !record
        .package
        .endpoint_policy
        .endpoints
        .iter()
        .any(|endpoint| {
            endpoint.path == "/_arkret/edge/applet/configuration"
                && endpoint.method == AppletEndpointMethod::Post
                && endpoint.authentication_kind == Some(AppletEndpointAuth::WebhookSignature)
        })
    {
        return Err(AppError::capability_denied(
            "Applet configuration endpoint is not declared",
        ));
    }
    let method = state
        .service_verification_method("notary-key")
        .map_err(unavailable)?;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        state.service_did(),
        method.clone(),
    );
    let mut execution = Execution {
        command: request.command,
        intent: intent.clone(),
        governance_station_id: governor.clone(),
        governance_generation: authority.generation,
        issued_at: at,
        expires_at: at + chrono::Duration::minutes(5),
        proof: AppletConfigurationSignature {
            verification_method: method.clone(),
            jws: String::new(),
        },
    };
    execution.sign(&signer).map_err(unavailable)?;
    let (base, transport) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &record.package.base_url,
        "Applet configuration",
        state.config().development_mode,
        std::time::Duration::from_secs(15),
    )
    .map_err(unavailable)?;
    let mut builder = arkret_http_client::Client::builder(base)
        .http_client(transport)
        .retry(arkret_http_client::RetryConfig::disabled())
        .http_message_signer(arkret_http_client::HttpMessageSigner::new(
            method.to_string(),
            state.notary_signing_key().as_ref().clone(),
        ));
    if state.config().development_mode {
        builder = builder.allow_insecure_localhost();
    }
    let client = builder.build().map_err(unavailable)?;
    let source = client
        .applet_configuration_execute(
            &arkret_canonical::canonical_sha256(&execution).map_err(unavailable)?,
            &execution,
        )
        .await
        .map_err(unavailable)?;
    let resolution = crate::routing::identity::agents::evidence::fetch_service_resolution(
        state,
        &intent.service_id,
        Some(&record.package.base_url),
    )
    .await
    .map_err(unavailable)?;
    let source_document = arkret_identity::authenticated_service_document_at(
        &resolution,
        &intent.service_id,
        source.evaluated_at,
    )
    .map_err(unavailable)?;
    let retained = state
        .event_queries()
        .retain_configuration_source(
            &governor,
            &intent,
            &source,
            &coland_storage::AppletEventProducerGuard {
                service_did_document: source_document,
            },
            &current,
        )
        .await
        .map_err(service_error)?;
    if request.command == Command::Cancel
        || matches!(
            retained.admission_status,
            Admission::Cancelled | Admission::Denied | Admission::Accepted
        )
    {
        return Ok(retained);
    }
    let Some(event) = source.create_event.as_deref() else {
        return Ok(retained);
    };
    let mut approval_signatures = request.approval_signatures.clone().unwrap_or_default();
    if let Some(review_id) = &retained.review_request_id {
        use arkret_models_integration::ManagementReviewStatus as ReviewStatus;
        let caller = ActorId::service(intent.service_id.clone());
        let management_votes = approval_signatures.iter().filter(|signature| matches!(
            &signature.input.approval_context, arkret_wire::ApprovalContext::Management { request_id, .. } if request_id == review_id.as_str()
        )).cloned().collect::<Vec<_>>();
        let material = state
            .persistence()
            .management_review_material(&caller, review_id.as_str(), &management_votes)
            .await
            .map_err(coland_services::ServiceError::from)
            .map_err(service_error)?;
        let expected_ref = arkret_models_integration::AppletConfigurationRef {
            request_id: intent.request_id.clone(),
            intent_digest: intent.digest().map_err(unavailable)?,
        };
        let arkret_models_integration::ManagementReviewTarget::Event { event: reviewed } =
            &material.request.target;
        if material.request.configuration_ref.as_ref() != Some(&expected_ref)
            || reviewed.as_ref() != event
        {
            return Err(unavailable(
                "configuration review changed its original binding",
            ));
        }
        let mut accounts = material
            .accounts
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        accounts.insert(ingress.requester_account_id.clone());
        let mut review_current =
            crate::approval_admission::observe_management_accounts(state, accounts)
                .await
                .map_err(service_error)?;
        review_current.applet_event = super::prepare_event_current(state, &material.request.target)
            .await
            .map_err(service_error)?;
        if material.outcome.status == ReviewStatus::Pending && !management_votes.is_empty() {
            let at = chrono::Utc::now();
            let mut all_votes = material.outcome.approval_signatures.clone();
            for signature in &management_votes {
                if !all_votes.contains(signature) {
                    all_votes.push(signature.clone());
                }
            }
            let methods =
                crate::approval_admission::prepare_approval_methods(state, &all_votes, at)
                    .await
                    .map_err(service_error)?;
            // The authenticated administrator forwards original votes. This is
            // the existing decision gate, with the real Account as caller.
            state
                .persistence()
                .management_review_decide(
                    &ActorId::account(ingress.requester_account_id.clone()),
                    &arkret_models_integration::ManagementReviewDecisionRequestBody {
                        request_id: review_id.to_string(),
                        expected_status: ReviewStatus::Pending,
                        decision: arkret_models_integration::ManagementReviewDecision::Approve,
                        approval_signatures: management_votes,
                    },
                    &methods,
                    &review_current,
                    at,
                )
                .await
                .map_err(coland_services::ServiceError::from)
                .map_err(service_error)?;
        }
        let review = state
            .persistence()
            .management_review_status(
                &caller,
                &arkret_models_integration::ManagementReviewLookupRequestBody {
                    request_id: review_id.to_string(),
                },
                &review_current,
                chrono::Utc::now(),
            )
            .await
            .map_err(coland_services::ServiceError::from)
            .map_err(service_error)?;
        if review.status != ReviewStatus::Approved && review.status != ReviewStatus::Consumed {
            return state
                .event_queries()
                .applet_configuration(
                    &governor,
                    &intent,
                    Command::Recover,
                    &review_current,
                    &Ingress {
                        request: ConfigurationRequest {
                            command: Command::Recover,
                            ..request.clone()
                        },
                        ..ingress.clone()
                    },
                )
                .await
                .map_err(service_error);
        }
        for signature in review.approval_signatures {
            if !approval_signatures.contains(&signature) {
                approval_signatures.push(signature);
            }
        }
    }
    // Admission occurs after the Applet has authored its native identity.
    // The earlier transport issuance time cannot predate the creation Commit.
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let submission = arkret_wire::EventAdmissionSubmission {
        event: event.clone(),
        approval_signatures: (!approval_signatures.is_empty()).then_some(approval_signatures),
    };
    let prepared = crate::approval_admission::prepare_event_approvals(state, &submission, at)
        .await
        .map_err(service_error)?;
    let producer = super::prepare_event_current(
        state,
        &arkret_models_integration::management_review::ManagementReviewTarget::Event {
            event: Box::new(event.clone()),
        },
    )
    .await
    .map_err(service_error)?
    .ok_or_else(|| unavailable("current Service authority absent"))?;
    let digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(
            &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
                submission,
            ),
        )
        .map_err(unavailable)?,
    )
    .map_err(unavailable)?;
    state
        .authority_commits()
        .admit_realm_actor_creation(
            event,
            &coland_storage::AppletEventProducerGuard {
                service_did_document: producer.service_did_document,
            },
            &governor,
            method,
            state.notary_signing_key().as_ref(),
            at,
            prepared.as_ref(),
            &digest,
        )
        .await
        .map_err(service_error)?;
    state
        .event_queries()
        .applet_configuration(
            &governor,
            &intent,
            Command::Recover,
            &current,
            &Ingress {
                request: ConfigurationRequest {
                    command: Command::Recover,
                    ..request.clone()
                },
                ..ingress.clone()
            },
        )
        .await
        .map_err(service_error)
}
