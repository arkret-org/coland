//! Invite addressing protocol surface.
//!
//! Implements the v1 private invite delivery endpoint and the body-only
//! online locator resolver from `sync/invite-addressing.md`.

#[cfg(feature = "conformance-harness")]
mod delivery_probe;

use arkret_canonical as canonical;
use arkret_identifiers::{DidCoreId, Hash, InviteLocatorId};
#[cfg(test)]
use arkret_models_collaboration::governance::invite_addressing::{
    DisclosedOutcome, DisclosureLevel, InviteDelivery, InviteDeliveryEntry,
};
use arkret_models_collaboration::governance::invite_addressing::{
    IntroductionEvidence, InviteDeliveryOutcome, InviteDeliveryOutcomeStatus,
    InviteDeliveryRequestBody, InviteLocatorIssueOutcome, InviteLocatorIssueRequestBody,
    InviteLocatorResolveRequestBody, InviteLocatorRevokeOutcome, InviteLocatorRevokeRequestBody,
    InviteLocatorRotateRequestBody, InviteLocatorStatus, InviteReceivePolicy, PrincipalLocator,
    PrincipalLocatorProof, PrincipalLocatorProofPurpose, SelfInviteDispatchRequestBody,
};
#[cfg(test)]
use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
use arkret_models_collaboration::governance::realm_join_intake::{
    AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind,
};
use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInviteAcceptanceAttestation, ThirdPartyInviteAcceptanceAttestationOutcome,
    ThirdPartyInviteAcceptanceAttestationRequestBody,
};
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_models_identity::proof::DetachedPayloadProof;
use arkret_wire::receive_policy::EffectiveNewSourceQuota;
#[cfg(test)]
use arkret_wire::{AccountDataKey, InviteReceiveAction};
use arkret_wire::{ReceivePolicyConstraints, ReceivePolicySurface};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;
#[cfg(test)]
use coland_domain::invite_receive::*;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_http::util::sha256_hex;
use coland_services::events::{
    AcceptedEvent, InviteLocatorInsertResult as InviteLocatorInsertOutcome,
    InviteLocatorRotateCommand as InviteLocatorRotateMutation,
    InviteLocatorState as InviteLocatorRecord,
};
use coland_services::federation::{EnqueueFederationDeliveryCommand, FederationDeliveryRecord};
use coland_services::identity::SessionIdentityState as SessionRecord;
use coland_storage::NewSourceAdmission;
use salvo::http::HeaderValue;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const HEADER_DESTINATION_SERVICE_ID: &str = "destination-service-id";
/// HTTP binding of `ak.peer.invites.command.submit.v1` — the only endpoint a
/// remote private invite delivery is ever addressed to.
const PEER_INVITES_ENDPOINT: &str = "/_arkret/peer/invites";
const ACTIVE_LOCATOR_LIMIT: usize = 16;
const INVITE_LOCATOR_CACHE_CONTROL: &str = "private, no-store";

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("invites").post(peer_invites_submit))
}

pub(crate) fn open_router() -> Router {
    Router::new().push(Router::with_path("invite-locators/resolve").post(resolve_invite_locator))
}

pub(crate) fn self_router() -> Router {
    Router::new()
        .push(
            Router::with_path("third-party-invites/acceptance-attestation")
                .post(third_party_invite_acceptance_attestation),
        )
        .push(Router::with_path("invite-locators").post(issue_invite_locator))
        .push(Router::with_path("invite-locators/rotate").post(rotate_invite_locator))
        .push(Router::with_path("invite-locators/revoke").post(revoke_invite_locator))
        .push(Router::with_path("invites/dispatch").post(self_invites_dispatch))
}

#[handler]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.third_party_invite.read.acceptance_attestation.v1")
)]
async fn third_party_invite_acceptance_attestation(
    aa: AuthArgs,
    body: JsonBody<ThirdPartyInviteAcceptanceAttestationRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<ThirdPartyInviteAcceptanceAttestationOutcome> {
    use coland_storage::PersistenceError;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let caller = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    let station = DidCoreId::new(state.service_id())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let (_, method) = state.current_service_receipt_binding().await.map_err(|_| {
        crate::app_error!(RevisionUnavailable, "Station assertion method unavailable")
    })?;
    let sign = |attestation: &ThirdPartyInviteAcceptanceAttestation| {
        let internal =
            |error: arkret_wire::WireError| PersistenceError::Internal(error.to_string());
        let mut proof = attestation.signature.unsigned();
        proof.payload_digest = attestation.payload_digest().map_err(internal)?;
        proof.domain = Some(
            arkret_wire::ProofContextId::THIRD_PARTY_INVITE_ACCEPTANCE_ATTESTATION_PROOF_V1.into(),
        );
        let bytes = attestation
            .unsigned_proof_binding_bytes(&proof)
            .map_err(internal)?;
        let jws =
            arkret_signatures::jws::sign_jws_ed25519(&bytes, state.notary_signing_key().as_ref())
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        proof.finalize(jws).map_err(internal)
    };
    let outcome = state
        .persistence()
        .third_party_invite_acceptance_attestation(
            &body.into_inner(),
            &caller,
            &station,
            &method,
            &now,
            &sign,
        )
        .await
        .map_err(|error| match error {
            PersistenceError::NotFound(_) => AppError::not_found("third-party invite unavailable"),
            PersistenceError::Conflict(_) => crate::app_error!(
                RevisionUnavailable,
                "accepted invite checkpoint unavailable"
            ),
            _ => AppError::internal("acceptance attestation unavailable"),
        })?;
    outcome
        .acceptance_attestation
        .validate_freshness(now())
        .map_err(|_| crate::app_error!(RevisionUnavailable, "acceptance observation expired"))?;
    res.add_header("Cache-Control", "private, no-store", true)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

fn new_invite_locator(
    subject_id: &str,
    recipient_id: &str,
    options: InviteLocatorIssueRequestBody,
) -> Result<(InviteLocatorRecord, String), AppError> {
    options
        .validate_minimal()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let issued_at = now();
    let expires_at = issued_at + Duration::seconds(i64::from(options.effective_ttl_seconds()));
    let (token, token_digest) = new_invite_locator_secret();
    let record = InviteLocatorRecord {
        locator_id: format!("ak:invite_locator:{}", uuid::Uuid::now_v7()),
        token_digest,
        subject_id: subject_id.to_owned(),
        recipient_id: recipient_id.to_owned(),
        issued_at,
        expires_at,
        one_time_use: options.one_time_use.unwrap_or(false),
        display_hint: options.display_hint,
        revoked_at: None,
        consumed_at: None,
    };
    Ok((record, token))
}

fn new_invite_locator_secret() -> (String, String) {
    let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
    let token_digest = format!("sha256:{}", sha256_hex(token.as_bytes()));
    (token, token_digest)
}

fn set_invite_locator_secret_response_headers(res: &mut Response) {
    res.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static(INVITE_LOCATOR_CACHE_CONTROL),
    );
}

fn locator_issue_outcome(
    record: &InviteLocatorRecord,
    locator_token: String,
) -> Result<InviteLocatorIssueOutcome, AppError> {
    Ok(InviteLocatorIssueOutcome {
        locator_id: InviteLocatorId::new(record.locator_id.clone())
            .map_err(|error| AppError::internal(format!("stored invite locator id: {error}")))?,
        locator_token,
        expires_at: record.expires_at,
        one_time_use: record.one_time_use,
    })
}

#[endpoint(summary = "Issue an invite locator", tags("invites"))]
async fn issue_invite_locator(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<InviteLocatorIssueRequestBody>,
) -> JsonResult<InviteLocatorIssueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let (record, token) =
        new_invite_locator(&session.actor, state.service_id(), body.into_inner())?;
    match state
        .invite_locators()
        .insert_locator(&record, ACTIVE_LOCATOR_LIMIT, now())
        .await
        .map_err(|error| AppError::internal(format!("invite locator insert: {error}")))?
    {
        InviteLocatorInsertOutcome::Inserted => {
            set_invite_locator_secret_response_headers(res);
            json_ok(locator_issue_outcome(&record, token)?)
        }
        InviteLocatorInsertOutcome::ActiveLimitReached => Err(crate::app_error!(
            FailedPrecondition,
            "active invite locator limit reached",
        )
        .with_wire_code("failed_precondition")),
    }
}

#[endpoint(summary = "Rotate an invite locator", tags("invites"))]
async fn rotate_invite_locator(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<InviteLocatorRotateRequestBody>,
) -> JsonResult<InviteLocatorIssueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate_minimal()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let (token, token_digest) = new_invite_locator_secret();
    let mutation = InviteLocatorRotateMutation {
        locator_id: format!("ak:invite_locator:{}", uuid::Uuid::now_v7()),
        token_digest,
        issued_at: now(),
        ttl_seconds: body.ttl_seconds,
        one_time_use: body.one_time_use,
        display_hint: body.display_hint,
    };
    let Some(record) = state
        .invite_locators()
        .rotate_locator(&session.actor, body.locator_id.as_str(), &mutation, now())
        .await
        .map_err(|error| AppError::internal(format!("invite locator rotate: {error}")))?
    else {
        return Err(invite_locator_not_found());
    };
    set_invite_locator_secret_response_headers(res);
    json_ok(locator_issue_outcome(&record, token)?)
}

#[endpoint(summary = "Revoke an invite locator", tags("invites"))]
async fn revoke_invite_locator(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<InviteLocatorRevokeRequestBody>,
) -> JsonResult<InviteLocatorRevokeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate_minimal()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let revoked_at = now();
    let Some(record) = state
        .invite_locators()
        .revoke_locator(&session.actor, body.locator_id.as_str(), revoked_at)
        .await
        .map_err(|error| AppError::internal(format!("invite locator revoke: {error}")))?
    else {
        return Err(invite_locator_not_found());
    };
    json_ok(InviteLocatorRevokeOutcome {
        locator_id: InviteLocatorId::new(record.locator_id)
            .map_err(|error| AppError::internal(format!("stored invite locator id: {error}")))?,
        status: InviteLocatorStatus::Revoked,
        revoked_at: record.revoked_at.unwrap_or(revoked_at),
    })
}

#[endpoint(
    operation_id = "ak.peer.invites.command.submit",
    summary = "Submit a peer invite delivery",
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.invites.command.submit.v1"))]
async fn peer_invites_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteDeliveryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::events::peer::validate_peer_request(state, req, true).await?;
    let delivery = req
        .parse_json::<InviteDeliveryRequestBody>()
        .await
        .map_err(|error| {
            // openapi_routes.rs draws this line for every other route: a body
            // that parses as JSON but violates the declared schema is a
            // schema_violation, and only a body that never parsed is
            // json_invalid. Closed-schema violations remain schema errors.
            if let salvo::http::ParseError::SerdeJson(serde_error) = &error
                && serde_error.classify() == serde_json::error::Category::Data
            {
                return crate::app_error!(
                    SchemaViolation,
                    format!(
                        "ak.peer.invites.command.submit.v1 request body violates the declared schema: {serde_error}"
                    ),
                );
            }
            AppError::json_invalid("invalid ak.peer.invites.command.submit.v1 request body")
        })?;
    let body = serde_json::to_value(&delivery).map_err(|error| {
        AppError::internal(format!("invite delivery request serialize: {error}"))
    })?;

    delivery.validate_minimal().map_err(|error| {
        super::events::peer::schema_violation(format!("invalid invite delivery request: {error}"))
    })?;

    let destination_id = required_header(req, HEADER_DESTINATION_SERVICE_ID)?;
    if destination_id != delivery.invite_address.account_id.station_id.as_str() {
        return Err(super::events::peer::cross_domain_replay(
            "Destination-Service-ID must equal invite_address.account_id.station_id",
        ));
    }
    let source_id = required_header(req, HEADER_SOURCE_SERVICE_ID)?;

    json_ok(
        receive_private_invite_delivery(state, &delivery, &body, &source_id, "peer.invites.submit")
            .await?,
    )
}

async fn receive_private_invite_delivery(
    state: &AppState,
    delivery: &InviteDeliveryRequestBody,
    body: &Value,
    source_id: &str,
    audit_operation: &'static str,
) -> Result<InviteDeliveryOutcome, AppError> {
    if delivery.invite_address.account_id.station_id != state.service_core_id() {
        return Err(super::events::peer::cross_domain_replay(
            "Invite recipient differs from its hosting Station",
        ));
    }
    validate_invite_delivery_event_binding(body, delivery)?;
    #[cfg(feature = "conformance-harness")]
    delivery_probe::pause(
        state,
        &delivery.invite_address.account_id,
        &arkret_wire::InviteId::from_event_id(&delivery.invite_event.event_id),
    )
    .await?;
    let source =
        DidCoreId::new(source_id.to_owned()).map_err(|e| AppError::param_invalid(e.to_string()))?;
    let command=arkret_models_collaboration::consent_private::ConsentPrivateCommand::InviteDelivery(arkret_models_collaboration::consent_private::ConsentPrivateInviteDeliveryCommand{
        kind:arkret_models_collaboration::consent_private::ConsentPrivateInviteDeliveryCommandKind::InviteDelivery,
        body:arkret_models_collaboration::consent_private::ConsentPrivateInviteDeliveryBody{notification_source_service_id:source,delivery:delivery.clone()},
    });
    let context=arkret_models_collaboration::consent_private::ConsentPrivateContext::Station(arkret_models_collaboration::consent_private::ConsentPrivateStationContext{kind:arkret_models_collaboration::consent_private::ConsentPrivateStationContextKind::Station,actor_id:arkret_wire::ActorId::service(state.service_core_id())});
    let outcome = super::consent_private::execute(
        state,
        &delivery.invite_address.account_id,
        context,
        command,
    )
    .await;
    match outcome {
        Ok(arkret_models_collaboration::consent_private::ConsentPrivateCommandOutcome::InviteDelivery(outcome))=>Ok(outcome.body),
        Ok(_)=>Err(AppError::internal("Invite authority returned another closed command")),
        Err(error)=>{
            // Authorization/source failures stay failures. Private authority
            // availability never reveals the holder's policy to the requester.
            if error.wire_code()=="temporarily_unavailable" {
                tracing::warn!(op=audit_operation,"private Invite authority is unavailable");
                Ok(InviteDeliveryOutcome{status:InviteDeliveryOutcomeStatus::Deferred,disclosed_outcome:None,received_at:Some(now()),retry_after_ms:None})
            } else {Err(error)}
        }
    }
}

pub(crate) async fn prepare_private_invite(
    state: &AppState,
    request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
) -> Result<Option<coland_storage::PreparedPrivateInviteDelivery>, AppError> {
    let arkret_models_collaboration::consent_private::ConsentPrivateCommand::InviteDelivery(
        command,
    ) = &request.command
    else {
        return Ok(None);
    };
    let delivery = &command.body.delivery;
    let body =
        serde_json::to_value(delivery).map_err(|e| AppError::param_invalid(e.to_string()))?;
    validate_invite_delivery_event_binding(&body, delivery)?;
    arkret_schema::validate_event_for_submit(&delivery.invite_event)
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let verified = verify_invite_commit(state, delivery).await?;
    let holder = &request.holder_account_id;
    let locator_verified = match &delivery.introduction_evidence {
        IntroductionEvidence::LocatorRef { principal_locator } => verified_locator_for_recipient(
            state,
            principal_locator,
            holder.principal_id.as_str(),
            holder.station_id.as_str(),
            now(),
        ),
        _ => false,
    };
    let constraints = constraints_for_surface(state, ReceivePolicySurface::InviteDelivery).cloned();
    Ok(Some(
        coland_storage::PreparedPrivateInviteDelivery::from_verified_receipt(
            request,
            &verified,
            locator_verified,
            constraints,
        )
        .map_err(|e| AppError::param_invalid(e.to_string()))?,
    ))
}

#[endpoint(
    operation_id = "ak.self.invites.command.dispatch",
    summary = "Dispatch a private invite delivery",
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.invites.command.dispatch.v1"))]
async fn self_invites_dispatch(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteDeliveryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let raw_body = req
        .payload()
        .await
        .map_err(|_| {
            AppError::json_invalid("invalid ak.self.invites.command.dispatch.v1 request body")
        })?
        .to_vec();
    let body: Value = serde_json::from_slice(&raw_body).map_err(|_| {
        AppError::json_invalid("invalid ak.self.invites.command.dispatch.v1 request body")
    })?;
    let dispatch: SelfInviteDispatchRequestBody =
        serde_json::from_value(body.clone()).map_err(|error| {
            AppError::param_invalid(format!("invalid invite dispatch request: {error}"))
        })?;
    dispatch
        .validate_minimal()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;

    let accepted = require_dispatchable_invite_event(state, &session, &dispatch).await?;
    // `canonical_bytes` is the Event digest preimage and deliberately omits
    // identity/proof fields such as `event_id`.  Private delivery carries the
    // complete accepted Event, which is stored separately as the envelope.
    let invite_event: arkret_wire::Event = serde_json::from_value(accepted.envelope.clone())
        .map_err(|error| AppError::internal(format!("stored invite Event is invalid: {error}")))?;
    let (invite_commit, governance) = governance_invite_commit(state, &invite_event).await?;
    let producer_signer_fact = state
        .authority_commits()
        .account_device_signer_fact(&invite_event, &invite_commit)
        .await
        .map_err(receipt_refusal)?;
    if invite_event
        .human_device_producer()
        .map_err(|e| AppError::param_invalid(e.to_string()))?
        .is_some()
        && producer_signer_fact.is_none()
    {
        return Err(AppError::from_rejection(
            coland_http::error::ErrorCode::TemporarilyUnavailable,
            "original accepted Invite Human signer fact is unavailable",
        ));
    }
    let delivery = InviteDeliveryRequestBody::new(
        invite_event,
        invite_commit,
        producer_signer_fact,
        vec![RealmJoinCandidate {
            service_kind: RealmJoinCandidateServiceKind::Station,
            service_id: governance,
            endpoint_url: None,
            source: AuthorityLocatorSource::Invite,
        }],
        dispatch.invite_address,
        dispatch.introduction_evidence,
        dispatch.idempotency_key,
    )
    .map_err(|e| AppError::internal(format!("invite submission encoding: {e}")))?;
    delivery
        .validate_minimal()
        .map_err(|error| AppError::internal(format!("invite delivery is malformed: {error}")))?;
    let delivery_body = serde_json::to_value(&delivery)
        .map_err(|error| AppError::internal(format!("invite delivery encoding failed: {error}")))?;

    if delivery.invite_address.account_id.station_id.as_str() == state.service_id() {
        // §7 — the local target runs the same steps 4-9 the peer ingress runs.
        return json_ok(
            receive_private_invite_delivery(
                state,
                &delivery,
                &delivery_body,
                state.service_id(),
                "self.invites.dispatch",
            )
            .await?,
        );
    }
    json_ok(enqueue_remote_invite_delivery(state, &delivery, &delivery_body, &accepted).await?)
}

/// Spec invite-addressing.md §7 — the accepted Event preconditions
/// of `ak.self.invites.command.dispatch.v1`.
///
/// The order is closed: resolve the accepted Event by `event_id` first, then
/// compare its stored signing actor.
/// Each failure is `failed_precondition` carrying its own reason code, and none
/// of them may produce a delivery, an outbox enqueue or a holder-private write,
/// so they are evaluated before either dispatch branch does anything at all.
///
/// This operation MUST NOT re-verify the signature of an Event this service
/// already admitted. Delivery uses the accepted, validated Event envelope stored at admission;
/// `canonical_bytes` is only the digest preimage and is never a wire Event carrier.
async fn require_dispatchable_invite_event(
    state: &AppState,
    session: &SessionRecord,
    dispatch: &SelfInviteDispatchRequestBody,
) -> Result<AcceptedEvent, AppError> {
    let Some(accepted) = state
        .event_queries()
        .canonical_event(dispatch.invite_event_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("invite event lookup: {error}")))?
    else {
        return Err(invite_event_precondition(
            "invite_event has not been accepted by this Station",
        ));
    };
    let session_principal = DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor is invalid: {error}")))?;
    let session_station = DidCoreId::new(session.audience.clone())
        .map_err(|error| AppError::internal(format!("session audience is invalid: {error}")))?;
    let session_actor = if session.agent_session().is_some() {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            session_principal,
            session_station,
        ))
    } else {
        let account_pk = session
            .account_pk
            .ok_or_else(|| AppError::unauthenticated("session account binding is missing"))?;
        let account = state
            .identities()
            .account_by_id(account_pk)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::unauthenticated("session account no longer exists"))?;
        if account.account_id.principal_id != session_principal
            || account.account_id.station_id != session_station
        {
            return Err(AppError::unauthenticated(
                "session does not bind the stored account",
            ));
        }
        arkret_wire::ActorId::account(account.account_id)
    };
    let accepted_actor: arkret_wire::ActorId = serde_json::from_str(&accepted.actor_id)
        .map_err(|error| AppError::internal(format!("stored Event actor is invalid: {error}")))?;
    let event: arkret_wire::Event =
        serde_json::from_value(accepted.envelope.clone()).map_err(|error| {
            AppError::internal(format!("stored Event envelope is invalid: {error}"))
        })?;
    if event.actor_id != accepted_actor {
        return Err(AppError::internal(
            "stored Event actor does not match its canonical envelope",
        ));
    }
    if event.executed_by.as_ref().unwrap_or(&accepted_actor) != &session_actor {
        return Err(invite_event_precondition(
            "invite_event was not signed by the authenticated session actor",
        ));
    }
    Ok(accepted)
}

/// The Realm-stream authority commit of the accepted invite Event. Only the
/// current governance Station of the invite Realm emits a delivery
/// (`invite-delivery-request.schema.json`), and it names itself as the
/// authority locator hint.
async fn governance_invite_commit(
    state: &AppState,
    invite_event: &arkret_wire::Event,
) -> Result<(arkret_wire::RealmCommit, DidCoreId), AppError> {
    let authority = state
        .authority_commits()
        .current_authority(&invite_event.realm_id)
        .await
        .map_err(|error| AppError::internal(format!("invite Realm authority lookup: {error}")))?
        .filter(|authority| authority.service_id == state.service_core_id())
        .ok_or_else(|| {
            invite_event_precondition(
                "only the current governance Station of the invite Realm emits its delivery",
            )
        })?;
    let committed = state
        .authority_commits()
        .committed_event(&invite_event.event_id)
        .await
        .map_err(|error| AppError::internal(format!("invite commit lookup: {error}")))?
        .ok_or_else(|| {
            invite_event_precondition("invite_event has no Realm-stream authority commit")
        })?;
    Ok((committed.commit, authority.service_id))
}

fn invite_event_precondition(message: &'static str) -> AppError {
    crate::app_error!(FailedPrecondition, message).with_wire_code("failed_precondition")
}

/// Spec invite-addressing.md §7 — hand the exact canonical request body to the
/// durable service-to-service outbox bound for `ak.peer.invites.command.submit.v1`.
///
/// The payload is the JCS form of the bytes the caller sent, never a
/// re-encoding of the typed model, so every retry under the same
/// `idempotency_key` reproduces byte-identical wire bytes and the receiver
/// computes the same request digest. Deduplication is the outbox's own
/// `(peer_id, idempotency_key)` uniqueness.
async fn enqueue_remote_invite_delivery(
    state: &AppState,
    delivery: &InviteDeliveryRequestBody,
    body: &Value,
    accepted: &AcceptedEvent,
) -> Result<InviteDeliveryOutcome, AppError> {
    validate_invite_delivery_event_binding(body, delivery)?;
    let recipient_id = &delivery.invite_address.account_id.station_id;
    let resolver = state
        .service_route_resolver()
        .map_err(|error| AppError::internal(error.to_owned()))?;
    let entry = resolver
        .resolve_carrier(
            &delivery.invite_address.service_resolution,
            recipient_id,
            "station",
            now(),
        )
        .await
        .map_err(|error| {
            crate::app_error!(
                FailedPrecondition,
                format!("recipient service has no verified route: {error}"),
            )
        })?;
    let payload_json =
        String::from_utf8(canonical::canonical_json_bytes(body).map_err(|error| {
            super::events::peer::schema_violation(format!(
                "ak.self.invites.command.dispatch.v1 body is not canonicalizable: {error}"
            ))
        })?)
        .map_err(|error| {
            AppError::internal(format!("invite delivery body is not utf8: {error}"))
        })?;
    let enqueued_id = uuid::Uuid::new_v4().to_string();
    let enqueued = state
        .federation()
        .enqueue_delivery(EnqueueFederationDeliveryCommand {
            delivery: FederationDeliveryRecord {
                id: enqueued_id.clone(),
                peer_id: recipient_id.clone(),
                peer_url: Some(entry.base_url().trim_end_matches('/').to_owned()),
                endpoint: PEER_INVITES_ENDPOINT.to_owned(),
                idempotency_key: delivery.idempotency_key.clone(),
                payload_json,
                coalescing_key: None,
                coalescing_position: None,
                realm_fanout: None,
                created_at: now().timestamp(),
            },
        })
        .await
        .map_err(|error| AppError::internal(format!("invite delivery enqueue: {error}")))?;
    let duplicate = enqueued.id != enqueued_id;
    super::append_audit_log(
        state,
        None,
        "self.invites.dispatch",
        json!({
            "idempotency_key": delivery.idempotency_key,
            "event_id": accepted.event_id,
            "invitee_id": delivery.invite_address.account_id.principal_id,
            "recipient_id": delivery.invite_address.account_id.station_id,
            "introduction_kind": delivery.introduction_evidence.kind(),
            "outbox_id": enqueued.id,
            "endpoint": PEER_INVITES_ENDPOINT,
        }),
        if duplicate { "duplicate" } else { "accepted" },
    )
    .await;
    Ok(InviteDeliveryOutcome {
        status: if duplicate {
            InviteDeliveryOutcomeStatus::Duplicate
        } else {
            InviteDeliveryOutcomeStatus::Accepted
        },
        // The recipient's receive decision is not knowable here, and §5.1
        // forbids inventing one, so the sender never echoes a disclosed
        // outcome for a remote target.
        disclosed_outcome: None,
        received_at: Some(now()),
        retry_after_ms: None,
    })
}

/// Merge one accepted delivery into the current `ak.account.invite_delivery`
/// cell (spec invite-addressing.md §7 write semantics): purge entries expired
/// at `received_at`, replace any prior entry for the same invite, append the
/// new entry, then evict the oldest entries beyond
/// [`InviteDelivery::MAX_ENTRIES`]. The result is validated against the SDK
/// cell contract before it is offered to the CAS write.

#[endpoint(
    operation_id = "ak.open.invite_locator.read.resolve",
    summary = "Resolve an invite locator",
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.invite_locator.read.resolve.v1"))]
async fn resolve_invite_locator(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PrincipalLocator> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if locator_token_appears_in_url(req) {
        return Err(AppError::param_invalid(
            "locator_token must be sent in the JSON body, never in URL path or query",
        ));
    }
    let body = req
        .parse_json::<InviteLocatorResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid invite locator resolve request body"))?;
    body.validate_minimal()
        .map_err(|_| invite_locator_not_found())?;
    let locator_token = body.locator_token.trim();
    let token_digest = format!("sha256:{}", sha256_hex(locator_token.as_bytes()));
    let locator_ref = state
        .invite_locators()
        .resolve_and_consume_locator(&token_digest, now())
        .await
        .map_err(|error| AppError::internal(format!("invite locator resolve: {error}")))?
        .ok_or_else(invite_locator_not_found)?;
    let subject_id =
        DidCoreId::new(locator_ref.subject_id.clone()).map_err(|_| invite_locator_not_found())?;
    let issued_at = locator_ref.issued_at;
    let expires_at = locator_ref.expires_at;
    let locator_ref_digest = Hash::new(locator_ref.token_digest.clone())
        .map_err(|error| AppError::internal(format!("locator_ref_digest invalid: {error}")))?;
    let display_hint = locator_ref.display_hint;
    let recipient_id = DidCoreId::new(locator_ref.recipient_id).map_err(|error| {
        AppError::internal(format!(
            "configured service DID invalid for principal locator: {error}"
        ))
    })?;
    let mut locator = PrincipalLocator {
        schema: arkret_wire::SchemaId::PRINCIPAL_LOCATOR_V1.to_owned(),
        account_id: arkret_wire::AccountId::new(subject_id, recipient_id.clone()),
        service_resolution: ServiceResolutionCarrier::ResolutionUrl {
            resolution_url: format!(
                "{}{}",
                state.config().public_base_url.trim_end_matches('/'),
                arkret_models_identity::canonical_service_resolution_path(&recipient_id)
            ),
        },
        route_assistance: None,
        issued_at,
        expires_at,
        locator_ref_digest,
        display_hint,
        proofs: Vec::new(),
    };
    let mut proof =
        DetachedPayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: state.service_verification_method("notary-key").map_err(
                |error| AppError::internal(format!("principal locator signing method: {error}")),
            )?,
            payload_digest: locator.payload_digest().map_err(|error| {
                AppError::internal(format!("principal locator digest: {error}"))
            })?,
            created_at: now(),
            domain: None,
            audience: None,
            jws: String::new(),
        };
    let signing_bytes = locator
        .proof_signing_bytes(&proof)
        .map_err(|error| AppError::internal(format!("principal locator transcript: {error}")))?;
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &signing_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("principal locator sign: {error}")))?;
    locator.proofs = vec![PrincipalLocatorProof {
        proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
        proof,
    }];
    locator.validate_minimal().map_err(|error| {
        AppError::internal(format!("principal locator validation failed: {error}"))
    })?;
    json_ok(locator)
}

/// Run the new-source admission chokepoint for one first contact.
///
/// `consent-model.md` section 6.1.1.3 puts all three first-contact surfaces --
/// private invite delivery, `ak.self.consent.command.request.v1` and a stranger's
/// first Contact request -- on this one seen-source ledger and this one quota,
/// so they share the function, the digest and the effective ceiling. Only the
/// object dropped on refusal differs: a quarantine entry for the first two, the
/// establishment of the Contact `pending_incoming` row for the third
/// (`identity/contact-and-direct-conversation.md` section 1.1).
///
/// Returns `true` when the caller may proceed -- either because this source was
/// already admitted inside the retention window, or because it fit under both
/// sliding ceilings and was just charged. `false` means the delivery is silently
/// dropped: no ledger write, no cell write, and the same opaque outcome the
/// requester sees for every other member of the section 6.1.1 equivalence class.
pub(crate) async fn admit_quarantine_new_source(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    inviter_id: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, AppError> {
    let quota = effective_new_source_quota(state, account_id)?;
    let source_digest = new_source_ledger_digest(state, account_id, inviter_id).await?;
    let admission = state
        .persistence()
        .invite_new_source_ledger_store()
        .admit_new_source(account_id, &source_digest, received_at, &quota)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(admission != NewSourceAdmission::Denied)
}

/// Intersect the deployment ceiling with the holder override.
///
/// An absent deployment object is not "quota off": section 6.1.1.1 makes the
/// quota a MUST, so the specification defaults apply and the empty constraints
/// object produces exactly those.
///
/// `applies_to` is deliberately NOT consulted here. Section 6.1.1.1 makes
/// `new_source_quota` the threshold of the single holder admission chokepoint
/// of section 6.1.1.3, where invite delivery, contact delivery and the section
/// 6.1.2 consent request share one ledger and one set of thresholds; filtering
/// it per surface would put two sets of thresholds on one ledger. `applies_to`
/// only selects the introduction-evidence and disclosure members, which is why
/// `constraints_for_surface` still applies it everywhere else in this file.
fn effective_new_source_quota(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
) -> Result<EffectiveNewSourceQuota, AppError> {
    let constraints = state
        .config()
        .receive_policy_constraints
        .as_ref()
        .and_then(|constraints| constraints.new_source_quota.clone())
        .unwrap_or_default();
    let policy = resolve_core_invite_receive_policy(state, account_id);
    constraints
        .effective(policy.new_source_quota.as_ref())
        .map_err(|error| AppError::internal(error.to_string()))
}

/// Equality-only source tag under the holder's immutable durable private key.
pub(crate) async fn new_source_ledger_digest(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    inviter_id: &str,
) -> Result<String, AppError> {
    let source = arkret_wire::DidCoreId::new(inviter_id.to_owned())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    state
        .persistence()
        .invite_new_source_ledger_store()
        .source_digest(account_id, &source)
        .await
        .map_err(|error| crate::app_error!(TemporarilyUnavailable, error.to_string()))
}

/// Effective trust tier of an introduction evidence kind, *after* any
/// `consent_grant` verification downgrade has been resolved by the caller.
/// Read the subject's private `invite_receive_policy`, falling back to the
/// conservative protocol default when the subject has never published one.
///
/// `invite-addressing.md` section 5 makes that default normative: a subject
/// without a published policy accepts only the high-trust introduction kinds
/// and quarantines or drops everything else. Erroring out instead would both
/// break that default and leak, through a distinguishable status, whether the
/// subject has ever published a policy — which section 5.1 requires to stay
/// indistinguishable from an ordinary quarantine.
pub(crate) fn resolve_core_invite_receive_policy(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
) -> InviteReceivePolicy {
    state
        .contacts()
        .invite_policy(account_id)
        .unwrap_or_else(|| InviteReceivePolicy::spec_default(account_id.clone()))
}

#[cfg(test)]
fn evaluate_invite_receive(
    state: &AppState,
    policy: &InviteReceivePolicy,
    evidence: &IntroductionEvidence,
    inviter_actor_id: &arkret_wire::ActorId,
    subject: &str,
    recipient_id: &str,
    source_id: &str,
    same_station: bool,
    verified_consent: bool,
) -> ReceiveDecision {
    let at = now();
    let locator_verified = match evidence {
        IntroductionEvidence::LocatorRef { principal_locator } => {
            verified_locator_for_recipient(state, principal_locator, subject, recipient_id, at)
        }
        _ => false,
    };
    coland_domain::invite_receive::evaluate_resolved(
        constraints_for_surface(state, ReceivePolicySurface::InviteDelivery),
        locator_verified,
        at,
        policy,
        evidence,
        inviter_actor_id,
        subject,
        recipient_id,
        source_id,
        same_station,
        verified_consent,
    )
}

fn verified_locator_for_recipient(
    state: &AppState,
    locator: &PrincipalLocator,
    subject: &str,
    recipient_id: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    if locator.validate_minimal().is_err()
        || locator.account_id.principal_id.as_str() != subject
        || locator.account_id.station_id.as_str() != recipient_id
        || locator.issued_at > at
        || locator.expires_at <= at
    {
        return false;
    }
    locator.proofs.iter().any(|entry| {
        let proof = &entry.proof;
        if entry.proof_purpose != PrincipalLocatorProofPurpose::RecipientServiceAcceptance
            || proof.kind != "detached_jws"
            || proof.created_at < locator.issued_at
            || proof.created_at > at
            || proof.created_at >= locator.expires_at
        {
            return false;
        }
        let Ok(transcript) = locator.proof_signing_bytes(proof) else {
            return false;
        };
        crate::jws_verify::verify_did_controlled_jws(
            &transcript,
            &proof.jws,
            proof.verification_method.as_str(),
            recipient_id,
            state,
        )
        .is_ok()
    })
}

#[cfg(test)]
pub(crate) fn evaluate_contact_receive(
    state: &AppState,
    policy: &InviteReceivePolicy,
    evidence: &ContactIntroductionEvidence,
    requester_id: &str,
    subject: &str,
    recipient_id: &str,
    source_id: &str,
) -> ReceiveDecision {
    let now = now();
    let constraints = constraints_for_surface(state, ReceivePolicySurface::ContactRequest);
    let effective_kind: &'static str = match evidence {
        ContactIntroductionEvidence::LocatorRef { principal_locator } => {
            if verified_locator_for_recipient(state, principal_locator, subject, recipient_id, now)
            {
                "locator_ref"
            } else {
                "explicit_address"
            }
        }
        ContactIntroductionEvidence::SharedRealm { realm_id, .. } => {
            if policy.trusted_realm_ids.is_empty()
                || policy
                    .trusted_realm_ids
                    .iter()
                    .any(|trusted| trusted == realm_id)
            {
                "shared_realm"
            } else {
                "explicit_address"
            }
        }
        ContactIntroductionEvidence::HandleClaim {
            handle,
            handle_claim,
            resolved_by,
            ..
        } => {
            if handle_claim_evidence_valid(
                policy,
                constraints,
                handle,
                handle_claim,
                resolved_by.as_ref(),
                subject,
                recipient_id,
                now,
            ) {
                "handle_claim"
            } else {
                "explicit_address"
            }
        }
        ContactIntroductionEvidence::SameStation => "same_station",
        ContactIntroductionEvidence::ExplicitAddress => "explicit_address",
    };

    let requester_actor = DidCoreId::new(requester_id.to_owned())
        .ok()
        .zip(DidCoreId::new(source_id.to_owned()).ok())
        .map(|(principal_id, station_id)| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal_id, station_id))
        });
    if requester_actor.as_ref().is_some_and(|requester| {
        policy
            .denied_actor_ids
            .iter()
            .any(|actor| actor == requester)
    }) || principal_service_blocked(policy, constraints, source_id)
        || !principal_service_trusted(policy, constraints, source_id)
        || !subject_did_method_accepted(constraints, subject)
        || kind_forbidden_by_constraints(constraints, effective_kind)
        || !kind_permitted_by_constraints(constraints, effective_kind)
    {
        return opaque_drop(effective_kind);
    }

    // consent-model.md §6.1 step 2 — the holder's `require_explicit_consent`
    // profile applies to first-contact delivery exactly as to invites.
    if policy.consent_profile.requires_explicit_consent() && effective_kind != "consent_grant" {
        return opaque_drop(effective_kind);
    }

    let trust_tier = trust_tier_for_kind(effective_kind);
    let action = receive_action_for_kind(policy, constraints, effective_kind);
    let disclosure_level = match trust_tier {
        TrustTier::High => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.high_trust.clone())
            .unwrap_or(DisclosureLevel::Outcome),
        TrustTier::Discovery => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.discovery_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
        TrustTier::Low => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.low_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
    };
    let disclosed_outcome = disclosed_outcome_for_action(disclosure_level, &action);
    ReceiveDecision {
        action,
        effective_kind,
        trust_tier,
        disclosed_outcome,
    }
}

fn constraints_for_surface(
    state: &AppState,
    surface: ReceivePolicySurface,
) -> Option<&ReceivePolicyConstraints> {
    state
        .config()
        .receive_policy_constraints
        .as_ref()
        .filter(|constraints| {
            constraints
                .applies_to
                .as_ref()
                .is_none_or(|surfaces| surfaces.contains(&surface))
        })
}

/// Verify the original Invite Full receipt using its governance chain,
/// exact immutable signer fact and actual Event Ed signature before holder
/// lookup. Locator hints discover the authority; no member scan or current
/// producer key lookup supplies the missing historical fact.
async fn verify_invite_commit(
    state: &AppState,
    delivery: &InviteDeliveryRequestBody,
) -> Result<
    arkret_identity::account_device_signer_evidence::VerifiedAccountDeviceHistoricalSignerFact,
    AppError,
> {
    // Reject malformed or cryptographically impossible source material before
    // network discovery and before any holder-private lookup. This is a
    // rejection-only precheck: successful receipt still requires the complete
    // independent historical governance verification below.
    delivery.validate_minimal().map_err(|e| {
        AppError::from_rejection(
            coland_http::error::ErrorCode::SchemaViolation,
            e.to_string(),
        )
    })?;
    if let Some(fact) = delivery.producer_signer_fact.as_ref() {
        let suite = delivery
            .invite_event
            .realm_id
            .digest_suite_code()
            .digest_suite();
        fact.validate_commit_binding(
            &arkret_wire::CommittedEventFullView {
                event: delivery.invite_event.clone(),
                commit: delivery.invite_commit.clone(),
            },
            suite,
        )
        .map_err(|error| {
            AppError::from_rejection(
                coland_http::error::ErrorCode::SignatureInvalid,
                error.to_string(),
            )
        })?;
    }
    match delivery.producer_signer_fact.as_ref() {
        Some(fact) => arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
            &delivery.invite_event,fact,state.projections().realm_digest_suite(delivery.invite_event.realm_id.as_str())
        ).map_err(|e| AppError::from_rejection(coland_http::error::ErrorCode::SignatureInvalid,e.to_string()))?,
        None if delivery.invite_event.human_device_producer().map_err(|e| AppError::param_invalid(e.to_string()))?.is_some() =>
            return Err(AppError::from_rejection(coland_http::error::ErrorCode::TemporarilyUnavailable,"original Invite Human source is unavailable")),
        None => {},
    }
    let unavailable = |detail: String| {
        AppError::from_rejection(
            coland_http::error::ErrorCode::TemporarilyUnavailable,
            detail,
        )
    };
    let nonce =
        arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()))
            .map_err(|error| AppError::internal(format!("authority bundle nonce: {error}")))?;
    let realm_id = &delivery.invite_event.realm_id;
    let mut located = super::realm_join::resolve_verified_authority(
        state,
        realm_id,
        &delivery.authority_locator_hints,
        &nonce,
    )
    .await
    .map_err(|error| unavailable(format!("invite Realm authority is unavailable: {error}")))?;
    super::realm_join::insert_historical_method_key(
        state,
        &mut located.keys,
        &delivery.invite_commit.signature.verification_method,
        delivery.invite_commit.signature.created_at,
    )
    .await
    .map_err(|error| unavailable(format!("invite_commit signing key is unavailable: {error}")))?;
    let received = coland_services::committed_receipt::verify_committed_event_receipt_with_fact(
        state.persistence(),
        &delivery.invite_event,
        &delivery.invite_commit,
        coland_services::committed_receipt::CommitContinuity::Standalone,
        &located.authority,
        &located.keys,
        &state.service_core_id(),
        state.projections().realm_digest_suite(realm_id.as_str()),
        delivery
            .producer_signer_fact
            .clone()
            .map(Into::into)
            .as_ref(),
    )
    .await
    .map_err(receipt_refusal)?;
    match received {
        coland_services::committed_receipt::ReceivedProducer::GovernanceCommittedHumanDevice
        | coland_services::committed_receipt::ReceivedProducer::HostedHumanDevice(_) => {
            let fact=delivery.producer_signer_fact.as_ref().ok_or_else(||unavailable("Invite original human source is missing".to_owned()))?;
            arkret_identity::account_device_signer_evidence::verify_historical_account_device_committed_event(
                &arkret_wire::CommittedEventFullView{event:delivery.invite_event.clone(),commit:delivery.invite_commit.clone()},fact,&located.authority,&located.keys,delivery.invite_event.realm_id.digest_suite_code().digest_suite()
            ).map_err(|e|AppError::from_rejection(coland_http::error::ErrorCode::SignatureInvalid,e.to_string()))
        },
        coland_services::committed_receipt::ReceivedProducer::OtherSigner
        | coland_services::committed_receipt::ReceivedProducer::GovernanceCommittedService => Err(unavailable(
            "invite producer is not a human Account device; its signer evidence is not connected"
                .to_owned(),
        )),
    }
}

fn receipt_refusal(error: coland_services::ServiceError) -> AppError {
    let code = match &error {
        coland_services::ServiceError::SchemaViolation(_) => {
            Some(coland_http::error::ErrorCode::SchemaViolation)
        }
        _ => error
            .conflict_code()
            .and_then(|code| coland_http::error::ErrorCode::from_wire(code.as_str())),
    };
    match code {
        Some(code) => AppError::from_rejection(code, error.to_string()),
        None => AppError::internal(error.to_string()),
    }
}

/// Spec invite-addressing.md §7 step 4's first clause.
fn validate_invite_delivery_event_kind(body: &Value) -> Result<(), AppError> {
    if body.pointer("/invite_event/kind").and_then(Value::as_str)
        != Some(arkret_wire::EventKind::InviteCreate.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.kind must be ak.invite.create",
        ));
    }
    Ok(())
}

/// Spec invite-addressing.md §7 steps 4-7 — the target-independent bindings
/// between `invite_event` and the delivery envelope. The receiving service and
/// the dispatching service both owe these.
fn validate_invite_delivery_event_binding(
    body: &Value,
    delivery: &InviteDeliveryRequestBody,
) -> Result<(), AppError> {
    validate_invite_delivery_event_kind(body)?;
    let payload = body
        .pointer("/invite_event/payload")
        .and_then(Value::as_object)
        .ok_or_else(|| super::events::peer::schema_violation("invite_event.payload is required"))?;
    let invitee = payload
        .get("invitee_account_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::AccountId>(value).ok());
    let expected = arkret_wire::AccountId::new(
        delivery.invite_address.account_id.principal_id.clone(),
        delivery.invite_address.account_id.station_id.clone(),
    );
    if invitee.as_ref() != Some(&expected) {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.invitee_account_id must bind invite_address subject and recipient Station",
        ));
    }
    let evidence_digest =
        canonical::canonical_sha256(&body["introduction_evidence"]).map_err(|error| {
            super::events::peer::schema_violation(format!(
                "introduction_evidence is not canonical-hashable: {error}"
            ))
        })?;
    if payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        != Some(evidence_digest.as_str())
    {
        return Err(super::events::peer::schema_violation(
            "invite_event.payload.introduction_evidence_digest must equal digest(canonical_json(introduction_evidence))",
        ));
    }
    Ok(())
}

fn required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            super::events::peer::schema_violation(format!(
                "required federation header {name} missing"
            ))
        })
}

fn locator_token_appears_in_url(req: &Request) -> bool {
    req.uri().query().is_some()
}

fn invite_locator_not_found() -> AppError {
    AppError::not_found("invite locator not found")
}

#[cfg(test)]
mod invite_locator_security_tests {

    use coland_services::identity::AccountProfileState;
    use coland_test_support::AppStateTestExt as _;
    use coland_test_support::pcr_genesis::PcrGenesisFixture;

    use super::*;

    const PRODUCTION_HOLDER: &str = "ak:did_core:web:holder.example";
    const PRODUCTION_INVITER: &str = "ak:did_core:web:inviter_id.example";
    const PRODUCTION_REALM: &str = "ak:realm:AYkVIjHoT1TUr0UDS-J-SsVmyIMnmNBsp4GAAxZiFj2W";
    const PRODUCTION_INVITE_EVENT: &str = "ak:event:AbMdINsWEW01xiLsvC3anbe65njppPPCVoNeYM6ES_E2";

    #[tokio::test]
    async fn locator_trust_requires_the_account_bound_recipient_signature() {
        let state = production_holder_state().await;
        let at = now();
        let mut locator = PrincipalLocator {
            schema: arkret_wire::SchemaId::PRINCIPAL_LOCATOR_V1.to_owned(),
            account_id: arkret_wire::AccountId::new(
                DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
                state.service_core_id().clone(),
            ),
            service_resolution: ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: "https://coland.test/_arkret/open/services/resolution".to_owned(),
            },
            route_assistance: None,
            issued_at: at,
            expires_at: at + Duration::minutes(5),
            locator_ref_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            display_hint: None,
            proofs: Vec::new(),
        };
        let mut proof = DetachedPayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: state.service_verification_method("notary-key").unwrap(),
            payload_digest: locator.payload_digest().unwrap(),
            created_at: at,
            domain: None,
            audience: None,
            jws: String::new(),
        };
        proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &locator.proof_signing_bytes(&proof).unwrap(),
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
        locator.proofs.push(PrincipalLocatorProof {
            proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
            proof,
        });
        assert!(verified_locator_for_recipient(
            &state,
            &locator,
            PRODUCTION_HOLDER,
            state.service_id(),
            at
        ));

        let mut forged = locator.clone();
        forged.account_id.principal_id = DidCoreId::new(PRODUCTION_INVITER.to_owned()).unwrap();
        forged.proofs[0].proof.payload_digest = forged.payload_digest().unwrap();
        assert!(!verified_locator_for_recipient(
            &state,
            &forged,
            PRODUCTION_INVITER,
            state.service_id(),
            at
        ));

        let mut raw_payload_signature = locator.clone();
        let mut payload = serde_json::to_value(&raw_payload_signature).unwrap();
        payload.as_object_mut().unwrap().remove("proofs");
        raw_payload_signature.proofs[0].proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &canonical::canonical_json_bytes(&payload).unwrap(),
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
        assert!(!verified_locator_for_recipient(
            &state,
            &raw_payload_signature,
            PRODUCTION_HOLDER,
            state.service_id(),
            at
        ));
        assert!(!verified_locator_for_recipient(
            &state,
            &locator,
            PRODUCTION_HOLDER,
            state.service_id(),
            locator.expires_at
        ));
    }

    async fn production_holder_state() -> AppState {
        production_holder_state_with_config(crate::config::AppConfig {
            development_mode: false,
            seed_demo_data: false,
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("coland-invite-service-fanout-test-blobs"),
            ),
            ..crate::config::AppConfig::test_default()
        })
        .await
    }

    async fn production_holder_state_with_config(config: crate::config::AppConfig) -> AppState {
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let created_at = now();
        state
            .identities()
            .save_account(AccountProfileState {
                pk: coland_storage::AccountPk(0),
                account_id: arkret_wire::AccountId::new(
                    DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
                    state.service_core_id().clone(),
                ),
                principal_id: DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
                localpart: "holder".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at,
            })
            .await
            .expect("holder account");
        state
    }

    /// A production Station whose holder stands on a genuinely accepted PCR
    /// genesis. Station-materialized fanout reaches only devices of the
    /// holder's accepted device projection, so the founding device is the one
    /// target (device-lifecycle.md section 7).
    async fn accepted_holder_state() -> (AppState, String, String) {
        let config = crate::config::AppConfig {
            development_mode: false,
            seed_demo_data: false,
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("coland-invite-service-fanout-test-blobs"),
            ),
            ..crate::config::AppConfig::test_default()
        };
        let service_did =
            AppState::new(config.clone(), coland_storage_postgres::Db { pool: None }).service_did();
        let persisted = coland_test_support::app_state_with_service_did(
            coland_test_support::app_config(),
            service_did,
        );
        let state = AppState::new_with_persistence(
            config,
            coland_storage_postgres::Db { pool: None },
            persisted.test_persistence(),
        );
        let fixture = PcrGenesisFixture::new(state.service_did());
        fixture
            .admit_into(state.test_persistence().as_ref())
            .await
            .expect("accepted PCR genesis");
        let holder = fixture.history.account.principal_id.clone();
        state
            .identities()
            .save_account(AccountProfileState {
                pk: coland_storage::AccountPk(0),
                account_id: arkret_wire::AccountId::new(holder.clone(), state.service_core_id()),
                principal_id: holder.clone(),
                localpart: "holder".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: now(),
            })
            .await
            .expect("holder account");
        (
            state,
            holder.to_string(),
            fixture.history.founding_device_id.to_string(),
        )
    }

    fn fixture_locator_hint() -> RealmJoinCandidate {
        RealmJoinCandidate {
            service_kind: RealmJoinCandidateServiceKind::Station,
            service_id: DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
            endpoint_url: None,
            source: AuthorityLocatorSource::Invite,
        }
    }

    fn production_invite_delivery(state: &AppState) -> InviteDeliveryRequestBody {
        production_invite_delivery_for(state, PRODUCTION_HOLDER)
    }

    fn production_invite_delivery_for(state: &AppState, holder: &str) -> InviteDeliveryRequestBody {
        let event: arkret_wire::Event = serde_json::from_value(json!({
            "event_id": PRODUCTION_INVITE_EVENT,
            "kind": arkret_wire::EventKind::InviteCreate.as_str(),
            "realm_id": PRODUCTION_REALM,
            "scope_ref": { "kind": "realm", "realm_id": PRODUCTION_REALM },
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": PRODUCTION_INVITER, "station_id": state.service_id()
            }},
            "created_at": "2026-08-21T00:00:00.000Z",
            "payload": {
                "invitee_account_id": {"principal_id": holder, "station_id": state.service_id()},
                "introduction_evidence_digest": canonical::canonical_sha256(&IntroductionEvidence::ExplicitAddress).unwrap(),
                "expires_at": "2099-01-01T00:00:00.000Z"
            }
        }))
        .expect("invite Event");
        let service_id = DidCoreId::new(state.service_id().to_owned()).unwrap();
        let address =
            arkret_models_collaboration::governance::invite_addressing::InviteAddress::station(
                DidCoreId::new(holder.to_owned()).unwrap(),
                service_id,
                ServiceResolutionCarrier::ResolutionUrl {
                    resolution_url: "https://coland.test/.well-known/arkret/current".to_owned(),
                },
            );
        // These fixtures exercise the receive policy, quarantine and fanout
        // helpers directly; §7 step 4 has its own coverage and is not on their
        // path.
        let invite_commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                event.event_id.as_str().as_bytes(),
            )),
            realm_id: event.realm_id.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position: 1,
            previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([0x01; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.realm_id.event_id(),
            ),
            committed_at: now(),
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: state.service_verification_method("notary-key").unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: now(),
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        };
        serde_json::from_value(json!({
            "schema": arkret_wire::SchemaId::INVITE_DELIVERY_REQUEST_V1,
            "invite_event": event, "invite_commit": invite_commit,
            "authority_locator_hints": [{"service_kind":"station", "service_id":state.service_core_id(),
                "endpoint_url":null, "source":"invite"}],
            "invite_address":address, "introduction_evidence":IntroductionEvidence::ExplicitAddress,
            "idempotency_key":"ak:idempotency:production-service-fanout"
        })).expect("legacy policy-only fixture; not a new accepted Human submission")
    }

    /// `invite-addressing.md` §7 — a step-4 rejection MUST leave zero
    /// holder-private writes, zero outbox entries and zero quota charged.
    ///
    /// A malformed notification fails before any holder-private lookup or write.
    #[tokio::test]
    async fn a_step_four_rejection_writes_nothing_holder_private() {
        let state = production_holder_state().await;
        let delivery = production_invite_delivery(&state);
        let body = serde_json::to_value(&delivery).unwrap();
        let session = SessionRecord {
            token_hash: "peer-invite:test".to_owned(),
            account_pk: None,
            actor: PRODUCTION_INVITER.to_owned(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "peer-invite:test".to_owned(),
            },
            audience: state.service_id().clone(),
            session_public_key: None,
            session_grant: None,
            expires_at: now() + Duration::minutes(5),
            created_at: now(),
            revoked_at: None,
        };
        let error = receive_private_invite_delivery(
            &state,
            &delivery,
            &body,
            state.service_id(),
            "peer.invites.submit",
        )
        .await
        .expect_err("a malformed notification fails authentication");
        assert_eq!(error.wire_code(), "schema_violation");

        let holder_actor =
            arkret_wire::ActorId::account(delivery.invite_address.account_id.clone()).to_string();
        assert!(
            state
                .account_data()
                .entry(&holder_actor, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
                .await
                .expect("holder quarantine read")
                .is_none(),
            "a step-4 rejection must not create the holder quarantine cell"
        );
        assert!(
            state
                .account_data()
                .entry(&holder_actor, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
                .await
                .expect("holder invite delivery read")
                .is_none(),
            "a step-4 rejection must not create the holder invite delivery cell"
        );
    }

    #[tokio::test]
    async fn genuine_invite_source_refusals_precede_holder_quarantine_delivery_and_outbox_writes() {
        use coland_storage::EventCommitUnitOfWork as _;
        use coland_test_support::AppStateTestExt as _;
        let (state, holder, _) = accepted_holder_state().await;
        let (sender, pool) =
            coland_test_support::app_state_with_pool(coland_test_support::app_config());
        let fixture =
            coland_test_support::historical_human::HumanFixture::new(&pool, sender.service_did())
                .await;
        fixture.admit(&pool).await;
        let pcr = &fixture.pcr;
        let template = production_invite_delivery_for(&state, &holder);
        let previous = fixture.unit.transactions.last().unwrap();
        let at = previous.commit.committed_at + Duration::seconds(1);
        let event = coland_test_support::device_authorization_history::sign_event(
            arkret_wire::test_support::raw_event_at(
                arkret_wire::EventKind::InviteCreate.as_str(),
                previous.event.scope_ref.clone(),
                pcr.history.account.principal_id.clone(),
                pcr.history.account.station_id.clone(),
                serde_json::to_value(&template.invite_event.payload).unwrap(),
                at,
            )
            .unwrap(),
            pcr.history.device_verification_method.clone(),
            pcr.history.founding_device_signing_seed,
        );
        let request =
            coland_test_support::historical_human::request_for_event(&fixture, previous, event, at);
        coland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(request.clone())
            .await
            .unwrap();
        let accepted = sender
            .test_persistence()
            .authority_commits()
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap();
        let fact = sender
            .test_persistence()
            .authority_commits()
            .account_device_signer_fact(&accepted.event, &accepted.commit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Some(fact.clone().into()),
            request.authority_commit.producer_signer_fact
        );
        arkret_signatures::detached_object::verify_detached_object_signature(
            &accepted.commit.signature,
            &arkret_canonical::canonical::unsigned_value(&accepted.commit, &["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: ed25519_dalek::SigningKey::from_bytes(
                    &coland_test_support::device_authorization_history::STATION_AUTHORITY_SEED,
                )
                .verifying_key()
                .to_bytes()
                .to_vec(),
            },
        )
        .unwrap();
        let valid = InviteDeliveryRequestBody::new(
            accepted.event,
            accepted.commit,
            Some(fact),
            template.authority_locator_hints,
            template.invite_address,
            template.introduction_evidence,
            "ak:idempotency:true-source-refusal",
        )
        .unwrap();
        assert!(
            state
                .test_persistence()
                .federation_outbox()
                .snapshot_all()
                .await
                .unwrap()
                .is_empty()
        );
        let mut missing = valid.clone();
        missing.producer_signer_fact = None;
        let mut wrong_digest = valid.clone();
        wrong_digest.invite_commit.producer_signer_fact_digest =
            Some(arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"another fact")).unwrap());
        let mut wrong_key = valid.clone();
        wrong_key
            .producer_signer_fact
            .as_mut()
            .unwrap()
            .key
            .public_key_b64u =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[0x79; 32])
                    .verifying_key()
                    .as_bytes(),
            ))
            .unwrap();
        wrong_key.invite_commit.producer_signer_fact_digest = Some(
            wrong_key
                .producer_signer_fact
                .as_ref()
                .unwrap()
                .digest()
                .unwrap(),
        );
        coland_test_support::historical_human::seal_commit(
            &mut wrong_key.invite_commit,
            &pcr.history.station_did,
        );
        let mut legacy = valid.clone();
        legacy.producer_signer_fact = None;
        legacy.invite_commit.producer_signer_fact_digest = None;
        coland_test_support::historical_human::seal_commit(
            &mut legacy.invite_commit,
            &pcr.history.station_did,
        );
        let session = SessionRecord {
            token_hash: "fixture-peer-invite".into(),
            account_pk: None,
            actor: pcr.history.account.principal_id.to_string(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: pcr.history.founding_device_id.to_string(),
            },
            audience: state.service_id().clone(),
            session_public_key: None,
            session_grant: None,
            expires_at: now() + Duration::minutes(5),
            created_at: now(),
            revoked_at: None,
        };
        for (name, delivery, code) in [
            ("missing", missing, "schema_violation"),
            ("wrong_digest", wrong_digest, "signature_invalid"),
            ("wrong_real_key", wrong_key, "signature_invalid"),
            ("legacy", legacy, "temporarily_unavailable"),
        ] {
            let body = serde_json::to_value(&delivery).unwrap();
            let error = receive_private_invite_delivery(
                &state,
                &delivery,
                &body,
                state.service_id(),
                "peer.invites.submit",
            )
            .await
            .unwrap_err();
            assert_eq!(error.wire_code(), code, "{name}");
            let holder = arkret_wire::ActorId::account(delivery.invite_address.account_id.clone())
                .to_string();
            for key in [
                AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
                AccountDataKey::ACCOUNT_INVITE_DELIVERY,
            ] {
                assert!(
                    state
                        .account_data()
                        .entry(&holder, key)
                        .await
                        .unwrap()
                        .is_none(),
                    "{name}: zero holder-private writes"
                );
            }
            assert!(
                state
                    .test_persistence()
                    .federation_outbox()
                    .snapshot_all()
                    .await
                    .unwrap()
                    .is_empty(),
                "{name}: zero receiver outbox writes"
            );
            assert!(
                state
                    .test_persistence()
                    .authority_commits()
                    .committed_event(&delivery.invite_event.event_id)
                    .await
                    .unwrap()
                    .is_none(),
                "{name}: receipt does not admit target Event/Commit"
            );
        }
    }

    #[test]
    fn issued_secret_is_192_bit_opaque_and_never_enters_the_durable_record() {
        let (record, token) = new_invite_locator(
            "did:webvh:z6mkfixture:alice.example",
            "did:webvh:z6mkfixture:ps.example",
            InviteLocatorIssueRequestBody::default(),
        )
        .unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&token).unwrap().len(), 24);
        assert!(serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(&token).unwrap()).is_err());
        let durable = format!("{record:?}");
        assert!(!durable.contains(&token));
        assert_eq!(
            record.token_digest,
            format!("sha256:{}", sha256_hex(token.as_bytes()))
        );
    }

    /// `consent-model.md` section 6.1 step 2 -- under the holder's
    /// `require_explicit_consent` profile every delivery without verified
    /// `consent_grant` evidence is an opaque drop, even when the evidence kind
    /// is allowlisted, configured to notify and disclosed with `outcome`. The
    /// drop is what upstream maps to the same opaque `deferred` as a
    /// quarantine, so the profile itself is not observable by the requester.
    #[tokio::test]
    async fn require_explicit_consent_profile_drops_every_non_consent_grant_delivery() {
        let state = production_holder_state().await;
        let holder_account = arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        );
        let mut policy = InviteReceivePolicy::spec_default(holder_account);
        policy
            .holder_allowed_introduction_kinds
            .extend(["explicit_address".to_owned(), "same_station".to_owned()]);
        policy.explicit_address_behavior = InviteReceiveAction::Notify;
        policy.disclosure = Some(
            arkret_models_collaboration::governance::invite_addressing::DisclosurePolicy {
                high_trust: Some(DisclosureLevel::Outcome),
                discovery_trust: Some(DisclosureLevel::Outcome),
                low_trust: Some(DisclosureLevel::Outcome),
            },
        );
        let inviter_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_INVITER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        ));
        let evaluate_invite = |policy: &InviteReceivePolicy| {
            evaluate_invite_receive(
                &state,
                policy,
                &IntroductionEvidence::ExplicitAddress,
                &inviter_actor,
                PRODUCTION_HOLDER,
                state.service_id(),
                state.service_id(),
                true,
                false,
            )
        };
        let evaluate_contact = |policy: &InviteReceivePolicy| {
            evaluate_contact_receive(
                &state,
                policy,
                &ContactIntroductionEvidence::ExplicitAddress,
                PRODUCTION_INVITER,
                PRODUCTION_HOLDER,
                state.service_id(),
                state.service_id(),
            )
        };

        // Default profile: the holder's own notify choice stands.
        assert_eq!(policy.consent_profile, arkret_wire::ConsentProfile::Default);
        assert_eq!(evaluate_invite(&policy).action, InviteReceiveAction::Notify);
        assert_eq!(
            evaluate_contact(&policy).action,
            InviteReceiveAction::Notify
        );

        policy.consent_profile = arkret_wire::ConsentProfile::RequireExplicitConsent;
        let invite = evaluate_invite(&policy);
        assert_eq!(invite.action, InviteReceiveAction::Drop);
        assert!(
            invite.disclosed_outcome.is_none(),
            "the profile drop must stay inside the opaque deferred class"
        );
        let contact = evaluate_contact(&policy);
        assert_eq!(contact.action, InviteReceiveAction::Drop);
        assert!(contact.disclosed_outcome.is_none());
    }

    /// `invite-addressing.md` §5 — `holder_allowed_introduction_kinds` is an
    /// allowlist and an evidence kind outside it MUST NOT reach a user
    /// notification, however the holder configured that kind's own behavior.
    /// The behavior field alone used to decide the outcome, so a holder who set
    /// `explicit_address_behavior = notify` without allowlisting the kind was
    /// notified anyway.
    #[tokio::test]
    async fn a_kind_outside_the_allowlist_never_notifies() {
        let state = production_holder_state().await;
        let holder_account = arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_HOLDER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        );
        let mut policy = InviteReceivePolicy::spec_default(holder_account);
        policy.explicit_address_behavior = InviteReceiveAction::Notify;
        policy.handle_claim_behavior = Some(InviteReceiveAction::Notify);
        let inviter_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(PRODUCTION_INVITER.to_owned()).unwrap(),
            state.service_core_id().clone(),
        ));

        // `spec_default` allowlists only the high-trust kinds, so the delivery
        // downgrades to the low-trust tier and must stay out of the inbox.
        let invite = evaluate_invite_receive(
            &state,
            &policy,
            &IntroductionEvidence::ExplicitAddress,
            &inviter_actor,
            PRODUCTION_HOLDER,
            state.service_id(),
            state.service_id(),
            true,
            false,
        );
        assert_eq!(invite.effective_kind, "same_station");
        assert_eq!(invite.action, InviteReceiveAction::Quarantine);

        let contact = evaluate_contact_receive(
            &state,
            &policy,
            &ContactIntroductionEvidence::ExplicitAddress,
            PRODUCTION_INVITER,
            PRODUCTION_HOLDER,
            state.service_id(),
            state.service_id(),
        );
        assert_eq!(contact.effective_kind, "explicit_address");
        assert_eq!(contact.action, InviteReceiveAction::Quarantine);

        // Allowlisting the kind is what makes the holder's own `notify` choice
        // effective.
        policy
            .holder_allowed_introduction_kinds
            .push("same_station".to_owned());
        let invite = evaluate_invite_receive(
            &state,
            &policy,
            &IntroductionEvidence::ExplicitAddress,
            &inviter_actor,
            PRODUCTION_HOLDER,
            state.service_id(),
            state.service_id(),
            true,
            false,
        );
        assert_eq!(invite.action, InviteReceiveAction::Notify);
    }

    #[tokio::test]
    async fn invite_delivery_binding_rejects_same_principal_at_another_station() {
        let state = production_holder_state().await;
        let delivery = production_invite_delivery(&state);
        let body = serde_json::to_value(&delivery).unwrap();
        validate_invite_delivery_event_binding(&body, &delivery).unwrap();
        let mut wrong_station = body.clone();
        wrong_station["invite_event"]["payload"]["invitee_account_id"]["station_id"] =
            json!("ak:did_core:web:another-station.example");
        assert!(validate_invite_delivery_event_binding(&wrong_station, &delivery).is_err());
        let mut bare_principal = body;
        bare_principal["invite_event"]["payload"]["invitee_account_id"] = json!(PRODUCTION_HOLDER);
        assert!(validate_invite_delivery_event_binding(&bare_principal, &delivery).is_err());
    }

    #[test]
    fn quarantine_is_never_disclosed_even_on_outcome_routes() {
        assert_eq!(
            disclosed_outcome_for_action(
                DisclosureLevel::Outcome,
                &InviteReceiveAction::Quarantine
            ),
            None
        );
        assert_eq!(
            disclosed_outcome_for_action(DisclosureLevel::Outcome, &InviteReceiveAction::Notify),
            Some(DisclosedOutcome::Delivered)
        );
        assert_eq!(
            disclosed_outcome_for_action(DisclosureLevel::Outcome, &InviteReceiveAction::Drop),
            Some(DisclosedOutcome::Blocked)
        );
    }

    #[test]
    fn invite_delivery_entry_activity_follows_expiry() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let entry_with_expiry = |expires_at: &str| InviteDeliveryEntry {
            invite_id: arkret_identifiers::InviteId::new(
                "ak:invite:AZYDg8DDhw3K_txXc2FaKw9baWMbenl1vvUcRFfpjp3K".to_owned(),
            )
            .unwrap(),
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:AYkVIjHoT1TUr0UDS-J-SsVmyIMnmNBsp4GAAxZiFj2W".to_owned(),
            )
            .unwrap(),
            inviter_account_id: arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
            ),
            authority_locator_hints: vec![fixture_locator_hint()],
            received_at: at,
            expires_at: chrono::DateTime::parse_from_rfc3339(expires_at)
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        assert!(invite_delivery_entry_active(
            &entry_with_expiry("2026-08-05T10:00:00.000Z"),
            at
        ));
        assert!(!invite_delivery_entry_active(
            &entry_with_expiry("2026-07-05T10:00:00.000Z"),
            at
        ));
        assert!(!invite_delivery_entry_active(
            &entry_with_expiry("2026-08-01T00:00:00.000Z"),
            at
        ));
    }

    #[test]
    fn invite_delivery_cell_merge_matches_the_spec_write_semantics() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let entry =
            |received_at: chrono::DateTime<chrono::Utc>, expires_at: &str| InviteDeliveryEntry {
                invite_id: arkret_identifiers::InviteId::new(
                    "ak:invite:AZYDg8DDhw3K_txXc2FaKw9baWMbenl1vvUcRFfpjp3K".to_owned(),
                )
                .unwrap(),
                realm_id: arkret_identifiers::RealmId::new(
                    "ak:realm:AYkVIjHoT1TUr0UDS-J-SsVmyIMnmNBsp4GAAxZiFj2W".to_owned(),
                )
                .unwrap(),
                inviter_account_id: arkret_wire::AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                    DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
                ),
                authority_locator_hints: vec![fixture_locator_hint()],
                received_at,
                expires_at: chrono::DateTime::parse_from_rfc3339(expires_at)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            };

        // A redelivery of the same invite replaces the previous entry instead
        // of taking a second slot, and an expired prior entry is purged.
        let earlier = at - chrono::Duration::days(1);
        let prior = InviteDelivery::new(at, vec![entry(earlier, "2026-07-05T10:00:00.000Z")]);
        let merged =
            merge_invite_delivery_cell(Some(prior), entry(at, "2026-08-05T10:00:00.000Z"), at)
                .expect("merge into a cell holding only a stale entry");
        assert_eq!(merged.delivery_entries.len(), 1);
        assert_eq!(merged.delivery_entries[0].received_at, at);
        assert_eq!(merged.updated_at, at);
        assert_eq!(merged.schema, InviteDelivery::SCHEMA);
        merged.validate().expect("merged cell validates");

        // Overflow evicts from the front (oldest first) down to the cap.
        let invite_id_for = |seed: u8| {
            arkret_identifiers::InviteId::from_event_id(&arkret_identifiers::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [seed; 32],
            ))
        };
        let full = InviteDelivery::new(
            at,
            (0..InviteDelivery::MAX_ENTRIES)
                .map(|index| {
                    let mut held = entry(earlier, "2026-08-05T10:00:00.000Z");
                    held.invite_id = invite_id_for(index as u8);
                    held
                })
                .collect(),
        );
        let mut new_entry = entry(at, "2026-08-05T10:00:00.000Z");
        new_entry.invite_id = invite_id_for(u8::MAX);
        let merged =
            merge_invite_delivery_cell(Some(full), new_entry, at).expect("merge into a full cell");
        assert_eq!(merged.delivery_entries.len(), InviteDelivery::MAX_ENTRIES);
        assert_eq!(
            merged
                .delivery_entries
                .last()
                .map(|entry| entry.invite_id.clone()),
            Some(invite_id_for(u8::MAX))
        );
    }
}
