//! `authority_forward` on both Stations of device-lifecycle §8.2.2.
//!
//! A real Account Device producer is resolved by one rule for every Event kind. When
//! the producer's Account lives on another Station, the forwarding Station
//! (the Account Station, "A") signs a fresh `account_device_signer_evidence`
//! from its own live PCR gate for every forwarding attempt and persists it
//! before sending; the governance Station ("B") admits the producer only from
//! that `producer_device_evidence`.
//!
//! B's order is fixed: an exact duplicate Event returns its original outcome;
//! then the Event-decided presence rule; then the evidence (source Station,
//! Service history at `attested_at`, expiry, authorization window over the
//! Event `created_at` and now, device status, producer/fragment/key binding);
//! then the ordinary membership, capability, policy and revision admission
//! with the complete evidence retained in the Event's Commit transaction.
//! Every refusal writes nothing.

use arkret_models_collaboration::authority_commit::{
    MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES, MlsGenesisMaterial, PeerAuthorityForwardEventRequest,
    PeerAuthorityForwardMlsRequest, PeerAuthoritySubmitOutcome, PeerAuthoritySubmitRequest,
    SelfAuthoritySubmitRequest,
};
use arkret_models_identity::{AccountDeviceSignerEvidence, ForwardAccountDeviceSignerEvidence};
use arkret_wire::{
    AuthoritySubmitOutcome, DidCoreId, ErrorCode, Event, EventAdmissionSubmission,
    MlsCommitSubmission,
};
use chrono::{DateTime, Utc};
use coland_services::authority_commit::AuthenticatedPeerContext;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{ConflictCode, ForwardAttemptStatus, ForwardedProducerDeviceEvidence};

use super::AppState;

fn temporarily_unavailable(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!(
        "{}: {detail}",
        ConflictCode::TemporarilyUnavailable
    ))
}

pub(super) fn wire_refusal(error: arkret_wire::WireError) -> ServiceError {
    ServiceError::protocol(
        error.error_code().unwrap_or(ErrorCode::SchemaViolation),
        error,
    )
}

#[cfg(feature = "test-support")]
pub(crate) async fn fresh_forward_request(
    state: &AppState,
    mut request: PeerAuthoritySubmitRequest,
    destination: &DidCoreId,
) -> ServiceResult<PeerAuthoritySubmitRequest> {
    fresh_device_request(state, destination, &mut request).await?;
    Ok(request)
}

/// Governance Station check of one forwarded Account Device producer.
///
/// `evidence` has already passed the Event-decided presence rule, so `None`
/// means the producer is not an Account Device producer.
fn verify_forwarded_producer(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    event: &Event,
    evidence: Option<&ForwardAccountDeviceSignerEvidence>,
    body_digest: &arkret_wire::Hash,
    now: DateTime<Utc>,
) -> ServiceResult<Option<ForwardedProducerDeviceEvidence>> {
    arkret_event_draft::validate_event_for_submit(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let digest_suite = state
        .projections()
        .realm_digest_suite(event.realm_id.as_str());
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let Some(evidence) = evidence else {
        return Ok(None);
    };
    let verified =
        arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
            evidence,
            event,
            &peer.source_service_id,
            &state.service_core_id(),
            body_digest,
            digest_suite,
            now,
        )
        .map_err(|error| {
            ServiceError::protocol(
                error.error_code().unwrap_or(ErrorCode::SignatureInvalid),
                error,
            )
        })?;
    Ok(Some(ForwardedProducerDeviceEvidence::new(
        evidence.clone(),
        verified.into_fact(),
    )?))
}

pub(super) fn resolve_forwarded_producer(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    event: &Event,
    device: Option<&ForwardAccountDeviceSignerEvidence>,
    agent: Option<&arkret_models_identity::AgentProducerEvidence>,
    body_digest: &arkret_wire::Hash,
    now: DateTime<Utc>,
) -> ServiceResult<(
    super::authority_self_event_unit::AdmittedProducer,
    arkret_signatures::PublicKeyMaterial,
)> {
    // Structural PCR candidates must never weaken ordinary producer admission.
    arkret_models_collaboration::authority_commit::validate_producer_agent_evidence_presence(
        event, agent,
    )
    .map_err(wire_refusal)?;
    arkret_models_collaboration::authority_commit::validate_producer_device_evidence_presence(
        event, device,
    )
    .map_err(wire_refusal)?;
    if let Some(device) = verify_forwarded_producer(state, peer, event, device, body_digest, now)? {
        let key = forwarded_producer_key(Some(&device.evidence))?;
        return Ok((
            super::authority_self_event_unit::AdmittedProducer::Forwarded(Box::new(device)),
            key,
        ));
    }
    if let Some(agent) = agent {
        let verified = arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
            event,
            agent,
            &peer.source_service_id,
            now,
            None,
        )
        .map_err(|error| {
            ServiceError::protocol(
                error.error_code().unwrap_or(ErrorCode::SignatureInvalid),
                error,
            )
        })?;
        let key = verified.key().clone();
        return Ok((
            super::authority_self_event_unit::AdmittedProducer::ForwardedAgent(Box::new(verified)),
            key,
        ));
    }
    if let Some(service) = resolve_service_producer(state, event)? {
        return Ok(service);
    }
    Err(ServiceError::protocol(
        ErrorCode::DependencyMissing,
        "forwarded producer authority is unavailable",
    ))
}

pub(super) fn resolve_service_producer(
    state: &AppState,
    event: &Event,
) -> ServiceResult<
    Option<(
        super::authority_self_event_unit::AdmittedProducer,
        arkret_signatures::PublicKeyMaterial,
    )>,
> {
    if matches!(event.actual_signer(), arkret_wire::ActorId::Service { .. }) {
        let proof = event.producer_proof.as_ref().ok_or_else(|| {
            ServiceError::protocol(
                ErrorCode::SignatureInvalid,
                "Service producer proof is absent",
            )
        })?;
        crate::jws_verify::validate_verification_method_controller(
            event.actual_signer().signing_principal_id().as_str(),
            proof.verification_method.as_str(),
        )
        .map_err(|error| ServiceError::protocol(ErrorCode::SignatureInvalid, error))?;
        let (controller, _) = proof
            .verification_method
            .as_str()
            .rsplit_once('#')
            .ok_or_else(|| {
                ServiceError::protocol(
                    ErrorCode::SignatureInvalid,
                    "Service method has no fragment",
                )
            })?;
        let did = arkret_wire::Did::new(controller.to_owned())
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let document = crate::jws_verify::resolve_did_document(state, &did)
            .map_err(temporarily_unavailable)?;
        let key = arkret_identity::public_key_material_from_document(
            &document,
            &proof.verification_method,
        )
        .map_err(temporarily_unavailable)?;
        // Registration epoch, installation, grant, producer proof and source
        // fact are independently rechecked under the accepting transaction.
        return Ok(Some((
            super::authority_self_event_unit::AdmittedProducer::Applet(
                coland_storage::AppletEventProducerGuard {
                    service_did_document: document,
                },
            ),
            key,
        )));
    }
    Ok(None)
}

fn is_native_device(event: &arkret_wire::Event) -> bool {
    event.applet_id.is_some()
        && event.executed_by.is_none()
        && event.actor_id.as_account_id().is_some()
}

fn require_native_origin(
    peer: &AuthenticatedPeerContext,
    event: &arkret_wire::Event,
) -> ServiceResult<()> {
    if is_native_device(event)
        && event
            .actor_id
            .as_account_id()
            .is_some_and(|account| account.station_id != peer.source_service_id)
    {
        return Err(ServiceError::Conflict(
            "capability_denied: native forwarding peer is not the producer Account Station".into(),
        ));
    }
    Ok(())
}

fn refuse_bare_native_mls(event: &arkret_wire::Event) -> ServiceResult<()> {
    if is_native_device(event) && event.kind == arkret_wire::EventKind::MlsCommit {
        return Err(ServiceError::SchemaViolation(
            "native MLS requires the complete MlsCommitSubmission".into(),
        ));
    }
    Ok(())
}

/// B: admit one forwarded ordinary Event at `now`.
pub(crate) async fn admit_forwarded_event(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: PeerAuthorityForwardEventRequest,
    now: DateTime<Utc>,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event_submission.event;
    require_native_origin(peer, event)?;
    refuse_bare_native_mls(event)?;
    super::authority_port::refuse_actor_private_event(&event.kind)?;
    if request.is_native_pcr_candidate()
        && state
            .persistence()
            .principal_resolution_for_realm(&event.realm_id)
            .await?
            .is_some()
    {
        return super::authority_pcr::admit_forwarded(state, peer, &request).await;
    }
    if let Some(outcome) = super::authority_self_event_unit::exact_replay(state, event).await? {
        return Ok(outcome);
    }
    request.validate().map_err(wire_refusal)?;
    let (producer, key) = resolve_forwarded_producer(
        state,
        peer,
        event,
        request.producer_device_evidence.as_ref(),
        request.producer_agent_evidence.as_ref(),
        &arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request)
            .map_err(wire_refusal)?,
        now,
    )?;

    if let Some(outcome) = super::authority_port::refuse_unrouted_event(state, event).await? {
        return Ok(outcome);
    }
    if matches!(
        event.kind,
        arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
    ) {
        if request.event_submission.approval_signatures.is_some() {
            return Err(ServiceError::SchemaViolation(
                "an MLS Event carries no approval signatures".to_owned(),
            ));
        }
        return super::authority_mls_unit::admit_mls_event(
            state,
            event,
            &[],
            request.mls_genesis_material.as_ref(),
            producer,
            &key,
        )
        .await;
    }
    super::authority_port::require_guarded_unit_event(&request.event_submission)?;
    super::authority_self_event_unit::commit_event_unit(
        state,
        &request.event_submission,
        producer,
        super::authority_self_event_unit::SelfEventUnitEffects::default(),
    )
    .await
}

/// B: admit one forwarded MLS Commit submission at `now`. The Commit Event's
/// producer is verified exactly like an ordinary Event, then the Commit and
/// every Welcome enter the same MLS unit as a self submission.
pub(crate) async fn admit_forwarded_mls(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: PeerAuthorityForwardMlsRequest,
    now: DateTime<Utc>,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.mls_submission.commit_event;
    require_native_origin(peer, event)?;
    let native = event.applet_id.is_some()
        && event.executed_by.is_none()
        && event.actor_id.as_account_id().is_some();
    let native_request = if native {
        super::authority_managed_device::mls::NativeMlsRequest::from_request(
            &SelfAuthoritySubmitRequest::MlsCommit(request.mls_submission.clone()),
        )?
    } else {
        None
    };
    if let Some(context) = native_request.as_ref() {
        if let Some(original) = context.replay(state).await? {
            return match original {arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome::Ordinary(outcome)=>Ok(outcome),_=>Err(ServiceError::internal("native MLS stored an incompatible outcome"))};
        }
    }
    if let Some(outcome) = super::authority_self_event_unit::exact_replay(state, event).await? {
        if native {
            return Err(ServiceError::Conflict(
                "duplicate_conflict: native forwarded MLS differs from its accepted complete unit"
                    .into(),
            ));
        }
        return Ok(outcome);
    }
    request.validate().map_err(wire_refusal)?;
    let (producer, key) = resolve_forwarded_producer(
        state,
        peer,
        event,
        request.producer_device_evidence.as_ref(),
        request.producer_agent_evidence.as_ref(),
        &arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request)
            .map_err(wire_refusal)?,
        now,
    )?;

    if native {
        super::authority_mls_unit::admit_native_mls_event(
            state,
            event,
            &request.mls_submission.welcomes,
            None,
            producer,
            &key,
            native_request,
        )
        .await
    } else {
        super::authority_mls_unit::admit_mls_event(
            state,
            event,
            &request.mls_submission.welcomes,
            None,
            producer,
            &key,
        )
        .await
    }
}

/// The attested device key a verified forwarded producer proof verified
/// under; the same producer seals the Commit's Welcomes with it.
fn forwarded_producer_key(
    evidence: Option<&ForwardAccountDeviceSignerEvidence>,
) -> ServiceResult<arkret_signatures::PublicKeyMaterial> {
    let evidence = evidence.ok_or_else(|| {
        ServiceError::internal("a verified forwarded human producer carries its evidence")
    })?;
    let multibase = evidence
        .device_projection_attestation
        .attestation
        .device_signing_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            ServiceError::protocol(
                ErrorCode::SignatureInvalid,
                "attested device signing key is not did:key",
            )
        })?;
    Ok(arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    })
}

/// Human controller dependency for the independently registered native Agent unit.
async fn prepare_directory_device_evidence(
    state: &AppState,
    event: &Event,
    retain: bool,
) -> ServiceResult<Option<AccountDeviceSignerEvidence>> {
    let Some(producer) = event.account_device_producer().map_err(wire_refusal)? else {
        return Ok(None);
    };
    if producer.account_id.station_id != state.service_core_id() {
        return Err(ServiceError::SchemaViolation(
            "only the producer's Account Station forwards its device evidence".to_owned(),
        ));
    }
    let admission = state
        .persistence()
        .pcr_device_admission(
            &producer.account_id,
            &producer.device_id,
            crate::wire::now(),
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("PCR device status: {error}")))?;
    if let Some(refusal) = ServiceError::device_admission_refusal(
        admission,
        "producer device is not active at the forwarding Station",
    ) {
        return Err(refusal);
    }
    let facet =
        crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
            state,
            producer.account_id.principal_id.as_str(),
            producer.device_id.as_str(),
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("device directory: {error}")))?;
    let issued = if retain {
        crate::routing::identity::keys::issue_current_account_device_signer_evidence(
            state,
            &producer.account_id,
            &producer.device_id,
            &facet,
        )
        .await
        .map(|value| value.map(|(evidence, _)| evidence))
    } else {
        crate::routing::identity::keys::prepare_current_account_device_signer_evidence(
            state,
            &producer.account_id,
            &producer.device_id,
            &facet,
        )
        .await
        .map(|value| value.map(|(evidence, _)| evidence))
    }
    .map_err(|error| match error.conflict_code() {
        Some(_) => error,
        None => temporarily_unavailable(format!("producer device evidence: {error}")),
    })?;
    let evidence = issued.ok_or_else(|| {
        temporarily_unavailable("current producer device material is unavailable")
    })?;
    Ok(Some(evidence))
}

/// Freeze Account Device authorization before signing the complete forward body.
pub(crate) fn fresh_device_request<'a>(
    state: &'a AppState,
    destination: &'a DidCoreId,
    request: &'a mut PeerAuthoritySubmitRequest,
) -> impl std::future::Future<Output = ServiceResult<()>> + Send + 'a {
    crate::boxed_future(move || fresh_device_request_inner(state, destination, request))
}

async fn fresh_device_request_inner(
    state: &AppState,
    destination: &DidCoreId,
    request: &mut PeerAuthoritySubmitRequest,
) -> ServiceResult<()> {
    let event = match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => &v.event_submission.event,
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => &v.mls_submission.commit_event,
        _ => {
            return Err(ServiceError::SchemaViolation(
                "Device source requires authority_forward".into(),
            ));
        }
    };
    let Some(producer) = event.account_device_producer().map_err(wire_refusal)? else {
        return Ok(());
    };
    if producer.account_id.station_id != state.service_core_id() {
        return Err(ServiceError::SchemaViolation(
            "only the producer's Account Station may issue its forward source".into(),
        ));
    }
    let prepared = state
        .persistence()
        .prepare_forward_request(request, destination)
        .await?
        .ok_or_else(|| temporarily_unavailable("locked origin source is unavailable"))?;
    let service_resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|e| temporarily_unavailable(e.message))?;
    let attestation =
        arkret_signatures::device_projection::sign_forward_device_projection_attestation(
            prepared.device,
            state
                .service_verification_method("notary-key")
                .map_err(ServiceError::internal)?,
            state.notary_signing_key().as_ref(),
        )
        .map_err(wire_refusal)?;
    let evidence = ForwardAccountDeviceSignerEvidence {
        device_projection_attestation: attestation,
        service_resolution,
    };
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => {
            v.producer_device_evidence = Some(evidence);
            v.validate().map_err(wire_refusal)?;
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => {
            v.producer_device_evidence = Some(evidence);
            v.validate().map_err(wire_refusal)?;
        }
        _ => unreachable!("checked forward branch"),
    }
    state.persistence().retain_forward_request(request).await?;
    Ok(())
}

pub(crate) async fn fresh_non_managed_device_evidence(
    state: &AppState,
    event: &Event,
    destination: &DidCoreId,
    body_digest: &arkret_wire::Hash,
) -> ServiceResult<Option<ForwardAccountDeviceSignerEvidence>> {
    let Some(producer) = event.account_device_producer().map_err(wire_refusal)? else {
        return Ok(None);
    };
    if producer.account_id.station_id != state.service_core_id() {
        return Err(ServiceError::SchemaViolation(
            "only the producer's Account Station may issue its forward source".into(),
        ));
    }
    let admission = state
        .persistence()
        .pcr_device_admission(
            &producer.account_id,
            &producer.device_id,
            crate::wire::now(),
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("PCR Device status: {error}")))?;
    if let Some(refusal) = ServiceError::device_admission_refusal(
        admission,
        "producer Device is not active at its origin Station",
    ) {
        return Err(refusal);
    }
    let Some(forward_core) = state
        .persistence()
        .prepare_non_managed_forward_current_signer_evidence(event, destination, body_digest)
        .await?
    else {
        return Ok(None);
    };
    let service_resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|error| temporarily_unavailable(error.message))?;
    let attestation =
        arkret_signatures::device_projection::sign_forward_device_projection_attestation(
            forward_core,
            state
                .service_verification_method("notary-key")
                .map_err(ServiceError::internal)?,
            state.notary_signing_key().as_ref(),
        )
        .map_err(wire_refusal)?;
    let evidence = ForwardAccountDeviceSignerEvidence {
        device_projection_attestation: attestation,
        service_resolution,
    };
    // Same original PCR lock re-prepares every immutable field and checks the
    // fresh projection before retaining the complete signed origin root.
    state
        .persistence()
        .retain_forward_current_signer_evidence(event, &evidence)
        .await?;
    Ok(Some(evidence))
}

/// Use the existing deployment-private AA operation. Request identity comes
/// from the registered exact endpoint/credential, never from an Event header.
async fn request_origin_controller_gate(
    state: &AppState,
    principal: &DidCoreId,
    request_id: arkret_wire::RequestId,
) -> ServiceResult<arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestation>
{
    use arkret_models_identity::agent_signer_evidence::{
        ControllerAccountGateIssuanceInput, ControllerAccountGateIssuanceOutcome,
    };
    let channel = state
        .config()
        .internal_authority_channel
        .as_ref()
        .ok_or_else(|| {
            temporarily_unavailable("Agent Origin has no registered controller gate channel")
        })?;
    let input = ControllerAccountGateIssuanceInput {
        request_id: request_id.clone(),
        principal_id: principal.clone(),
        agent_authority_id: state.service_core_id(),
    };
    let body = arkret_canonical::canonical_json_bytes(&input).map_err(temporarily_unavailable)?;
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        channel.controller_gate_url(),
        "registered controller gate issuance",
        state.config().development_mode,
        std::time::Duration::from_secs(10),
    )
    .map_err(|_| temporarily_unavailable("controller gate egress is unavailable"))?;
    // The client is pinned and redirect-disabled by the common egress helper.
    let mut response = client
        .post(url)
        .bearer_auth(channel.credential())
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| temporarily_unavailable("controller gate response is unavailable"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(temporarily_unavailable(
            "controller gate issuance was refused",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| temporarily_unavailable("controller gate response is unavailable"))?
    {
        if bytes.len().saturating_add(chunk.len())
            > arkret_models_identity::AGENT_AUTHORITY_EVIDENCE_MAX_CANONICAL_BYTES
        {
            return Err(temporarily_unavailable(
                "controller gate response exceeds formal carrier bound",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let outcome: ControllerAccountGateIssuanceOutcome =
        serde_json::from_slice(&bytes).map_err(|_| {
            temporarily_unavailable("controller gate outcome is not closed typed material")
        })?;
    let gate = outcome.controller_account_gate_attestation;
    gate.validate().map_err(wire_refusal)?;
    if outcome.request_id != request_id
        || gate.principal_id != *principal
        || gate.authority_id != state.service_core_id()
        || !gate.is_valid_at(crate::wire::now())
    {
        return Err(wire_refusal(arkret_wire::WireError::ProtocolCode {
            code: ErrorCode::SignatureInvalid,
            message: "controller gate response differs from registered request".into(),
        }));
    }
    // Signature, actual assertion method and observation history are verified
    // by the full Agent verifier, not inferred from HTTP success or this shape.
    Ok(gate)
}

/// Assemble, independently verify, then retain a full Origin Agent sibling.
/// The default storage port refuses until the same-cut PG assembler exists.
pub(crate) async fn fresh_producer_agent_evidence(
    state: &AppState,
    event: &Event,
) -> ServiceResult<Option<arkret_models_identity::AgentProducerEvidence>> {
    if event
        .account_device_producer()
        .map_err(wire_refusal)?
        .is_some()
        || event.actual_signer().as_account_id().is_none()
    {
        return Ok(None);
    }
    let account = event
        .actual_signer()
        .as_account_id()
        .expect("checked above");
    if account.station_id != state.service_core_id() {
        return Err(wire_refusal(arkret_wire::WireError::ProtocolCode {
            code: ErrorCode::SignatureInvalid,
            message: "Agent Origin differs from producer Account Station".into(),
        }));
    }
    use arkret_models_identity::agent_signer_evidence::AgentDetachedJws;
    use arkret_models_identity::{
        AgentAuthorityStateAttestation, AgentAuthorityStateEvidence, AgentProducerEvidence,
    };
    let at = crate::wire::now();
    let original = state
        .authority_commits()
        .prepare_agent_origin_state(event, at)
        .await?;
    original.validate_binding(account).map_err(wire_refusal)?;
    let request_id = state
        .authority_commits()
        .agent_origin_controller_gate_request(event, &original)
        .await?;
    let gate = request_origin_controller_gate(
        state,
        &original.authorization.controller_principal_id,
        request_id,
    )
    .await?;
    let issued_at = crate::wire::now();
    let state_digest = original.digest().map_err(wire_refusal)?;
    let mut attestation = AgentAuthorityStateAttestation {
        authority_id: state.service_core_id(),
        verification_method: state
            .service_verification_method("notary-key")
            .map_err(|_| temporarily_unavailable("Agent state issuer method is unavailable"))?,
        state_digest: state_digest.clone(),
        issued_at,
        expires_at: issued_at + chrono::Duration::seconds(300),
        proof: AgentDetachedJws {
            kind: arkret_wire::NonEmptyString::new(arkret_wire::proof_kind::DETACHED_JWS)
                .map_err(temporarily_unavailable)?,
            jws: arkret_wire::NonEmptyString::new("pending").map_err(temporarily_unavailable)?,
        },
    };
    attestation.proof.jws = arkret_wire::NonEmptyString::new(
        arkret_signatures::sign_ed25519_detached_jws(
            state.notary_signing_key().as_ref(),
            &attestation.signing_bytes().map_err(wire_refusal)?,
        )
        .map_err(|_| temporarily_unavailable("Agent state signing failed"))?,
    )
    .map_err(temporarily_unavailable)?;
    let jwk =
        arkret_signatures::jwk::JsonWebKey::ed25519(original.authorization.public_key.key.clone());
    let signer = arkret_models_identity::authenticated_signer_resolution_evidence::build_agent_signer_evidence(
        original.agent_id.clone(),original.authorization.verification_method.clone(),
        serde_json::from_value(serde_json::to_value(jwk).map_err(temporarily_unavailable)?)
            .map_err(temporarily_unavailable)?,
        original.authorization.accepted_commit_id.clone(),original.authorization.accepted_at,
    ).map_err(wire_refusal)?;
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|_| temporarily_unavailable("Agent current issuer history is unavailable"))?;
    let evidence = AgentProducerEvidence {
        authenticated_signer_evidence: signer,
        agent_authority_state_evidence: AgentAuthorityStateEvidence {
            schema: arkret_wire::NonEmptyString::new(
                arkret_wire::SchemaId::AGENT_AUTHORITY_STATE_EVIDENCE_V1,
            )
            .map_err(temporarily_unavailable)?,
            state: Some(original),
            state_digest,
            attestation,
        },
        controller_account_gate_attestation: gate,
        authority_resolution: resolution,
    };
    let verified = arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
        event,
        &evidence,
        &state.service_core_id(),
        crate::wire::now(),
        None,
    )
    .map_err(|error| {
        ServiceError::protocol(
            error.error_code().unwrap_or(ErrorCode::SignatureInvalid),
            error,
        )
    })?;
    state
        .authority_commits()
        .retain_agent_forward_evidence_at_same_cut(event, verified.evidence(), crate::wire::now())
        .await?;
    Ok(Some(verified.evidence().clone()))
}

/// A: the raw GroupInfo and ratchet tree an `ak.mls.genesis` forward
/// carries (encryption-and-audit.md §5.1.2), read from this Station's Blob
/// store and proven to address the Genesis refs; `None` for every other kind.
/// A Blob that is missing, larger than one carrier member holds or does not
/// address its ref is a bare `failed_precondition` before anything is
/// forwarded.
async fn forwarded_genesis_material(
    state: &AppState,
    event: &Event,
) -> ServiceResult<Option<MlsGenesisMaterial>> {
    if event.kind != arkret_wire::EventKind::MlsGenesis {
        return Ok(None);
    }
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::to_value(&event.payload)
            .and_then(serde_json::from_value)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let mut blobs = Vec::with_capacity(2);
    for blob_ref in [&payload.group_info_ref, &payload.ratchet_tree_ref] {
        let unavailable = || {
            ServiceError::Conflict(format!(
                "{}: Genesis Blob {blob_ref} is not a local Blob addressing its bytes",
                ConflictCode::FailedPrecondition
            ))
        };
        let bytes = crate::routing::mls::load_mls_public_blob(
            state,
            blob_ref.as_str(),
            MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES,
        )
        .await
        .map_err(|_| unavailable())?;
        let digest = blob_ref
            .as_str()
            .strip_prefix("ak:blob:")
            .ok_or_else(unavailable)?;
        arkret_canonical::verify_digest(&bytes, digest).map_err(|_| unavailable())?;
        blobs.push(bytes);
    }
    Ok(Some(MlsGenesisMaterial::from_bytes(&blobs[0], &blobs[1])))
}

/// A: forward one self-submitted Event to its current governance Station and
/// relay that Station's outcome.
#[cfg(feature = "test-support")]
pub(crate) async fn forward_self_event(
    state: &AppState,
    governance: &DidCoreId,
    submission: EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    crate::boxed_future(|| forward_self_event_inner(state, governance, submission, None)).await
}

pub(crate) async fn forward_self_event_with_session(
    state: &AppState,
    governance: &DidCoreId,
    submission: EventAdmissionSubmission,
    session: &coland_services::identity::SessionIdentityState,
) -> ServiceResult<AuthoritySubmitOutcome> {
    crate::boxed_future(|| forward_self_event_inner(state, governance, submission, Some(session)))
        .await
}

async fn require_live_forward(state: &AppState, event: &arkret_wire::Event) -> ServiceResult<()> {
    state
        .authority_commits()
        .require_held_replica_write_lifecycle(event)
        .await?;
    // Joining and a bound invite claim acquire authority through their own
    // registered admission. They never reuse a departed replica's old basis.
    if super::committed_replication::hosted_member_join_event(state, event)
        .is_some_and(|member| event.actor_id.as_account_id() == Some(&member))
        || event.kind == arkret_wire::EventKind::InviteClaim
    {
        return Ok(());
    }
    // circle.md section 9.1 permits the member's explicit cleanup of a stale
    // parent-bound Circle join; governing admission still verifies that cut.
    if event.kind == arkret_wire::EventKind::CircleMemberState {
        let payload: arkret_models_collaboration::events_payloads::CircleMemberStatePayload =
            serde_json::from_value(
                serde_json::to_value(&event.payload)
                    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
            )
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if payload.membership
            == arkret_models_collaboration::governance::circle::CircleMembership::Leave
            && payload.member_id == event.actor_id
        {
            return Ok(());
        }
    }
    let stream =
        arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .map_err(wire_refusal)?;
    let parent = arkret_wire::CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    for checked in std::iter::once(&parent).chain((stream != parent).then_some(&stream)) {
        if state
            .authority_commits()
            .replica_stream_has_hosted_member(checked, &state.service_core_id())
            .await?
            == Some(false)
        {
            return Err(ServiceError::protocol(
                ErrorCode::FailedPrecondition,
                "held stream has no live hosted-member authority",
            ));
        }
    }
    Ok(())
}

async fn forward_self_event_inner(
    state: &AppState,
    governance: &DidCoreId,
    submission: EventAdmissionSubmission,
    session: Option<&coland_services::identity::SessionIdentityState>,
) -> ServiceResult<AuthoritySubmitOutcome> {
    require_live_forward(state, &submission.event).await?;
    // Device admission and Genesis material are preflight gates.  In
    // particular, a revoked/pending/fenced producer must leave no queued
    // Event behind at the forwarding Station.
    let material = forwarded_genesis_material(state, &submission.event).await?;
    let mut request = PeerAuthorityForwardEventRequest {
        branch:
            arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
        event_submission: submission.clone(),
        mls_genesis_material: material,
        producer_device_evidence: None,
        producer_agent_evidence: None,
    };
    request.producer_agent_evidence =
        fresh_producer_agent_evidence(state, &submission.event).await?;
    let mut request = PeerAuthoritySubmitRequest::AuthorityForwardEvent(request);
    fresh_device_request(state, governance, &mut request).await?;
    let session = session.ok_or_else(|| {
        ServiceError::protocol(
            ErrorCode::Unauthenticated,
            "forward transport requires the authenticated request context",
        )
    })?;
    validate_recovery_caller(state, session, &submission.event).await?;
    require_live_forward(state, &submission.event).await?;
    // Retain the producer's exact signed Event before any forwarding attempt.
    // A transport failure leaves this row queued for an exact replay or a
    // later committed replica; neither path makes it visible as accepted.
    state
        .authority_commits()
        .queue_event(&submission.event, crate::wire::now())
        .await?;

    state
        .authority_commits()
        .retain_forwarded_submission(
            &submission.event,
            &SelfAuthoritySubmitRequest::Event(submission.clone()),
            crate::wire::now(),
        )
        .await?;
    send_forward(state, governance, request, session).await
}

/// A: forward one self-submitted MLS Commit; the Commit Event's producer
/// decides the evidence exactly as for an ordinary Event.
pub(super) async fn forward_self_mls(
    state: &AppState,
    governance: &DidCoreId,
    submission: MlsCommitSubmission,
    session: &coland_services::identity::SessionIdentityState,
) -> ServiceResult<AuthoritySubmitOutcome> {
    require_live_forward(state, &submission.commit_event).await?;
    // Match ordinary forwarding: the live device gate precedes every durable
    // forwarding effect, including the local queued Event.
    let mut request = PeerAuthorityForwardMlsRequest {
        branch:
            arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
        mls_submission: submission.clone(),
        producer_device_evidence: None,
        producer_agent_evidence: None,
    };
    request.producer_agent_evidence =
        fresh_producer_agent_evidence(state, &submission.commit_event).await?;
    let mut request = PeerAuthoritySubmitRequest::AuthorityForwardMls(request);
    fresh_device_request(state, governance, &mut request).await?;
    require_live_forward(state, &submission.commit_event).await?;
    state
        .authority_commits()
        .queue_event(&submission.commit_event, crate::wire::now())
        .await?;

    state
        .authority_commits()
        .retain_forwarded_submission(
            &submission.commit_event,
            &SelfAuthoritySubmitRequest::MlsCommit(submission.clone()),
            crate::wire::now(),
        )
        .await?;
    send_forward(state, governance, request, session).await
}

/// Assemble the same complete native unit for origin admission and transport.
pub(crate) fn prepare_native_forward_request<'a>(
    state: &'a AppState,
    governance: &'a DidCoreId,
    submission: &'a SelfAuthoritySubmitRequest,
) -> impl std::future::Future<Output = ServiceResult<PeerAuthoritySubmitRequest>> + Send + 'a {
    crate::boxed_future(move || prepare_native_forward_request_inner(state, governance, submission))
}

async fn prepare_native_forward_request_inner(
    state: &AppState,
    governance: &DidCoreId,
    submission: &SelfAuthoritySubmitRequest,
) -> ServiceResult<PeerAuthoritySubmitRequest> {
    let event = match submission {
        SelfAuthoritySubmitRequest::Event(v) => &v.event,
        SelfAuthoritySubmitRequest::MlsCommit(v) => &v.commit_event,
        _ => {
            return Err(ServiceError::SchemaViolation(
                "native forward requires an Event or complete MLS unit".into(),
            ));
        }
    };
    if matches!(submission, SelfAuthoritySubmitRequest::Event(_)) {
        refuse_bare_native_mls(event)?;
    }
    let mut request=match submission {
        SelfAuthoritySubmitRequest::Event(v)=>PeerAuthoritySubmitRequest::AuthorityForwardEvent(PeerAuthorityForwardEventRequest{
            branch:arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,event_submission:v.clone(),
            mls_genesis_material:forwarded_genesis_material(state,event).await?,producer_device_evidence:None,producer_agent_evidence:None,
        }),
        SelfAuthoritySubmitRequest::MlsCommit(v)=>PeerAuthoritySubmitRequest::AuthorityForwardMls(PeerAuthorityForwardMlsRequest{
            branch:arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,mls_submission:v.clone(),
            producer_device_evidence:None,producer_agent_evidence:None,
        }),_=>unreachable!("checked native forward branch"),
    };
    fresh_device_request(state, governance, &mut request).await?;
    Ok(request)
}

/// Recover an exact frozen remote submission before today's producer admission.
/// The HTTP boundary still authenticates the full Account and standard holder.
pub(crate) async fn recover_forwarded_original(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    submission: &SelfAuthoritySubmitRequest,
) -> ServiceResult<Option<AuthoritySubmitOutcome>> {
    let event = match submission {
        SelfAuthoritySubmitRequest::Event(value) => &value.event,
        SelfAuthoritySubmitRequest::MlsCommit(value) => &value.commit_event,
        _ => return Ok(None),
    };
    super::authority_self_event_unit::validate_replay_event_identity(event)?;
    let commits = state.authority_commits();
    let Some(queued) = commits.queued_event(&event.event_id).await? else {
        return Ok(None);
    };
    let Some(attempt) = queued.forward_attempt else {
        validate_recovery_caller(state, session, event).await?;
        return super::authority_self_event_unit::exact_replay(state, event).await;
    };
    let Some(original) = attempt.original_submission else {
        return Ok(None);
    };
    if original != *submission || queued.event != *event {
        return Err(ServiceError::Conflict(
            "duplicate_conflict: forwarding recovery differs from its complete original".into(),
        ));
    }
    validate_recovery_caller(state, session, event).await?;
    let authority = commits
        .current_authority(&event.realm_id)
        .await?
        .ok_or_else(|| {
            temporarily_unavailable("forward recovery has no current governing tenure")
        })?;
    let governance = authority.service_id;
    let mut located = if let Some(commit) = attempt.accepted_commit.as_ref() {
        verify_forwarded_acknowledgement(state, &governance, event, commit).await?
    } else {
        crate::routing::realm_join::resolve_verified_authority_of_service(
            state,
            &event.realm_id,
            &governance,
        )
        .await
        .map_err(|e| temporarily_unavailable(e.message))?
    };
    validate_recovery_caller(state, session, event).await?;
    if let Some(commit) = attempt.accepted_commit.as_ref()
        && verify_bound_invite_claim(state, &governance, event, commit, &located, session).await?
    {
        return Ok(Some(AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate,
            commit: commit.clone(),
        }));
    }
    if attempt.accepted_commit.is_none() {
        let stream = arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .map_err(wire_refusal)?;
        if commits.replica_anchor_for_stream(&stream).await?.is_none() {
            // A queued first join has no accepted result to recover. Continue
            // through current admission and exact forwarding; the replica
            // recovery helper must still require an Accepted opening join.
            return Ok(None);
        }
    }
    let original_commit = super::replica_anchor::ensure_forwarded_target(
        state,
        &governance,
        event,
        attempt.accepted_commit.as_ref(),
        &mut located,
        session,
    )
    .await
    .map_err(temporarily_unavailable)?;
    validate_recovery_caller(state, session, event).await?;
    match original_commit {
        Some(commit) => Ok(Some(AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate,
            commit,
        })),
        None if attempt.accepted_commit.is_none() => Ok(None),
        None => Err(temporarily_unavailable(
            "accepted forward original remains unavailable",
        )),
    }
}

pub(super) async fn validate_recovery_caller(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    event: &Event,
) -> ServiceResult<()> {
    use arkret_models_identity::session_credential::{
        SessionGrantCredentialClass, SessionGrantHolderBinding,
    };
    let actor = crate::routing::identity::session_actor::validated_session_actor(state, session)
        .await
        .map_err(|e| ServiceError::protocol(ErrorCode::Unauthenticated, e.message))?;
    let account = actor.as_account_id().ok_or_else(|| {
        ServiceError::protocol(
            ErrorCode::Unauthenticated,
            "recovery requires a full Account",
        )
    })?;
    let grant = session.session_grant.as_ref().ok_or_else(|| {
        ServiceError::protocol(
            ErrorCode::Unauthenticated,
            "recovery requires a standard grant",
        )
    })?;
    // Recovery authenticates the original actual producer. Attributed Agent
    // commands retain the controller author in their immutable Event bytes;
    // they must not be mistaken for a different caller on exact retry.
    let delegated_agent = session.agent_session().is_some()
        && event.executed_by.as_ref() == Some(&actor)
        && event.actor_id != actor;
    if event.actual_signer() != &actor
        || (event.executed_by.is_some() && !delegated_agent)
        || grant.account_id != *account
        || grant.credential_class != SessionGrantCredentialClass::Standard
        || account.station_id != state.service_core_id()
        || session.expires_at <= crate::wire::now()
        || session.revoked_at.is_some()
    {
        return Err(ServiceError::protocol(
            ErrorCode::Unauthenticated,
            "recovery credential does not bind the exact original Account",
        ));
    }
    match &grant.holder_binding {
        SessionGrantHolderBinding::HumanDevice { device_binding }
            if session
                .human_device_id()
                .is_some_and(|id| id == device_binding)
                && grant
                    .device_binding
                    .as_ref()
                    .is_some_and(|binding| binding.device_id.as_str() == device_binding) => {}
        SessionGrantHolderBinding::AgentRuntime { agent_id, .. }
            if session.agent_session().is_some()
                && agent_id == &account.principal_id
                && grant.device_binding.is_none() => {}
        _ => {
            return Err(ServiceError::protocol(
                ErrorCode::Unauthenticated,
                "recovery standard holder does not bind the authenticated endpoint",
            ));
        }
    }
    Ok(())
}

fn forwarded_device(
    request: &PeerAuthoritySubmitRequest,
) -> Option<&ForwardAccountDeviceSignerEvidence> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => v.producer_device_evidence.as_ref(),
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => v.producer_device_evidence.as_ref(),
        _ => None,
    }
}

async fn send_forward(
    state: &AppState,
    governance: &DidCoreId,
    request: PeerAuthoritySubmitRequest,
    session: &coland_services::identity::SessionIdentityState,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = match &request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) => {
            &request.event_submission.event
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(request) => {
            &request.mls_submission.commit_event
        }
        _ => unreachable!("only authority forwards reach send_forward"),
    };
    let mut governing_accepted = false;
    let result = async {
        let body = arkret_canonical::canonical_json_bytes(&request)
            .map_err(|error| ServiceError::internal(error.to_string()))?;
        validate_recovery_caller(state, session, event).await?;
        require_live_forward(state, event).await?;
        if forwarded_device(&request).is_some() {
            state.persistence().retain_forward_request(&request).await?;
        }
        let response = crate::routing::federation::outbox::submit_authority_forward(
            state,
            governance.as_str(),
            &body,
        )
        .await
        .map_err(temporarily_unavailable)?;
        let outcome = relay_governance_response(&request, response)?;
        if let AuthoritySubmitOutcome::Accepted { commit, .. } = &outcome {
            governing_accepted = true;
            let mut located =
                verify_forwarded_acknowledgement(state, governance, event, commit).await?;
            // This durable witness is not a replica: it authorizes no read or current value.
            state
                .authority_commits()
                .retain_forwarded_acceptance(event, commit, crate::wire::now())
                .await?;
            validate_recovery_caller(state, session, event).await?;
            if verify_bound_invite_claim(state, governance, event, commit, &located, session)
                .await?
            {
                return Ok(outcome);
            }
            super::replica_anchor::ensure_forwarded_target(
                state,
                governance,
                event,
                Some(commit),
                &mut located,
                session,
            )
            .await
            .map_err(temporarily_unavailable)?
            .ok_or_else(|| temporarily_unavailable("accepted forward original is unavailable"))?;
        }
        Ok::<_, ServiceError>(outcome)
    }
    .await;
    record_forward_result(state, event, &result, governing_accepted).await?;
    result
}

async fn record_forward_result(
    state: &AppState,
    event: &Event,
    result: &ServiceResult<AuthoritySubmitOutcome>,
    governing_accepted: bool,
) -> ServiceResult<()> {
    let (status, reason_code) = if governing_accepted {
        // Materialization failure is operation availability, not an admission rejection.
        (ForwardAttemptStatus::Forwarding, None)
    } else {
        match result {
            Ok(AuthoritySubmitOutcome::Accepted { .. }) => (ForwardAttemptStatus::Forwarding, None),
            Ok(AuthoritySubmitOutcome::Rejected { reason_code, .. }) => {
                (ForwardAttemptStatus::Rejected, Some(reason_code.as_str()))
            }
            Err(error) if error.conflict_code() == Some(ConflictCode::TemporarilyUnavailable) => {
                (ForwardAttemptStatus::TemporarilyUnavailable, None)
            }
            Err(error) => match error.conflict_code() {
                Some(code) => (ForwardAttemptStatus::Rejected, Some(code.as_str())),
                None if matches!(error, ServiceError::SchemaViolation(_)) => {
                    (ForwardAttemptStatus::Rejected, Some("schema_violation"))
                }
                None if matches!(error, ServiceError::UnsupportedEventKind(_)) => (
                    ForwardAttemptStatus::Rejected,
                    Some("unsupported_event_kind"),
                ),
                None => (ForwardAttemptStatus::TemporarilyUnavailable, None),
            },
        }
    };
    state
        .authority_commits()
        .record_forward_attempt(&event.event_id, status, reason_code, crate::wire::now())
        .await?;
    Ok(())
}

/// A claim is not a join: its bound self result needs no member scan or replica.
async fn verify_bound_invite_claim(
    state: &AppState,
    governance: &DidCoreId,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
    located: &crate::routing::realm_join::LocatedRealmAuthority,
    session: &coland_services::identity::SessionIdentityState,
) -> ServiceResult<bool> {
    if event.kind != arkret_wire::EventKind::InviteClaim {
        return Ok(false);
    }
    validate_recovery_caller(state, session, event).await?;
    let commits = state.authority_commits();
    let queued = commits
        .queued_event(&event.event_id)
        .await?
        .ok_or_else(|| temporarily_unavailable("bound claim has no frozen submission"))?;
    let attempt = queued
        .forward_attempt
        .ok_or_else(|| temporarily_unavailable("bound claim has no retained forward"))?;
    if queued.event != *event
        || attempt.accepted_commit.as_ref() != Some(commit)
        || !matches!(attempt.original_submission,
            Some(SelfAuthoritySubmitRequest::Event(ref original)) if original.event == *event)
    {
        return Err(temporarily_unavailable(
            "bound claim differs from its frozen accepted original",
        ));
    }
    let fact = state
        .persistence()
        .forwarded_bound_account_device_signer_fact(event, commit, governance)
        .await
        .map_err(temporarily_unavailable)?
        .ok_or_else(|| {
            temporarily_unavailable("bound claim historical producer source is unavailable")
        })?;
    coland_services::committed_receipt::verify_committed_event_receipt_with_source(
        state.persistence(),
        event,
        commit,
        coland_services::committed_receipt::CommitContinuity::Standalone,
        &located.authority,
        &located.keys,
        &state.service_core_id(),
        event.realm_id.digest_suite_code().digest_suite(),
        Some(&fact.into()),
    )
    .await
    .map_err(temporarily_unavailable)?;
    validate_recovery_caller(state, session, event).await?;
    if commits.current_authority(&event.realm_id).await?.as_ref()
        != Some(&located.current_authority())
    {
        return Err(temporarily_unavailable(
            "bound claim governing tenure changed",
        ));
    }
    validate_recovery_caller(state, session, event).await?;
    Ok(true)
}

pub(super) async fn verify_forwarded_acknowledgement(
    state: &AppState,
    governance: &DidCoreId,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
) -> ServiceResult<crate::routing::realm_join::LocatedRealmAuthority> {
    let mut located = crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        &event.realm_id,
        governance,
    )
    .await
    .map_err(|error| temporarily_unavailable(format!("Realm authority: {error}")))?;
    if arkret_identity::RealmAuthorityKeyDirectory::public_key_at(
        &located.keys,
        &commit.signature.verification_method,
        commit.signature.created_at,
    )
    .is_none()
    {
        crate::routing::realm_join::insert_historical_method_key(
            state,
            &mut located.keys,
            &commit.signature.verification_method,
            commit.signature.created_at,
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("RealmCommit signing key: {error}")))?;
    }
    event
        .verify_event_id_matches_content_with_digest_suite(
            event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(wire_refusal)?;
    commit.validate_shape().map_err(wire_refusal)?;
    let stream =
        arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .map_err(wire_refusal)?;
    if commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref != stream
    {
        return Err(ServiceError::protocol(
            ErrorCode::SignatureInvalid,
            "governing acknowledgement names another original",
        ));
    }
    located
        .authority
        .verify_commit(commit, &located.keys)
        .map_err(|e| ServiceError::protocol(ErrorCode::SignatureInvalid, e))?;
    Ok(located)
}

/// The governance Station's registered refusal of a forward, as this
/// Station's own. The problem type names the code; a registered reason the
/// refusal carries (such as `epoch_update_required` on
/// `failed_precondition`) is kept so the relayed refusal renders identically.
/// A server failure or an unregistered answer is retryable unavailability.
pub(super) fn relayed_refusal(status: u16, body: &[u8]) -> ServiceError {
    let problem = serde_json::from_slice::<arkret_wire::Problem>(body).ok();
    let code = problem.as_ref().and_then(arkret_wire::Problem::error_code);
    let (Some(problem), Some(code)) = (problem, code) else {
        return temporarily_unavailable(format!("governance Station answered HTTP {status}"));
    };
    if status >= 500 {
        return temporarily_unavailable(format!("governance Station answered HTTP {status}"));
    }
    if code == ErrorCode::NotFound {
        return ServiceError::NotFound(problem.detail);
    }
    let reason = problem
        .extensions
        .get("reason_code")
        .and_then(serde_json::Value::as_str)
        .and_then(ConflictCode::from_detail);
    match reason {
        Some(reason) => ServiceError::Conflict(format!("{reason}: {}", problem.detail)),
        None => ServiceError::protocol(code, problem.detail),
    }
}

/// Relay the governance Station's answer to exactly this forward: a typed
/// outcome bound to the forwarded Event, or its registered refusal code.
pub(super) fn relay_governance_response(
    request: &PeerAuthoritySubmitRequest,
    response: crate::routing::federation::outbox::PeerSubmitResponse,
) -> ServiceResult<AuthoritySubmitOutcome> {
    if !(200..300).contains(&response.status) {
        return Err(relayed_refusal(response.status, &response.body));
    }
    let outcome = serde_json::from_slice::<PeerAuthoritySubmitOutcome>(&response.body)
        .map_err(|error| temporarily_unavailable(format!("invalid forward outcome: {error}")))?;
    outcome
        .validate_for_request(request)
        .map_err(|error| temporarily_unavailable(format!("invalid forward outcome: {error}")))?;
    let PeerAuthoritySubmitOutcome::AuthorityForward(value) = outcome else {
        return Err(temporarily_unavailable(
            "governance Station answered another peer branch",
        ));
    };
    let event = match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) => {
            &request.event_submission.event
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(request) => {
            &request.mls_submission.commit_event
        }
        _ => {
            return Err(ServiceError::internal(
                "only authority_forward is relayed to a self submitter",
            ));
        }
    };
    let arkret_models_collaboration::authority_commit::PeerAuthorityForwardOutcomeValue::Ordinary(
        outcome,
    ) = value.outcome
    else {
        return Err(temporarily_unavailable(
            "single Event forward received an atomic outcome",
        ));
    };
    if let AuthoritySubmitOutcome::Accepted { commit, .. } = &outcome {
        let stream_ref = arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if commit.event_ref != event.event_id
            || commit.realm_id != event.realm_id
            || commit.stream_ref != stream_ref
        {
            return Err(temporarily_unavailable(
                "governance Station Commit does not cover the forwarded Event",
            ));
        }
    }
    Ok(outcome)
}

#[cfg(test)]
#[path = "authority_forward_tests.rs"]
mod tests;

/// Capture the original producer root before the Event acceptance timestamp.
/// This is the Directory sibling, never a repackaged Forward signature.
pub(super) async fn prepare_control_source(
    state: &AppState,
    event: &Event,
) -> ServiceResult<
    Option<(
        arkret_models_identity::AgentSignerDependency,
        arkret_models_identity::AuthenticatedServiceResolution,
    )>,
> {
    let relevant = matches!(
        event.kind,
        arkret_wire::EventKind::AgentKeyAuthorize
            | arkret_wire::EventKind::AgentKeyRevoke
            | arkret_wire::EventKind::SelfAgentPause
            | arkret_wire::EventKind::SelfAgentResume
            | arkret_wire::EventKind::SelfAgentDeactivate
    ) || (matches!(
        event.kind,
        arkret_wire::EventKind::ProfileCreate | arkret_wire::EventKind::ProfileUpdate
    ) && event
        .executed_by
        .as_ref()
        .is_some_and(|actor| actor.as_account_id().is_some()))
        || (event.kind == arkret_wire::EventKind::RealmCreate
            && event
                .payload
                .get("object")
                .and_then(|v| v.get("purpose"))
                .and_then(serde_json::Value::as_str)
                == Some("agent_control"));
    if !relevant {
        return Ok(None);
    }
    let transactional_origin = matches!(
        event.kind,
        arkret_wire::EventKind::AgentKeyAuthorize
            | arkret_wire::EventKind::ProfileCreate
            | arkret_wire::EventKind::ProfileUpdate
    );
    let dependency = if let Some(root) =
        prepare_directory_device_evidence(state, event, !transactional_origin).await?
    {
        arkret_models_identity::AgentSignerDependency::AccountDevice {
            signer_resolution_evidence_ref: root.signer_evidence_ref().map_err(wire_refusal)?,
            account_device_signer_evidence: root,
        }
    } else if let Some(agent) = fresh_producer_agent_evidence(state, event).await? {
        arkret_models_identity::AgentSignerDependency::Agent {
            signer_resolution_evidence_ref: agent
                .authenticated_signer_evidence
                .signer_evidence_ref()
                .map_err(wire_refusal)?,
            agent_evidence: Box::new(agent),
        }
    } else {
        return Err(temporarily_unavailable(
            "control original registered Service dependency is unavailable",
        ));
    };
    let history =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|_| temporarily_unavailable("control issuer original history unavailable"))?;
    Ok(Some((dependency, history)))
}

pub(super) async fn stage_control_source(
    state: &AppState,
    transaction: &coland_storage::AuthorityCommitTransaction,
    original: Option<(
        arkret_models_identity::AgentSignerDependency,
        arkret_models_identity::AuthenticatedServiceResolution,
    )>,
) -> ServiceResult<()> {
    if let Some((dependency, history)) = original {
        state
            .authority_commits()
            .stage_agent_control_source(
                &arkret_wire::CommittedEventFullView {
                    event: transaction.event.clone(),
                    commit: transaction.commit.clone(),
                },
                &dependency,
                &history,
            )
            .await?;
    }
    Ok(())
}

// Routing's dedicated Agent key/lifecycle ingress uses the same authenticated
// producer source as self-events, without a second lookup or private carrier.
impl AppState {
    pub(crate) async fn exact_accepted_agent_control_original(
        &self,
        event: &Event,
    ) -> ServiceResult<Option<arkret_wire::AuthoritySubmitOutcome>> {
        super::authority_self_event_unit::exact_replay(self, event).await
    }

    pub(crate) async fn prepare_agent_control_original_source(
        &self,
        event: &Event,
    ) -> ServiceResult<
        Option<(
            arkret_models_identity::AgentSignerDependency,
            arkret_models_identity::AuthenticatedServiceResolution,
        )>,
    > {
        prepare_control_source(self, event).await
    }
    pub(crate) async fn stage_agent_control_original_source(
        &self,
        transaction: &coland_storage::AuthorityCommitTransaction,
        original: Option<(
            arkret_models_identity::AgentSignerDependency,
            arkret_models_identity::AuthenticatedServiceResolution,
        )>,
    ) -> ServiceResult<()> {
        stage_control_source(self, transaction, original).await
    }
}

#[cfg(test)]
#[path = "authority_forward_recovery_tests.rs"]
mod recovery_tests;
