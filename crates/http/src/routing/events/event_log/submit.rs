use arkret_event_draft::EventPayloadExt as _;

use super::*;

const IDENTITY_CREATION_CONTROL_PROOF_MAX_FUTURE_SKEW_SECONDS: i64 = 30;

mod ghost_provision;
pub(in crate::routing) use ghost_provision::{applet_committed_ref, submit_applet_authoring_unit};
mod sidecar_ensure;
pub(crate) use sidecar_ensure::submit_sidecar_ensure_batch;

#[cfg(test)]
fn stamp_projection_operation_received_at(
    operation: &mut arkret_event_draft::ProjectedEventOperation,
    received_at: chrono::DateTime<chrono::Utc>,
) {
    if !matches!(
        &operation.event_kind,
        arkret_wire::EventKind::MemberState | arkret_wire::EventKind::CircleMemberState
    ) {
        return;
    }
    let Some(payload) = operation.payload.as_object_mut() else {
        return;
    };
    payload.insert(
        "event_received_at".to_owned(),
        Value::String(arkret_canonical::format_timestamp_canonical(received_at)),
    );
}

#[cfg(test)]
#[derive(Debug)]
#[expect(
    dead_code,
    reason = "The test fixture retains its complete envelope while each unit case inspects only its relevant fields."
)]
pub(in crate::routing) struct ValidatedEventEnvelope {
    pub(in crate::routing) event_id: EventId,
    pub(in crate::routing) actor: arkret_wire::ActorId,
    pub(in crate::routing) actor_id: DidCoreId,
    /// Submitting device, absent for a deviceless service session.
    pub(in crate::routing) device_id: Option<DeviceId>,
    pub(in crate::routing) realm_id: RealmId,
    pub(in crate::routing) kind: String,
    pub(in crate::routing) schema_id: String,
    pub(in crate::routing) canonical_digest: String,
    pub(in crate::routing) digest_suite: arkret_canonical::DigestSuite,
    pub(in crate::routing) canonical_bytes: Vec<u8>,
    pub(in crate::routing) producer_signing_key: Option<arkret_wire::DidKey>,
}

#[cfg(test)]
impl ValidatedEventEnvelope {}

#[derive(Debug)]
pub(in crate::routing) struct EventValidationError {
    pub(in crate::routing) status: StatusCode,
    pub(in crate::routing) code: &'static str,
    pub(in crate::routing) message: String,
    pub(in crate::routing) reason_code: Option<&'static str>,
}

#[derive(Debug)]
pub(in crate::routing) enum SubmitOneError {
    Rejected {
        error: Box<AppError>,
        details: Option<Value>,
    },
    #[cfg(test)]
    Quarantined {
        event_id: String,
        reason_code: String,
        message: String,
    },
}

#[derive(Debug)]
pub(in crate::routing) struct SubmittedEventOutcome {
    pub event_id: String,
    pub duplicate: bool,
}

#[cfg(test)]
pub(super) fn map_event_hash_collision(
    event_id: impl Into<String>,
    error: &coland_services::ServiceError,
) -> Option<SubmitOneError> {
    error.is_conflict("event_hash_collision").then(|| {
        SubmitOneError::quarantine(
            event_id,
            "witness_disagreement",
            "verified Event variants disagree for the same full EventId",
        )
    })
}

#[cfg(test)]
#[derive(Debug, Clone)]
#[expect(
    dead_code,
    reason = "The test fixture retains its complete envelope while each unit case inspects only its relevant fields."
)]
pub(in crate::routing) struct RealmBootstrapBatchContext {
    pub(in crate::routing) realm_id: String,
    pub(in crate::routing) actor_id: String,
    /// Digest suite staged by the leading Realm-create Event.
    ///
    /// Follow-up Events in an atomic bootstrap unit are validated before the
    /// Realm projection exists, so their content-bound identities must resolve
    /// the suite from the same signed unit rather than from durable state.
    pub(in crate::routing) digest_algorithm: Option<String>,
    pub(in crate::routing) identity_anchor_event_id: Option<String>,
    /// Typed SDK payload for the candidate device in the second slot of a
    /// registration-anchor or PCR-recovery unit.  Admission parses the wire
    /// Event exactly once at the boundary and carries this DTO through proof
    /// validation; downstream code must not rediscover security fields by
    /// walking `serde_json::Value`.
    pub(in crate::routing) identity_anchor_candidate_device: Option<
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
    >,
    /// Resolution commitment that defines the DID URL base for the candidate
    /// device Event proof.  For genesis this is the exact typed
    /// `RealmCreatePayload.object.initial_resolution`; recovery may load the
    /// same public SDK DTO from the accepted PCR resolution projection.
    pub(in crate::routing) identity_anchor_resolution:
        Option<arkret_models_identity::ResolutionCommitment>,
    /// This batch already passed the closed four-Event Direct Conversation
    /// founding-plan validator, so its member/Strand follow-ups may be
    /// admitted before the new Realm has a durable membership projection.
    pub(in crate::routing) direct_conversation_founding: bool,
}

#[cfg(test)]
/// Closed authorization context for trusted internal protocol adapters. This
/// does not skip schema, proof, actor-lock, idempotency or reducer admission;
/// it only supplies the protocol-specific substitute for ordinary Realm
/// membership (and, for the exact applet-provisioning Event, delegated-grant
/// lookup) after the adapter has verified its durable binding.
#[derive(Debug, Clone)]
pub(in crate::routing) struct InternalEventAdmission {
    realm_id: String,
    actor_id: arkret_wire::ActorId,
    session_actor_id: String,
    kind: String,
    device_id: String,
    binding: InternalEventBinding,
}

#[cfg(test)]
#[derive(Debug, Clone)]
#[expect(
    dead_code,
    reason = "The test fixture retains its complete envelope while each unit case inspects only its relevant fields."
)]
enum InternalEventBinding {
    AppletFormal {
        event_id: String,
        applet_id: arkret_wire::AppletId,
        staged_producer_authority: Option<(arkret_wire::DidUrl, arkret_wire::DidKey)>,
    },
    SidecarEnsure {
        event_id: String,
    },
    AgentMembershipCascade {
        event_id: String,
        initiator_id: arkret_wire::ActorId,
    },
    PeerFederatedEvent {
        event_id: String,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    },
    ProofAuthenticatedEvent {
        event_id: String,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    },
    PeerAgentMembershipCascade {
        event_id: String,
        initiator_id: arkret_wire::ActorId,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    },
}

#[cfg(test)]
impl InternalEventAdmission {
    pub(in crate::routing) fn applet_formal(
        realm_id: impl Into<String>,
        actor_id: arkret_wire::ActorId,
        kind: impl Into<String>,
        event_id: impl Into<String>,
        applet_id: arkret_wire::AppletId,
        staged_producer_authority: Option<(arkret_wire::DidUrl, arkret_wire::DidKey)>,
    ) -> Self {
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.signing_principal_id().to_string(),
            actor_id,
            kind: kind.into(),
            device_id: String::new(),
            binding: InternalEventBinding::AppletFormal {
                event_id: event_id.into(),
                applet_id,
                staged_producer_authority,
            },
        }
    }

    pub(in crate::routing::events::event_log) fn matches(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
    ) -> bool {
        session.actor == self.session_actor_id
            && match &session.endpoint {
                coland_services::identity::SessionEndpointState::HumanDevice { device_id } => {
                    device_id == &self.device_id
                }
                coland_services::identity::SessionEndpointState::ServiceSynthetic => {
                    self.device_id.is_empty()
                }
                coland_services::identity::SessionEndpointState::AgentRuntime { .. } => false,
            }
            && object
                .get("actor_id")
                .cloned()
                .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
                .as_ref()
                == Some(&self.actor_id)
            && self.matches_realm_coordinate(object)
            && (self.kind.is_empty()
                || object.get("kind").and_then(Value::as_str) == Some(self.kind.as_str()))
            && match &self.binding {
                InternalEventBinding::AppletFormal {
                    event_id,
                    applet_id,
                    ..
                } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                        && object.get("applet_id").and_then(Value::as_str)
                            == Some(applet_id.as_str())
                }
                InternalEventBinding::SidecarEnsure { event_id } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                }
                InternalEventBinding::AgentMembershipCascade {
                    event_id,
                    initiator_id,
                } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                        && object
                            .get("executed_by")
                            .cloned()
                            .map(serde_json::from_value::<arkret_wire::ActorId>)
                            .transpose()
                            .ok()
                            .map(|actor| actor.unwrap_or_else(|| self.actor_id.clone()))
                            .as_ref()
                            == Some(initiator_id)
                }
                InternalEventBinding::PeerFederatedEvent { event_id, .. } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                }
                InternalEventBinding::ProofAuthenticatedEvent { event_id, .. } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                }
                InternalEventBinding::PeerAgentMembershipCascade {
                    event_id,
                    initiator_id,
                    ..
                } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                        && object
                            .get("executed_by")
                            .cloned()
                            .map(serde_json::from_value::<arkret_wire::ActorId>)
                            .transpose()
                            .ok()
                            .map(|actor| actor.unwrap_or_else(|| self.actor_id.clone()))
                            .as_ref()
                            == Some(initiator_id)
                }
            }
    }

    fn matches_realm_coordinate(&self, object: &serde_json::Map<String, Value>) -> bool {
        if let Some(realm_id) = object.get("realm_id").and_then(Value::as_str) {
            return realm_id == self.realm_id;
        }
        if object.get("kind").and_then(Value::as_str)
            != Some(arkret_wire::EventKind::RealmCreate.as_str())
        {
            return false;
        }
        object
            .get("event_id")
            .and_then(Value::as_str)
            .and_then(|event_id| arkret_wire::EventId::new(event_id.to_owned()).ok())
            .is_some_and(|event_id| {
                arkret_wire::RealmId::from_event_id(&event_id).as_str() == self.realm_id
            })
    }

    pub(in crate::routing::events::event_log) fn applet_formal_producer_signing_key(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
        verification_method: &str,
    ) -> Option<&arkret_wire::DidKey> {
        if !self.matches(session, object) {
            return None;
        }
        match &self.binding {
            InternalEventBinding::AppletFormal {
                staged_producer_authority:
                    Some((producer_verification_method, producer_signing_key)),
                ..
            } if producer_verification_method.as_str() == verification_method => {
                Some(producer_signing_key)
            }
            _ => None,
        }
    }
}

impl SubmitOneError {
    pub(in crate::routing) fn new(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let code = code.into();
        let message = message.into();
        let error = if let Some(code) = ErrorCode::from_wire(&code) {
            AppError::from_rejection(code, message)
        } else {
            let mapped = match status {
                StatusCode::PRECONDITION_FAILED => ErrorCode::FailedPrecondition,
                StatusCode::CONFLICT => ErrorCode::Conflict,
                StatusCode::FORBIDDEN => ErrorCode::CapabilityDenied,
                StatusCode::UNAUTHORIZED => ErrorCode::Unauthenticated,
                StatusCode::BAD_REQUEST => ErrorCode::ParamInvalid,
                StatusCode::UNPROCESSABLE_ENTITY => ErrorCode::SchemaViolation,
                _ => ErrorCode::InternalError,
            };
            AppError::from_rejection(mapped, message).with_internal_reason(code)
        };
        Self::Rejected {
            error: Box::new(error),
            details: None,
        }
    }

    pub(in crate::routing) fn with_details(mut self, details: impl serde::Serialize) -> Self {
        match &mut self {
            Self::Rejected {
                details: wire_details,
                ..
            } => {
                *wire_details = serde_json::to_value(details).ok();
            }
            #[cfg(test)]
            Self::Quarantined { .. } => {}
        }
        self
    }

    #[cfg(test)]
    /// A registered operation-semantic rejection is always a schema violation
    /// at the top level, while its stable machine discriminator belongs in
    /// `error.details.reason_code`. Keeping this mapping here prevents each
    /// admission lane from silently flattening the reason back into prose.
    /// Discriminators that are not registered reason codes are routed to the
    /// unstable `reason_detail` key instead.
    pub(in crate::routing) fn semantic_schema_violation(reason_code: &'static str) -> Self {
        let detail_key = if arkret_wire::ReasonCode::is_registered(reason_code) {
            "reason_code"
        } else {
            "reason_detail"
        };
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            reason_code,
        )
        .with_details(serde_json::json!({
            detail_key: reason_code,
        }))
    }

    #[cfg(test)]
    pub(in crate::routing) fn quarantine(
        event_id: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Quarantined {
            event_id: event_id.into(),
            reason_code: code.into(),
            message: message.into(),
        }
    }

    pub(in crate::routing) fn rejection(&self) -> Option<&AppError> {
        match self {
            Self::Rejected { error, .. } => Some(error),
            #[cfg(test)]
            Self::Quarantined { .. } => None,
        }
    }

    #[cfg(test)]
    pub(in crate::routing) fn details(&self) -> Option<&Value> {
        match self {
            Self::Rejected { details, .. } => details.as_ref(),
            #[cfg(test)]
            Self::Quarantined { .. } => None,
        }
    }

    pub(in crate::routing) fn quarantine_event_id(&self) -> Option<String> {
        match self {
            #[cfg(test)]
            Self::Quarantined { event_id, .. } => Some(event_id.clone()),
            Self::Rejected { .. } => None,
        }
    }

    pub(in crate::routing) fn status(&self) -> StatusCode {
        self.rejection()
            .map_or(StatusCode::OK, AppError::http_status)
    }

    pub(in crate::routing) fn code(&self) -> String {
        match self {
            Self::Rejected { error, .. } => error
                .reason_code
                .as_deref()
                .unwrap_or_else(|| error.wire_code())
                .to_owned(),
            #[cfg(test)]
            Self::Quarantined { reason_code, .. } => reason_code.clone(),
        }
    }

    pub(in crate::routing) fn message(&self) -> String {
        match self {
            Self::Rejected { error, .. } => error.message.to_string(),
            #[cfg(test)]
            Self::Quarantined { message, .. } => message.clone(),
        }
    }
}

/// Map a rejected Event submission onto the HTTP error family without losing the
/// wire discriminator.
///
/// A caller-signed Event that ordinary admission rejects has a real reason, and
/// `context` names the surface that submitted it. Reducer rejection reasons (for
/// example `circle_realm_mismatch` or `grant_exceeds_issuer_authority`) are
/// stable *reason* codes, not top-level error codes: one that is not a registered
/// error code keeps its semantic HTTP class and travels in `reason_code` when it
/// is a registered reason code (internal discriminators fall back to the unstable
/// `reason_detail`), rather than being flattened into a misleading 500
/// internal_error.
pub(in crate::routing) fn submit_one_error_to_app_error(
    context: &str,
    status: StatusCode,
    code: impl Into<String>,
    detail: &str,
) -> AppError {
    let code = code.into();
    let message = format!("{context}: {detail}");
    if code == arkret_wire::ReasonCode::APPROVAL_REQUIRED {
        return crate::app_error!(ClaimRequired, message).with_reason_code(code);
    }
    if code == arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    // The Circle subset invariant is a registered sub-reason of
    // `failed_precondition`, not a top-level error code. Preserve the 422
    // admission class and carry the exact reducer discriminator separately.
    if code == arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    // relation.md §4 and the error registry bind this reducer sub-reason to
    // top-level failed_precondition (HTTP 409). Do not preserve the internal
    // projection-preflight 412 carrier: 412 is reserved for HTTP precondition
    // preconditions and is not the registered wire status for this verdict.
    if code == arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    // The bounded inline snapshot capacity is a registered failed_precondition
    // reason of every Realm-stream append, not a top-level code.
    if code == arkret_wire::ReasonCode::SNAPSHOT_CAPACITY_EXCEEDED {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    // AK-NC grant authority clause: a first-issued grant outside its issuer's
    // authority is `failed_precondition` with this registered reason.
    if code == arkret_wire::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    if let Some(mapped) = ErrorCode::from_wire(&code) {
        return AppError::from_rejection(mapped, message);
    }
    let mapped = match status {
        StatusCode::PRECONDITION_FAILED => ErrorCode::FailedPrecondition,
        StatusCode::CONFLICT => ErrorCode::Conflict,
        StatusCode::FORBIDDEN => ErrorCode::CapabilityDenied,
        StatusCode::UNAUTHORIZED => ErrorCode::Unauthenticated,
        StatusCode::BAD_REQUEST => ErrorCode::ParamInvalid,
        StatusCode::UNPROCESSABLE_ENTITY => ErrorCode::SchemaViolation,
        _ => ErrorCode::InternalError,
    };
    AppError::from_rejection(mapped, message).with_internal_reason(code)
}

impl From<EventValidationError> for SubmitOneError {
    fn from(error: EventValidationError) -> Self {
        let mut rendered = Self::new(error.status, error.code, error.message);
        if let Some(reason_code) = error.reason_code {
            let registered = arkret_wire::ReasonCode::is_registered(reason_code);
            match &mut rendered {
                Self::Rejected { error, .. } => {
                    error.attach_internal_reason(reason_code);
                }
                #[cfg(test)]
                Self::Quarantined { .. } => {}
            }
            let detail_key = if registered {
                "reason_code"
            } else {
                "reason_detail"
            };
            rendered = rendered.with_details(serde_json::json!({
                detail_key: reason_code,
            }));
        }
        rendered
    }
}

pub(super) fn event_validation_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> EventValidationError {
    EventValidationError {
        status,
        code,
        message: message.into(),
        reason_code: None,
    }
}

/// Accept the one registered pre-grant PCR genesis carrier after the peer
/// transport has authenticated the Account Authority service.
pub(in crate::routing) async fn submit_peer_pcr_genesis(
    state: &AppState,
    request: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
    exact_request_body: Vec<u8>,
) -> Result<
    arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResponseBody,
    SubmitOneError,
> {
    request.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("invalid PCR genesis relay: {error}"),
        )
    })?;
    let create_payload: arkret_models_collaboration::events_payloads::RealmCreatePayload = request
        .genesis_unit
        .create()
        .typed_payload::<arkret_wire::event_spec::RealmCreate>()
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("invalid PCR genesis create payload: {error}"),
            )
        })?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "PCR genesis omits its founding device descriptor",
            )
        })?;
    let accepted_device_id = descriptor.device_id.clone();
    // Exact replay is resolved before the short-lived proof's freshness gate.
    // The PG ledger compares the original HTTP bytes and idempotency key,
    // including after proof expiry; matching Event ids alone prove no replay.
    if let Some(outcome) = state
        .authority_commits()
        .pcr_genesis_replay(request, &exact_request_body)
        .await
        .map_err(|error| {
            let (status, code) = if error.is_conflict_kind() {
                (StatusCode::CONFLICT, "duplicate_conflict")
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            };
            SubmitOneError::new(
                status,
                code,
                format!("PCR genesis replay lookup failed: {error}"),
            )
        })?
    {
        outcome.validate_against(request).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored PCR genesis replay result is invalid: {error}"),
            )
        })?;
        return Ok(outcome);
    }
    validate_identity_creation_control_proof(state, request).await?;
    let authority = coland_storage::CurrentRealmAuthority {
        realm_id: request.pcr_realm_id.clone(),
        generation: 0,
        service_id: request.account_authority_id.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            request.genesis_unit.create().event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let verification_method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("PCR authority signing method is invalid: {error}"),
        )
    })?;
    let queued_at = Utc::now();
    let unit = state
        .authority_commits()
        .prepare_pcr_genesis_unit(
            request.clone(),
            exact_request_body,
            &authority,
            verification_method,
            state.notary_signing_key().as_ref(),
            queued_at,
        )
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("PCR genesis authority preparation failed: {error}"),
            )
        })?;
    let result = state
        .authority_commits()
        .admit_pcr_genesis_unit(&unit, queued_at)
        .await
        .map_err(|error| {
            let (status, code) = if error.is_conflict_kind() {
                (StatusCode::CONFLICT, "duplicate_conflict")
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            };
            SubmitOneError::new(status, code, format!("PCR genesis commit failed: {error}"))
        })?;
    let outcome = match result {
        coland_storage::PcrGenesisCommitOutcome::Committed(outcome)
        | coland_storage::PcrGenesisCommitOutcome::Duplicate(outcome) => outcome,
    };
    if outcome.accepted_device_id != accepted_device_id {
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "PCR genesis result changed the founding device binding",
        ));
    }
    outcome.validate_against(request).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("committed PCR genesis outcome is invalid: {error}"),
        )
    })?;
    Ok(outcome)
}

async fn validate_identity_creation_control_proof(
    state: &AppState,
    request: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
) -> Result<(), SubmitOneError> {
    let proof = &request.identity_creation_control_proof;
    let now = Utc::now();
    // The complete historical registration evidence carries no freshness gate
    // against this receiver's clock: its `accepted_at` is the relaying
    // Authority's registry acceptance instant, not a claim about now.
    if !identity_creation_control_proof_window_valid(proof.issued_at, proof.expires_at, now)
        || proof.audience_id.as_str() != state.service_id().as_str()
    {
        return Err(SubmitOneError::new(
            StatusCode::UNAUTHORIZED,
            "signature_invalid",
            "identity creation control proof is expired or has the wrong audience",
        ));
    }
    let validated_anchor = arkret_identity::validate_principal_registration_anchor(
        &request.principal_registration_anchor,
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNAUTHORIZED,
            "signature_invalid",
            format!("principal registration anchor is invalid: {error}"),
        )
    })?;
    arkret_signatures::webvh::verify_identity_creation_control_proof(&validated_anchor, proof)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::UNAUTHORIZED,
                "signature_invalid",
                format!("identity creation proof is invalid: {error}"),
            )
        })?;
    let registration_did_operation = match &request.principal_registration_anchor {
        arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            ..
        } => registration_did_operation.as_ref(),
    };
    arkret_signatures::webvh::verify_registration_did_evidence_draft(
        registration_did_operation,
        &request.registration_did_evidence.draft(),
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "historical_did_evidence_invalid",
            format!("frozen registration DID evidence is invalid: {error}"),
        )
    })?;
    Ok(())
}

fn identity_creation_control_proof_window_valid(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    issued_at <= now + Duration::seconds(IDENTITY_CREATION_CONTROL_PROOF_MAX_FUTURE_SKEW_SECONDS)
        && expires_at > now
        && expires_at - issued_at <= Duration::minutes(5)
}

mod value;

pub(in crate::routing) use value::{
    submit_applet_revoke_event_submission, submit_event_value, submit_initial_event_submission,
};
// `submit_one_error_to_app_error` is defined in this module, so it needs no
// re-export here; `event_log.rs` names it directly.

#[cfg(test)]
#[path = "submit_tests.rs"]
mod tests;
