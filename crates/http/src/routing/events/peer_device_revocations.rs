use arkret_wire::{
    AcceptedDevicePossessionProof, AccountId, CommittedEventRef, DeviceId,
    DeviceRevocationAdmissionDecision, DeviceRevocationAdmissionInput,
    DeviceRevocationDeniedAction, EventId, Hash, RealmCommitId,
};
use chrono::{DateTime, Utc};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::ServiceErrorKind;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::peer::{cross_domain_replay, schema_violation};
use crate::state::AppState;

/// Admit the origin-derived selector, or classify why it could not be derived.
///
/// The derivation-domain section of `device-lifecycle.md` makes this a two-way split,
/// never a three-way one:
///
/// * the derivation is a partial function — an unknown device, a device that belongs to another
///   account, a never-authorized device and an authorization that is no longer current all leave it
///   undefined. On this authenticated peer surface every one of them MUST collapse into the same
///   anti-enumeration `authority_mismatch` receipt, so the caller cannot tell them apart. That is
///   expressed here as `Ok(None)`.
/// * a projection row that claims current / active / verified while omitting its schema-required
///   authorization Event id or generation ref is a projection integrity failure, not an ordinary
///   "unauthorized" answer. It MUST surface as an internal availability fault and MUST NOT be
///   returned as `allow`.
fn admit_origin_current_selector(
    derived: Result<coland_storage::DeviceRevocationGateSelector, coland_services::ServiceError>,
) -> Result<Option<coland_storage::DeviceRevocationGateSelector>, AppError> {
    match derived {
        Ok(selector) => Ok(Some(selector)),
        Err(error) if matches!(error.kind(), ServiceErrorKind::NotFound) => Ok(None),
        Err(error) => Err(AppError::internal(format!(
            "origin device authorization projection is unavailable: {error}"
        ))),
    }
}

/// The receipt members a linearized gate status projects to, before typed-id
/// parsing.
struct GateDecisionProjection {
    decision: DeviceRevocationAdmissionDecision,
    derived_binding: Option<CommittedEventRef>,
}

/// The product-private current-device admission adapter projects only `allow`
/// with the origin-derived selector. Every other decision,
/// `authority_mismatch` included, MUST return no `derived_binding` so the
/// receipt cannot be read as an oracle for "does this device exist".
fn project_gate_decision(
    status: coland_storage::DeviceRevocationGateStatus,
    origin_current_selector: Option<&coland_storage::DeviceRevocationGateSelector>,
) -> GateDecisionProjection {
    let decision = status.admission_decision();
    GateDecisionProjection {
        decision,
        derived_binding: origin_current_selector
            .filter(|_| decision == DeviceRevocationAdmissionDecision::Allow)
            .map(|selector| selector.authorization_ref.clone()),
    }
}

fn current_binding_stable(
    before: Option<&coland_storage::DeviceRevocationGateSelector>,
    after: Option<&coland_storage::DeviceRevocationGateSelector>,
) -> bool {
    before == after
}

fn accepted_device_proof_requires_verification(
    origin_current_selector: Option<&coland_storage::DeviceRevocationGateSelector>,
) -> bool {
    // Device authorization derivation is a partial function. An unknown,
    // foreign, or never-authorized device must reach this authenticated peer
    // surface as the same `authority_mismatch` decision, not fail while
    // resolving the proof key and become an account/device enumeration oracle.
    origin_current_selector.is_some()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentDeviceCheckRequest {
    account_id: AccountId,
    device_id: DeviceId,
    expected_device_authorize_event_id: Option<EventId>,
    expected_device_generation_ref: Option<u64>,
    action_class: DeviceRevocationDeniedAction,
    intent_digest: Hash,
    accepted_device_possession_proof: Option<AcceptedDevicePossessionProof>,
    requested_at: DateTime<Utc>,
}

impl CurrentDeviceCheckRequest {
    fn admission_input(&self) -> DeviceRevocationAdmissionInput {
        DeviceRevocationAdmissionInput {
            account_id: self.account_id.clone(),
            device_id: self.device_id.clone(),
            expected_device_authorize_event_id: self.expected_device_authorize_event_id.clone(),
            expected_device_generation_ref: self.expected_device_generation_ref,
            action_class: self.action_class,
            intent_digest: self.intent_digest.clone(),
            accepted_device_possession_proof: self.accepted_device_possession_proof.clone(),
            requested_at: self.requested_at,
        }
    }
}

fn initial_issue_authorization_ref(
    request: &CurrentDeviceCheckRequest,
    current: Option<&coland_storage::DeviceRevocationGateSelector>,
) -> Option<CommittedEventRef> {
    // Initial registration/recovery issues use the authority's terminal
    // ledger, not a previously issued grant binding. Freeze the independently
    // derived active authorization for the same durable gate comparison.
    // Returning issues and refreshes carry an accepted-device proof and never
    // adopt it; neither do explicit expectations.
    if request.action_class == DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh
        && request.accepted_device_possession_proof.is_none()
        && request.expected_device_authorize_event_id.is_none()
        && request.expected_device_generation_ref.is_none()
    {
        current.map(|selector| selector.authorization_ref.clone())
    } else {
        None
    }
}

fn returning_issue_authorization_ref(
    request: &CurrentDeviceCheckRequest,
    current: Option<&coland_storage::DeviceRevocationGateSelector>,
    current_generation_ref: Option<u64>,
    verified: Option<&crate::jws_verify::VerifiedPrincipalDeviceSignatureBinding>,
) -> Option<CommittedEventRef> {
    // A returning issue has no predecessor grant. Its independently verified
    // durable-device proof supplies the exact current binding for the gate.
    if request.action_class != DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh
        || !matches!(
            request.accepted_device_possession_proof,
            Some(AcceptedDevicePossessionProof::Issue(_))
        )
        || request.expected_device_authorize_event_id.is_some()
        || request.expected_device_generation_ref.is_some()
    {
        return None;
    }
    let current = current?;
    let verified = verified?;
    (current.authorization_ref.event_id == verified.authorization_event_id
        && current_generation_ref == Some(verified.generation_ref))
    .then(|| current.authorization_ref.clone())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentDeviceCheckOutcome {
    account_id: AccountId,
    device_id: DeviceId,
    authorization_event_id: Option<EventId>,
    device_generation_ref: Option<u64>,
    action_class: DeviceRevocationDeniedAction,
    intent_digest: Hash,
    accepted_device_possession_proof_digest: Option<Hash>,
    decision: DeviceRevocationAdmissionDecision,
    linearization_seq: u64,
    linearized_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    accepted_commit_id: Option<RealmCommitId>,
}

fn require_account_authority_request(request: &CurrentDeviceCheckRequest) -> Result<(), AppError> {
    match request.action_class {
        DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh
        | DeviceRevocationDeniedAction::DevicePairingCodeClaim
        // The Account Authority checks the approver before admitting its exact
        // device-authorize Event. This is eligibility, not Event acceptance.
        | DeviceRevocationDeniedAction::EventWrite => {}
        DeviceRevocationDeniedAction::KeypackageClaim
        | DeviceRevocationDeniedAction::ToDeviceWrite => {
            return Err(schema_violation(
                "private current-device check only admits account-authority device actions",
            ));
        }
    }
    request
        .admission_input()
        .validate()
        .map_err(|error| schema_violation(error.to_string()))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "coland.account_authority.current_device.check"))]
pub(super) async fn check_private_current_device(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CurrentDeviceCheckOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");

    // Authentication precedes every principal/device lookup. A caller must not
    // use this operation as an account oracle.
    //
    // `service-http-binding.md` §2.2.3 registers this operation on the
    // deployment-internal authenticated channel, and the only admitted caller
    // relationship is "the Account Authority bound to this exact account → this
    // origin Station". There is no external calling branch: a request that did
    // not arrive over that registered channel is rejected here, before any
    // device-private state is read, and there is no fallback to a service
    // signature, to a self-reported `Source-Service-ID`, or to an anonymous
    // call. When no channel is registered the operation fails closed.
    //
    // Every plaintext proxy on the channel is part of the trusted deployment
    // TCB, which is why the receipt below has no detached proof or
    // `verification_method` and neither direction signs the transport shell.
    crate::routing::events::peer::authenticate_account_authority_private_request(state, req)?;

    let request = req
        .parse_json::<CurrentDeviceCheckRequest>()
        .await
        .map_err(|_| AppError::json_invalid("invalid private current-device check request body"))?;
    require_account_authority_request(&request)?;

    // The target Station is the local fixed-route receiver, not an identity
    // repeated in channel headers.
    if request.account_id.station_id != state.service_core_id() {
        return Err(cross_domain_replay(
            "device revocation gate request is routed to the wrong Station",
        ));
    }

    // Identity-anchor admission uses the same principal-scoped lock. Holding it
    // through proof verification and receipt construction keeps the memory
    // adapter linearizable and avoids needless optimistic retries in one
    // process. PostgreSQL correctness does not rely on this process-local lock:
    // the durable gate is followed by an exact current-binding revalidation.
    let generation_lock =
        crate::routing::identity::device_generation::device_generation_admission_lock(
            request.account_id.principal_id.as_str(),
        );
    let _generation_guard = generation_lock.lock().await;

    let origin_current_selector = admit_origin_current_selector(
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            request.account_id.principal_id.as_str(),
            request.device_id.as_str(),
        )
        .await,
    )?;
    let current_generation_ref =
        crate::routing::identity::device_generation::current_device_generation(
            state,
            request.account_id.principal_id.as_str(),
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("current device generation is unavailable: {error}"))
        })?
        .map(|generation| generation.current_ref);

    // A handoff/session DPoP proves possession of the short-lived holder key,
    // not of the durable accepted-device key. Returning issue and human
    // refresh therefore carry one closed proof, verified here against the
    // origin's accepted current device authority before any allow receipt can
    // be minted. Initial registration/recovery issue deliberately has no such
    // proof because its accepted binding comes from its own terminal ledger.
    let accepted_device_possession_proof_digest = request
        .accepted_device_possession_proof
        .as_ref()
        .map(AcceptedDevicePossessionProof::proof_digest)
        .transpose()
        .map_err(|error| schema_violation(error.to_string()))?;
    let verified_proof_binding = if let Some(proof) = request
        .accepted_device_possession_proof
        .as_ref()
        .filter(|_| accepted_device_proof_requires_verification(origin_current_selector.as_ref()))
    {
        let (issued_at, expires_at, signature) = match proof {
            AcceptedDevicePossessionProof::Issue(proof) => {
                (proof.issued_at, proof.expires_at, proof.signature.as_str())
            }
            AcceptedDevicePossessionProof::Refresh(proof) => {
                (proof.issued_at, proof.expires_at, proof.signature.as_str())
            }
        };
        let now = chrono::Utc::now();
        if request.requested_at < issued_at
            || request.requested_at >= expires_at
            || now < issued_at
            || now >= expires_at
        {
            return Err(schema_violation(
                "accepted-device possession proof is outside its validity window",
            ));
        }
        let signing_bytes = proof
            .canonical_signing_bytes()
            .map_err(|error| schema_violation(error.to_string()))?;
        let verified_binding = crate::jws_verify::verify_principal_authorized_ed25519_signature_with_account_authority_async(
            &signing_bytes,
            signature,
            proof.verification_method().as_str(),
            &request.account_id,
            &request.device_id,
            state,
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                %error,
                principal_id = %request.account_id.principal_id,
                device_id = %request.device_id,
                "accepted-device possession proof verification failed"
            );
            schema_violation("accepted-device possession proof is invalid")
        })?;
        Some(verified_binding)
    } else {
        None
    };
    if let Some(verified_binding) = verified_proof_binding.as_ref()
        && !origin_current_selector.as_ref().is_some_and(|selector| {
            selector.authorization_ref.event_id == verified_binding.authorization_event_id
                && current_generation_ref == Some(verified_binding.generation_ref)
        })
    {
        return Err(schema_violation(
            "accepted-device proof key is no longer the current device generation",
        ));
    }
    let expected_authorization_ref = match request.expected_device_authorize_event_id.as_ref() {
        Some(event_id) if request.expected_device_generation_ref == current_generation_ref => state
            .persistence()
            .committed_event(event_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .map(|record| CommittedEventRef {
                event_id: event_id.clone(),
                commit_id: record.commit.commit_id,
                stream_ref: record.commit.stream_ref,
                stream_position: record.commit.stream_position,
            }),
        _ => initial_issue_authorization_ref(&request, origin_current_selector.as_ref()).or_else(
            || {
                returning_issue_authorization_ref(
                    &request,
                    origin_current_selector.as_ref(),
                    current_generation_ref,
                    verified_proof_binding.as_ref(),
                )
            },
        ),
    };
    let linearization = state
        .persistence()
        .linearize_device_revocation_gate(
            coland_storage::DeviceRevocationGateLinearizationRequest {
                principal_id: request.account_id.principal_id.clone(),
                station_id: request.account_id.station_id.clone(),
                device_id: request.device_id.to_string(),
                expected_authorization_ref,
                origin_current_selector: origin_current_selector.clone(),
                action_class: request.action_class,
                intent_digest: request.intent_digest.to_string(),
                requested_at: request.requested_at,
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "device revocation gate linearization failed: {error}"
            ))
        })?;

    // Optimistic current-device linearization. Revocation acceptance is
    // already ordered with this intent by the durable per-device gate head.
    // Re-read the independently projected authorization/generation after that
    // durable point and require the exact content-addressed Event + monotonic
    // generation snapshot observed during proof verification. A generation
    // or key transition that committed before the gate is rejected here; one
    // that commits afterwards is correctly ordered after this decision.
    let post_linearization_selector = admit_origin_current_selector(
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            request.account_id.principal_id.as_str(),
            request.device_id.as_str(),
        )
        .await,
    )?;
    if !current_binding_stable(
        origin_current_selector.as_ref(),
        post_linearization_selector.as_ref(),
    ) {
        return Err(AppError::conflict(
            "device authorization changed while the gate decision was linearized",
        )
        .with_internal_reason("device_generation_changed"));
    }

    let GateDecisionProjection {
        decision,
        derived_binding,
    } = project_gate_decision(
        linearization.status.clone(),
        origin_current_selector.as_ref(),
    );
    let (authorization_event_id, device_generation_ref, accepted_commit_id) = match derived_binding
    {
        Some(binding) => (
            Some(binding.event_id),
            current_generation_ref,
            Some(binding.commit_id),
        ),
        None => (None, None, None),
    };
    if decision == DeviceRevocationAdmissionDecision::Allow && accepted_commit_id.is_none() {
        return Err(AppError::internal(
            "allowed current-device binding has no accepted RealmCommit",
        ));
    }

    let outcome = CurrentDeviceCheckOutcome {
        account_id: request.account_id.clone(),
        device_id: request.device_id.clone(),
        authorization_event_id,
        device_generation_ref,
        action_class: request.action_class,
        intent_digest: request.intent_digest.clone(),
        accepted_device_possession_proof_digest,
        decision,
        linearization_seq: linearization.linearization_seq,
        linearized_at: linearization.linearized_at,
        expires_at: linearization.expires_at,
        accepted_commit_id,
    };
    json_ok(outcome)
}

#[cfg(test)]
mod tests {
    use coland_services::ServiceError;
    use coland_storage::{DeviceRevocationGateSelector, DeviceRevocationGateStatus};

    use super::*;

    const PRINCIPAL: &str = "ak:did_core:webvh:z6mkfixture:alice.example";
    const STATION: &str = "ak:did_core:web:coland.example";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000030";
    const AUTHORIZE_EVENT: &str = "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa";

    fn selector() -> DeviceRevocationGateSelector {
        let event_id = arkret_wire::EventId::new(AUTHORIZE_EVENT).unwrap();
        DeviceRevocationGateSelector {
            principal_id: arkret_wire::DidCoreId::new(PRINCIPAL).unwrap(),
            station_id: arkret_wire::DidCoreId::new(STATION).unwrap(),
            device_id: DEVICE.to_owned(),
            authorization_ref: arkret_wire::CommittedEventRef {
                commit_id: RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    event_id.as_str().as_bytes(),
                )),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: arkret_wire::RealmId::from_event_id(
                        &arkret_wire::EventId::from_digest(
                            arkret_canonical::DigestSuite::Sha256,
                            [0x52; 32],
                        ),
                    ),
                },
                stream_position: 1,
                event_id,
            },
        }
    }

    fn bound_request(action_class: DeviceRevocationDeniedAction) -> CurrentDeviceCheckRequest {
        let current = selector();
        CurrentDeviceCheckRequest {
            account_id: AccountId::new(current.principal_id, current.station_id),
            device_id: DeviceId::new(DEVICE).unwrap(),
            expected_device_authorize_event_id: Some(current.authorization_ref.event_id),
            expected_device_generation_ref: Some(1),
            action_class,
            intent_digest: Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            accepted_device_possession_proof: None,
            requested_at: Utc::now(),
        }
    }

    fn issue_proof(request: &CurrentDeviceCheckRequest) -> AcceptedDevicePossessionProof {
        AcceptedDevicePossessionProof::Issue(arkret_wire::AcceptedDeviceIssuePossessionProof {
            context: arkret_wire::AcceptedDevicePossessionProofContext::V1,
            purpose: arkret_wire::AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue,
            request_id: arkret_wire::RequestId::new(
                "ak:request:01970000-0000-7000-8000-000000000021",
            )
            .unwrap(),
            account_subject: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            account_handoff_grant_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            account_id: request.account_id.clone(),
            device_id: request.device_id.clone(),
            audience_id: arkret_wire::DidCoreId::new(STATION).unwrap(),
            holder_jkt: "A".repeat(43),
            session_intent_digest: request.intent_digest.clone(),
            issued_at: request.requested_at,
            expires_at: request.requested_at + chrono::Duration::seconds(300),
            verification_method: arkret_wire::DidUrl::new("did:web:alice.example#device-1")
                .unwrap(),
            signature: arkret_wire::Base64UrlString::new("A".repeat(86)).unwrap(),
        })
    }

    fn refresh_proof(request: &CurrentDeviceCheckRequest) -> AcceptedDevicePossessionProof {
        AcceptedDevicePossessionProof::Refresh(arkret_wire::AcceptedDeviceRefreshPossessionProof {
            context: arkret_wire::AcceptedDevicePossessionProofContext::V1,
            purpose: arkret_wire::AcceptedDeviceRefreshPossessionPurpose::SessionGrantRefresh,
            predecessor_session_grant_id: arkret_wire::SessionGrantId::new(
                "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            )
            .unwrap(),
            account_id: request.account_id.clone(),
            device_id: request.device_id.clone(),
            audience_id: arkret_wire::DidCoreId::new(STATION).unwrap(),
            holder_jkt: "A".repeat(43),
            session_intent_digest: request.intent_digest.clone(),
            issued_at: request.requested_at,
            expires_at: request.requested_at + chrono::Duration::seconds(300),
            verification_method: arkret_wire::DidUrl::new("did:web:alice.example#device-1")
                .unwrap(),
            signature: arkret_wire::Base64UrlString::new("A".repeat(86)).unwrap(),
        })
    }

    #[test]
    fn private_check_admits_only_account_authority_device_actions() {
        for action in [
            DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
            DeviceRevocationDeniedAction::DevicePairingCodeClaim,
            DeviceRevocationDeniedAction::EventWrite,
        ] {
            assert!(require_account_authority_request(&bound_request(action)).is_ok());
        }
        for action in [
            DeviceRevocationDeniedAction::KeypackageClaim,
            DeviceRevocationDeniedAction::ToDeviceWrite,
        ] {
            assert!(require_account_authority_request(&bound_request(action)).is_err());
        }
    }

    #[test]
    fn private_code_claim_requires_complete_current_device_binding() {
        let mut request = bound_request(DeviceRevocationDeniedAction::DevicePairingCodeClaim);
        assert!(require_account_authority_request(&request).is_ok());
        request.accepted_device_possession_proof = Some(issue_proof(&request));
        assert!(require_account_authority_request(&request).is_err());
        request.accepted_device_possession_proof = None;
        request.expected_device_generation_ref = None;
        assert!(require_account_authority_request(&request).is_err());
        request.expected_device_generation_ref = Some(0);
        assert!(require_account_authority_request(&request).is_err());
    }

    #[test]
    fn session_grant_issue_or_refresh_is_told_apart_by_its_proof() {
        let mut registration =
            bound_request(DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh);
        registration.expected_device_authorize_event_id = None;
        registration.expected_device_generation_ref = None;
        assert!(require_account_authority_request(&registration).is_ok());

        let mut returning = registration.clone();
        returning.accepted_device_possession_proof = Some(issue_proof(&returning));
        assert!(require_account_authority_request(&returning).is_ok());

        let mut refresh = registration;
        refresh.accepted_device_possession_proof = Some(refresh_proof(&refresh));
        assert!(
            require_account_authority_request(&refresh).is_err(),
            "a refresh must carry its predecessor grant's exact device binding"
        );
        let bound = bound_request(DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh);
        refresh.expected_device_authorize_event_id = bound.expected_device_authorize_event_id;
        refresh.expected_device_generation_ref = bound.expected_device_generation_ref;
        assert!(require_account_authority_request(&refresh).is_ok());

        let mut code_claim = bound_request(DeviceRevocationDeniedAction::DevicePairingCodeClaim);
        code_claim.accepted_device_possession_proof = Some(issue_proof(&code_claim));
        assert!(require_account_authority_request(&code_claim).is_err());
    }

    #[test]
    fn returning_issue_freezes_only_the_verified_current_device_binding() {
        let current = selector();
        let mut request = CurrentDeviceCheckRequest {
            account_id: AccountId::new(current.principal_id.clone(), current.station_id.clone()),
            device_id: DeviceId::new(DEVICE).unwrap(),
            expected_device_authorize_event_id: None,
            expected_device_generation_ref: None,
            action_class: DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
            intent_digest: Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            accepted_device_possession_proof: None,
            requested_at: Utc::now(),
        };
        request.accepted_device_possession_proof = Some(issue_proof(&request));
        let verified = crate::jws_verify::VerifiedPrincipalDeviceSignatureBinding {
            authorization_event_id: current.authorization_ref.event_id.clone(),
            generation_ref: 1,
        };
        let resolve = |request: &CurrentDeviceCheckRequest,
                       verified: Option<
            &crate::jws_verify::VerifiedPrincipalDeviceSignatureBinding,
        >| {
            returning_issue_authorization_ref(request, Some(&current), Some(1), verified)
        };
        let adopted = resolve(&request, Some(&verified));
        assert_eq!(adopted, Some(current.authorization_ref.clone()));
        let gate = coland_storage::DeviceRevocationGateLinearizationRequest {
            principal_id: current.principal_id.clone(),
            station_id: current.station_id.clone(),
            device_id: current.device_id.clone(),
            expected_authorization_ref: adopted,
            origin_current_selector: Some(current.clone()),
            action_class: DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
            intent_digest: request.intent_digest.to_string(),
            requested_at: request.requested_at,
        };
        assert_eq!(
            coland_storage::selector_comparison_status(&gate, Some(&current)),
            None
        );
        assert!(resolve(&request, None).is_none());
        assert!(
            returning_issue_authorization_ref(&request, None, Some(1), Some(&verified)).is_none()
        );
        assert!(
            returning_issue_authorization_ref(&request, Some(&current), Some(2), Some(&verified))
                .is_none()
        );
        let mut foreign = verified.clone();
        foreign.authorization_event_id = EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"different authorization"),
        );
        assert!(resolve(&request, Some(&foreign)).is_none());
        request.expected_device_generation_ref = Some(1);
        assert!(resolve(&request, Some(&verified)).is_none());
        request.expected_device_generation_ref = None;
        request.expected_device_authorize_event_id = Some(verified.authorization_event_id.clone());
        assert!(resolve(&request, Some(&verified)).is_none());
        request.expected_device_authorize_event_id = None;
        let issue = request.accepted_device_possession_proof.take();
        assert!(
            resolve(&request, Some(&verified)).is_none(),
            "a proofless issue is a registration/recovery issue, never a returning one"
        );
        request.accepted_device_possession_proof = Some(refresh_proof(&request));
        assert!(resolve(&request, Some(&verified)).is_none());
        request.accepted_device_possession_proof = issue;
        request.action_class = DeviceRevocationDeniedAction::DevicePairingCodeClaim;
        assert!(resolve(&request, Some(&verified)).is_none());
    }

    #[test]
    fn initial_issue_freezes_current_binding_without_weakening_returning_checks() {
        let current = selector();
        let mut request = CurrentDeviceCheckRequest {
            account_id: AccountId::new(current.principal_id.clone(), current.station_id.clone()),
            device_id: DeviceId::new(DEVICE).unwrap(),
            expected_device_authorize_event_id: None,
            expected_device_generation_ref: None,
            action_class: DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
            intent_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            accepted_device_possession_proof: None,
            requested_at: Utc::now(),
        };
        let adopted = initial_issue_authorization_ref(&request, Some(&current));
        assert_eq!(adopted, Some(current.authorization_ref.clone()));
        let mut gate = coland_storage::DeviceRevocationGateLinearizationRequest {
            principal_id: current.principal_id.clone(),
            station_id: current.station_id.clone(),
            device_id: current.device_id.clone(),
            expected_authorization_ref: adopted,
            origin_current_selector: Some(current.clone()),
            action_class: DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
            intent_digest: request.intent_digest.to_string(),
            requested_at: request.requested_at,
        };
        assert_eq!(
            coland_storage::selector_comparison_status(&gate, Some(&current)),
            None
        );
        assert!(initial_issue_authorization_ref(&request, None).is_none());
        let mut returning = request.clone();
        returning.accepted_device_possession_proof = Some(issue_proof(&returning));
        let mut refresh = request.clone();
        refresh.accepted_device_possession_proof = Some(refresh_proof(&refresh));
        let mut code_claim = request.clone();
        code_claim.action_class = DeviceRevocationDeniedAction::DevicePairingCodeClaim;
        for not_initial in [returning, refresh, code_claim] {
            gate.expected_authorization_ref =
                initial_issue_authorization_ref(&not_initial, Some(&current));
            assert_eq!(
                coland_storage::selector_comparison_status(&gate, Some(&current)),
                Some(DeviceRevocationGateStatus::GenerationMismatch)
            );
        }
        request.expected_device_generation_ref = Some(999);
        assert!(initial_issue_authorization_ref(&request, Some(&current)).is_none());
        request.expected_device_generation_ref = None;
        request.expected_device_authorize_event_id =
            Some(current.authorization_ref.event_id.clone());
        assert!(initial_issue_authorization_ref(&request, Some(&current)).is_none());
    }

    fn allow_outcome() -> CurrentDeviceCheckOutcome {
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        CurrentDeviceCheckOutcome {
            account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(PRINCIPAL).unwrap(),
                arkret_wire::DidCoreId::new(STATION).unwrap(),
            ),
            device_id: arkret_wire::DeviceId::new(DEVICE).unwrap(),
            authorization_event_id: Some(arkret_wire::EventId::new(AUTHORIZE_EVENT).unwrap()),
            device_generation_ref: Some(1),
            action_class: DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
            intent_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            accepted_device_possession_proof_digest: Some(
                Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            ),
            decision: DeviceRevocationAdmissionDecision::Allow,
            linearization_seq: 9,
            linearized_at: now,
            expires_at: now + chrono::Duration::seconds(30),
            accepted_commit_id: Some(RealmCommitId::from_digest([0xee; 32])),
        }
    }

    /// `device-lifecycle.md` §2.2 closes this receipt in both directions: the
    /// deployment-internal channel of `service-http-binding.md` §2.2.3 carries
    /// its authenticity, so the emitted receipt carries neither `proof` nor
    /// `verification_method`, and a receipt that presents either member is
    /// rejected whole rather than verified "if present".
    #[test]
    fn current_device_outcome_is_closed_against_legacy_receipt_members() {
        let outcome = allow_outcome();
        let encoded = serde_json::to_value(&outcome).expect("outcome serializes");
        let members = encoded.as_object().expect("outcome is a JSON object");
        assert!(!members.contains_key("proof"));
        assert!(!members.contains_key("verification_method"));
        assert!(!members.contains_key("decision_receipt"));
        assert!(!members.contains_key("target_device_authorize_event_id"));
        assert!(!members.contains_key("blocking_proposal_digest"));
        assert!(!members.contains_key("covering_seal_id"));
        // The intent binding, the accepted-device proof digest, the 30s fence
        // and the origin-derived selector are all still on the receipt: this
        // ruling pruned the detached signature, not the decision content.
        assert!(members.contains_key("intent_digest"));
        assert!(members.contains_key("accepted_device_possession_proof_digest"));
        assert!(members.contains_key("linearization_seq"));
        assert!(members.contains_key("expires_at"));
        assert!(members.contains_key("accepted_commit_id"));
        assert!(members.contains_key("authorization_event_id"));

        for member in ["proof", "verification_method"] {
            let mut forged = encoded.clone();
            forged[member] = serde_json::json!({
                "kind": "detached_jws",
                "verification_method": "did:web:coland.example#notary-key",
            });
            assert!(
                serde_json::from_value::<CurrentDeviceCheckOutcome>(forged).is_err(),
                "an outcome carrying `{member}` must be rejected whole"
            );
        }
    }

    #[test]
    fn optimistic_linearization_rejects_any_current_binding_change() {
        let before = selector();
        let mut different_commit = before.clone();
        different_commit.authorization_ref.stream_position += 1;
        let mut different_authorization = before.clone();
        different_authorization.authorization_ref.event_id =
            EventId::new(format!("ak:event:A{}", "b".repeat(43))).unwrap();

        assert!(current_binding_stable(Some(&before), Some(&before)));
        assert!(current_binding_stable(None, None));
        assert!(!current_binding_stable(
            Some(&before),
            Some(&different_commit)
        ));
        assert!(!current_binding_stable(
            Some(&before),
            Some(&different_authorization)
        ));
        assert!(!current_binding_stable(Some(&before), None));
    }

    /// Canonical positive: a fully derivable selector is admitted and flows
    /// into the `allow` receipt as the origin-derived binding.
    #[test]
    fn derivable_selector_is_admitted_and_only_allow_carries_it() {
        let admitted =
            admit_origin_current_selector(Ok(selector())).expect("derivable selector is admitted");
        assert!(admitted.is_some());

        let projected =
            project_gate_decision(DeviceRevocationGateStatus::Active, admitted.as_ref());
        assert_eq!(projected.decision, DeviceRevocationAdmissionDecision::Allow);
        assert_eq!(
            projected.derived_binding,
            Some(selector().authorization_ref)
        );
        assert!(accepted_device_proof_requires_verification(
            admitted.as_ref()
        ));
    }

    /// An unknown / never-authorized / foreign device leaves the derivation
    /// undefined (`NotFound`). On this authenticated peer surface that is the
    /// anti-enumeration case: an `authority_mismatch` receipt with no derived
    /// binding and no revocation evidence, never an HTTP error that would
    /// distinguish the four causes.
    #[test]
    fn undefined_derivation_becomes_a_bindingless_authority_mismatch() {
        let admitted = admit_origin_current_selector(Err(ServiceError::NotFound(
            "device authorization is unavailable".to_owned(),
        )))
        .expect("an undefined derivation is not an error on the peer surface");
        assert!(admitted.is_none());

        let projected = project_gate_decision(
            DeviceRevocationGateStatus::AuthorityMismatch,
            admitted.as_ref(),
        );
        assert_eq!(
            projected.decision,
            DeviceRevocationAdmissionDecision::AuthorityMismatch
        );
        assert!(projected.derived_binding.is_none());
        assert!(!accepted_device_proof_requires_verification(None));
    }

    /// A projection row that claims verified / current but omits its
    /// schema-required authorization Event id or generation ref is a projection
    /// integrity failure. It MUST become an internal availability fault, and it
    /// MUST NOT be laundered into the `authority_mismatch` receipt.
    ///
    /// The receipt itself is closed (no `proof`, no `verification_method`), so
    /// this is the only remaining way an unusable projection could have been
    /// published as a decision.
    #[test]
    fn malformed_verified_projection_is_an_internal_fault_not_a_decision() {
        let error = admit_origin_current_selector(Err(ServiceError::SchemaViolation(
            "device authorization omits its accepted Event id".to_owned(),
        )))
        .expect_err("a projection integrity failure must not be signed as a decision");
        assert_eq!(error.code, arkret_wire::ErrorCode::InternalError);
    }

    /// No non-allow decision may leak the origin-derived selector, even when
    /// the selector itself was derivable.
    #[test]
    fn non_allow_decisions_never_carry_the_derived_binding() {
        let selector = selector();
        let cases = [
            (
                DeviceRevocationGateStatus::Revoked {
                    revoke_ref: selector.authorization_ref.clone(),
                    committed_at: Utc::now(),
                },
                DeviceRevocationAdmissionDecision::Revoked,
            ),
            (
                DeviceRevocationGateStatus::GenerationMismatch,
                DeviceRevocationAdmissionDecision::GenerationMismatch,
            ),
            (
                DeviceRevocationGateStatus::AuthorityMismatch,
                DeviceRevocationAdmissionDecision::AuthorityMismatch,
            ),
        ];
        for (status, expected) in cases {
            let projected = project_gate_decision(status, Some(&selector));
            assert_eq!(projected.decision, expected);
            assert!(
                projected.derived_binding.is_none(),
                "{expected:?} must not carry the origin-derived selector"
            );
        }
    }
}
