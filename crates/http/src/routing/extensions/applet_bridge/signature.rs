//! Inbound transaction-push per-delivery RFC 9421 source-signature
//! verification (`applet-integration.md` §7.3.1).

use arkret_canonical as canonical;
use arkret_models_integration::applet::HttpMessageSignatureAlgorithm;
use arkret_signatures::http_signature::{
    HttpMessageVerificationError, HttpSignatureScenario, SignatureError, SignatureInput,
    SignaturePolicyError, SignatureVerificationPolicy,
};
use coland_http::error::AppError;
use coland_http::http_signature;
use salvo::http::Method;
use salvo::prelude::*;

use super::record::{applet_id_param, applet_record};
use super::types::AppletRecord;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub(super) struct VerifiedAppletServiceSignature {
    pub(super) request_digest: String,
    pub(super) delivery_authentication_record: serde_json::Value,
    pub(super) delivery_authentication_record_digest: String,
    pub(super) native_maintenance: Option<NativeBackupMaintenance>,
    pub(super) authenticated_document: arkret_identity::DidDocument,
}

#[derive(Clone, Debug)]
pub(super) struct NativeBackupMaintenance {
    pub(super) realm_id: arkret_wire::RealmId,
    pub(super) applet_id: arkret_wire::AppletId,
    pub(super) service_id: arkret_wire::DidCoreId,
}

#[derive(Clone, Debug)]
pub(super) struct VerifiedAppletAuthorityService {
    pub applet_id: arkret_wire::AppletId,
    pub service_id: arkret_wire::DidCoreId,
    pub effective_scope: arkret_wire::ScopeRef,
}

/// Authentication remains required after a fence; audit authority is checked
/// separately against only this Service's explicitly requested grant rows.
#[handler]
pub(super) async fn require_authority_material_signature(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let verification=async {
        let state=depot.get_typed::<AppState>().expect("state injected");
        if !inbound_transaction_signature_present(req) { return Err(applet_signature_error_required("Applet authority reads require Service RFC 9421 authentication")); }
        http_signature::reject_content_encoding(req, || applet_signature_error_invalid("signed JSON cannot use Content-Encoding"))?;
        let bytes=req.payload().await.map_err(|e|AppError::json_invalid(e.to_string()))?.to_vec();
        let body: arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialRequestBody=serde_json::from_slice(&bytes).map_err(|e|AppError::json_invalid(e.to_string()))?;
        body.validate().map_err(|e|AppError::schema_violation(e.to_string()))?;
        let source=applet_required_header(req,"source-service-id")?;
        if applet_required_header(req,"destination-service-id")?!=*state.service_id() { return Err(applet_signature_error_invalid("destination does not identify this Station")); }
        let applet=applet_id_param(req)?;
        let applet_id = arkret_wire::AppletId::new(applet).map_err(|e| AppError::param_invalid(e.to_string()))?;
        let signature_input=http_signature::parse_signature_input_header(req).map_err(applet_verification_error)?;
        let mut conditional=vec!["content-digest"];
        if req.headers().contains_key("idempotency-key") { conditional.push("idempotency-key"); }
        let policy=SignatureVerificationPolicy::for_scenario(HttpSignatureScenario::ServiceToServiceV1,&conditional).map_err(|e|applet_verification_error(HttpMessageVerificationError::Policy(e)))?;
        // Audit access authenticates the Service's current assertion method;
        // the immutable installation method remains a creation/delivery fence.
        let did = arkret_identity::verification_method_did(&signature_input.key_id)
            .map_err(|_| applet_signature_error_invalid("Service keyid must be a DID URL"))?;
        let core = arkret_wire::project_did_to_core_id(&did)
            .map_err(|_| applet_signature_error_invalid("Service keyid cannot project"))?;
        if signature_input.label != "sig1" || core.as_str() != source {
            return Err(applet_signature_error_invalid("Service keyid must identify this exact source Service"));
        }
        let key=authority_material_current_service_key(state,&source,&signature_input.key_id).await?;
        http_signature::verify_signed_canonical_json_request(req,&crate::routing::federation::signature_target_uri(req,state),&crate::routing::federation::signature_authority(req,state),&bytes,&key,&policy).map_err(applet_verification_error)?;
        Ok(VerifiedAppletAuthorityService { applet_id, service_id:core, effective_scope:body.effective_scope })
    }.await;
    match verification {
        Ok(verified) => {
            depot.insert_typed(verified);
            ctrl.call_next(req, depot, res).await;
        }
        Err(error) => error.write(req, depot, res).await,
    }
}

pub(crate) struct VerifiedAppletService {
    pub service_id: arkret_wire::DidCoreId,
    pub verification_method: arkret_wire::DidUrl,
    pub public_key: [u8; 32],
    pub authenticated_document: arkret_identity::DidDocument,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) async fn verify_self_control_service(
    state: &AppState,
    req: &mut Request,
) -> Result<VerifiedAppletService, AppError> {
    verify_self_service(state, req, false).await
}

pub(crate) async fn verify_self_service_grant_read(
    state: &AppState,
    req: &mut Request,
) -> Result<VerifiedAppletService, AppError> {
    if req.method() != Method::GET
        || req
            .headers()
            .get("arkret-operation")
            .and_then(|h| h.to_str().ok())
            != Some(arkret_wire::ServiceOperationId::SELF_AUTHZ_GRANTS_READ_EFFECTIVE_V1)
    {
        return Err(AppError::unauthenticated(
            "Service grant read operation differs",
        ));
    }
    verify_self_service(state, req, true).await
}

/// Transport authentication for the three registered native manager archive
/// operations only. The consuming storage unit still proves the exact current
/// manager, full target actor, role and immutable target-source disclosure cut.
pub(crate) async fn verify_native_backup_manager_service(
    state: &AppState,
    req: &mut Request,
) -> Result<VerifiedAppletService, AppError> {
    let operation = req
        .headers()
        .get("arkret-operation")
        .and_then(|value| value.to_str().ok())
        .and_then(arkret_wire::ServiceOperationId::from_wire)
        .filter(|operation| {
            matches!(
                *operation,
                arkret_wire::ServiceOperationId::SelfKeysBackupsReadListV1
                    | arkret_wire::ServiceOperationId::SelfKeysBackupsCommandIssueUnlockChallengeV1
                    | arkret_wire::ServiceOperationId::SelfKeysBackupsCommandUnlockV1
            )
        })
        .ok_or_else(|| AppError::unauthenticated("Service native archive operation differs"))?;
    if !crate::routing::identity::session_pop::request_matches_operation(req, operation) {
        return Err(AppError::unauthenticated(
            "Service native archive operation does not match its method and path",
        ));
    }
    verify_self_service(
        state,
        req,
        operation == arkret_wire::ServiceOperationId::SelfKeysBackupsReadListV1,
    )
    .await
}

async fn verify_self_service(
    state: &AppState,
    req: &mut Request,
    read: bool,
) -> Result<VerifiedAppletService, AppError> {
    if req.headers().contains_key("authorization")
        || req.headers().contains_key("dpop")
        || req.headers().contains_key("arkret-managed-device")
        || req.headers().contains_key("arkret-realm-actor-control")
    {
        return Err(AppError::unauthenticated(
            "Service control authentication cannot mix credentials",
        ));
    }
    http_signature::reject_content_encoding(req, || {
        applet_signature_error_invalid("signed JSON cannot use Content-Encoding")
    })?;
    let source = applet_required_header(req, "source-service-id")?;
    let source = arkret_wire::DidCoreId::new(source)
        .map_err(|e| applet_signature_error_invalid(e.to_string()))?;
    if applet_required_header(req, "destination-service-id")? != *state.service_id() {
        return Err(applet_signature_error_invalid(
            "destination does not identify this Station",
        ));
    }
    let input =
        http_signature::parse_signature_input_header(req).map_err(applet_verification_error)?;
    let did = arkret_identity::verification_method_did(&input.key_id)
        .map_err(|e| applet_signature_error_invalid(e.to_string()))?;
    if input.label != "sig1"
        || arkret_wire::project_did_to_core_id(&did)
            .map_err(|e| applet_signature_error_invalid(e.to_string()))?
            != source
    {
        return Err(applet_signature_error_invalid(
            "keyid does not identify the exact source Service",
        ));
    }
    let bytes = req
        .payload()
        .await
        .map_err(|e| AppError::json_invalid(e.to_string()))?
        .to_vec();
    if read && !bytes.is_empty() {
        return Err(AppError::param_invalid(
            "Service GET must have an empty body",
        ));
    }
    let mut conditional = if read {
        Vec::new()
    } else {
        vec!["content-digest"]
    };
    if req.headers().contains_key("idempotency-key") {
        conditional.push("idempotency-key");
    }
    let policy = SignatureVerificationPolicy::for_scenario(
        HttpSignatureScenario::ServiceToServiceV1,
        &conditional,
    )
    .map_err(|e| applet_verification_error(HttpMessageVerificationError::Policy(e)))?;
    let (key, authenticated_document) =
        authority_material_current_service_identity(state, source.as_str(), &input.key_id).await?;
    let verified = if read {
        http_signature::verify_signed_http_request(
            req,
            &crate::routing::federation::signature_target_uri(req, state),
            &crate::routing::federation::signature_authority(req, state),
            &[],
            &key,
            &policy,
        )
    } else {
        http_signature::verify_signed_canonical_json_request(
            req,
            &crate::routing::federation::signature_target_uri(req, state),
            &crate::routing::federation::signature_authority(req, state),
            &bytes,
            &key,
            &policy,
        )
    }
    .map_err(applet_verification_error)?;
    Ok(VerifiedAppletService {
        service_id: source,
        verification_method: arkret_wire::DidUrl::new(input.key_id)
            .map_err(|e| applet_signature_error_invalid(e.to_string()))?,
        public_key: key.to_bytes(),
        authenticated_document,
        expires_at: chrono::DateTime::from_timestamp(verified.signature_input.expires, 0)
            .ok_or_else(|| applet_signature_error_invalid("invalid signature expiry"))?,
    })
}

async fn authority_material_current_service_key(
    state: &AppState,
    source: &str,
    verification_method: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    authority_material_current_service_identity(state, source, verification_method)
        .await
        .map(|(key, _)| key)
}

async fn authority_material_current_service_identity(
    state: &AppState,
    source: &str,
    verification_method: &str,
) -> Result<(ed25519_dalek::VerifyingKey, arkret_identity::DidDocument), AppError> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|e| applet_signature_error_invalid(e.to_string()))?;
    if arkret_wire::project_did_to_core_id(&did)
        .map_err(|e| applet_signature_error_invalid(e.to_string()))?
        .as_str()
        != source
    {
        return Err(applet_signature_error_invalid("Service identity differs"));
    }
    // A local Service must prove its published native history as well. The
    // federation transport's fixed notary-key shortcut is not an assertion
    // relationship and must not authorize an Applet material read.
    let document: arkret_identity::DidDocument =
        if source == state.service_id() {
            let authenticated =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await?;
            serde_json::from_value(
                serde_json::to_value(authenticated.normalized_did_document)
                    .map_err(|e| applet_signature_error_invalid(e.to_string()))?,
            )
            .map_err(|e| applet_signature_error_invalid(e.to_string()))?
        } else {
            match state.dids().resolve_current_service_did(&did).await {
                Ok(current) => current.document,
                Err(error) => {
                    state.discard_federation_peer_verification_keys(source, verification_method);
                    return Err(applet_signature_error_invalid(error.to_string()));
                }
            }
        };
    let method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|e| applet_signature_error_invalid(e.to_string()))?;
    let key = (|| {
        arkret_identity::validate_verification_method_relationship(
            &document,
            &method,
            &did,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )
        .map_err(|e| applet_signature_error_invalid(e.to_string()))?;
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|e| applet_signature_error_invalid(e.to_string()))
    })()
    .inspect_err(|_| {
        state.discard_federation_peer_verification_keys(source, verification_method);
    })?;
    Ok((key, document))
}

#[handler]
pub(super) async fn require_inbound_transaction_signature(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let verification = async {
        if !inbound_transaction_signature_present(req) {
            return Err(applet_signature_error_required(
                "inbound transaction push MUST carry an RFC 9421 Signature / Signature-Input; \
                 plain bearer is rejected",
            ));
        }
        let state = depot
            .get_typed::<AppState>()
            .expect("state injected")
            .clone();
        let idempotency_key = applet_required_header(req, "idempotency-key")?;
        http_signature::reject_content_encoding(req, || {
            applet_signature_error_invalid(
                "applet signed JSON requests must not use Content-Encoding",
            )
        })?;
        let payload = req
            .payload()
            .await
            .map_err(|error| {
                AppError::json_invalid(format!("unable to read applet transaction body: {error}"))
            })?
            .to_vec();
        verify_inbound_applet_service_signature(
            &state,
            req,
            &payload,
            &idempotency_key,
            Some("/source_id"),
            Some("/applet_id"),
        )
        .await
    }
    .await;

    match verification {
        Ok(verified) => {
            depot.insert_typed(verified);
            ctrl.call_next(req, depot, res).await;
        }
        Err(error) => error.write(req, depot, res).await,
    }
}

/// Provision previews authenticate an installed Service without inventing the
/// transaction delivery's mandatory idempotency header or delivery record.
#[derive(Clone, Debug)]
pub(super) struct VerifiedAppletProvisionService {
    pub(super) install: AppletRecord,
}

#[handler]
pub(super) async fn require_provision_preview_signature(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let verification = async {
        if !inbound_transaction_signature_present(req) {
            return Err(applet_signature_error_required(
                "Applet preview requires RFC 9421 Service authentication",
            ));
        }
        let state = depot
            .get_typed::<AppState>()
            .expect("state injected")
            .clone();
        let verified = verify_self_control_service(&state, req).await?;
        let bytes = req
            .payload()
            .await
            .map_err(|e| AppError::json_invalid(e.to_string()))?;
        let body: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| AppError::json_invalid(e.to_string()))?;
        let scope = signed_preview_scope(&body)?;
        let applet = applet_id_param(req)?;
        let install =
            active_install_for_service_id(&state, verified.service_id.as_str(), &applet, &scope)
                .await?
                .ok_or_else(|| {
                    AppError::capability_denied(
                        "source Service has no active installation for this Applet and scope",
                    )
                    .with_wire_code("applet_registration_unauthorized")
                })?;
        let method =
            applet_registration_verification_method(&install, verified.service_id.as_str())?;
        if method != verified.verification_method.as_str() {
            return Err(applet_signature_error_invalid(
                "preview differs from the installed Service method",
            ));
        }
        Ok(VerifiedAppletProvisionService { install })
    }
    .await;
    match verification {
        Ok(verified) => {
            depot.insert_typed(verified);
            ctrl.call_next(req, depot, res).await;
        }
        Err(error) => error.write(req, depot, res).await,
    }
}

/// Inbound transaction-push per-delivery source-signature verification
/// (`applet-integration.md` §7.3.1).
///
/// Covered RFC 9421 components (MUST, symmetric with `federation.md` §3.2):
/// `@method`, `@target-uri`, `@authority`, `content-digest`,
/// `source-service-id`, `destination-service-id`, `idempotency-key`, plus the
/// `created` / `expires` signature parameters. Failure codes (all 401 with the
/// discriminating `reason`, `error.code` stays generic `unauthenticated`):
/// - missing `Signature` / bearer-only → `http_signature_required`
/// - bad signature / `content-digest` mismatch / `source_id` header↔body mismatch →
///   `http_signature_invalid`
/// - `created` / `expires` outside the freshness window → `signature_window_invalid`
/// - `Source-Service-ID` with no active effective install / not matching the registration service
///   DID → 403 `applet_registration_unauthorized`.
async fn verify_inbound_applet_service_signature(
    state: &AppState,
    req: &Request,
    body_bytes: &[u8],
    idempotency_key: &str,
    source_service_json_pointer: Option<&str>,
    applet_id_json_pointer: Option<&str>,
) -> Result<VerifiedAppletServiceSignature, AppError> {
    // §7.3.1 ordering: a transaction push carrying only `Authorization: Bearer`
    // (no `Signature` / `Signature-Input`) MUST be rejected before any other
    // work. This is the cheapest, highest-priority gate and is what separates a
    // plain-bearer caller from a (mis)signed one.
    if !inbound_transaction_signature_present(req) {
        return Err(applet_signature_error_required(
            "Applet service requests MUST carry an RFC 9421 Signature / Signature-Input; \
             plain bearer is rejected",
        ));
    }

    let request_digest = arkret_canonical::sha256_digest(body_bytes);
    // Bound trust headers select the verification key and MUST identify this
    // service. The body/header binding is checked after the shared verifier has
    // authenticated the canonical body bytes.
    let header_source = applet_required_header(req, "source-service-id")?;
    let header_idempotency = applet_required_header(req, "idempotency-key")?;
    if header_idempotency != idempotency_key {
        return Err(applet_signature_error_invalid(
            "Idempotency-Key header does not match the signed transcript binding",
        ));
    }
    let destination_id = applet_required_header(req, "destination-service-id")?;
    if destination_id != *state.service_id() {
        return Err(applet_signature_error_invalid(
            "Destination-Service-ID does not match this edge service",
        ));
    }

    let request_body =
        serde_json::from_slice::<serde_json::Value>(body_bytes).map_err(|error| {
            applet_signature_error_invalid(format!("invalid Applet service request JSON: {error}"))
        })?;
    let source_id = source_service_json_pointer
        .map(|pointer| {
            request_body
                .pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    applet_signature_error_invalid(format!(
                        "signed Applet service request body requires {pointer}"
                    ))
                })
        })
        .transpose()?
        .unwrap_or_else(|| header_source.clone());
    let applet_id = applet_id_json_pointer
        .map(|pointer| {
            request_body
                .pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    applet_signature_error_invalid(format!(
                        "signed Applet service request body requires {pointer}"
                    ))
                })
        })
        .transpose()?
        .map_or_else(|| applet_id_param(req), Ok)?;
    if header_source != source_id {
        return Err(applet_signature_error_invalid(
            "Source-Service-ID header does not match the signed body binding".to_owned(),
        ));
    }
    let transaction: arkret_models_integration::applet_models::AppletEventTransactionRequestBody =
        serde_json::from_value(request_body.clone())
            .map_err(|error| AppError::schema_violation(error.to_string()))?;
    let realm = signed_transaction_realm(&transaction.events)?;

    // The freshness window is a self-contained property of Signature-Input.
    // Evaluate it before registration lookup so an expired signed delivery is
    // always the spec-pinned 401 `signature_window_invalid`, rather than
    // leaking whether this edge currently has an effective Applet install.
    let signature_input =
        http_signature::parse_signature_input_header(req).map_err(applet_verification_error)?;
    let policy =
        SignatureVerificationPolicy::for_scenario(HttpSignatureScenario::AppletTransactionV1, &[])
            .map_err(|error| {
                applet_verification_error(HttpMessageVerificationError::Policy(error))
            })?;
    let content_digest_header = applet_required_header(req, "content-digest")?;
    policy
        .validate(
            &signature_input,
            Some(&content_digest_header),
            chrono::Utc::now().timestamp(),
        )
        .map_err(|error| applet_verification_error(HttpMessageVerificationError::Policy(error)))?;

    let native_only = !transaction.events.is_empty()
        && transaction.signals.is_empty()
        && transaction.committed_events.is_empty()
        && transaction
            .events
            .iter()
            .all(|event| event.kind == arkret_wire::EventKind::KeyBackupActiveSeries);
    let applet = arkret_wire::AppletId::new(applet_id.clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let service = arkret_wire::DidCoreId::new(header_source.clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    // Only the explicit common Realm/Applet/Service pair selects a current key;
    // submitted resources or installation status never select its identity.
    let registration = state
        .authority_commits()
        .applet_registration(&realm, &applet, &service)
        .await
        .map_err(|error| {
            AppError::capability_denied(error.to_string())
                .with_wire_code("applet_registration_unauthorized")
        })?;
    if registration.service_id != service || registration.applet_id != applet {
        return Err(applet_signature_error_invalid(
            "current registration pair differs",
        ));
    }
    let verification_method = registration.webhook_signature_policy.key_ref.to_string();
    if !registration
        .webhook_signature_policy
        .accepted_signature_algorithms
        .contains(&HttpMessageSignatureAlgorithm::Ed25519)
    {
        return Err(applet_signature_error_invalid(
            "current registration does not permit ed25519",
        ));
    }
    let (verifying_key, authenticated_document) =
        authority_material_current_service_identity(state, &header_source, &verification_method)
            .await?;
    registration
        .manifest
        .registration_epoch_evidence
        .validate_against_did_document(&authenticated_document)
        .map_err(|error| applet_signature_error_invalid(error.to_string()))?;
    let registration_epoch = registration.registration_epoch.to_string();
    let native_maintenance = if native_only {
        if transaction.events.iter().any(|event| {
            event.actor_id != arkret_wire::ActorId::service(service.clone())
                || event.applet_id.as_ref() != Some(&applet)
                || event.scope_ref
                    != (arkret_wire::ScopeRef::RealmControl {
                        realm_id: realm.clone(),
                    })
                || event.authorization_ref.is_some()
                || event.executed_by.is_some()
        }) {
            return Err(applet_signature_error_invalid(
                "native maintenance transaction identity differs",
            ));
        }
        Some(NativeBackupMaintenance {
            realm_id: realm.clone(),
            applet_id: applet.clone(),
            service_id: service.clone(),
        })
    } else {
        None
    };

    let target_uri = crate::routing::federation::signature_target_uri(req, state);
    let authority = crate::routing::federation::signature_authority(req, state);
    applet_validate_signature_input(&signature_input, &verification_method)?;
    let verified = http_signature::verify_signed_canonical_json_request(
        req,
        &target_uri,
        &authority,
        body_bytes,
        &verifying_key,
        &policy,
    )
    .map_err(applet_verification_error)?;
    let content_digest = verified
        .content_digest
        .as_ref()
        .expect("applet signature policy requires Content-Digest")
        .wire_value
        .as_str();

    let (delivery_authentication_record, delivery_authentication_record_digest) =
        applet_delivery_authentication_record_digest(
            &source_id,
            &destination_id,
            idempotency_key,
            content_digest,
            &verification_method,
            &registration_epoch,
            &verifying_key,
            &verified.signature_input,
        )?;
    // Authenticate RFC 9421/body first, then prove all item sources before a
    // replay slot/effect. Native maintenance retains its own target/manager gate.
    let guard = coland_storage::AppletEventProducerGuard {
        service_did_document: authenticated_document.clone(),
    };
    if native_only {
        for event in &transaction.events {
            state
                .authority_commits()
                .prepare_service_signer_fact(event, &guard, chrono::Utc::now())
                .await
                .map_err(|error| AppError::capability_denied(error.to_string()))?;
        }
    } else {
        state
            .authority_commits()
            .preflight_applet_transaction(
                &transaction.events,
                &coland_storage::AppletTransactionReplayRecord {
                    applet_id: applet,
                    source_id: source_id.clone(),
                    idempotency_key: idempotency_key.to_owned(),
                    delivery_authentication_record: delivery_authentication_record.clone(),
                    delivery_authentication_record_digest: delivery_authentication_record_digest
                        .clone(),
                    request_digest: request_digest.clone(),
                    outcome: None,
                    received_at: chrono::Utc::now(),
                    completed_at: None,
                },
                &guard,
            )
            .await
            .map_err(super::configuration::service_error)?;
    }
    Ok(VerifiedAppletServiceSignature {
        request_digest,
        delivery_authentication_record,
        delivery_authentication_record_digest,
        native_maintenance,
        authenticated_document,
    })
}

fn signed_transaction_realm(
    events: &[arkret_wire::Event],
) -> Result<arkret_wire::RealmId, AppError> {
    let first = events.first().ok_or_else(|| {
        applet_signature_error_invalid("signed Applet transaction requires an Event")
    })?;
    if events.iter().any(|event| {
        event.realm_id != first.realm_id || event.scope_ref.realm_id_opt() != Some(&first.realm_id)
    }) {
        return Err(applet_signature_error_invalid(
            "one signed Applet transaction requires one common Realm",
        ));
    }
    Ok(first.realm_id.clone())
}

fn signed_preview_scope(body: &serde_json::Value) -> Result<arkret_wire::ScopeRef, AppError> {
    serde_json::from_value(
        body.pointer("/effective_scope").cloned().ok_or_else(|| {
            applet_signature_error_invalid("signed preview requires effective_scope")
        })?,
    )
    .map_err(|error| {
        applet_signature_error_invalid(format!("invalid exact preview scope: {error}"))
    })
}

fn inbound_transaction_signature_present(req: &Request) -> bool {
    req.headers().get("signature").is_some() && req.headers().get("signature-input").is_some()
}

/// Find an active (non-revoked) effective install whose registration service
/// DID equals `source_id`. The registration carries the service DID in
/// its required SDK-owned installed package.
async fn active_install_for_service_id(
    state: &AppState,
    source_id: &str,
    applet_id: &str,
    scope: &arkret_wire::ScopeRef,
) -> Result<Option<AppletRecord>, AppError> {
    // Existing PK is exactly (Applet, Service, full scope). Unsupported scopes
    // had no matching row in the old scan, and must not become an internal error.
    if !matches!(
        scope,
        arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
    ) {
        return Ok(None);
    }
    Ok(applet_record(state, applet_id, source_id, scope)
        .await?
        .filter(|record| {
            record.revoked_at.is_none()
                && matches!(record.status.as_str(), "installed" | "partially_installed")
                && record.identity.globally_fenced_at.is_none()
                && record.applet_id.as_str() == applet_id
                && record.package.service_id.as_str() == source_id
                && record.effective_scope == *scope
        }))
}

/// Resolve the verification method to verify the inbound signature against.
///
/// §7.3.1 anchor: the Applet registration `service_id`'s installed
/// `webhook_signature_policy.key_ref` must name the source service DID's method and the
/// installed auth metadata must accept the algorithm this verifier implements.
pub(super) fn applet_registration_verification_method(
    install: &AppletRecord,
    source_id: &str,
) -> Result<String, AppError> {
    let package = &install.package;
    let key_ref = package.webhook_signature_policy.key_ref.trim();
    let key_controller = key_ref
        .split_once('#')
        .map(|(controller, _)| controller)
        .unwrap_or(key_ref);
    let key_controller = arkret_identifiers::Did::new(key_controller.to_owned())
        .and_then(|did| arkret_identifiers::project_did_to_core_id(&did))
        .map_err(|_| {
            applet_signature_error_invalid(
                "Applet webhook_signature_policy.key_ref must name a resolvable DID verification method",
            )
        })?;
    if key_ref.is_empty() || key_controller.as_str() != source_id {
        return Err(applet_signature_error_invalid(
            "Applet webhook_signature_policy.key_ref must be controlled by Source-Service-ID",
        ));
    }
    if !package
        .webhook_signature_policy
        .accepted_signature_algorithms
        .contains(&HttpMessageSignatureAlgorithm::Ed25519)
    {
        return Err(applet_signature_error_invalid(
            "Applet webhook_signature_policy.accepted_signature_algorithms must include ed25519 for inbound transaction signatures",
        ));
    }
    Ok(key_ref.to_owned())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn applet_delivery_authentication_record_digest(
    source_id: &str,
    destination_id: &str,
    idempotency_key: &str,
    content_digest: &str,
    verification_method: &str,
    registration_epoch: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
    signature_input: &SignatureInput,
) -> Result<(serde_json::Value, String), AppError> {
    let record = serde_json::json!({
        "operation_id": arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
        "direction": "applet_to_arkret_inbound",
        "source_id": source_id,
        "destination_id": destination_id,
        "signature_label": signature_input.label,
        "verification_method": verification_method,
        "verification_key_digest": canonical::sha256_digest(verifying_key.to_bytes()),
        "signature_algorithm": signature_input.algorithm,
        "registration_epoch": registration_epoch,
        "idempotency_key": idempotency_key,
        "content_digest": content_digest,
        "covered_components": signature_input.covered_components.iter()
            .map(|component| component.canonical_name()).collect::<Vec<_>>(),
        "created": signature_input.created,
        "expires": signature_input.expires,
    });
    let typed: arkret_models_integration::AppletDeliveryAuthenticationRecord =
        serde_json::from_value(record.clone()).map_err(|error| {
            applet_signature_error_invalid(format!(
                "invalid delivery authentication record: {error}"
            ))
        })?;
    let digest = typed
        .stable_digest()
        .map_err(applet_signature_error_invalid)?;
    Ok((record, digest.to_string()))
}

pub(super) fn applet_required_header(req: &Request, name: &str) -> Result<String, AppError> {
    http_signature::required_header(req, name, |name| {
        applet_signature_error_invalid(format!("missing required inbound signature header: {name}"))
    })
}

/// Apply the Applet registration binding after the SDK has parsed the RFC 9421
/// input. Algorithm, component coverage and freshness are owned by the shared
/// SDK verifier.
pub(super) fn applet_validate_signature_input(
    signature_input: &SignatureInput,
    expected_verification_method: &str,
) -> Result<(), AppError> {
    if signature_input.label != "sig1" {
        return Err(applet_signature_error_invalid(
            "Signature-Input must use the sig1 label",
        ));
    }
    if signature_input.key_id != expected_verification_method {
        return Err(applet_signature_error_invalid(
            "Signature-Input keyid does not match the Applet registration verification method",
        ));
    }
    Ok(())
}

fn applet_verification_error(error: HttpMessageVerificationError) -> AppError {
    match error {
        HttpMessageVerificationError::MissingHeader("Signature-Input" | "Signature") => {
            applet_signature_error_required(error.to_string())
        }
        HttpMessageVerificationError::Signature(
            SignatureError::MissingSignatureInputParameter("created" | "expires"),
        )
        | HttpMessageVerificationError::Policy(
            SignaturePolicyError::InvalidValidityWindow
            | SignaturePolicyError::CreatedInFuture
            | SignaturePolicyError::CreatedTooOld
            | SignaturePolicyError::Expired,
        ) => applet_signature_error_window(error.to_string()),
        _ => applet_signature_error_invalid(error.to_string()),
    }
}

/// 401 `http_signature_required` — no per-delivery RFC 9421 signature present.
///
/// `applet-integration.md` §7.3.1 pins the RFC 9457 Problem `type` as the only
/// machine discriminator, so each signature failure carries its own registered
/// top-level code rather than a generic code plus a `reason` extension.
pub(super) fn applet_signature_error_required(message: impl Into<String>) -> AppError {
    crate::app_error!(HttpSignatureRequired, message)
}

/// 401 `http_signature_invalid` — signature present but verification, digest,
/// or source binding failed.
pub(super) fn applet_signature_error_invalid(message: impl Into<String>) -> AppError {
    crate::app_error!(HttpSignatureInvalid, message)
}

/// 401 `signature_window_invalid` — `created` / `expires` outside the freshness
/// window.
pub(super) fn applet_signature_error_window(message: impl Into<String>) -> AppError {
    crate::app_error!(SignatureWindowInvalid, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn development_mode_does_not_derive_an_applet_fallback_key() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let error = authority_material_current_service_identity(
            &state,
            "ak:did_core:web:registered-applet.invalid",
            "did:web:unregistered-applet.invalid#applet-webhook",
        )
        .await
        .expect_err("current-pair identity mismatch cannot derive any development fallback key");
        assert_eq!(error.wire_code(), "http_signature_invalid");
    }

    #[test]
    fn transaction_authentication_uses_common_realm_not_effect_scope() {
        let realm =
            arkret_wire::RealmId::new("ak:realm:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH")
                .unwrap();
        let mut first=crate::test_event::raw_event(arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::realm(realm.clone()),
            arkret_wire::DidCoreId::new("ak:did_core:web:applet.example").unwrap(),1,
            arkret_wire::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            serde_json::json!({"strand_id":"ak:strand:AQ9vwMrZNs64XfX4CVfhG2FPvja_JU2XLAIWCbvWK5kG","content":{"kind":"ak.content.text","body":"hello"}})).unwrap();
        let mut circle = first.clone();
        circle.scope_ref = arkret_wire::ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: arkret_wire::CircleId::new(
                "ak:circle:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH",
            )
            .unwrap(),
        };
        assert_eq!(
            signed_transaction_realm(&[first.clone(), circle.clone()]).unwrap(),
            realm
        );
        first.realm_id =
            arkret_wire::RealmId::new("ak:realm:AQpwDm7ZXVTjUWCnaqcmxxZ49Y8CpzFJ-vLzmvCjBXfw")
                .unwrap();
        assert!(signed_transaction_realm(&[first, circle]).is_err());
        assert!(signed_transaction_realm(&[]).is_err());
        let mut genesis=crate::test_event::raw_event(arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::realm(realm.clone()),
            arkret_wire::DidCoreId::new("ak:did_core:web:applet.example").unwrap(),1,
            arkret_wire::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            serde_json::json!({"strand_id":"ak:strand:AQ9vwMrZNs64XfX4CVfhG2FPvja_JU2XLAIWCbvWK5kG","content":{"kind":"ak.content.text","body":"hello"}})).unwrap();
        genesis.scope_ref = arkret_wire::ScopeRef::RealmGenesis;
        assert!(
            signed_transaction_realm(&[genesis]).is_err(),
            "untrusted Genesis scope must fail closed without panicking"
        );
    }

    #[test]
    fn preview_requires_a_complete_scope_pointer() {
        let realm = "ak:realm:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH";
        let circle = serde_json::json!({"kind":"circle","realm_id":realm,"circle_id":"ak:circle:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH"});
        assert_eq!(
            serde_json::to_value(
                signed_preview_scope(&serde_json::json!({"effective_scope":circle.clone()}))
                    .unwrap()
            )
            .unwrap(),
            circle
        );
        assert!(signed_preview_scope(&serde_json::json!({"effective_scope":realm})).is_err());
        assert!(signed_preview_scope(&serde_json::json!({})).is_err());
    }
}

#[cfg(test)]
mod delivery_freshness_tests {
    use super::*;

    #[test]
    fn fresh_retry_window_passes_but_expired_signature_keeps_registered_401_code() {
        let policy = SignatureVerificationPolicy::for_scenario(
            HttpSignatureScenario::AppletTransactionV1,
            &[],
        )
        .unwrap();
        let input = |created, expires| {
            arkret_signatures::http_signature::parse_signature_input(
            &format!("sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"arkret-operation\" \"source-service-id\" \"destination-service-id\" \"idempotency-key\");created={created};expires={expires};keyid=\"did:web:app#key\";alg=\"ed25519\""),
        ).unwrap()
        };
        policy
            .validate(&input(200, 260), Some("sha-256=:abc=:"), 200)
            .unwrap();
        let error = policy
            .validate(&input(100, 160), Some("sha-256=:abc=:"), 200)
            .unwrap_err();
        let problem = applet_verification_error(HttpMessageVerificationError::Policy(error));
        assert_eq!(
            problem.code,
            coland_http::error::ErrorCode::SignatureWindowInvalid
        );
    }
}
