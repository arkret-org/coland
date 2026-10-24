//! Moderation user-facing endpoints.
//!
//! - `POST /_arkret/self/moderation/report` (`ak.self.moderation.command.report.v1`) — submit the
//!   caller-authored signed report Event through ordinary Event admission.

#[cfg(test)]
use std::collections::BTreeSet;

use arkret_identifiers::{EventId, RealmId};
use arkret_models_collaboration::events_payloads::moderation::FrankingProof;
use arkret_wire::{ActorId, EventKind, ScopeRef};
use coland_http::error::AppError;
#[cfg(test)]
use coland_http::error::ErrorCode;
use coland_http::result::{JsonResult, json_ok};
use coland_services::runtime_guards::MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES;
#[cfg(test)]
use ed25519_dalek::Signer as _;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

#[cfg(test)]
use super::now;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{ModerationReportRequestBody, ModerationReportResponseBody};

pub(super) fn protocol_router() -> Router {
    Router::new().push(Router::with_path("moderation/report").post(moderation_report))
}

#[cfg(test)]
fn authored_event_wire_value(
    event: &arkret_wire::AuthoredEvent,
) -> Result<Value, serde_json::Error> {
    serde_json::to_value(event.event())
}

#[cfg(test)]
pub(super) async fn validate_moderation_report_safety(
    state: &AppState,
    realm_id: &str,
    reporter_id: &str,
    reporter_actor: Option<&ActorId>,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
    source_service: Option<&str>,
    source_ip_hash: &str,
) -> Result<(), AppError> {
    let rate_reporter = reporter_actor
        .map(ToString::to_string)
        .unwrap_or_else(|| reporter_id.to_owned());
    let rate = state.record_moderation_report_attempt(
        &rate_reporter,
        source_service,
        realm_id,
        source_ip_hash,
        target_ref,
    );
    if rate.rate_limited {
        return Err(
            crate::app_error!(RateLimited, "moderation report rate limit exceeded",)
                .with_reason_detail(format!(
                    "bucket={} count={} limit={} retry_after_ms={}",
                    rate.bucket.as_deref().unwrap_or("unknown"),
                    rate.count,
                    rate.limit,
                    rate.retry_after_ms
                )),
        );
    }

    validate_moderation_report_content_safety(
        state,
        realm_id,
        reporter_actor,
        target_ref,
        effective_scope,
        evidence_package,
        franking_proof,
    )
    .await
}

async fn validate_signed_moderation_report_safety(
    state: &AppState,
    realm_id: &str,
    reporter_actor: &ActorId,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
) -> Result<(), AppError> {
    // Target visibility and exact scope are decided by the accepting current writer,
    // after the governing cut is locked; no reducer projection authorizes a report.
    let _ = (reporter_actor, target_ref);
    let effective_scope = moderation_effective_scope_value(realm_id, effective_scope)?;
    validate_moderation_evidence_package(evidence_package, &effective_scope)?;
    validate_moderation_franking_proof(state, realm_id, franking_proof).await?;
    Ok(())
}

#[cfg(test)]
async fn validate_moderation_report_content_safety(
    state: &AppState,
    realm_id: &str,
    reporter_actor: Option<&ActorId>,
    target_ref: &str,
    effective_scope: Option<&ScopeRef>,
    evidence_package: &Value,
    franking_proof: &Value,
) -> Result<(), AppError> {
    let effective_scope = moderation_effective_scope_value(realm_id, effective_scope)?;
    let target_scope =
        moderation_target_effective_scope_value(state, realm_id, reporter_actor, target_ref)?;
    if target_scope != effective_scope {
        return Err(moderation_target_not_found());
    }
    validate_moderation_evidence_package(evidence_package, &effective_scope)?;
    validate_moderation_franking_proof(state, realm_id, franking_proof).await?;
    Ok(())
}

fn moderation_effective_scope_value(
    realm_id: &str,
    effective_scope: Option<&ScopeRef>,
) -> Result<Value, AppError> {
    match effective_scope {
        None => Ok(json!({"kind": "realm", "realm_id": realm_id})),
        Some(ScopeRef::Realm {
            realm_id: scope_realm,
        }) => {
            if scope_realm.as_str() != realm_id {
                return Err(AppError::param_invalid(
                    "effective_scope.realm_id must match report realm_id",
                ));
            }
            Ok(json!({"kind": "realm", "realm_id": scope_realm.as_str()}))
        }
        Some(ScopeRef::Circle {
            realm_id: scope_realm,
            circle_id,
        }) => {
            if scope_realm.as_str() != realm_id {
                return Err(AppError::param_invalid(
                    "effective_scope.realm_id must match report realm_id",
                ));
            }
            Ok(json!({
                "kind": "circle",
                "realm_id": scope_realm.as_str(),
                "circle_id": circle_id.as_str(),
            }))
        }
        // `ScopeRef` is #[non_exhaustive]; fail closed on any scope
        // kind this build does not understand rather than guessing a shape.
        Some(_) => Err(AppError::param_invalid(
            "effective_scope kind is not supported",
        )),
    }
}

#[cfg(test)]
fn moderation_target_not_found() -> AppError {
    AppError::not_found("moderation target not found")
}

#[cfg(test)]
fn moderation_target_effective_scope_value(
    state: &AppState,
    realm_id: &str,
    reporter_actor: Option<&ActorId>,
    target_ref: &str,
) -> Result<Value, AppError> {
    if target_ref == realm_id {
        return Ok(json!({"kind": "realm", "realm_id": realm_id}));
    }
    let projection = state.projections().snapshot();
    let scope_circle_id = if let Some(message) = moderation_target_message(&projection, target_ref)
        .filter(|message| message.realm_id == realm_id)
    {
        message
            .content
            .get("scope_circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| projection.strand_scope_circle_id(&message.thread_id))
    } else if let Some(strand) = projection
        .strands
        .get(target_ref)
        .filter(|strand| strand.realm_id == realm_id)
    {
        strand.scope_circle_id.clone()
    } else if let Some(morph) = projection
        .morphs
        .get(target_ref)
        .filter(|morph| morph.realm_id == realm_id)
    {
        morph.scope_circle_id.clone()
    } else if let Some(space) = projection
        .space_containers
        .get(target_ref)
        .filter(|space| space.realm_id == realm_id)
    {
        space.scope_circle_id.clone()
    } else if let Some(relation) = projection
        .relations
        .get(target_ref)
        .filter(|relation| relation.realm_id == realm_id)
    {
        relation.scope_circle_id.clone()
    } else {
        return Err(moderation_target_not_found());
    };
    if let Some(circle_id) = scope_circle_id {
        let reporter_actor = reporter_actor.ok_or_else(moderation_target_not_found)?;
        if !projection.circle_scope_visible_to_actor(&circle_id, &reporter_actor.to_string()) {
            return Err(moderation_target_not_found());
        }
        return Ok(json!({
            "kind": "circle",
            "realm_id": realm_id,
            "circle_id": circle_id,
        }));
    }
    Ok(json!({"kind": "realm", "realm_id": realm_id}))
}

#[cfg(test)]
fn moderation_target_message<'a>(
    projection: &'a coland_domain::reducer::ProjectionState,
    target_ref: &str,
) -> Option<&'a coland_domain::reducer::MessageState> {
    projection.messages.get(target_ref).or_else(|| {
        target_ref
            .strip_prefix("ak:message:")
            .and_then(|suffix| projection.messages.get(&format!("ak:event:{suffix}")))
    })
}

fn validate_moderation_evidence_package(
    evidence_package: &Value,
    effective_scope: &Value,
) -> Result<Option<Value>, AppError> {
    if evidence_package.is_null() {
        return Ok(None);
    }
    let object = evidence_package
        .as_object()
        .ok_or_else(|| AppError::param_invalid("evidence_package must be an object"))?;
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(evidence_package).map_err(|error| {
            AppError::json_invalid(format!(
                "evidence_package is not canonical-json encodable: {error}"
            ))
        })?;
    if canonical_bytes.len() > MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES {
        return Err(crate::app_error!(
            PayloadTooLarge,
            "evidence_package exceeds max_total_blob_bytes",
        )
        .with_reason_detail(format!(
            "max_total_blob_bytes={}",
            MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES
        )));
    }
    let Some(encryption) = object
        .get("encryption")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::param_invalid(
            "evidence_package.encryption is required",
        ));
    };
    let encryption = encryption.to_ascii_lowercase();
    if matches!(encryption.as_str(), "none" | "plaintext" | "cleartext") {
        return Err(AppError::param_invalid(
            "evidence_package must be encrypted",
        ));
    }
    if !object
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .is_some_and(is_valid_report_hash)
    {
        return Err(AppError::param_invalid(
            "evidence_package.ciphertext_digest must be a hash digest",
        ));
    }
    if object
        .get("plaintext_digest")
        .and_then(Value::as_str)
        .is_some_and(|digest| !is_valid_report_hash(digest))
    {
        return Err(AppError::param_invalid(
            "evidence_package.plaintext_digest must be a hash digest",
        ));
    }
    if object
        .get("recipients")
        .and_then(Value::as_array)
        .is_none_or(|recipients| recipients.is_empty())
    {
        return Err(AppError::param_invalid(
            "evidence_package.recipients must name at least one moderator audience",
        ));
    }
    let scope_matches = object.get("effective_scope") == Some(effective_scope)
        || object
            .get("audience")
            .and_then(|audience| audience.get("effective_scope"))
            == Some(effective_scope);
    if !scope_matches {
        return Err(AppError::param_invalid(
            "evidence_package audience must bind the report effective_scope",
        ));
    }
    if let Some(key) = contains_forbidden_key(evidence_package, EVIDENCE_PACKAGE_FORBIDDEN_KEYS) {
        return Err(AppError::param_invalid(format!(
            "evidence_package contains forbidden key `{key}`"
        )));
    }
    Ok(Some(evidence_package.clone()))
}

async fn validate_moderation_franking_proof(
    state: &AppState,
    realm_id: &str,
    franking_proof: &Value,
) -> Result<Option<Value>, AppError> {
    if franking_proof.is_null() {
        return Ok(None);
    }
    let object = franking_proof
        .as_object()
        .ok_or_else(|| AppError::param_invalid("franking_proof must be an object"))?;
    if object.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err(AppError::param_invalid(
            "franking_proof.realm_id must match report realm_id",
        ));
    }
    if arkret_identifiers::EventId::new(required_string_field(
        object,
        "event_id",
        "franking_proof",
    )?)
    .is_err()
    {
        return Err(AppError::param_invalid(
            "franking_proof.event_id must be an event id",
        ));
    }
    let received_by = required_string_field(object, "received_by", "franking_proof")?;
    arkret_wire::DidCoreId::new(received_by.to_owned())
        .map_err(|_| AppError::param_invalid("franking_proof.received_by must be a DID Core ID"))?;
    let replay_nonce = required_string_field(object, "replay_nonce", "franking_proof")?;
    if !is_valid_replay_nonce(replay_nonce) {
        return Err(AppError::param_invalid(
            "franking_proof.replay_nonce must be base64url 16..256 chars",
        ));
    }
    if required_string_field(object, "signature", "franking_proof")?.is_empty() {
        return Err(AppError::param_invalid(
            "franking_proof.signature must be non-empty",
        ));
    }
    let received_at = required_string_field(object, "received_at", "franking_proof")?;
    if arkret_canonical::validate_timestamp_canonical(received_at).is_err() {
        return Err(AppError::param_invalid(
            "franking_proof.received_at must be a canonical Arkret timestamp",
        ));
    }
    if let Some(key) = contains_forbidden_key(franking_proof, FRANKING_PROOF_FORBIDDEN_KEYS) {
        return Err(AppError::param_invalid(format!(
            "franking_proof contains forbidden key `{key}`"
        )));
    }
    let typed_proof: FrankingProof =
        serde_json::from_value(franking_proof.clone()).map_err(|error| {
            franking_proof_invalid(format!("franking_proof typed validation failed: {error}"))
        })?;
    let verification_key = crate::jws_verify::resolve_ed25519_pubkey_at(
        state,
        typed_proof.verification_method.as_str(),
        typed_proof.received_at,
    )
    .await
    .map_err(|error| {
        franking_proof_invalid(format!(
            "franking_proof verification method has no authenticated historical state: {error}"
        ))
    })?;
    arkret_signatures::franking_proof::verify_franking_proof_signature(
        &typed_proof,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: verification_key.as_bytes().to_vec(),
        },
    )
    .map_err(|error| franking_proof_invalid(error.to_string()))?;
    validate_franking_event_time_anchor(state, realm_id, &typed_proof).await?;
    Ok(Some(franking_proof.clone()))
}

async fn validate_franking_event_time_anchor(
    state: &AppState,
    realm_id: &str,
    proof: &FrankingProof,
) -> Result<(), AppError> {
    let target = state
        .event_queries()
        .canonical_event(proof.event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "franking_proof event anchor lookup failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            franking_proof_invalid(
                "franking_proof.event_id does not reference an accepted local event anchor",
            )
        })?;
    let target_realm_id = target
        .realm_id
        .as_deref()
        .ok_or_else(|| franking_proof_invalid("franking_proof event anchor is missing realm_id"))?;
    if target_realm_id != realm_id {
        return Err(franking_proof_invalid(
            "franking_proof event anchor realm_id does not match report realm_id",
        ));
    }
    let proof_payload = serde_json::to_value(proof).map_err(|error| {
        franking_proof_invalid(format!("franking_proof serialization failed: {error}"))
    })?;
    let mut matching = state
        .event_queries()
        .franking_proofs_for_target(realm_id, &proof.received_by, proof.event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("franking proof Event lookup failed: {error}"))
        })?
        .into_iter()
        .filter(|candidate| candidate.envelope.get("payload") == Some(&proof_payload));
    let proof_event = matching.next().ok_or_else(|| {
        franking_proof_invalid("franking_proof has no byte-identical accepted durable proof Event")
    })?;
    if matching.next().is_some() {
        return Err(franking_proof_invalid(
            "franking_proof has multiple byte-identical durable proof Events",
        ));
    }
    let realm = RealmId::new(realm_id.to_owned())
        .map_err(|error| franking_proof_invalid(format!("invalid Realm ID: {error}")))?;
    let durable_proof = franking_anchor_event(&proof_event)?;
    if durable_proof.kind != EventKind::ModerationFrankingProof
        || durable_proof.actor_id != ActorId::service(proof.received_by.clone())
        || durable_proof.payload
            != serde_json::from_value::<std::collections::BTreeMap<String, Value>>(proof_payload)
                .map_err(|error| {
                    franking_proof_invalid(format!("franking proof payload decode failed: {error}"))
                })?
    {
        return Err(franking_proof_invalid(
            "franking proof Event does not bind the receiving service and exact proof",
        ));
    }
    for record in [&proof_event, &target] {
        let event_id = &record.event_id;
        let committed = state
            .authority_commits()
            .committed_event(&EventId::new(event_id.clone()).map_err(|error| {
                franking_proof_invalid(format!("invalid committed Event ID: {error}"))
            })?)
            .await
            .map_err(|error| AppError::internal(format!("franking commit lookup failed: {error}")))?
            .ok_or_else(|| {
                franking_proof_invalid("franking proof or target lacks a covering RealmCommit")
            })?;
        validate_franking_covering_commit(record, &committed, &realm)?;
    }
    Ok(())
}

// Accepted storage is the admission authority. Recompute its content commitment
// and bind the exact envelope to the covering pair before using it as evidence.
// This does not turn a signed received_at claim into an existence-time proof.
fn franking_anchor_event(
    record: &coland_storage::CanonicalEventRecord,
) -> Result<arkret_wire::Event, AppError> {
    let event = crate::routing::events::event_log::canonical_event_for_read(record)
        .map_err(|error| franking_proof_invalid(error.message))?;
    let preimage = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|error| franking_proof_invalid(error.to_string()))?,
    )
    .map_err(|error| franking_proof_invalid(error.to_string()))?;
    if preimage != record.canonical_bytes {
        return Err(franking_proof_invalid(
            "franking anchor content commitment is inconsistent",
        ));
    }
    Ok(event)
}

pub(crate) fn validate_franking_covering_commit(
    record: &coland_storage::CanonicalEventRecord,
    committed: &coland_storage::CommittedEventRecord,
    realm: &RealmId,
) -> Result<(), AppError> {
    let event = franking_anchor_event(record)?;
    if record.realm_id.as_deref() != Some(realm.as_str())
        || event.realm_id != *realm
        || committed.event != event
        || committed.commit.realm_id != *realm
        || committed.commit.event_ref != event.event_id
    {
        return Err(franking_proof_invalid(
            "franking proof or target covering RealmCommit is inconsistent",
        ));
    }
    Ok(())
}

// Wire code for an invalid franking proof. `proof_invalid` is a registered
// `reason_code`, so it is sourced from the SDK as `arkret_wire::ReasonCode::PROOF_INVALID`
// rather than a local literal.
fn franking_proof_invalid(message: impl Into<String>) -> AppError {
    AppError::param_invalid(message).with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

fn required_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<&'a str, AppError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid(format!("{context}.{field} is required")))
}

fn is_valid_report_hash(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("blake3:"))
        .is_some_and(|hex| {
            hex.len() == 64 && hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        })
}

fn is_valid_replay_nonce(value: &str) -> bool {
    (16..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn contains_forbidden_key(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => object.iter().find_map(|(key, nested)| {
            if keys.contains(&key.as_str()) {
                Some(key.clone())
            } else {
                contains_forbidden_key(nested, keys)
            }
        }),
        Value::Array(values) => values
            .iter()
            .find_map(|nested| contains_forbidden_key(nested, keys)),
        _ => None,
    }
}

const EVIDENCE_PACKAGE_FORBIDDEN_KEYS: &[&str] = &[
    "plaintext",
    "plaintext_body",
    "body_plaintext",
    "message_plaintext",
    "history_key",
    "history_secret",
    "mls_epoch_secret",
    "epoch_secret",
    "epoch_key",
    "exporter_secret",
];

const FRANKING_PROOF_FORBIDDEN_KEYS: &[&str] = &[
    "plaintext",
    "plaintext_body",
    "attachment_filename",
    "reply_excerpt",
    "mentions",
    "private_handle",
    "plaintext_digest",
    "plaintext_hash",
    "mls_group_id",
    "epoch",
];

#[endpoint(
    operation_id = "ak.self.moderation.command.report",
    summary = "File a content moderation report",
    tags("moderation")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.moderation.command.report.v1"))]
async fn moderation_report(
    aa: AuthArgs,
    body: JsonBody<ModerationReportRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationReportResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(format!("report_event: {error}")))?;
    let event = &body.report_event.event;
    let payload: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
        serde_json::from_value(Value::Object(event.payload.clone().into_iter().collect()))
            .map_err(|error| AppError::param_invalid(format!("report_event payload: {error}")))?;
    let reporter_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let reporter_account = reporter_actor.as_account_id().ok_or_else(|| {
        AppError::capability_denied("self moderation reports require an authenticated account")
    })?;
    let event_value = serde_json::to_value(event)
        .map_err(|error| AppError::param_invalid(format!("report_event encode: {error}")))?;
    let canonical_bytes = crate::routing::events::event_log::event_canonical_bytes(&event_value)
        .map_err(|error| {
            AppError::param_invalid(format!("report_event canonical form: {}", error.message))
        })?;
    let exact_replay = state
        .event_queries()
        .canonical_event(event.event_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("moderation replay lookup failed: {error}")))?
        .is_some_and(|record| record.canonical_bytes == canonical_bytes);
    if !exact_replay {
        let evidence_package = payload
            .evidence_package
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("evidence package encode failed: {error}"))
            })?
            .unwrap_or(Value::Null);
        let franking_proof = payload
            .franking_proof
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| AppError::internal(format!("franking proof encode failed: {error}")))?
            .unwrap_or(Value::Null);
        validate_signed_moderation_report_safety(
            state,
            event.realm_id.as_str(),
            &reporter_actor,
            payload.target_ref.as_str(),
            payload.effective_scope.as_ref(),
            &evidence_package,
            &franking_proof,
        )
        .await?;
    }
    let accepted_target =
        arkret_models_collaboration::governance::moderation::ModerationReportAcceptedTargetBasis {
            target_ref: payload.target_ref.to_string(),
            effective_scope: event.scope_ref.clone(),
        };
    body.validate_authoring_context(reporter_account, &accepted_target)
        .map_err(|error| AppError::param_invalid(format!("report_event: {error}")))?;
    let report_id = body
        .report_id()
        .map_err(|error| AppError::param_invalid(format!("report_event: {error}")))?;
    crate::routing::events::event_log::submit_initial_event_submission(
        state,
        &session,
        body.report_event,
    )
    .await
    .map_err(|error| {
        crate::routing::events::event_log::submit_one_error_to_app_error(
            "moderation report Event submit failed",
            error.status(),
            error.code(),
            &error.message(),
        )
    })?;
    json_ok(ModerationReportResponseBody {
        report_id,
        status:
            arkret_models_collaboration::governance::moderation::ModerationReportStatus::Submitted,
        routed_to_ids: Vec::new(),
    })
}

/// The moderation queue View (content-moderation.md §3.3, §5.4) for the
/// authenticated caller, read from one durable cut.
///
/// Items are derived from the accepted `moderation_report` family; only a
/// moderator of the reported scope sees them. A Realm where the caller is not
/// a moderator contributes nothing, exactly like a Realm without reports.
/// Deployment operator status grants no Realm moderation capability.
pub(crate) async fn moderation_queue_for_session(
    state: &AppState,
    principal: &str,
    realm_filter: Option<&RealmId>,
) -> Result<
    Vec<arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem>,
    AppError,
> {
    let principal = arkret_wire::DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("session principal is invalid: {error}")))?;
    let actor = ActorId::account(arkret_wire::AccountId::new(
        principal,
        state.service_core_id().clone(),
    ));
    state
        .governance()
        .moderation_queue_for_actor(&actor, realm_filter)
        .await
        .map_err(|error| AppError::internal(format!("moderation queue read failed: {error}")))
}

/// Deployment-local management aggregation; its policy entries are original
/// accepted Events, never fabricated report queue items.
pub(crate) async fn moderation_management_view_for_session(
    state: &AppState,
    principal: &str,
    realm_filter: Option<&RealmId>,
) -> Result<coland_storage::ModerationManagementView, AppError> {
    let principal = arkret_wire::DidCoreId::new(principal.to_owned())
        .map_err(|error| AppError::internal(format!("session principal is invalid: {error}")))?;
    let actor = ActorId::account(arkret_wire::AccountId::new(
        principal,
        state.service_core_id().clone(),
    ));
    state
        .governance()
        .moderation_management_view_for_actor(&actor, realm_filter)
        .await
        .map_err(|error| {
            AppError::internal(format!("moderation management View read failed: {error}"))
        })
}

#[cfg(test)]
mod report_safety_tests {
    use coland_storage_postgres::Db;
    use serde_json::{Value, json};

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};

    const REALM: &str = "ak:realm:AUFiO2if_pcrsCPNPTKGbSLg0Q25_sBaNHxyQyo5pn7z";
    const TARGET: &str = "ak:message:AUDcGyskAu9_TgDdHy4-tLmIbJp1s_rpjKSw3apHadK8";
    const FRANKING_RECEIVED_AT: &str = "2026-04-30T00:00:00.000Z";
    const REPORTER: &str = "ak:did_core:web:alice.example";

    fn test_state() -> AppState {
        let state = AppState::new(
            AppConfig {
                object_storage: ObjectStorageConfig::local(
                    std::env::temp_dir().join("coland-moderation-tests"),
                ),
                development_mode: true,
                ..AppConfig::test_default()
            },
            Db { pool: None },
        );
        state.test_projection().lock().messages.insert(
            TARGET.replacen("ak:message:", "ak:event:", 1),
            coland_domain::reducer::MessageState {
                event_id: TARGET.replacen("ak:message:", "ak:event:", 1),
                message_id: TARGET.to_owned(),
                realm_id: REALM.to_owned(),
                sender: REPORTER.to_owned(),
                thread_id: REALM.to_owned(),
                content: json!({ "kind": "ak.content.text", "body": "reported" }),
                encrypted: false,
                operation_id: "ak:operation:01904100-0000-7000-8000-000000000777".to_owned(),
                created_at: chrono::Utc::now(),
                revision_of: None,
                redacted_at: None,
            },
        );
        state
    }

    fn realm_scope() -> Value {
        json!({"kind": "realm", "realm_id": REALM})
    }

    fn restricted_circle_state() -> (AppState, ActorId, String) {
        let state = test_state();
        let reporter = ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(REPORTER).unwrap(),
            state.service_core_id().clone(),
        ));
        let circle_id = "ak:circle:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M".to_owned();
        {
            let mut projection = state.test_projection().lock();
            projection
                .messages
                .get_mut(&TARGET.replacen("ak:message:", "ak:event:", 1))
                .unwrap()
                .content["scope_circle_id"] = json!(circle_id);
            projection.circles.insert(
                circle_id.clone(),
                coland_domain::reducer::CircleProjection {
                    circle_id: circle_id.clone(),
                    realm_id: REALM.into(),
                    profile_ref: None,
                    title: "Restricted reports".into(),
                    summary: None,
                    display: json!({}),
                    directory_visibility: "members".into(),
                    join_rule: "invite".into(),
                    history_access: "since_join".into(),
                    mls_group_ref: None,
                    state: coland_domain::reducer::CircleLifecycleState::Active,
                    state_changed_at: None,
                    created_by: reporter.to_string(),
                    created_at: now(),
                    updated_by: None,
                    updated_at: None,
                    members: BTreeSet::from([reporter.to_string()]),
                },
            );
        }
        (state, reporter, circle_id)
    }

    #[test]
    fn report_circle_visibility_requires_exact_reporter_actor() {
        let (state, reporter, circle_id) = restricted_circle_state();
        assert_eq!(
            moderation_target_effective_scope_value(&state, REALM, Some(&reporter), TARGET)
                .unwrap(),
            json!({"kind": "circle", "realm_id": REALM, "circle_id": circle_id}),
        );
        let foreign = ActorId::account(arkret_wire::AccountId::new(
            reporter.signing_principal_id().clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        let service = ActorId::service(reporter.signing_principal_id().clone());
        for other in [&foreign, &service] {
            assert!(
                moderation_target_effective_scope_value(&state, REALM, Some(other), TARGET)
                    .is_err()
            );
        }
    }

    #[test]
    fn unmapped_mimi_reporter_cannot_use_principal_as_circle_membership() {
        let (state, ..) = restricted_circle_state();
        assert!(moderation_target_effective_scope_value(&state, REALM, None, TARGET).is_err());
        // The provider-authenticated facade keeps its existing Realm reporting
        // behavior, but no principal-only hint confers private Circle access.
        assert_eq!(
            moderation_target_effective_scope_value(&state, REALM, None, REALM).unwrap(),
            realm_scope(),
        );
    }

    fn hash(ch: char) -> String {
        format!("sha256:{}", ch.to_string().repeat(64))
    }

    fn franking_event_fixture() -> (String, String, Vec<u8>) {
        let canonical_bytes = b"{}".to_vec();
        let canonical_digest = arkret_canonical::sha256_digest(&canonical_bytes);
        let digest = arkret_identifiers::Hash::new(canonical_digest.clone()).unwrap();
        let event_id = arkret_identifiers::EventId::from_event_digest(&digest)
            .unwrap()
            .to_string();
        (event_id, canonical_digest, canonical_bytes)
    }

    fn valid_evidence(scope: Value) -> Value {
        json!({
            "encryption": "xchacha20poly1305",
            "recipients": ["did:web:moderator.example#key-1"],
            "ciphertext_digest": hash('a'),
            "plaintext_digest": hash('b'),
            "effective_scope": scope,
        })
    }

    fn valid_franking(state: &AppState) -> Value {
        let (event_id, ..) = franking_event_fixture();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            state.notary_signing_key().verifying_key().as_bytes(),
        );
        let signer = arkret_wire::Did::new(format!("did:key:{multibase}")).unwrap();
        let mut proof = FrankingProof {
            realm_id: RealmId::new(REALM.to_owned()).unwrap(),
            event_id: EventId::new(event_id).unwrap(),
            received_by: arkret_wire::project_did_to_core_id(&signer).unwrap(),
            verification_method: arkret_wire::DidUrl::new(format!("{signer}#{multibase}")).unwrap(),
            received_at: chrono::DateTime::parse_from_rfc3339(FRANKING_RECEIVED_AT)
                .unwrap()
                .with_timezone(&chrono::Utc),
            replay_nonce: "nonce_0123456789".to_owned(),
            signature: String::new(),
        };
        let bytes = proof.canonical_signing_bytes().unwrap();
        proof.signature =
            arkret_canonical::base64url_encode(state.notary_signing_key().sign(&bytes).to_bytes());
        serde_json::to_value(proof).unwrap()
    }

    #[test]
    fn authored_event_wire_value_is_the_bare_event_envelope() {
        let realm_id = RealmId::new(REALM.to_owned()).unwrap();
        let event = crate::test_event::raw_event(
            arkret_wire::EventKind::MessageCreate.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            crate::test_actor_id_str("did:web:alice.example"),
            0,
            arkret_wire::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            json!({
                "strand_id": arkret_wire::StrandId::from_event_id(
                    &EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x31; 32]),
                ),
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"},
            }),
        )
        .unwrap();
        let authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

        let wire = authored_event_wire_value(&authored).unwrap();

        assert_eq!(wire["event_id"], json!(authored.event_id()));
        assert!(wire.get("digest_suite").is_none());
        assert!(wire.get("event").is_none());
    }

    #[test]
    fn evidence_package_must_bind_effective_scope() {
        let scope = realm_scope();
        let good = valid_evidence(scope.clone());
        assert!(validate_moderation_evidence_package(&good, &scope).is_ok());

        let bad_scope = json!({
            "kind": "realm",
            "realm_id": "ak:realm:AY0gS_Ca_ad26DoNgNiV6G3woRWfh98gR3yAOYzEkyz5",
        });
        let bad = valid_evidence(bad_scope);
        let error = validate_moderation_evidence_package(&bad, &scope).unwrap_err();
        assert_eq!(error.code, ErrorCode::ParamInvalid);
    }

    #[test]
    fn evidence_package_over_max_total_blob_bytes_is_rejected() {
        let scope = realm_scope();
        let mut evidence = valid_evidence(scope.clone());
        evidence
            .as_object_mut()
            .unwrap()
            .insert("padding".to_owned(), json!("x".repeat(70 * 1024)));
        let error = validate_moderation_evidence_package(&evidence, &scope).unwrap_err();
        assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    }

    #[tokio::test]
    async fn duplicate_target_report_hits_layered_rate_limit() {
        let state = test_state();
        let first = validate_moderation_report_safety(
            &state,
            REALM,
            REPORTER,
            None,
            TARGET,
            None,
            &Value::Null,
            &Value::Null,
            None,
            "source-ip-hash",
        )
        .await;
        assert!(first.is_ok());

        let second = validate_moderation_report_safety(
            &state,
            REALM,
            REPORTER,
            None,
            TARGET,
            None,
            &Value::Null,
            &Value::Null,
            None,
            "source-ip-hash",
        )
        .await
        .unwrap_err();
        assert_eq!(second.code, ErrorCode::RateLimited);
    }

    fn anchor_fixture() -> (
        coland_storage::CanonicalEventRecord,
        coland_storage::CommittedEventRecord,
    ) {
        let realm = RealmId::new(REALM).unwrap();
        let event = crate::test_event::raw_event_at(
            EventKind::MessageCreate.as_str(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            crate::test_actor_id_str("did:web:alice.example"),
            0,
            arkret_wire::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            json!({
                "strand_id": arkret_wire::StrandId::from_event_id(
                    &EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x31; 32]),
                ),
                "track_name": "discussion",
                "encrypted_content": {
                    "version": "1.0",
                    "content_type": "application/vnd.arkret.message+json",
                    "encryption_context": {
                        "epoch": "0",
                        "group_state_ref": EventId::from_digest(
                            arkret_canonical::DigestSuite::Sha256, [0x32; 32],
                        ),
                    },
                    "ciphertext": "Y2lwaGVydGV4dA",
                },
            }),
            chrono::DateTime::parse_from_rfc3339(FRANKING_RECEIVED_AT)
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .unwrap();
        let record = coland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(realm.to_string()),
            kind: event.kind.as_str().to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(&event).unwrap(),
            received_at: event.created_at,
        };
        // Structural-only accepted-read fixtures exercise commitment binding,
        // not producer admission or RealmCommit cryptographic verification.
        let pair = coland_storage::CommittedEventRecord {
            commit: arkret_wire::RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: arkret_wire::RealmCommitId::from_digest([0x33; 32]),
                realm_id: realm.clone(),
                stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id: realm },
                stream_position: 4,
                previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([0x34; 32])),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x35; 32]),
                ),
                committed_at: event.created_at,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:station.example#authority",
                    )
                    .unwrap(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "00".repeat(32)))
                        .unwrap(),
                    created_at: event.created_at,
                    signature: arkret_wire::Base64UrlString::new("c3RydWN0dXJhbA").unwrap(),
                },
            },
            event,
        };
        (record, pair)
    }

    #[test]
    fn franking_anchor_binds_exact_encrypted_event_content_and_covering_commit() {
        let (record, pair) = anchor_fixture();
        validate_franking_covering_commit(&record, &pair, &RealmId::new(REALM).unwrap()).unwrap();
    }

    #[test]
    fn franking_anchor_rejects_modified_ciphertext_under_original_event_id() {
        let (mut record, pair) = anchor_fixture();
        record.envelope["payload"]["encrypted_content"]["ciphertext"] = json!("bW9kaWZpZWQ");
        let error =
            validate_franking_covering_commit(&record, &pair, &RealmId::new(REALM).unwrap())
                .unwrap_err();
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );
    }

    #[test]
    fn franking_anchor_rejects_modified_stored_preimage() {
        let (mut record, pair) = anchor_fixture();
        record.canonical_bytes.push(b' ');
        assert!(
            validate_franking_covering_commit(&record, &pair, &RealmId::new(REALM).unwrap())
                .is_err()
        );
    }

    #[test]
    fn franking_anchor_rejects_covering_pair_with_different_event_or_realm() {
        let (record, pair) = anchor_fixture();
        let realm = RealmId::new(REALM).unwrap();
        let mut altered = pair.clone();
        altered.event.payload.get_mut("encrypted_content").unwrap()["ciphertext"] =
            json!("bW9kaWZpZWQ");
        assert!(validate_franking_covering_commit(&record, &altered, &realm).is_err());
        altered = pair.clone();
        altered.commit.event_ref =
            EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x36; 32]);
        assert!(validate_franking_covering_commit(&record, &altered, &realm).is_err());
        altered = pair;
        altered.commit.realm_id = arkret_wire::RealmId::from_event_id(&altered.commit.event_ref);
        assert!(validate_franking_covering_commit(&record, &altered, &realm).is_err());
    }

    #[tokio::test]
    async fn franking_valid_signature_cannot_impersonate_another_receiving_service() {
        let state = test_state();
        let mut proof: FrankingProof = serde_json::from_value(valid_franking(&state)).unwrap();
        proof.received_by = arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        proof.signature = arkret_canonical::base64url_encode(
            state
                .notary_signing_key()
                .sign(&proof.canonical_signing_bytes().unwrap())
                .to_bytes(),
        );
        let error = validate_moderation_franking_proof(
            &state,
            REALM,
            &serde_json::to_value(proof).unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );
        assert!(
            error.message.contains("does not project to received_by"),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn franking_without_event_time_anchor_is_rejected() {
        let state = test_state();
        let proof = valid_franking(&state);
        let error = validate_moderation_franking_proof(&state, REALM, &proof)
            .await
            .unwrap_err();
        assert_eq!(error.wire_code(), "param_invalid");
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );
        assert!(
            error.message.contains("accepted local event anchor"),
            "{error:?}"
        );
    }
}
