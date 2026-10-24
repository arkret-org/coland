//! Identity / DID endpoint handlers.

use std::collections::BTreeMap;

use super::*;

pub(crate) const IDENTITY_REGISTRY_OPERATION_BUNDLES: &[&str] = &[
    arkret_wire::OperationBundleDescriptor::IDENTITY_REGISTRY_DESCRIBE_V1,
    arkret_wire::OperationBundleDescriptor::IDENTITY_REGISTRY_HTTP_CORE_V1,
];

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.registry.read.describe",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.registry.read.describe.v1"))]
pub(crate) async fn identity_describe(
    depot: &mut Depot,
) -> JsonResult<arkret_models_discovery::ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let supported_did_methods = state
        .config()
        .did_resolver_allow_methods
        .iter()
        .map(|method| format!("did:{method}"))
        .collect::<Vec<_>>();
    let trust_roots = identity_trust_roots(state);
    let mut description = crate::routing::system::describe::build_server_description(state);
    description.service_kind = arkret_wire::ServiceKind::IdentityRegistry;
    description.supported_profiles = vec![arkret_wire::ProfileId::IDENTITY_REGISTRY_V1.to_owned()];
    description.profile_bindings.clear();
    description.supported_operation_bundles = IDENTITY_REGISTRY_OPERATION_BUNDLES
        .iter()
        .map(|bundle| (*bundle).to_owned())
        .collect();
    description.transport_bindings = vec![arkret_models_discovery::TransportBinding::HttpJson {
        base_url: format!("{}/", state.config().public_base_url.trim_end_matches('/')),
        extension_profile_required: (),
    }];
    description.supported_features.clear();
    description.verified_profiles.clear();
    description.interop_surfaces.clear();
    description.plaintext_visibility = arkret_models_discovery::PlaintextVisibility::none();
    description
        .extensions
        .insert(
            "x_coland_identity_registry".to_owned(),
            json!({
                "supported_did_methods": supported_did_methods,
                "resolver_allow_methods": state.config().did_resolver_allow_methods,
                "trust_roots": trust_roots
            }),
        )
        .map_err(|error| AppError::internal(format!("identity extension rejected: {error}")))?;
    description.validate().map_err(|error| {
        AppError::internal(format!(
            "identity ServiceDescribe validation failed: {error}"
        ))
    })?;
    json_ok(description)
}

fn ensure_webvh_document_id(did: &str, document: &Value) -> Result<(), AppError> {
    match document.get("id").and_then(Value::as_str) {
        Some(value) if value == did => Ok(()),
        Some(_) => Err(AppError::param_invalid(
            "log_entry.state.id does not match did",
        )),
        None => Err(AppError::param_invalid("log_entry.state.id is required")),
    }
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.identity.webvh.document.get",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.identity.webvh.document.get"))]
pub(crate) async fn embedded_webvh_document(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some(record) = embedded_webvh_record_for_request(state, req, res).await else {
        return;
    };
    render_json_bytes(
        res,
        "application/did+json; charset=utf-8",
        &record.did_document,
    );
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.identity.webvh.log.get",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.identity.webvh.log.get"))]
pub(crate) async fn embedded_webvh_log(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some(record) = embedded_webvh_record_for_request(state, req, res).await else {
        return;
    };
    let events = match state.dids().log_events(&record.did).await {
        Ok(events) => events,
        Err(error) => {
            tracing::error!(%error, "failed to read hosted WebVH history");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to read did log",
            );
            return;
        }
    };
    if events.is_empty() {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "did log not found");
        return;
    }
    let mut body = Vec::new();
    for event in events {
        let Ok(entry) = arkret_canonical::canonical_json_bytes(&event.operation) else {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to encode did log",
            );
            return;
        };
        body.extend(entry);
        body.push(b'\n');
    }
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/jsonl; charset=utf-8".parse().unwrap(),
    );
    res.headers_mut().insert(
        header::CONTENT_LENGTH,
        body.len().to_string().parse().unwrap(),
    );
    res.write_body(body).ok();
}

#[salvo::oapi::endpoint(operation_id = "ak.root.identity.read.resolve", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.read.resolve.v1"))]
pub(crate) async fn identity_resolve(
    body: JsonBody<IdentityResolveRequestBody>,
    depot: &mut Depot,
) -> JsonResult<IdentityResolveResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    json_ok(resolve_identity(state, body.into_inner()).await?)
}

async fn resolve_identity(
    state: &AppState,
    body: IdentityResolveRequestBody,
) -> Result<IdentityResolveResponseBody, AppError> {
    let requires_webvh_evidence = body
        .requested_evidence_kinds
        .contains(&IdentityMethodEvidenceKind::DidWebvh);
    let did = body.did.as_str();
    if let Ok(Some(record)) = state.dids().document(did).await {
        // G3.S3: every did:webvh resolution MUST first re-validate the
        // log chain, SCID derivation, configured witness quorum, and
        // rotation control authorisation. Rotation entries fail closed
        // when witness quorum is missing.
        // `degraded_no_witness` is a spec-defined health state
        // (identity-did.md health-status section): hosting stays reachable
        // but witness evidence is missing or expired. No coland code path
        // currently enters that state because witness verification and the
        // degradation window remain unimplemented.
        // Rotation control authorisation accepts a previous-controller
        // proof, a genesis-declared recovery key (key-management.md §3.3),
        // or an organization governance quorum (identity-did.md §8.1–§8.2).
        // Spec: identity-did.md §3.4 + §4.2.1 + §7 + §8.
        let method_evidence = if did.starts_with("did:webvh:") {
            run_webvh_resolution_checks(state, did, &record).await?
        } else {
            None
        };
        require_requested_webvh_evidence(requires_webvh_evidence, method_evidence.as_ref())?;
        return Ok(identity_resolve_outcome(
            body.did,
            record.did_document,
            key_log_head_hash(record.key_log_head)?,
            Some(record.sequence),
            method_evidence,
        ));
    }
    if let Some(document) = super::document::federation_peer_id_document(state, did) {
        require_requested_webvh_evidence(requires_webvh_evidence, None)?;
        return Ok(identity_resolve_outcome(
            body.did, document, None, None, None,
        ));
    }
    let document = state.dids().resolve_did(&body.did).await.map_err(|error| {
        tracing::warn!(%error, %did, "DID resolution failed");
        crate::app_error!(
            CurrentDidAuthorityUnavailable,
            "DID resolution did not produce a verified document",
        )
    })?;
    // A missing/unresolvable DID is not an empty identity. In particular, never
    // manufacture a development placeholder on this public read path.
    require_requested_webvh_evidence(requires_webvh_evidence, None)?;
    Ok(identity_resolve_outcome(
        body.did,
        serde_json::to_value(&document).map_err(|error| {
            AppError::internal(format!(
                "resolved DID document cannot be serialized: {error}"
            ))
        })?,
        None,
        None,
        None,
    ))
}

fn require_requested_webvh_evidence(
    required: bool,
    evidence: Option<&IdentityMethodEvidence>,
) -> Result<(), AppError> {
    if required && !matches!(evidence, Some(IdentityMethodEvidence::DidWebvh { .. })) {
        return Err(crate::app_error!(
            CurrentDidAuthorityUnavailable,
            "requested did_webvh method evidence is unavailable from a fully verified history",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.document.resource.get",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.document.resource.get.v1"))]
pub(crate) async fn identity_document(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityDocumentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::param_invalid("invalid did"));
    }
    let typed_did = Did::new(did.clone()).map_err(|_| AppError::param_invalid("invalid did"))?;
    let resolved = resolve_identity(
        state,
        IdentityResolveRequestBody {
            did: typed_did,
            requested_evidence_kinds: Vec::new(),
        },
    )
    .await?;
    json_ok(IdentityDocumentView {
        did_document: resolved.did_document,
        normalized_view: None,
        method_evidence: None,
        cached_at: None,
    })
}

fn key_log_head_hash(value: Option<String>) -> Result<Option<Hash>, AppError> {
    value
        .map(Hash::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("invalid key_log_head digest: {error}")))
}

fn did_log_event_digest(operation: &Value) -> Result<String, AppError> {
    arkret_canonical::canonical_sha256(operation)
        .map_err(|error| AppError::internal(format!("DID log entry digest failed: {error}")))
}

fn identity_resolve_outcome(
    did: Did,
    document: Value,
    key_log_head: Option<Hash>,
    sequence: Option<u64>,
    method_evidence: Option<IdentityMethodEvidence>,
) -> IdentityResolveResponseBody {
    let mut did_document =
        serde_json::from_value::<BTreeMap<String, Value>>(document).unwrap_or_default();
    did_document
        .entry("id".to_owned())
        .or_insert_with(|| Value::String(did.as_str().to_owned()));
    IdentityResolveResponseBody {
        did_document,
        key_log_head,
        sequence,
        method_evidence,
        receipts: Vec::new(),
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.root.identity.log.read.list", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.log.read.list.v1"))]
pub(crate) async fn identity_log(
    did: salvo::oapi::extract::QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IdentityLogListResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::param_invalid("invalid did"));
    }
    let method = did_method_token(&did)?;
    let (method, native_history, entries) = match method.as_str() {
        // The persisted operation is the accepted method-native did.jsonl
        // object. Returning it directly avoids creating a second Arkret log
        // envelope, sequence, digest chain, or proof transcript.
        "did:webvh" => (
            arkret_models_identity::DidMethodUri::Webvh,
            Some(true),
            state
                .dids()
                .log_events(&did)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|record| record.operation)
                .collect(),
        ),
        // did:web has no method-native append-only history.
        "did:web" => (
            arkret_models_identity::DidMethodUri::Web,
            Some(false),
            Vec::new(),
        ),
        _ => {
            return Err(AppError::param_invalid(
                "DID method does not expose a supported native history",
            ));
        }
    };
    json_ok(IdentityLogListResponseBody {
        did: Did::new(did).map_err(|error| AppError::internal(error.to_string()))?,
        method,
        native_history,
        entries,
        next_cursor: None,
        has_more: false,
    })
}

fn did_method_token(did: &str) -> Result<String, AppError> {
    let method_name = did
        .strip_prefix("did:")
        .and_then(|value| value.split(':').next())
        .ok_or_else(|| AppError::param_invalid("invalid did method"))?;
    Ok(format!("did:{method_name}"))
}

#[cfg(test)]
mod identity_log_tests {
    use super::did_method_token;

    #[test]
    fn identity_log_reports_the_canonical_registered_did_method_token() {
        assert_eq!(
            did_method_token("did:webvh:scid:example.com:webvh:alice").expect("valid did:webvh"),
            "did:webvh"
        );
        assert_eq!(
            did_method_token("did:web:example.com:alice").expect("valid did:web"),
            "did:web"
        );
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.root.identity.receipts.read.list", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.receipts.read.list.v1"))]
pub(crate) async fn identity_receipts(
    did: salvo::oapi::extract::QueryParam<String, true>,
    _depot: &mut Depot,
) -> JsonResult<IdentityReceiptListResponseBody> {
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::param_invalid("invalid did"));
    }
    json_ok(IdentityReceiptListResponseBody {
        receipts: Vec::new(),
        threshold_met: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.command.submit_did_operation",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.command.submit_did_operation.v1")
)]
pub(crate) async fn identity_submit_did_operation(
    depot: &mut Depot,
    body: JsonBody<DidOperationSubmitRequestBody>,
) -> JsonResult<DidOperationSubmitResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let did = body.did.as_str().to_owned();
    let typed_did = body.did;
    let did_method = did
        .strip_prefix("did:")
        .and_then(|value| value.split(':').next())
        .ok_or_else(|| AppError::param_invalid("invalid did"))?;
    if body.did_method.as_str() != did_method {
        return Err(AppError::param_invalid(
            "did_method must exactly match the DID method discriminator",
        ));
    }
    if did_method != "webvh" {
        return Err(AppError::param_invalid(
            "DID method is not supported by this operation adapter",
        ));
    }
    let next_seq = body
        .sequence
        .ok_or_else(|| AppError::param_invalid("sequence is required for did:webvh submission"))?;
    if next_seq > i64::MAX as u64 {
        return Err(AppError::param_invalid(
            "sequence exceeds the supported persistence range",
        ));
    }
    let expected_previous_head = body
        .previous_event_digest
        .as_ref()
        .map(|digest| digest.as_str().to_owned());
    let operation = Value::Object(body.operation.into_iter().collect());
    let version_id = operation
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("operation.versionId is required"))?
        .to_owned();
    let operation_seq = version_id
        .split_once('-')
        .and_then(|(sequence, hash)| (!hash.is_empty()).then_some(sequence))
        .and_then(|sequence| sequence.parse::<u64>().ok())
        .ok_or_else(|| AppError::param_invalid("operation.versionId must be <sequence>-<hash>"))?;
    if operation_seq != next_seq {
        return Err(crate::app_error!(
            CasConflict,
            "request sequence must equal the native operation versionId sequence",
        ));
    }
    let document = operation
        .get("state")
        .filter(|document| document.is_object())
        .cloned()
        .ok_or_else(|| AppError::param_invalid("operation.state is required"))?;
    ensure_webvh_document_id(&did, &document)?;
    let event_digest = did_log_event_digest(&operation)?;
    let events = state
        .dids()
        .log_events(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    // The submitted alias need not exist yet. Locate the predecessor through
    // the accepted native head; the complete candidate chain below authorizes
    // the new location, and the store repeats the head CAS under its core lock.
    let predecessor_did = events
        .last()
        .and_then(|event| event.operation.pointer("/state/id"))
        .and_then(Value::as_str)
        .unwrap_or(&did);
    let existing = state
        .dids()
        .document(predecessor_did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(existing_event) = events.iter().find(|event| {
        event.sequence == next_seq
            || event.operation.get("versionId").and_then(Value::as_str) == Some(version_id.as_str())
    }) {
        if existing_event.event_digest == event_digest && existing_event.operation == operation {
            return did_operation_submit_outcome(
                arkret_models_identity::identity::DidOperationSubmitStatus::Duplicate,
                typed_did,
                next_seq,
                &version_id,
                existing_event.created_at,
            );
        }
        return Err(crate::app_error!(
            CasConflict,
            "DID operation conflicts with an existing sequence or versionId",
        ));
    }
    let expected_next_seq = match events.last() {
        None => 1,
        Some(event) => event.sequence.checked_add(1).ok_or_else(|| {
            crate::app_error!(CasConflict, "current DID operation sequence cannot advance",)
        })?,
    };
    if next_seq != expected_next_seq {
        return Err(crate::app_error!(
            CasConflict,
            "DID operation sequence must advance the current log head exactly once",
        ));
    }
    let current_head = events.last().map(|event| event.event_digest.clone());
    if expected_previous_head
        .as_ref()
        .is_some_and(|expected| current_head.as_ref() != Some(expected))
    {
        return Err(crate::app_error!(
            CasConflict,
            "previous_event_digest does not match the current log head",
        ));
    }
    let stored_state_matches_log = match (existing.as_ref(), events.last()) {
        (None, None) => true,
        (Some(document), Some(head)) => {
            document.sequence == head.sequence
                && document.key_log_head.as_deref() == Some(head.event_digest.as_str())
        }
        _ => false,
    };
    if !stored_state_matches_log {
        return Err(crate::app_error!(
            CasConflict,
            "stored DID document and native log head are inconsistent",
        ));
    }

    let mut candidate: Vec<WebvhLogEntry> = events
        .iter()
        .map(|event| WebvhLogEntry::new(event.operation.clone()))
        .collect();
    candidate.push(WebvhLogEntry::new(operation.clone()));
    if let Err(message) = verify_webvh_log_proof(&operation) {
        return Err(crate::app_error!(SignatureInvalid, message));
    }
    validate_log_chain(&candidate)?;
    verify_scid_against_did(&did, &candidate[0])?;
    verify_log_subject(&did, &candidate)?;
    validate_witness_policy_for_log(&candidate)?;
    validate_rotation_authorization_for_log(&candidate)?;

    let submitted_at = now();
    let document_record = WebvhDocumentRecord {
        did: did.clone(),
        did_document: document.clone(),
        key_log_head: Some(event_digest.clone()),
        sequence: next_seq,
        method_evidence: json!({
            "mode": "submitted_operation",
            "source": arkret_wire::ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION_V1,
            "version_id": version_id,
        }),
        // put_document authoritatively overwrites freshness evidence with
        // the ingestion instant, so placeholders are enough here.
        fetched_at: submitted_at,
        expires_at: submitted_at,
        updated_at: submitted_at,
    };
    let admitted_document: arkret_identity::DidDocument = serde_json::from_value(document)
        .map_err(|error| {
            crate::app_error!(SchemaViolation, format!("DID document is invalid: {error}"),)
        })?;
    crate::test_material_admission::enforce_did_document_admission(
        &admitted_document,
        Some(&state.config().trust_domain),
    )
    .map_err(|error| crate::app_error!(SignatureInvalid, error))?;
    let commit = state
        .dids()
        .commit_formal_log_operation(
            &state.config().trust_domain,
            current_head,
            document_record.clone(),
            WebvhLogRecord {
                event_digest: event_digest.clone(),
                did: did.clone(),
                sequence: next_seq,
                operation: operation.clone(),
                created_at: submitted_at,
            },
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    match commit {
        WebvhLogCommitOutcome::Conflict => {
            return Err(crate::app_error!(
                CasConflict,
                "DID operation lost a concurrent head comparison",
            ));
        }
        WebvhLogCommitOutcome::Duplicate => {
            let accepted_at = state
                .dids()
                .log_events(&did)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .into_iter()
                .find(|event| event.event_digest == event_digest && event.operation == operation)
                .map(|event| event.created_at)
                .ok_or_else(|| {
                    AppError::internal(
                        "duplicate DID operation has no durable original acceptance row",
                    )
                })?;
            return did_operation_submit_outcome(
                arkret_models_identity::identity::DidOperationSubmitStatus::Duplicate,
                typed_did,
                next_seq,
                &version_id,
                accepted_at,
            );
        }
        WebvhLogCommitOutcome::Accepted => {}
    }
    for event in &events {
        if let Some(alias) = event.operation.pointer("/state/id").and_then(Value::as_str)
            && let Ok(alias) = Did::new(alias)
        {
            state.dids().discard_cached_document(&alias);
        }
    }
    if let Err(error) = state.cache_resolved_did_document(document_record) {
        tracing::warn!(%error, "failed to cache submitted DID document");
    }
    append_audit_log(
        state,
        Some(&did),
        "identity.submit_did_operation",
        json!({
            "did": did.clone(),
            "sequence": next_seq,
            "accepted_entry_digest": event_digest.clone(),
        }),
        "accepted",
    )
    .await;
    did_operation_submit_outcome(
        arkret_models_identity::identity::DidOperationSubmitStatus::Accepted,
        typed_did,
        next_seq,
        &version_id,
        submitted_at,
    )
}

fn did_operation_submit_outcome(
    status: arkret_models_identity::identity::DidOperationSubmitStatus,
    did: Did,
    sequence: u64,
    version_id: &str,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> JsonResult<DidOperationSubmitResponseBody> {
    let operation_ref = format!("{did}?versionId={version_id}");
    json_ok(DidOperationSubmitResponseBody {
        status,
        did,
        accepted_at,
        sequence: Some(sequence),
        operation_ref,
        receipts: Vec::new(),
    })
}
