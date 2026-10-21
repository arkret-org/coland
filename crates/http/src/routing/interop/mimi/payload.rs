use super::*;

pub(super) fn typed_body_value<T: Serialize>(
    body: T,
    context: &'static str,
) -> Result<Value, AppError> {
    serde_json::to_value(body)
        .map_err(|error| AppError::internal(format!("{context} request body serialize: {error}")))
}

pub(super) async fn persist_mimi_canonical_message_event(
    state: &AppState,
    realm_id: &str,
    room_uri: MimiRoomUri,
    binding_event_id: EventId,
    source_provider_id: arkret_wire::DidCoreId,
    request: &MimiSubmitMessageRequestBody,
    payload: arkret_models_collaboration::events_payloads::message::MessageCreatePayload,
) -> Result<String, AppError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let event = crate::state::author_mimi_event::<arkret_wire::event_spec::MessageCreate>(
        state,
        arkret_wire::ScopeRef::Realm { realm_id },
        payload,
    )
    .await
    .map_err(mimi_admission_error)?;
    let event_id = event.event_id.to_string();
    use arkret_wire::PayloadSigner as _;
    let method = event
        .producer_proof
        .as_ref()
        .expect("authored Event proof")
        .verification_method
        .clone();
    let mut receipt = json!({"schema":arkret_wire::SchemaId::MIMI_INTEROP_V1,
        "receipt_kind":"content_mapping_receipt","profile":arkret_wire::ProfileId::MIMI_INTEROP_V1,
        "mimi_room_uri":room_uri,"source_format":request.ciphertext.content_type,
        "target_format":arkret_wire::CapabilityActionId::MESSAGE_CREATE,"original_envelope_digest":event.payload["mimi_provenance"]["source_envelope_digest"],
        "mapped_operation_id":event.event_id.as_str().trim_start_matches("ak:event:"),"arkret_event_id":event.event_id,
    });
    let bytes = arkret_canonical::canonical_json_bytes(&receipt)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        state.service_did(),
        method,
    );
    let signature = signer
        .sign_payload(&bytes)
        .map_err(|e| AppError::internal(e.to_string()))?;
    receipt["proof"] = serde_json::to_value(arkret_wire::PayloadProof {
        kind: "detached_jws".into(),
        verification_method: signature.verification_method,
        payload_digest: signature.payload_digest,
        created_at: signature.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: signature.jws,
    })
    .map_err(|e| AppError::internal(e.to_string()))?;
    let guard = coland_storage::SelfProducerCommitGuard::MimiFacade {
        service_id: state.service_core_id(),
        verification_method: event
            .producer_proof
            .as_ref()
            .expect("authored Event proof")
            .verification_method
            .clone(),
        room_uri,
        binding_event_id,
        attributed_actor: request.sender_actor_id.clone(),
        source_provider_id,
        reporter_authority: None,
        mapping_receipt: Some(receipt),
        reporter_device_guard: None,
        submit_request: Some(
            serde_json::to_value(request).map_err(|e| AppError::internal(e.to_string()))?,
        ),
    };
    crate::state::commit_mimi_event(state, event, guard, None)
        .await
        .map_err(mimi_admission_error)?;
    Ok(event_id)
}

pub(super) fn mimi_admission_error(error: coland_services::ServiceError) -> AppError {
    let detail = error.to_string();
    if detail.contains("mimi_observer_write_forbidden") {
        return AppError::capability_denied(detail)
            .with_reason_code(arkret_wire::ReasonCode::MIMI_OBSERVER_WRITE_FORBIDDEN);
    }
    if detail.contains("mimi_governance_binding_mismatch")
        || detail.contains("mimi_mls_group_id_mismatch")
    {
        return AppError::capability_denied(detail)
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH);
    }
    if error.is_conflict_kind() || error.is_not_found() {
        AppError::capability_denied(detail)
    } else {
        AppError::internal(detail)
    }
}

pub(super) fn decode_mimi_update_payload(body: &Value) -> Result<Option<Value>, AppError> {
    let Some(opaque) = body.get("update").and_then(|update| update.get("payload")) else {
        return Err(
            AppError::param_invalid("MIMI room update requires update.payload")
                .with_internal_reason("mimi_payload_invalid"),
        );
    };
    decode_optional_mimi_opaque_json(opaque, "payload_digest", "MIMI room update payload")
}

pub(super) fn mimi_room_binding_payload(update_payload: &Value) -> Option<&Value> {
    if update_payload.get("kind").and_then(Value::as_str)
        != Some(arkret_wire::event_kind_str::MIMI_ROOM_BINDING)
    {
        return None;
    }
    update_payload.get("payload")
}

pub(super) fn decode_mimi_ciphertext_payload(
    ciphertext: &MimiCiphertext,
) -> Result<Value, AppError> {
    let bytes =
        arkret_canonical::base64url_decode(ciphertext.payload.as_str()).map_err(|error| {
            AppError::param_invalid(format!("MIMI ciphertext payload is not base64url: {error}"))
                .with_internal_reason("mimi_payload_invalid")
        })?;
    if arkret_canonical::sha256_digest(&bytes) != ciphertext.ciphertext_digest.as_str() {
        return Err(
            AppError::param_invalid("MIMI ciphertext payload digest mismatch")
                .with_internal_reason("mimi_payload_digest_mismatch"),
        );
    }
    arkret_canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
        AppError::param_invalid(format!(
            "MIMI ciphertext payload is not canonical JSON: {error}"
        ))
        .with_internal_reason("mimi_payload_invalid")
    })
}

pub(super) fn decode_mimi_associated_data(
    associated_data: Option<&MimiOpaquePayload>,
) -> Result<Option<Value>, AppError> {
    let Some(associated_data) = associated_data else {
        return Ok(None);
    };
    let Some(payload) = associated_data.payload.as_ref() else {
        return Ok(None);
    };
    let bytes = arkret_canonical::base64url_decode(payload.as_str()).map_err(|error| {
        AppError::param_invalid(format!("MIMI associated_data is not base64url: {error}"))
            .with_internal_reason("mimi_payload_invalid")
    })?;
    if arkret_canonical::sha256_digest(&bytes) != associated_data.payload_digest.as_str() {
        return Err(
            AppError::param_invalid("MIMI associated_data digest mismatch")
                .with_internal_reason("mimi_payload_digest_mismatch"),
        );
    }
    arkret_canonical::from_canonical_json_slice::<Value>(&bytes)
        .map(Some)
        .map_err(|error| {
            AppError::param_invalid(format!(
                "MIMI associated_data is not canonical JSON: {error}"
            ))
            .with_internal_reason("mimi_payload_invalid")
        })
}

pub(super) fn decode_optional_mimi_opaque_json(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
) -> Result<Option<Value>, AppError> {
    let Some(bytes) = decode_mimi_opaque_bytes(opaque, digest_field, context)? else {
        return Ok(None);
    };
    let value = arkret_canonical::from_canonical_json_slice::<Value>(&bytes).map_err(|error| {
        AppError::param_invalid(format!("{context} is not canonical JSON: {error}"))
            .with_internal_reason("mimi_payload_invalid")
    })?;
    Ok(Some(value))
}

pub(super) fn decode_mimi_opaque_bytes(
    opaque: &Value,
    digest_field: &str,
    context: &'static str,
) -> Result<Option<Vec<u8>>, AppError> {
    let digest = opaque
        .get(digest_field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::param_invalid(format!("{context} requires {digest_field}"))
                .with_internal_reason("mimi_payload_invalid")
        })?;
    let payload = match opaque.get("payload").and_then(Value::as_str) {
        Some(payload) if !payload.trim().is_empty() => payload,
        _ => return Ok(None),
    };
    let bytes = arkret_canonical::base64url_decode(payload).map_err(|error| {
        AppError::param_invalid(format!("{context} payload is not base64url: {error}"))
            .with_internal_reason("mimi_payload_invalid")
    })?;
    let observed = arkret_canonical::sha256_digest(&bytes);
    if observed != digest {
        return Err(
            AppError::param_invalid(format!("{context} digest mismatch"))
                .with_internal_reason("mimi_payload_digest_mismatch"),
        );
    }
    Ok(Some(bytes))
}

pub(super) fn mimi_provider_directory_value(
    state: &AppState,
) -> Result<arkret_models_collaboration::objects::interop::ProviderDirectory, AppError> {
    use arkret_models_collaboration::objects::interop::{
        ProviderDirectory, ProviderDirectoryMimi, ProviderDirectoryProof,
    };
    // Resolve the full controller from current accepted service material;
    // never reconstruct a DID from its stable core id.
    let service_did = state.service_resolution_commitment().did.clone();
    let service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service core id invalid: {error}")))?;
    let verification_method = arkret_wire::DidUrl::new(format!("{}#notary-key", service_did))
        .map_err(|error| AppError::internal(format!("service notary key id invalid: {error}")))?;
    let placeholder = arkret_wire::PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
            .map_err(|error| AppError::internal(format!("placeholder digest invalid: {error}")))?,
        created_at: chrono::Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
    };
    let mut directory = ProviderDirectory {
        schema: arkret_wire::SchemaId::MIMI_INTEROP_V1.to_owned(),
        service_id: service_id.clone(),
        service_kind: "mimi_provider_facade".to_owned(),
        supported_profiles: vec![arkret_wire::ProfileId::MIMI_INTEROP_V1.to_owned()],
        mimi: ProviderDirectoryMimi {
            protocol_draft: "draft-ietf-mimi-protocol-06".to_owned(),
            content_draft: "draft-ietf-mimi-content-08".to_owned(),
            room_policy_draft: "draft-ietf-mimi-room-policy-03".to_owned(),
            identifier_draft: "draft-kohbrok-mimi-identifiers-01".to_owned(),
            base_url: mimi_base_url(state),
            provider_id: MimiUri::new(mimi_provider_id(state)).map_err(|error| {
                AppError::internal(format!("derived MIMI provider id is invalid: {error}"))
            })?,
            endpoints: mimi_provider_directory_endpoints(&state.config().public_base_url)?,
            features: [
                "consent",
                "identifier_query",
                "key_material",
                "notify",
                "proxy_download",
                "report_abuse",
                "room_update",
                "submit_message",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            mls_cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
            content_profiles: [
                "application/mimi-content",
                "application/vnd.arkret.content+json",
                "text/markdown;variant=GFM-MIMI",
                "text/plain;charset=utf-8",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            room_policy_components: [
                "asset_privacy",
                "history_access",
                "join_rule",
                "membership",
                "message_expiration",
                "roles",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            extra: Default::default(),
        },
        proof: ProviderDirectoryProof(placeholder),
        extra: Default::default(),
    };
    directory.proof.0.payload_digest = directory
        .payload_digest()
        .map_err(|error| AppError::internal(format!("directory digest: {error}")))?;
    let binding = directory
        .proof_binding_bytes()
        .map_err(|error| AppError::internal(format!("directory proof binding: {error}")))?;
    directory.proof.0.jws =
        arkret_signatures::sign_ed25519_detached_jws(state.notary_signing_key().as_ref(), &binding)
            .map_err(|error| AppError::internal(format!("directory signing: {error}")))?;
    directory.validate().map_err(|error| {
        AppError::internal(format!("directory capability declaration: {error}"))
    })?;
    Ok(directory)
}

fn mimi_provider_directory_endpoints(
    public_base: &str,
) -> Result<Vec<arkret_models_collaboration::objects::interop::ProviderDirectoryEndpoint>, AppError>
{
    use arkret_models_collaboration::objects::interop::ProviderDirectoryEndpoint;
    use arkret_wire::ServiceOperationId as Op;
    let base = url::Url::parse(public_base)
        .map_err(|error| AppError::internal(format!("directory service base: {error}")))?;
    let prefix = base.path().trim_end_matches('/');
    Ok([
        ("consent", Op::OpenMimiCommandRequestConsentV1),
        ("identifier_query", Op::OpenMimiReadIdentifiersV1),
        ("key_material", Op::OpenMimiExchangeRequestKeyMaterialV1),
        ("notify", Op::OpenMimiCommandNotifyV1),
        ("proxy_download", Op::OpenMimiCommandProxyDownloadV1),
        ("report_abuse", Op::OpenMimiCommandReportAbuseV1),
        ("room_update", Op::OpenMimiCommandUpdateRoomV1),
        ("submit_message", Op::OpenMimiCommandSubmitMessageV1),
    ]
    .into_iter()
    .map(|(feature, operation)| {
        let descriptor = arkret_wire::SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .find(|row| row.id == operation)
            .expect("registered MIMI operation");
        ProviderDirectoryEndpoint {
            endpoint_id: feature.to_owned(),
            relative_path: format!("{prefix}{}", descriptor.http_path),
        }
    })
    .collect())
}

#[cfg(test)]
mod directory_endpoint_tests {
    #[test]
    fn registered_root_relative_routes_preserve_the_service_mount_prefix() {
        for (base, prefix) in [
            ("https://station.example/", ""),
            ("https://station.example/tenant/", "/tenant"),
        ] {
            let rows = super::mimi_provider_directory_endpoints(base).unwrap();
            assert_eq!(rows.len(), 8);
            assert_eq!(
                rows[0].relative_path,
                format!("{prefix}/_arkret/open/mimi/consent/request")
            );
            assert_eq!(
                rows[2].relative_path,
                format!("{prefix}/_arkret/open/mimi/key-material")
            );
            for row in rows {
                let url = url::Url::parse(base)
                    .unwrap()
                    .join(&row.relative_path)
                    .unwrap();
                assert_eq!(
                    url.origin().ascii_serialization(),
                    "https://station.example"
                );
                assert!(
                    url.path()
                        .starts_with(&format!("{prefix}/_arkret/open/mimi/"))
                );
            }
        }
    }
}

pub(super) fn mimi_base_url(state: &AppState) -> String {
    format!(
        "{}/_arkret/open/mimi",
        state.config().public_base_url.trim_end_matches('/')
    )
}

pub(super) fn mimi_provider_id(state: &AppState) -> String {
    service_did_mimi_provider_id(state.service_did().as_str())
}

/// A `did:web` / `did:webvh` service id projected onto the MIMI provider id.
///
/// The DID form escapes an authority port as `%3A`, and a DID may be written
/// with a mixed-case host. Both are decoded/folded here so the derived value
/// meets the canonical `mimi://` authority rules of
/// `zh/extensions/mimi-interop.md` §4; every room URI built on top of it is the
/// `ak.component.mimi.room_binding.v1` cell subject, where two spellings would
/// address two cells.
pub(super) fn service_did_mimi_provider_id(service_did: &str) -> String {
    if let Some(domain) = service_did.strip_prefix("did:web:") {
        return format!("mimi://{}", canonical_mimi_authority(domain));
    }
    if let Some(rest) = service_did.strip_prefix("did:webvh:") {
        let mut parts = rest.splitn(2, ':');
        if parts.next().is_some_and(|scid| !scid.is_empty())
            && let Some(authority_and_path) = parts.next()
            && !authority_and_path.is_empty()
        {
            return format!("mimi://{}", canonical_mimi_authority(authority_and_path));
        }
    }
    format!("mimi://{}", service_did.replace(':', ".").to_lowercase())
}

/// DID authority (`host%3Aport:path:segments`) -> canonical `host[:port]/path`.
///
/// The two separators are decoded in this order on purpose: `:` is the DID path
/// separator and becomes `/`, while the escaped `%3A` is the authority port
/// separator and becomes `:`. Decoding the escape first would turn a port into
/// a path segment.
fn canonical_mimi_authority(authority: &str) -> String {
    authority
        .replace(':', "/")
        .replace("%3A", ":")
        .replace("%3a", ":")
        .to_lowercase()
}

/// Canonical room URI for a locally hosted MIMI room.
///
/// Validated through the SDK type rather than string-formatted, because a
/// non-canonical value would either be rejected downstream by the payload
/// schema or, worse, address a second cell for the same room.
pub(super) fn mimi_room_uri(state: &AppState, room_id: &str) -> Result<MimiRoomUri, AppError> {
    MimiRoomUri::new(format!("{}/rooms/{room_id}", mimi_provider_id(state))).map_err(|error| {
        AppError::param_invalid(format!(
            "room_id does not form a canonical MIMI room URI: {error}"
        ))
    })
}

pub(super) fn mimi_receipt(
    state: &AppState,
    operation_id: &str,
    body: &Value,
    extra: Value,
) -> Value {
    json!({
        "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
        "operation_id": operation_id,
        "service_id": state.service_id(),
        "provider_id": mimi_provider_id(state),
        "request_hash": arkret_canonical::sha256_digest(body.to_string().as_bytes()),
        "accepted_at": now(),
        "drafts": {
            "protocol": "draft-ietf-mimi-protocol-06",
            "content": "draft-ietf-mimi-content-08",
            "room_policy": "draft-ietf-mimi-room-policy-03",
            "identifiers": "draft-kohbrok-mimi-identifiers-01"
        },
        "extra": extra
    })
}

pub(super) struct MimiMappedContent {
    pub(super) content: Value,
    pub(super) policy: Value,
    pub(super) quarantine: Option<Value>,
    pub(super) status: &'static str,
}

pub(super) fn map_mimi_message_content(
    body: &Value,
    source_format: &str,
) -> Result<MimiMappedContent, AppError> {
    let mut content = mimi_content_payload(body, source_format);
    if !content.is_object() {
        return Err(AppError::param_invalid(
            "unsupported MIMI content format: content must map to an Arkret content block",
        ));
    }
    let content_kind = mimi_content_kind(body, &content).map(str::to_owned);
    if let Some(kind) = content_kind.as_deref()
        && matches!(
            kind,
            "m.text" | "text/plain" | "text/markdown" | "m.markdown"
        )
    {
        let object = content
            .as_object_mut()
            .expect("content object checked above");
        object.insert(
            "kind".to_owned(),
            Value::String(
                arkret_models_collaboration::events_payloads::CONTENT_KIND_TEXT.to_owned(),
            ),
        );
    }
    let e2ee_boundary = mimi_e2ee_boundary(body, &content);
    let plaintext_detected = mimi_plaintext_detected(body) || mimi_plaintext_detected(&content);
    let transcript_binding = mimi_transcript_binding(body, &content).cloned();
    let explicit_downgrade = mimi_explicit_downgrade(body, &content);

    if e2ee_boundary && plaintext_detected && transcript_binding.is_none() && !explicit_downgrade {
        return Err(AppError::param_invalid(
            "MIMI E2EE plaintext requires transcript_binding or explicit e2ee_downgrade marker",
        )
        .with_wire_code("mimi_e2ee_boundary_unmarked"));
    }

    let mut policy = json!({
        "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
        "e2ee_boundary": "none",
        "plaintext_detected": plaintext_detected,
        "plaintext_guard": "not_e2ee",
    });
    if e2ee_boundary && explicit_downgrade {
        let object = content.as_object_mut().expect("content object");
        object.insert(
            "e2ee_downgrade".to_owned(),
            Value::String("mimi_bridge".to_owned()),
        );
        policy = json!({
            "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
            "e2ee_boundary": "explicit_downgrade",
            "plaintext_detected": plaintext_detected,
            "plaintext_guard": "marked_explicit_downgrade",
            "downgrade_marker": "mimi_bridge",
        });
    } else if e2ee_boundary {
        if let Some(binding) = transcript_binding {
            let object = content.as_object_mut().expect("content object");
            object.insert("transcript_binding".to_owned(), binding.clone());
            policy = json!({
                "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
                "e2ee_boundary": "transcript_bound",
                "plaintext_detected": plaintext_detected,
                "plaintext_guard": "transcript_binding",
                "transcript_binding": binding,
            });
        } else {
            policy = json!({
                "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
                "e2ee_boundary": "opaque_ciphertext",
                "plaintext_detected": false,
                "plaintext_guard": "opaque_ciphertext_only",
            });
        }
    }

    if let Some(kind) = content_kind
        .as_deref()
        .filter(|kind| !valid_mimi_content_kind(kind))
    {
        let quarantine_id = ids::generate("mimi_quarantine");
        let quarantine = json!({
            "quarantine_id": quarantine_id,
            "unknown_content_kind": kind,
            "reason": "unknown_mimi_content_kind",
            "raw_payload_hash": arkret_canonical::sha256_digest(content.to_string().as_bytes()),
        });
        let content = json!({
            "kind": "ak.content.text",
            "body": "unsupported content from MIMI",
            "unknown_content_kind": kind,
            "quarantine": quarantine.clone(),
        });
        let mut policy = policy;
        if let Some(object) = policy.as_object_mut() {
            object.insert(
                "content_quarantine".to_owned(),
                Value::String("unknown_mimi_content_kind".to_owned()),
            );
        }
        return Ok(MimiMappedContent {
            content,
            policy,
            quarantine: Some(quarantine),
            status: "quarantined",
        });
    }

    Ok(MimiMappedContent {
        content,
        policy,
        quarantine: None,
        status: "mapped",
    })
}

pub(super) fn mimi_content_payload(body: &Value, source_format: &str) -> Value {
    body.get("content").cloned().unwrap_or_else(|| {
        let text = body
            .get("body")
            .or_else(|| body.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        json!({
            "kind": "ak.content.text",
            "body": text,
            "raw_mimi_source_format": source_format,
        })
    })
}

pub(super) fn mimi_content_kind<'a>(body: &'a Value, content: &'a Value) -> Option<&'a str> {
    body.get("content_kind")
        .or_else(|| body.get("mimi_content_kind"))
        .and_then(Value::as_str)
        .or_else(|| content.get("kind").and_then(Value::as_str))
}

pub(super) fn valid_mimi_content_kind(kind: &str) -> bool {
    matches!(
        kind,
        "m.text"
            | "text/plain"
            | "text/markdown"
            | "m.markdown"
            | arkret_wire::event_kind_str::MESSAGE_REVISE
            | arkret_wire::event_kind_str::MESSAGE_REDACT
            | "ak.content.text"
            | "ak.content.composite"
    )
}

pub(super) fn mimi_e2ee_boundary(body: &Value, content: &Value) -> bool {
    truthy_field(body, "e2ee")
        || truthy_field(body, "encrypted")
        || truthy_field(content, "e2ee")
        || truthy_field(content, "encrypted")
        || encryption_profile_enabled(body.get("encryption_profile"))
        || encryption_profile_enabled(body.get("source_encryption"))
        || encryption_profile_enabled(content.get("encryption_profile"))
        || encryption_profile_enabled(content.get("source_encryption"))
}

pub(super) fn truthy_field(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => matches!(
            value.as_str(),
            "true" | "e2ee" | "encrypted" | "mls" | "mls_rfc9420" | "mimi_mls"
        ),
        _ => false,
    }
}

pub(super) fn encryption_profile_enabled(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|profile| !matches!(profile, "" | "none" | "plaintext" | "unencrypted"))
}

pub(super) fn mimi_transcript_binding<'a>(
    body: &'a Value,
    content: &'a Value,
) -> Option<&'a Value> {
    body.get("transcript_binding")
        .or_else(|| body.get("mls_transcript_binding"))
        .or_else(|| content.get("transcript_binding"))
        .or_else(|| content.get("mls_transcript_binding"))
}

pub(super) fn mimi_explicit_downgrade(body: &Value, content: &Value) -> bool {
    downgrade_marker(body.get("e2ee_downgrade")) || downgrade_marker(content.get("e2ee_downgrade"))
}

pub(super) fn downgrade_marker(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|marker| marker == "mimi_bridge" || marker == "explicit")
}

pub(super) fn mimi_plaintext_detected(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            if matches!(
                key.as_str(),
                "body" | "text" | "plain_text" | "markdown" | "html"
            ) {
                value.as_str().is_some_and(|text| !text.trim().is_empty())
            } else if matches!(
                key.as_str(),
                "ciphertext" | "ciphertext_hash" | "digest" | "hash" | "original_envelope_hash"
            ) {
                false
            } else {
                mimi_plaintext_detected(value)
            }
        }),
        Value::Array(values) => values.iter().any(mimi_plaintext_detected),
        _ => false,
    }
}
