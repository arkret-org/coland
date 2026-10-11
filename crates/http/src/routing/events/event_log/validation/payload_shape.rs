use super::super::*;

// Wire-shape validators applied on the event ingest path.
//
// Each maps a [`coland_http::wire_validators::WireRejection`] to a
// `schema_violation`-class [`EventValidationError`] carrying the precise
// reason code.

/// Forbidden-wire-fields registry entry `sidecar_exchange_binding`
/// (spec/v1/artifacts/registry/forbidden-wire-fields.json, zh/models/sidecar.md
/// §7.2.1): the Agent Sidecar exchange binding, exchange control plaintext,
/// and `exchange_id` are legal only inside MLS-encrypted payload/metadata of
/// Sidecar-backing-Circle-scoped events. Any plaintext occurrence on the
/// submitted wire — the key `sidecar_exchange_binding`, the key `exchange_id`,
/// or a string value equal to one of the two Sidecar schema ids — is a
/// hard-reject `schema_violation`. `ak.agent.sidecar.exchange.control` needs
/// no exemption: its outer payload carries only `strand_id` plus an
/// `encrypted_payload` envelope whose ciphertext is an opaque string, so
/// conforming producers never trip this structural scan.
///
/// The machine-readable key (`sidecar_exchange_binding`) is queried from the
/// SDK projection of the registry; `exchange_id` and the two schema-id string
/// values exist only in the entry's prose notes, so they stay spelled out
/// here until the registry projects them.
const SIDECAR_FORBIDDEN_WIRE_CONTEXT: &str = "plaintext_metadata_or_shared_scope_payload";

const SIDECAR_FORBIDDEN_WIRE_STRING_VALUES: &[&str] = &[
    arkret_wire::SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1,
    arkret_wire::SchemaId::AGENT_SIDECAR_EXCHANGE_CONTROL_V1,
];

fn scan_sidecar_forbidden_wire_fields(value: &Value) -> Result<(), EventValidationError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject(
                    SIDECAR_FORBIDDEN_WIRE_CONTEXT,
                    key,
                ) || key == "exchange_id"
                {
                    return Err(sidecar_forbidden_wire_field_error(key));
                }
                scan_sidecar_forbidden_wire_fields(nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for nested in values {
                scan_sidecar_forbidden_wire_fields(nested)?;
            }
            Ok(())
        }
        Value::String(text) => {
            if SIDECAR_FORBIDDEN_WIRE_STRING_VALUES.contains(&text.as_str()) {
                return Err(sidecar_forbidden_wire_field_error(text));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn sidecar_forbidden_wire_field_error(token: &str) -> EventValidationError {
    event_validation_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
        format!(
            "`{token}` is Sidecar-exchange material and must not appear in plaintext event payloads \
             (forbidden-wire-fields sidecar_exchange_binding)"
        ),
    )
}

pub(super) fn validate_pre_schema_wire_shape(
    kind: &str,
    payload: &Value,
) -> Result<(), EventValidationError> {
    scan_sidecar_forbidden_wire_fields(payload)?;
    reject_carried_event_derived_object_id(kind, payload)?;
    if kind == arkret_wire::event_kind_str::MEMBER_IDENTITY_UPDATE {
        coland_http::wire_validators::member_identity::validate_member_identity_update_payload(
            payload,
        )
        .map_err(wire_rejection_to_validation_error)?;
    }
    Ok(())
}

fn reject_carried_event_derived_object_id(
    event_kind: &str,
    payload: &Value,
) -> Result<(), EventValidationError> {
    let derived_id_kinds = arkret_schema::event_derived_id_kinds_for_kind(event_kind);
    if derived_id_kinds.is_empty() {
        return Ok(());
    }
    let forbidden: Vec<(String, String)> = derived_id_kinds
        .into_iter()
        .map(|id_kind| (format!("{id_kind}_id"), format!("ak:{id_kind}:")))
        .collect();

    fn carried_id(
        object: &serde_json::Map<String, Value>,
        forbidden: &[(String, String)],
    ) -> Option<String> {
        object.iter().find_map(|(key, value)| {
            value.as_str().and_then(|text| {
                forbidden
                    .iter()
                    .any(|(field, prefix)| {
                        (key == field || key == "id") && text.starts_with(prefix)
                    })
                    .then(|| key.clone())
            })
        })
    }

    // A create object is either the payload itself or one direct closed-object
    // wrapper such as `object` / `grant`. References nested inside that object
    // may legitimately use the same typed id (for example
    // `issuer_authority_refs[].grant_id`) and are not identities for the
    // object being created.
    let carried_field = payload.as_object().and_then(|payload| {
        carried_id(payload, &forbidden).or_else(|| {
            payload
                .values()
                .filter_map(Value::as_object)
                .find_map(|object| carried_id(object, &forbidden))
        })
    });

    if let Some(field) = carried_field {
        let mut error = event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            format!(
                "{field} must be omitted for {event_kind}; the object id is derived from the create Event"
            ),
        );
        error.reason_code = Some(arkret_wire::ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED);
        return Err(error);
    }
    Ok(())
}

fn wire_rejection_to_validation_error(
    rejection: coland_http::wire_validators::WireRejection,
) -> EventValidationError {
    event_validation_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        rejection.message,
    )
}

pub(super) fn validate_space_container_lifecycle_payload(
    payload: &Value,
) -> Result<(), EventValidationError> {
    let Some(object) = payload.as_object() else {
        return Err(event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "space lifecycle payload must be an object",
        ));
    };
    let target = object
        .get("space_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "space lifecycle payload requires space_id",
            )
        })?;
    if validate_space_id(target).is_err() {
        return Err(event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "space lifecycle payload space_id must use ak:space:",
        ));
    }
    if object.get("target_ref").is_some() {
        return Err(event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "space lifecycle payload must use space_id, not target_ref",
        ));
    }
    Ok(())
}

pub(super) fn validate_event_audience_fields(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), EventValidationError> {
    if let Some(audience) = event_string_field(object, &["audience"])
        && audience != *state.service_id()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "audience_mismatch",
            "event audience must bind to this service DID",
        ));
    }
    if let Some(domain) = event_string_field(object, &["domain"])
        && domain != *state.service_id()
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "event domain must bind to this service DID",
        ));
    }
    if let Some(device_id) = event_string_field(object, &["device_id"])
        && device_id.as_str() != session.require_human_device_id()
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "event device_id must match the bearer session device",
        ));
    }
    Ok(())
}

mod tests {
    use super::*;

    #[test]
    fn plaintext_sidecar_exchange_binding_key_is_rejected_pre_schema() {
        let payload = json!({
            "message_id": "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "content": {"kind": "ak.content.text", "body": "hello"},
            "metadata": {
                "sidecar_exchange_binding": {
                    "role": "request"
                }
            }
        });
        let error = validate_pre_schema_wire_shape(
            arkret_wire::EventKind::MessageCreate.as_str(),
            &payload,
        )
        .expect_err("plaintext metadata must not carry the exchange binding");
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.code, "schema_violation");
    }

    #[test]
    fn plaintext_exchange_id_field_is_rejected_pre_schema() {
        let payload = json!({
            "message_id": "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "content": {"kind": "ak.content.text", "body": "hello"},
            "refs": [{"role": "after", "exchange_id": "018f-abc"}]
        });
        let error = validate_pre_schema_wire_shape(
            arkret_wire::EventKind::MessageCreate.as_str(),
            &payload,
        )
        .expect_err("plaintext exchange_id must be rejected in any nested position");
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.code, "schema_violation");
    }

    #[test]
    fn plaintext_sidecar_schema_id_values_are_rejected_pre_schema() {
        for schema_id in [
            "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "ak.schema.agent_sidecar_exchange_control.v1",
        ] {
            let payload = json!({
                "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "metadata": {"fields": {"schema": schema_id}}
            });
            let error = validate_pre_schema_wire_shape(
                arkret_wire::EventKind::MessageCreate.as_str(),
                &payload,
            )
            .expect_err("Sidecar schema ids must never appear as plaintext wire values");
            assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(error.code, "schema_violation");
        }
    }

    #[test]
    fn ordinary_message_and_exchange_control_outer_payload_pass_the_sidecar_scan() {
        let message = json!({
            "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "content": {"kind": "ak.content.text", "body": "hello"},
            "metadata": {"fields": {"jira_status": "open"}}
        });
        validate_pre_schema_wire_shape(arkret_wire::EventKind::MessageCreate.as_str(), &message)
            .expect("ordinary messages are unaffected by the sidecar forbidden-wire scan");

        // The exchange control Event's outer payload is only strand_id plus an
        // opaque encrypted envelope; the structural scan must not reject it.
        let control = json!({
            "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "encrypted_payload": {
                "ciphertext": "b3BhcXVlLW1scy1jaXBoZXJ0ZXh0",
                "content_type": "application/vnd.arkret.mls-ciphertext"
            }
        });
        validate_pre_schema_wire_shape(
            arkret_wire::EventKind::AgentSidecarExchangeControl.as_str(),
            &control,
        )
        .expect("conforming exchange control outer payloads carry no plaintext exchange material");
    }

    #[test]
    fn registry_declared_create_rejects_carried_object_id_with_stable_reason() {
        for (kind, payload) in [
            (
                "ak.circle.create",
                json!({"object": {"id": "ak:circle:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"}}),
            ),
            (
                "ak.message.create",
                json!({"message_id": "ak:message:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"}),
            ),
            (
                "ak.self.moderation.report",
                json!({"moderation_queue_item_id": "ak:moderation_queue_item:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"}),
            ),
        ] {
            let error = validate_pre_schema_wire_shape(kind, &payload)
                .expect_err("a create payload cannot carry its derived object id");
            assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(error.code, "schema_violation");
            assert_eq!(
                error.reason_code,
                Some(arkret_wire::ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED)
            );
        }
    }

    #[test]
    fn non_create_reference_to_an_event_derived_id_is_not_rejected() {
        validate_pre_schema_wire_shape(
            "ak.message.update",
            &json!({
                "message_id": "ak:message:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
            }),
        )
        .expect("only registry-declared create ids are producer-forbidden");
    }

    #[test]
    fn capability_create_allows_nested_parent_grant_reference() {
        validate_pre_schema_wire_shape(
            "ak.capability.grant",
            &json!({
                "grant": {
                    "issuer_authority_refs": [{
                        "kind": "grant",
                        "grant_id": "ak:grant:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
                    }]
                }
            }),
        )
        .expect("a parent grant reference is not the id of the grant being created");

        let error = validate_pre_schema_wire_shape(
            "ak.capability.grant",
            &json!({
                "grant": {
                    "id": "ak:grant:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
                }
            }),
        )
        .expect_err("the newly created grant cannot carry its own id");
        assert_eq!(
            error.reason_code,
            Some(arkret_wire::ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED)
        );
    }
}
