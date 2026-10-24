use super::*;

const DID_INCEPTION_REF_ROLE: &str = "did_inception";

const DID_RECOVERY_ANCHOR_REF_ROLE: &str = "did_recovery_anchor";

pub(super) fn principal_control_genesis_shape(
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
) -> bool {
    object.get("kind").and_then(Value::as_str) == Some(arkret_wire::EventKind::RealmCreate.as_str())
        && object
            .get("payload")
            .and_then(|payload| payload.pointer("/object/purpose"))
            .and_then(Value::as_str)
            == Some("principal_control")
        && object
            .get("actor_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
            .is_some_and(|actor| actor.signing_principal_id().as_str() == actor_id)
}

fn anchor_refs(object: &serde_json::Map<String, Value>) -> Vec<(&str, &str, bool)> {
    object
        .get("semantic_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| {
            let role = reference.get("role")?.as_str()?;
            matches!(role, DID_INCEPTION_REF_ROLE | DID_RECOVERY_ANCHOR_REF_ROLE).then(|| {
                (
                    role,
                    reference
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    reference
                        .get("critical")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                )
            })
        })
        .collect()
}

pub(super) async fn resolve_event_root_anchor_method(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
) -> Result<Option<String>, EventValidationError> {
    let actor_core_id = arkret_wire::DidCoreId::new(actor_id.to_owned()).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            format!("root-anchored Event actor_id must be a core id: {error}"),
        )
    })?;
    let refs = anchor_refs(object);
    if refs.is_empty() {
        return Ok(None);
    }
    if refs.len() != 1 || !refs[0].2 {
        return Err(event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "root-anchored Event requires exactly one critical DID anchor reference",
        ));
    }

    let (role, anchor_id, _) = refs[0];
    if role != DID_INCEPTION_REF_ROLE || !principal_control_genesis_shape(object, actor_id) {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "failed_precondition",
            "identity-root Event proof is restricted to the Account's PCR genesis",
        ));
    }
    let principal_did = principal_control_genesis_resolution_did(object, &actor_core_id)?;
    let records = state
        .dids()
        .log_events(principal_did.as_str())
        .await
        .map_err(|error| {
            event_validation_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                format!("original DID inception is unavailable: {error}"),
            )
        })?;
    let mut entries = records.iter().filter(|entry| entry.sequence == 1);
    let entry = entries.next().ok_or_else(|| {
        event_validation_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "original DID inception is missing",
        )
    })?;
    if entries.next().is_some()
        || entry.operation.get("versionId").and_then(Value::as_str) != Some(anchor_id)
    {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "signature_invalid",
            "critical inception reference does not select the unique original DID entry",
        ));
    }
    let operation: std::collections::BTreeMap<String, Value> =
        serde_json::from_value(entry.operation.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                error.to_string(),
            )
        })?;
    let normalized_did_document = operation
        .get("state")
        .cloned()
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "DID inception omits its normalized state",
            )
        })
        .and_then(|state| {
            serde_json::from_value(state).map_err(|error| {
                event_validation_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "schema_violation",
                    error.to_string(),
                )
            })
        })?;
    let anchor = arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
        registration_did_operation: Box::new(
            arkret_models_identity::DidOperationSubmitRequestBody {
                did: principal_did,
                did_method: arkret_models_identity::DidMethodName::Webvh,
                sequence: Some(1),
                previous_event_digest: None,
                operation: operation.clone(),
            },
        ),
        log_entries: vec![operation],
        witness_records: Vec::new(),
        normalized_did_document,
    };
    let root =
        arkret_identity::validate_principal_registration_anchor(&anchor).map_err(|error| {
            event_validation_error(
                StatusCode::UNAUTHORIZED,
                "signature_invalid",
                error.to_string(),
            )
        })?;
    if root.principal_id != actor_core_id {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "signature_invalid",
            "verified inception root does not bind the Event Account",
        ));
    }
    Ok(Some(root.root_verification_method.to_string()))
}

fn principal_control_genesis_resolution_did(
    object: &serde_json::Map<String, Value>,
    actor_core_id: &arkret_wire::DidCoreId,
) -> Result<arkret_wire::Did, EventValidationError> {
    let did = object
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("object"))
        .and_then(Value::as_object)
        .and_then(|payload_object| payload_object.get("initial_resolution"))
        .and_then(Value::as_object)
        .and_then(|resolution| resolution.get("did"))
        .and_then(Value::as_str)
        .and_then(|value| arkret_wire::Did::new(value.to_owned()).ok())
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "principal-control genesis must carry a valid initial_resolution.did",
            )
        })?;
    if !arkret_wire::project_did_to_core_id(&did).is_ok_and(|core_id| core_id == *actor_core_id) {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "signature_invalid",
            "principal-control genesis initial_resolution.did must project to actor_id",
        ));
    }
    Ok(did)
}

mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn principal_control_genesis_resolves_did_from_initial_resolution() {
        let did = arkret_wire::Did::new("did:webvh:zQ3shExampleScid:alice.example:webvh:user")
            .expect("DID");
        let actor_id = arkret_wire::project_did_to_core_id(&did).expect("core id");
        let event = json!({
            "payload": {
                "object": {
                    "initial_resolution": {
                        "did": did,
                        "method_history_head": "sha256:fixture",
                        "version_id": "version-1"
                    }
                }
            },
            "producer_proof": {
                "verification_method": "did:key:z6MkruntimeExample#z6MkruntimeExample"
            }
        })
        .as_object()
        .expect("event object")
        .clone();

        let resolved =
            principal_control_genesis_resolution_did(&event, &actor_id).expect("resolution DID");

        assert_eq!(resolved.as_str(), did.as_str());
    }
}
