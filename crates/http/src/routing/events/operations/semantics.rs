use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;

use super::*;

type OperationValidator = fn(&Operation) -> Result<(), &'static str>;

pub fn validate_operation_semantics(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        operation
            .validate_payload_object()
            .map_err(|_| "operation payload must be a JSON object")?;
        validate_canonical_json_value(&operation.payload)?;
        let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
            return Err("unregistered operation kind");
        };
        // Call participant cryptography and issuer/focus policy are verified
        // inside the guarded accepting transaction, against durable current.
        // Spec B1.13 / B1.14 — typed payload validators for the
        // new wire-broken shapes. These run BEFORE the per-kind schema
        // check so a removed `target_ref` payload is rejected with the
        // typed-shape reason rather than the generic SDK schema error.
        validate_typed_payload_shapes(&kind, operation)?;
        validate_moderation_report_provenance(state, &kind, operation)?;
        validate_operation_patch_semantics(&kind, operation)?;
        validate_reaction_target_kind(&kind, operation)?;
        validate_operation_payload_schema(&kind, operation)?;
        if kind == arkret_wire::EventKind::KeyBackupActiveSeries {
            validate_key_backup_active_series_structure(operation)?;
        }
    }
    Ok(())
}

fn validate_key_backup_active_series_structure(operation: &Operation) -> Result<(), &'static str> {
    let record = operation
        .typed_payload::<arkret_wire::event_spec::KeyBackupActiveSeries>()
        .map_err(|_| "key_backup_active_series_schema_violation")?;
    // Pointer transitions belong to the exact staged safety Cell during Seal
    // execution. The current live cache is neither the signed basis nor the
    // state after preceding members of this command unit.
    arkret_models_collaboration::events_payloads::validate_key_backup_active_series_record(&record)
        .map_err(|error| error.reason_code())
}

/// strand-and-message.md §9.8.2 — v1 core reactions may only target a
/// `ak:message:`. The reducer may key the OR-Set on a storage Event id, but
/// the signed `target_ref` itself must be the canonical Message object ref;
/// every other typed object kind
/// (`ak:strand:`, `ak:morph:`, `ak:circle:`, …) is rejected fail-closed with
/// active `schema_violation`. The narrower reason is reserved in v1.
/// Profiles MAY register additional target kinds; v1 core does not.
pub(crate) fn validate_reaction_target_kind(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kind,
        arkret_wire::EventKind::ReactionAdd | arkret_wire::EventKind::ReactionRemove
    ) {
        return Ok(());
    }
    let target = match kind {
        arkret_wire::EventKind::ReactionAdd => operation
            .typed_payload::<arkret_wire::event_spec::ReactionAdd>()
            .ok()
            .map(|payload| payload.target_ref.as_str().to_owned()),
        arkret_wire::EventKind::ReactionRemove => operation
            .typed_payload::<arkret_wire::event_spec::ReactionRemove>()
            .ok()
            .map(|payload| payload.target_ref.as_str().to_owned()),
        _ => None,
    };
    let Some(target) = target else {
        // Missing target is caught by REACTION_REQUIREMENTS; treat here as
        // unsupported; the active schema rejection still surfaces.
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    };
    if target.starts_with("ak:message:") {
        Ok(())
    } else {
        Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
    }
}

/// Spec B1.13 / B1.14 / B1.15 — typed payload validators dispatched on the
/// canonical event kind. Hooks the SDK typed payload shapes
/// (SpaceStateTransition / SpaceObjectTombstone / ConsentReplace) into the
/// coland operation admission pipeline.
///
/// For the space lifecycle events the SDK's typed payload requires
/// `space_id`. The validator here HARD-REJECTS the
/// wire-broken `target_ref` form; producers must emit canonical `space_id`.
fn validate_moderation_report_provenance(
    state: &AppState,
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kind != &arkret_wire::EventKind::SelfModerationReport {
        return Ok(());
    }
    let payload = operation
        .typed_payload::<arkret_wire::event_spec::SelfModerationReport>()
        .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    if payload.realm_id != operation.realm_id {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    let mimi = payload.provenance
        == Some(
            arkret_models_collaboration::events_payloads::ModerationReportProvenance::MimiFacade,
        );
    if (mimi && operation.context.sender != arkret_wire::ActorId::service(state.service_core_id()))
        || (!mimi && &payload.reporter_id != operation.context.sender.signing_principal_id())
    {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    match payload.provenance {
        Some(
            arkret_models_collaboration::events_payloads::ModerationReportProvenance::MimiFacade,
        ) if payload.source_provider_id.is_none() => {
            return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
        }
        None
        | Some(
            arkret_models_collaboration::events_payloads::ModerationReportProvenance::SelfAuthored,
        ) if payload.source_provider_id.is_some() => {
            return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
        }
        _ => {}
    }
    // The independent MimiFacade guard authenticates the local Service
    // producer and exact reporter Account at the accepting transaction cut.
    Ok(())
}

fn validate_typed_payload_shapes(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    match kind {
        arkret_wire::EventKind::ConsentReplace => {
            operation
                .typed_payload::<arkret_wire::event_spec::ConsentReplace>()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            Ok(())
        }
        arkret_wire::EventKind::PolicySet => operation
            .typed_payload::<arkret_wire::event_spec::PolicySet>()
            .map(|_| ())
            .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        // ak.space.archive / ak.space.restore use the typed
        // SpaceStateTransitionPayload (space_id, new_state, reason?).
        // The removed top-level `target_ref` form is rejected
        // unconditionally; everything else passes through to the
        // per-kind SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS validator below.
        arkret_wire::EventKind::SpaceArchive | arkret_wire::EventKind::SpaceRestore => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ak.space.archive/restore removed `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // ak.space.tombstone — same removed-field reject rule.
        arkret_wire::EventKind::SpaceTombstone => {
            if operation.payload.get("target_ref").is_some() {
                return Err(
                    "ak.space.tombstone removed `target_ref` form rejected by round-4 wire",
                );
            }
            Ok(())
        }
        // ak.audit.accessed — when `access_kind=e2ee_late_recovery`
        // the payload MUST carry `late_recovery_original_event_id`.
        arkret_wire::EventKind::AuditAccessed => {
            if let Some(access_kind) = operation
                .payload
                .get("access_kind")
                .and_then(|v| v.as_str())
                && access_kind == "e2ee_late_recovery"
                && operation
                    .payload
                    .get("late_recovery_original_event_id")
                    .is_none()
            {
                return Err("ak.audit.accessed access_kind=e2ee_late_recovery requires \
                     late_recovery_original_event_id (round-4 wire break)");
            }
            Ok(())
        }
        arkret_wire::EventKind::RealmMediaService => operation
            .typed_payload::<arkret_wire::event_spec::RealmMediaService>()
            .map(|_| ())
            .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        arkret_wire::EventKind::CallState => {
            let payload = operation
                .typed_payload::<arkret_wire::event_spec::CallState>()
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            payload.validate()?;
            if let Some(binding) = operation
                .payload
                .get("roster_delta")
                .filter(|delta| delta.get("op").and_then(Value::as_str) == Some("join"))
                .and_then(|delta| delta.get("participant"))
                .and_then(|participant| participant.get("participant_binding"))
                && (binding
                    .get("issuer_kid")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                    || binding
                        .get("signature")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty))
            {
                return Err(
                    "participant_binding_invalid: participant_binding issuer_kid and signature are \
                         required",
                );
            }
            Ok(())
        }
        arkret_wire::EventKind::ProfileCreate | arkret_wire::EventKind::ProfileUpdate => Ok(()),
        _ => Ok(()),
    }
}

pub(crate) fn validate_operation_schema_from_sdk_artifact(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    arkret_event_draft::validate_event_payload(kind, &operation.payload)
        .map_err(|_| "operation payload violates its typed SDK contract")?;
    if *kind == arkret_wire::EventKind::SchemaDefine {
        arkret_schema::validate_schema_definition_payload(&operation.payload)
            .map_err(|_| "operation payload violates SDK validator profile")?;
    }
    Ok(())
}

pub(crate) fn validate_operation_payload_schema(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    validate_operation_schema_from_sdk_artifact(kind, operation)?;
    if let Some(validate) = operation_extra_validator_for_kind(kind) {
        validate(operation)?;
    }
    Ok(())
}

pub(crate) fn validate_operation_payload_against_sdk_artifact(
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Err("unregistered operation kind");
    };
    validate_operation_schema_from_sdk_artifact(&kind, operation)
}

fn operation_extra_validator_for_kind(kind: &arkret_wire::EventKind) -> Option<OperationValidator> {
    match kind {
        arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise => {
            Some(validate_message_operation_payload)
        }
        arkret_wire::EventKind::RelationCreate
        | arkret_wire::EventKind::RelationUpdate
        | arkret_wire::EventKind::RelationTombstone => Some(validate_relation_operation_payload),
        arkret_wire::EventKind::ReadCursorAdvance => Some(validate_read_marker_payload),
        arkret_wire::EventKind::AccountDataSet => Some(validate_account_data_set_payload),
        arkret_wire::EventKind::InviteCreate => Some(validate_invite_create_payload),
        arkret_wire::EventKind::InviteCancel | arkret_wire::EventKind::InviteRevoke => {
            Some(validate_invite_ref_payload)
        }
        arkret_wire::EventKind::RealmHistoryAccess
        | arkret_wire::EventKind::CircleHistoryAccess => Some(validate_history_access_payload),
        arkret_wire::EventKind::ScopeReadReceiptPolicy => {
            Some(validate_read_receipt_policy_payload)
        }
        // views.md §3.1 — a shared View Event carrying `visibility="private"`
        // is `schema_violation` / `private_view_requires_account_data`; the
        // retired presentation-local fields are rejected in the same pass.
        arkret_wire::EventKind::ViewCreate
        | arkret_wire::EventKind::ViewUpdate
        | arkret_wire::EventKind::ViewReconcile => Some(validate_view_payload),
        arkret_wire::EventKind::MorphCreate => Some(validate_morph_create_payload),
        arkret_wire::EventKind::MorphUpdate => Some(validate_morph_update_payload),
        arkret_wire::EventKind::DeviceAuthorize => Some(validate_device_authorize_payload),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

    fn operation(kind: impl AsRef<str>, payload: Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(REALM_ID).unwrap(),
            kind.as_ref(),
            payload,
        )
    }

    #[test]
    fn policy_set_typed_payload_enforces_wrapper_subject_identity() {
        // Mirrors event-payload-value-closure-fixture.json
        // `policy_set_generic_policy_id_mismatch_rejected`: the payload is
        // otherwise well formed, so only the subject/value identity rule can
        // reject it.
        let payload = |value_id: &str| {
            serde_json::json!({
                "policy_id": "ak:policy:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f60",
                "value": {
                    "id": value_id,
                    "schema": "ak.schema.policy.v1",
                    "policy_kind": "access",
                    "rules": [{
                        "rule_id": "allow_read",
                        "kind": "action",
                        "effect": "allow",
                        "actions": ["ak.object.read"]
                    }],
                    "default_effect": "deny",
                    "created_by": {
                        "kind": "account",
                        "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixtureauthor",
                            "station_id": "ak:did_core:webvh:z6mkfixturestationexample"
                        }
                    },
                    "created_at": "2026-04-26T00:00:00.000Z"
                }
            })
        };
        let matching = operation(
            arkret_wire::EventKind::PolicySet,
            payload("ak:policy:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f60"),
        );
        assert_eq!(
            validate_typed_payload_shapes(&arkret_wire::EventKind::PolicySet, &matching),
            Ok(())
        );
        let mismatched = operation(
            arkret_wire::EventKind::PolicySet,
            payload("ak:policy:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f61"),
        );
        assert_eq!(
            validate_typed_payload_shapes(&arkret_wire::EventKind::PolicySet, &mismatched),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }
}
