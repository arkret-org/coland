// ════════════════════════════════════════════════════════════════════════
// Active Event admission lifecycle and policy gates.
// ════════════════════════════════════════════════════════════════════════
use super::*;

/// Reject any non-audit-class write on a Realm whose lifecycle state is
/// terminal (`ak.realm.tombstone` or `ak.realm.destroy` applied). Spec T07.
///
/// Returns `Some((ErrorCode::FailedPrecondition, reason))` when the write
/// MUST be rejected; `None` otherwise.
pub fn terminal_realm_check(
    realm_in_terminal_state: bool,
    kind: &str,
) -> Option<(ErrorCode, &'static str)> {
    if realm_in_terminal_state
        && !kind
            .parse::<arkret_wire::EventKind>()
            .is_ok_and(|kind| arkret_wire::events::kinds::is_audit_kind(&kind))
    {
        return Some((
            ErrorCode::FailedPrecondition,
            "Realm has reached ak.realm.tombstone or ak.realm.destroy \
             terminal state; only audit-class events are accepted",
        ));
    }
    None
}

/// Reject ordinary writes on a Realm with the reversible `ak.realm.freeze`
/// facet set. Lifecycle/admin escape hatches remain admissible so an
/// authorized actor can unfreeze, tombstone, or destroy the Realm.
pub fn frozen_realm_check(realm_frozen: bool, kind: &str, payload: &Value) -> Option<&'static str> {
    if realm_frozen
        && !kind
            .parse::<arkret_wire::EventKind>()
            .is_ok_and(|kind| arkret_wire::events::kinds::realm_write_gate_exempt(&kind, payload))
    {
        return Some("Realm is archived or frozen; ordinary writes are not accepted");
    }
    None
}

/// Validate a `ak.realm.policy_bundle` payload against the current media
/// plaintext authorization dependency.
///
/// When `media_service_decryption_allowed=true`, the service must be explicitly
/// authorized for the `media_plaintext` data class.
pub fn realm_policy_bundle_check(
    payload: &Value,
    media_plaintext_service_present: bool,
) -> Result<(), (ErrorCode, String)> {
    if let Some(join_policy) = payload.get("join_policy") {
        coland_services::operation_semantics::validate_join_policy_payload(join_policy).map_err(
            |reason| {
                (
                    ErrorCode::SchemaViolation,
                    format!("ak.realm.policy_bundle payload path join_policy invalid: {reason}"),
                )
            },
        )?;
    }

    // Media plaintext access requires a separately accepted service binding.
    if payload
        .get("media_service_decryption_allowed")
        .and_then(Value::as_bool)
        == Some(true)
        && !media_plaintext_service_present
    {
        return Err((
            ErrorCode::FailedPrecondition,
            "media_service_decryption_allowed=true requires the SFU/MCU service DID \
             to be listed in plaintext_visible_services[] with \
             data_classes[] containing media_plaintext"
                .to_owned(),
        ));
    }
    Ok(())
}
