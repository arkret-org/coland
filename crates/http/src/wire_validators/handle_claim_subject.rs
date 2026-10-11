//! Handle-claim subject validation.
//!
//! The claim `subject_id` MUST be a holder/principal `DidCoreId`, not a
//! server-local `account_id` (`ak:account:`), a DID, or a generic
//!   resource id. We delegate to the SDK `validate_handle_claim_subject` so coland / coauth /
//!   cotest agree on the exact rejection surface.

use serde_json::Value;

use super::WireRejection;

/// Reject a non-principal-core `subject_id`. Delegates to the SDK
/// `validate_handle_claim_subject` (the authoritative rejection rule).
pub fn validate_subject(claim: &Value) -> Result<(), WireRejection> {
    let Some(subject) = claim.get("subject_id").and_then(Value::as_str) else {
        // `subject_id` is optional on the carrier; absence is not a subject
        // violation (other schema layers enforce presence where required).
        return Ok(());
    };
    let principal_id = arkret_identifiers::DidCoreId::new(subject.to_owned()).map_err(|_| {
        WireRejection::new(format!(
            "handle claim subject must be a holder/principal core id ({subject})"
        ))
    })?;
    arkret_models_identity::handle::validate_handle_claim_subject(&principal_id)
        .map_err(|err| WireRejection::new(err.to_string()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_principal_core_subject() {
        let claim = json!({
            "subject_id": "ak:did_core:web:alice-principal.example",
        });
        assert!(validate_subject(&claim).is_ok());
    }

    #[test]
    fn rejects_non_core_typed_subject() {
        let claim = json!({
            "claim_kind": "handle_binding",
            "subject_id": "ak:member:01904100-0000-7000-8000-000000000001"
        });
        assert!(validate_subject(&claim).is_err());
    }

    #[test]
    fn rejects_account_id_subject() {
        let claim = json!({"subject_id": "ak:account:01904100-0000-7000-8000-000000000001"});
        assert!(validate_subject(&claim).is_err());
    }

    #[test]
    fn rejects_non_did_subject() {
        let claim = json!({"subject_id": "alice:acme.example"});
        assert!(validate_subject(&claim).is_err());
    }
}
