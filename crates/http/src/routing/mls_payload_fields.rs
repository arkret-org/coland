//! Canonical MLS field readers. Scope and transition epochs come from the sole governance binding.

use serde_json::Value;

#[cfg(test)]
pub(crate) fn mls_group_id(payload: &Value) -> Option<String> {
    let scope = group_state_effective_scope(payload)?;
    serde_json::from_value::<arkret_wire::ScopeRef>(scope)
        .ok()?
        .canonical_mls_group_id()
        .ok()
        .map(|group_id| group_id.as_str().to_owned())
}

/// The `mls_governance_binding` object all three MLS payloads require under
/// the name `governance_binding`.
pub(crate) fn governance_binding(value: &Value) -> Option<&Value> {
    value.get("governance_binding")
}

#[cfg(test)]
pub(crate) fn commit_base_epoch(payload: &Value) -> Option<u64> {
    arkret_canonical::serde_helpers::parse_uint64_decimal_value(
        governance_binding(payload)?.get("previous_epoch")?,
    )
}

#[cfg(test)]
pub(crate) fn group_state_effective_scope(payload: &Value) -> Option<Value> {
    governance_binding(payload)?.get("effective_scope").cloned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn transition_fields_come_only_from_the_binding() {
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let payload = json!({"governance_binding": {
            "effective_scope": {"kind":"realm", "realm_id":realm}, "previous_epoch":"7"
        }});
        let scope = serde_json::from_value::<arkret_wire::ScopeRef>(
            payload["governance_binding"]["effective_scope"].clone(),
        )
        .unwrap();
        assert_eq!(
            mls_group_id(&payload),
            Some(scope.canonical_mls_group_id().unwrap().as_str().to_owned())
        );
        assert_eq!(commit_base_epoch(&payload), Some(7));
        assert!(mls_group_id(&json!({"mls_group_id":"legacy"})).is_none());
        assert!(commit_base_epoch(&json!({"base_epoch":7})).is_none());
    }
}
