use super::*;

fn valid_history_access(value: &str) -> bool {
    matches!(value, "since_join" | "all_history_for_current_members")
}

fn valid_ratchet(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("all_history_for_current_members", "since_join") | ("since_join", "since_join")
    )
}

impl ProjectionState {
    pub(crate) fn apply_realm_history_access(&mut self, operation: &Operation) -> ProjectionEffect {
        let from = operation.payload.get("from").and_then(Value::as_str);
        let Some(to) = operation.payload.get("to").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        if !valid_history_access(to) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }

        let realm_id = operation.realm_id.to_string();
        let key = FacetRef::singleton(facet::REALM_HISTORY_ACCESS);
        let current = self.facet_value(&realm_id, &key).and_then(Value::as_str);
        match current {
            None if from.is_none() => {}
            None => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
                };
            }
            Some(current) => {
                if from != Some(current) {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
                    };
                }
                if !valid_ratchet(current, to) {
                    return ProjectionEffect::Rejected {
                        reason: "history_access_widening_forbidden".to_owned(),
                    };
                }
            }
        }
        if (self.realm_is_direct_conversation(&realm_id)
            || self.realm_is_principal_control(&realm_id))
            && to != "since_join"
        {
            return ProjectionEffect::Rejected {
                reason: "history_access_profile_fixed".to_owned(),
            };
        }

        self.set_facet(&realm_id, key, Value::String(to.to_owned()));
        ProjectionEffect::RealmBootstrapFacetProjected {
            realm_id,
            kind: arkret_wire::EventKind::RealmHistoryAccess
                .as_str()
                .to_owned(),
        }
    }

}
