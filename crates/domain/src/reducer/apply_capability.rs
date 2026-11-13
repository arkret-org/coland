//! Agent key authorization projection.
//!
//! Capability Grants are durable `capability_grant` typed current results
//! written and judged by the governing Station's storage; the in-process
//! projection neither holds nor evaluates them.

use super::*;

impl ProjectionState {
    /// Project `ak.agent.key.authorize`: record the authorized key for the
    /// agent. Realm grants are independent from key pairing. Idempotent: a
    /// re-authorization of the same key id converges.
    pub(crate) fn apply_agent_key_authorize(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_authorize_missing_agent_id".to_owned(),
            };
        };
        let Some(key_id) = operation
            .payload
            .get("key_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_authorize_missing_key_id".to_owned(),
            };
        };
        let authorized_event_ref = operation.context.accepted_event_id.to_string();
        let active = self
            .agent_authorized_keys
            .get(&agent_id)
            .cloned()
            .unwrap_or_default();
        let supersedes = match operation.payload.get("supersedes") {
            None => Vec::new(),
            Some(Value::Array(values)) => {
                let mut parsed = Vec::with_capacity(values.len());
                for value in values {
                    let Some(key_id) = value.get("key_id").and_then(Value::as_str) else {
                        return ProjectionEffect::Rejected {
                            reason: "agent_key_supersedes_invalid".to_owned(),
                        };
                    };
                    let Some(event_ref) = value.get("authorized_event_ref").and_then(Value::as_str)
                    else {
                        return ProjectionEffect::Rejected {
                            reason: "agent_key_supersedes_invalid".to_owned(),
                        };
                    };
                    parsed.push((key_id.to_owned(), event_ref.to_owned()));
                }
                parsed
            }
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: "agent_key_supersedes_invalid".to_owned(),
                };
            }
        };
        let pairing_replacement = operation
            .payload
            .get("approval_evidence")
            .and_then(|evidence| evidence.get("kind"))
            .and_then(Value::as_str)
            == Some("pairing_request")
            && !active.is_empty();
        let replacing_other_keys = active.keys().any(|active_key| active_key != &key_id);
        if pairing_replacement {
            let expected: std::collections::BTreeSet<_> = active
                .iter()
                .map(|(active_key, event_ref)| (active_key.clone(), event_ref.clone()))
                .collect();
            let supplied: std::collections::BTreeSet<_> = supersedes.iter().cloned().collect();
            if supplied.len() != supersedes.len() || supplied != expected {
                return ProjectionEffect::Rejected {
                    reason: "agent_key_supersedes_state_mismatch".to_owned(),
                };
            }
        } else if replacing_other_keys {
            let expected: std::collections::BTreeSet<_> = active
                .iter()
                .filter(|(active_key, _)| *active_key != &key_id)
                .map(|(active_key, event_ref)| (active_key.clone(), event_ref.clone()))
                .collect();
            let supplied: std::collections::BTreeSet<_> = supersedes.iter().cloned().collect();
            if supplied.len() != supersedes.len() || supplied != expected {
                return ProjectionEffect::Rejected {
                    reason: "agent_key_supersedes_state_mismatch".to_owned(),
                };
            }
        } else if !supersedes.is_empty() {
            return ProjectionEffect::Rejected {
                reason: "agent_key_supersedes_state_mismatch".to_owned(),
            };
        }
        let active = self
            .agent_authorized_keys
            .entry(agent_id.clone())
            .or_default();
        for (superseded_key, _) in supersedes {
            active.remove(&superseded_key);
        }
        active.insert(key_id.clone(), authorized_event_ref);
        ProjectionEffect::AgentKeyAuthorizeProjected { agent_id, key_id }
    }

    /// AKP-0008 §4.11 — project `ak.agent.key.revoke`: remove the key from
    /// the agent's authorized-key set (idempotent).
    pub(crate) fn apply_agent_key_revoke(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_revoke_missing_agent_id".to_owned(),
            };
        };
        let Some(key_id) = operation
            .payload
            .get("key_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_revoke_missing_key_id".to_owned(),
            };
        };
        if let Some(keys) = self.agent_authorized_keys.get_mut(&agent_id) {
            keys.remove(&key_id);
            if keys.is_empty() {
                self.agent_authorized_keys.remove(&agent_id);
            }
        }
        ProjectionEffect::AgentKeyRevokeProjected { agent_id, key_id }
    }

    pub fn active_agent_key_authorizations(&self, agent_id: &str) -> Vec<(String, String)> {
        self.agent_authorized_keys
            .get(agent_id)
            .map(|keys| {
                keys.iter()
                    .map(|(key_id, event_ref)| (key_id.clone(), event_ref.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// True when the agent principal has at least one accepted, non-revoked
    /// agent key authorization.
    pub fn agent_has_authorized_key(&self, agent_id: &str) -> bool {
        self.agent_authorized_keys
            .get(agent_id)
            .map(|keys| !keys.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests;
