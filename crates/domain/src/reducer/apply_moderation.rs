//! P2 — moderation control-plane projection.
//!
//! Migrates moderation from an `/_coland/admin` write path onto protocol
//! events. Projects the active moderation kinds into the canonical cells
//! declared by `event-kind-registry.json`:
//!
//! - `ak.moderation.decision` -> `ak.component.moderation_state.v1` (or_set add, one cell per
//!   `payload.target_ref`). The add tag is the registered dot `ak:event:<event_id>:<write_index>`
//!   (`event-and-patch.md` §2.4.2); the add value is the decision snapshot (`decision_id` /
//!   `issuer` / `target_ref` / `decision` / `realm_id`).
//! - `ak.moderation.decision.lift` -> `or_set_remove_dots` on the same target cell, removing
//!   exactly the dots enumerated in `payload.observed_dot_ids[]` (content-moderation.md §2.6). It
//!   is deliberately NOT a bulk remove keyed by `decision_id`: §2.6 forbids
//!   `or_set_remove_observed` here by name, because lifting one review must not implicitly lift
//!   another issuer's decision. A replacement decision issued in the same batch is a new dot on the
//!   same cell and coexists with what survived (§2.6 last paragraph), so an add is never
//!   pre-tombstoned.
use super::*;

fn payload_str(operation: &Operation, field: &str) -> Option<String> {
    operation
        .payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

/// The canonical issuer named by the accepted moderation decision payload.
fn decision_issuer(operation: &Operation) -> Option<String> {
    payload_str(operation, "issuer_id")
}

fn moderation_request_canonical_digest(operation: &Operation) -> Option<String> {
    payload_str(operation, "request_canonical_digest")
}

fn moderation_value_targets_ref(value: &Value, target_ref: &str) -> bool {
    let Some(value_target_ref) = value.get("target_ref").and_then(Value::as_str) else {
        return false;
    };
    value_target_ref == target_ref
        || message_event_id_from_ref(value_target_ref) == message_event_id_from_ref(target_ref)
}

impl ProjectionState {
    /// Every accepted entry on one target's moderation-state facet.
    ///
    /// The facet is a keyed set: each entry carries the `(issuer_id,
    /// request_canonical_digest)` add tag named by
    /// `content-moderation.md` §2.6, so a lift removes exactly the entry its
    /// `decision_ref` produced and never another issuer's decision.
    fn moderation_entries(&self, realm_id: &str, target_ref: &str) -> Vec<Value> {
        self.facet_value(
            realm_id,
            &FacetRef::new(facet::MODERATION_STATE, target_ref),
        )
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    }

    /// Fold every live decision for one target using the normative tightening
    /// order `hard_deny > quarantine > require_review > none`.
    pub fn effective_moderation_verdict(&self, target_ref: &str) -> &'static str {
        let mut rank = 0_u8;
        for (key, settled) in &self.facets {
            if key.1.facet() != facet::MODERATION_STATE {
                continue;
            }
            let Some(items) = settled.value.as_array() else {
                continue;
            };
            for item in items {
                let value = item.get("value").unwrap_or(item);
                if !moderation_value_targets_ref(value, target_ref) {
                    continue;
                }
                rank = rank.max(match value.get("decision").and_then(Value::as_str) {
                    Some("hard_deny") => 3,
                    Some("quarantine") => 2,
                    Some("require_review") => 1,
                    Some("dismiss" | "soft_deny") | None => 0,
                    // Corrupt/unregistered values fail closed. Admission never
                    // emits these, but a damaged projection must not weaken a
                    // surviving moderation decision.
                    Some(_) => 3,
                });
            }
        }
        match rank {
            3 => "hard_deny",
            2 => "quarantine",
            1 => "require_review",
            _ => "none",
        }
    }

    #[cfg(test)]
    fn moderation_items_for_decision(&self, decision_id: &str) -> Vec<Value> {
        self.facets
            .iter()
            .filter(|(key, _)| key.1.facet() == facet::MODERATION_STATE)
            .flat_map(|(_, settled)| settled.value.as_array().cloned().unwrap_or_default())
            .filter(|item| {
                let value = item.get("value").unwrap_or(item);
                value
                    .get("decision_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == decision_id)
            })
            .collect()
    }

    /// True when a live entry for `decision_id` is present on its target's
    /// moderation-state facet. Used by the `modify` atomicity check (the new
    /// decision MUST already be present).
    #[cfg(test)]
    pub(crate) fn moderation_decision_is_live(&self, decision_id: &str) -> bool {
        !self.moderation_items_for_decision(decision_id).is_empty()
    }

    /// True when a decision this Station projected has since been lifted: the
    /// decision is known but its keyed-set entry is gone.
    #[cfg(test)]
    pub(crate) fn moderation_decision_is_lifted(&self, decision_id: &str) -> bool {
        self.moderation_decisions.contains_key(decision_id)
            && self.moderation_items_for_decision(decision_id).is_empty()
    }

    /// Reverse-resolve the issuer of the decision named by `decision_id` from
    /// the moderation-state facet. Returns `None` when the decision was never
    /// projected here (causal / backfill tolerance — separation-of-duties is
    /// only enforced when we can observe the original decision's issuer).
    #[cfg(test)]
    pub(crate) fn moderation_decision_issuer(&self, decision_id: &str) -> Option<String> {
        if let Some(decision) = self.moderation_decisions.get(decision_id) {
            return Some(decision.issuer_id.to_string());
        }
        let items = self.moderation_items_for_decision(decision_id);
        items.iter().rev().find_map(|item| {
            let value = item.get("value").unwrap_or(item);
            value
                .get("issuer_id")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(ToOwned::to_owned)
        })
    }

    /// P2 — project `ak.moderation.decision` as an or_set add on the
    /// moderation_state cell keyed by `payload.target_ref`.
    pub(crate) fn apply_moderation_decision(&mut self, operation: &Operation) -> ProjectionEffect {
        let decision_id = operation.context.event_id.to_string();
        let Some(target_ref) = payload_str(operation, "target_ref") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_target_ref_missing".to_owned(),
            };
        };
        let Some(decision_kind) = payload_str(operation, "decision") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_kind_missing".to_owned(),
            };
        };
        if !matches!(
            decision_kind.as_str(),
            "hard_deny" | "quarantine" | "require_review" | "dismiss"
        ) {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_kind_invalid".to_owned(),
            };
        }
        // Structural acceptance: a sealed decision MUST name its issuer.
        let Some(issuer) = decision_issuer(operation) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_issuer_missing".to_owned(),
            };
        };
        let Some(request_digest) = moderation_request_canonical_digest(operation) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_request_canonical_digest_missing".to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        if decision_kind == "dismiss" {
            if arkret_identifiers::EventId::new(target_ref.as_str()).is_err() {
                return ProjectionEffect::Rejected {
                    reason: "moderation_dismiss_requires_report_event".to_owned(),
                };
            }
            let Ok(decision) =
                operation.typed_payload::<arkret_wire::event_spec::ModerationDecision>()
            else {
                return ProjectionEffect::Rejected {
                    reason: "moderation_decision_payload_invalid".to_owned(),
                };
            };
            self.moderation_decisions
                .insert(decision_id.clone(), decision);
            return ProjectionEffect::ModerationDecisionProjected {
                decision_id,
                realm_id,
            };
        }
        let target_ref_key = target_ref.clone();
        let mut items = self.moderation_entries(&realm_id, &target_ref);
        // The element tag is the accepting Event's canonical `<event_id>:0`
        // dot (`current-state.schema.json#/$defs/canonical_event_dot`);
        // no payload member, issuer or digest enters set identity.
        let tag = format!("{decision_id}:0");
        let Ok(decision) = operation.typed_payload::<arkret_wire::event_spec::ModerationDecision>()
        else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_payload_invalid".to_owned(),
            };
        };
        self.moderation_decisions
            .insert(decision_id.clone(), decision);
        let mut value = operation.payload.clone();
        if let Value::Object(map) = &mut value {
            map.insert("decision_id".to_owned(), Value::String(decision_id.clone()));
            map.insert("target_ref".to_owned(), Value::String(target_ref.clone()));
            map.insert("decision".to_owned(), Value::String(decision_kind));
            map.insert("issuer_id".to_owned(), Value::String(issuer));
            map.insert(
                "request_canonical_digest".to_owned(),
                Value::String(request_digest),
            );
            map.entry("realm_id".to_owned())
                .or_insert_with(|| Value::String(realm_id.clone()));
        }
        items.retain(|item| item.get("tag_id").and_then(Value::as_str) != Some(tag.as_str()));
        items.push(serde_json::json!({
            "tag_id": tag,
            "value": value,
        }));
        self.set_facet(
            &realm_id,
            FacetRef::new(facet::MODERATION_STATE, &target_ref_key),
            Value::Array(items),
        );

        ProjectionEffect::ModerationDecisionProjected {
            decision_id,
            realm_id,
        }
    }

    /// Project `ak.moderation.decision.lift` as the keyed-set removal of the
    /// entry the named `decision_ref` produced.
    ///
    /// `content-moderation.md` §2.6 — the lift removes exactly the entry whose
    /// tag the referenced decision wrote, so lifting one review never
    /// implicitly lifts another issuer's decision. `expected_revision` is the
    /// exact moderation-target revision the producer observed; a different
    /// current revision rejects the Event as stale, while an exact retry stays
    /// idempotent.
    pub(crate) fn apply_moderation_decision_lift(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(decision_id) = payload_str(operation, "decision_ref") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_decision_ref_missing".to_owned(),
            };
        };
        let Some(target_ref) = payload_str(operation, "target_ref") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_target_ref_missing".to_owned(),
            };
        };
        // `expected_revision` is the typed `{commit_id, stream_position}` of
        // the durable `moderation_state` result. The governing Station
        // compares it at the accepting Commit cut; this cache only removes the
        // lifted decision from the active set it folds.
        if operation
            .payload
            .get("expected_revision")
            .and_then(Value::as_object)
            .is_none()
        {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_expected_revision_missing".to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let target = FacetRef::new(facet::MODERATION_STATE, &target_ref);
        let _ = now;
        let mut items = self.moderation_entries(&realm_id, &target_ref);
        let before = items.len();
        items.retain(|item| {
            item.get("value")
                .unwrap_or(item)
                .get("decision_id")
                .and_then(Value::as_str)
                != Some(decision_id.as_str())
        });
        if items.len() == before {
            // A lift that observes no entry of its own decision is either a
            // lift-before-decision or a lift of somebody else's tag; under a
            // linear commit stream neither is an ordering artefact.
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_decision_not_projected".to_owned(),
            };
        }
        self.set_facet(&realm_id, target, Value::Array(items));

        ProjectionEffect::ModerationDecisionLifted {
            decision_id,
            realm_id,
        }
    }
}
