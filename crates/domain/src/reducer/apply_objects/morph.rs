//! `ProjectionState::apply_morph_*` reducers. Inherent-impl block on
//! `ProjectionState`; methods resolve by type, so cross-family
//! `self.apply_*` / `self.check_*` calls are unaffected.

use arkret_models_collaboration::events_payloads::ContentBlock;

use super::*;

impl ProjectionState {
    /// Apply `ak.morph.create`. Mirror of `apply_strand_create`.
    pub(crate) fn apply_morph_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "morph_create_missing_object".to_owned(),
            };
        };
        let Some(morph_id) = event_derived_object_id(operation, "ak:morph:") else {
            return ProjectionEffect::Rejected {
                reason: "morph_create_missing_event_id".to_owned(),
            };
        };
        if let Err(reason) = morph_forbidden_wire_field_in_create_payload(object) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        // AKP-0007 — when the Morph carries a `scope_circle_id`, the
        // Circle MUST belong to this Realm and be active. Mirrors the
        // Strand.scope_circle_id validation.
        if let Some(scope_circle_id) = object.get("scope_circle_id").and_then(Value::as_str)
            && let Err(reason) =
                self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let morph_kind = object
            .get("morph_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let scope_circle_id = object
            .get("scope_circle_id")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("ak:circle:"))
            .map(ToOwned::to_owned);
        let title = object
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("title"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = object_map_to_fields(object.get("fields"));
        let schema_refs = string_array_field(object, "schema_refs");
        let facets = object
            .get("facets")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default();
        // `common-fields.md` §5.3.1: `stage` is optional on create; a generic
        // mirror/data Morph omits it. `stage_changed_at` is reducer-derived, so
        // create leaves it absent and the first `ak.morph.stage.set` is an
        // initialization rather than a transition from an implied default.
        let stage = match object.get("stage") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let Some(stage) = value.as_str().and_then(object_stage_from_wire_value) else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                Some(stage)
            }
        };
        let realm_id = projection_object_realm_id(object, operation);
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| operation.context.sender.to_string());
        let versions = morph_document_body(&fields)
            .map(|body| vec![document_version_from_operation(&morph_id, operation, body)])
            .unwrap_or_default();

        let projection = MorphProjection {
            morph_id: morph_id.clone(),
            realm_id,
            scope_circle_id,
            morph_kind,
            title,
            fields,
            schema_refs,
            facets,
            versions,
            // The create Event's `object` was already validated against the
            // SDK `Morph` shape at admission, so `content` decodes as the
            // authoritative `ContentBlock`; reject defensively if it does not.
            content: match object.get("content").cloned() {
                Some(value) => match ContentBlock::from_value(value) {
                    Ok(content) => Some(content),
                    Err(_) => {
                        return ProjectionEffect::Rejected {
                            reason: "morph_content_invalid".to_owned(),
                        };
                    }
                },
                None => None,
            },
            encrypted_content: object.get("encrypted_content").cloned(),
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            stage,
            stage_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
        };
        self.morphs.insert(morph_id.clone(), projection);

        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `ak.morph.update`. Mirror of `apply_strand_update`.
    pub(crate) fn apply_morph_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "morph_update_missing_morph_id".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return self.queue_pending_replay(morph_id, operation, "morph_unknown");
        };
        if morph.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "morph_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if let Err(reason) = validate_patch_semantic_safety(patch, Some("morph")) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
            if let Some(title) = patch_metadata_string_value(patch, "title") {
                morph.title = title;
            }
            // `morph.md` §4 (line 149): `morph_kind` is immutable after
            // `ak.morph.create`. Admission rejects an update patch that names
            // it (`patch_path_reducer_managed`); the reducer never mutates
            // the field so the invariant also holds for any event that
            // bypasses admission.
            apply_morph_fields_patch(&mut morph.fields, patch);
        }
        morph.updated_by = Some(operation.context.sender.to_string());
        morph.updated_at = Some(now);
        if let Some(body) = morph_document_body(&morph.fields) {
            let next = document_version_from_operation(&morph_id, operation, body);
            let already_recorded = morph
                .versions
                .last()
                .is_some_and(|current| current.body_digest == next.body_digest);
            if !already_recorded {
                morph.versions.push(next);
            }
        }
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: morph.state,
        }
    }

    /// Apply `ak.morph.stage.set`. Behaviourally identical to
    /// [`ProjectionState::apply_strand_stage_set`]: the same §5.3.3 hard
    /// invariants, the same absence of any direction rule, and the same
    /// reducer-derived `stage_changed_at`. A Morph created without a stage
    /// takes its first value here as an initialization.
    pub(crate) fn apply_morph_stage_set(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Ok(payload) = operation.typed_payload::<arkret_wire::event_spec::MorphStageSet>()
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let morph_id = payload.morph_id.to_string();
        let Some(stage) = object_stage_from_wire_value(&payload.stage) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return self.queue_pending_replay(morph_id, operation, "morph_unknown");
        };
        if morph.state.is_terminal() {
            return ProjectionEffect::Rejected {
                reason: "morph_already_terminal".to_owned(),
            };
        }
        if morph.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "morph_not_active".to_owned(),
            };
        }
        if morph.stage.as_ref() == Some(&stage) {
            return ProjectionEffect::MorphLifecycle {
                morph_id,
                new_state: morph.state,
            };
        }
        morph.stage = Some(stage);
        morph.stage_changed_at = Some(now);
        morph.updated_by = Some(operation.context.sender.to_string());
        morph.updated_at = Some(now);
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: morph.state,
        }
    }

    /// Apply `ak.morph.archive` / `ak.morph.restore`. Mirror of
    /// `apply_strand_lifecycle`.
    pub(crate) fn apply_morph_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_target_ref".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return self.queue_pending_replay(morph_id, operation, "morph_unknown");
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "morph_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "morph_not_archived",
            ),
        };
        if !allowed_source.contains(&morph.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        morph.state = target_state;
        morph.state_changed_at = Some(now);
        morph.updated_by = Some(operation.context.sender.to_string());
        morph.updated_at = Some(now);
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: target_state,
        }
    }
}
