//! `ProjectionState::apply_strand_*` reducers and the strand-tracks preflight.
//! Inherent-impl block on `ProjectionState`; methods resolve by type, so
//! cross-family `self.apply_*` / `self.check_*` calls are unaffected.

use super::*;

impl ProjectionState {
    /// Apply `ak.strand.create` — populate the `strands` projection from
    /// the wire `object` field. Spec: common-fields.md §5 + strand schema.
    /// Idempotent: re-create with same id overwrites the existing entry
    /// (LWW), but the preflight will accept it since `ak.strand.create` has
    /// no source-state guard.
    pub(crate) fn apply_strand_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "strand_create_missing_object".to_owned(),
            };
        };
        let Some(strand_id) = event_derived_object_id(operation, "ak:strand:") else {
            return ProjectionEffect::Rejected {
                reason: "strand_create_missing_event_id".to_owned(),
            };
        };
        let metadata = object.get("metadata").and_then(Value::as_object);
        let title = metadata
            .and_then(|metadata| metadata.get("title"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let summary = metadata
            .and_then(|metadata| metadata.get("summary"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = metadata
            .and_then(|metadata| metadata.get("fields"))
            .and_then(Value::as_object)
            .map(|fields| {
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        if arkret_models_collaboration::objects::productivity::validate_calendar_event_metadata_fields(&fields).is_err() {
            return ProjectionEffect::Rejected {
                reason: "schema_violation".to_owned(),
            };
        }
        let tracks = match strand_tracks_from_object(object) {
            Ok(tracks) => tracks,
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        };
        if object.get("content").is_some() && object.get("encrypted_content").is_some() {
            return ProjectionEffect::Rejected {
                reason: "strand_description_content_conflict".to_owned(),
            };
        }
        if let Err(reason) = validate_track_content_surfaces(&tracks) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        // AKP-0007: intra-Realm discussion boundaries are expressed via
        // `scope_circle_id` (Circle); when present, validate the Circle is in
        // this Realm and active.
        if let Some(scope_circle_id) = object.get("scope_circle_id").and_then(Value::as_str)
            && let Err(reason) =
                self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = strand_position_from_create_payload(object) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = strand_forbidden_wire_field_in_create_payload(object) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        // `common-fields.md` §5.3.1: `stage` is optional on create and, when
        // present, MUST be one of the eight registered values. `stage_changed_at`
        // is reducer-derived (§5.3.3 rule 3) — create is an initialization, not a
        // transition, so it stays absent no matter what the wire object carries.
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

        let has_calendar_schedule = fields.contains_key("calendar");
        let projection = StrandProjection {
            strand_id: strand_id.clone(),
            realm_id,
            tracks,
            title,
            summary,
            content: object.get("content").cloned(),
            encrypted_content: object.get("encrypted_content").cloned(),
            fields,
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            stage,
            stage_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
            scope_circle_id: object
                .get("scope_circle_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            schema_refs: strand_schema_refs(object),
            schedule_revision_source: has_calendar_schedule
                .then(|| operation.context.event_id.event_digest().to_string()),
        };
        self.strands.insert(strand_id.clone(), projection);
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `ak.strand.update` to an existing Strand, including the independent
    /// top-level Description and nested Synthesis content surfaces.
    /// Spec common-fields.md §5.1: update on non-active object MUST fail
    /// with `strand_not_active`. Unknown Strand is queued for pending replay.
    pub(crate) fn apply_strand_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(strand_id) = strand_id_from_payload(&operation.payload).map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "strand_update_missing_target_ref".to_owned(),
            };
        };
        // AKP-0007: Strand scope is set at create time; `scope_circle_id`
        // rebinds fail below with `scope_rebind_forbidden`.
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return self.queue_pending_replay(strand_id, operation, "strand_unknown");
        };
        if strand.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "strand_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if let Err(reason) = validate_patch_semantic_safety(patch, Some("strand")) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
            if patch.contains_key("scope_circle_id") {
                return ProjectionEffect::Rejected {
                    reason: "scope_rebind_forbidden".to_owned(),
                };
            }
            let mut next_fields = strand.fields.clone();
            apply_strand_fields_patch(&mut next_fields, patch);
            if arkret_models_collaboration::objects::productivity::validate_calendar_event_metadata_fields(&next_fields).is_err() {
                return ProjectionEffect::Rejected {
                    reason: "schema_violation".to_owned(),
                };
            }
            // Freeze and patch the complete pre-update Strand before mutating
            // individual metadata fields below. Otherwise an `$op: unset`
            // for title/summary would be replayed against an already-mutated
            // document and could fail spuriously.
            let narrative_post = match apply_strand_narrative_patch(strand, patch) {
                Ok(post) => post,
                Err(reason) => {
                    return ProjectionEffect::Rejected {
                        reason: reason.to_owned(),
                    };
                }
            };
            if let Some(title) = patch_metadata_string_value(patch, "title") {
                strand.title = title.unwrap_or_default();
            }
            if let Some(summary) = patch_metadata_string_value(patch, "summary") {
                strand.summary = summary;
            }
            strand.content = narrative_post.content;
            strand.encrypted_content = narrative_post.encrypted_content;
            strand.tracks = narrative_post.tracks;
            strand.fields = next_fields;
            if let Some(refs) = patched_schema_refs(patch) {
                strand.schema_refs = refs;
            }
            if patch_touches_calendar_schedule(patch) {
                strand.schedule_revision_source =
                    Some(operation.context.event_id.event_digest().to_string());
            }
        }
        strand.updated_by = Some(operation.context.sender.to_string());
        strand.updated_at = Some(now);
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: strand.state,
        }
    }

    /// Apply `ak.strand.archive` / `ak.strand.restore`. Spec
    /// `common-fields.md §5.1` + `event-payload.schema.json`
    /// `object_lifecycle_payload`. Unknown Strand is queued for pending replay. The target id is
    /// carried by `target_ref` per spec.
    pub(crate) fn apply_strand_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(strand_id) = operation
            .payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_strand_id".to_owned(),
            };
        };
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return self.queue_pending_replay(strand_id, operation, "strand_unknown");
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "strand_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "strand_not_archived",
            ),
        };
        if !allowed_source.contains(&strand.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        strand.state = target_state;
        strand.state_changed_at = Some(now);
        strand.updated_by = Some(operation.context.sender.to_string());
        strand.updated_at = Some(now);
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: target_state,
        }
    }

    /// Read-only preflight for `ak.strand.tracks.update`. Spec
    /// common-fields.md §5.1 update-on-non-active rule: track mutations
    /// are a kind of update; parent Strand MUST be Active or the admission
    /// MUST `failed_precondition` with `strand_not_active` before
    /// persistence. Unknown Strand tolerated (causal / backfill — matches
    /// the lifecycle preflight family).
    pub fn check_strand_tracks_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        if !arkret_wire::events::kinds::is_strand_tracks_kind(&kind) {
            return Ok(());
        }
        let Some(strand_id) = operation.payload.get("target_ref").and_then(|v| v.as_str()) else {
            // Missing target_ref is caught by operation-schema validator
            // upstream; preflight tolerates absence (responsibilities split).
            return Ok(());
        };
        let Some(strand) = self.strands.get(strand_id) else {
            return Ok(());
        };
        if strand.state != ObjectLifecycleState::Active {
            return Err("strand_not_active");
        }
        let next_tracks = apply_strand_tracks_update_to_map(&strand.tracks, &operation.payload)?;
        if next_tracks.is_empty() {
            return Err("strand_tracks_empty");
        }
        validate_primary_track_transition(&strand.tracks, &next_tracks)?;
        Ok(())
    }

    /// Apply `ak.strand.move` / `ak.strand.reorder`. These events
    /// update the registered position current without changing Strand lifecycle
    /// state. This local reducer bumps `updated_at` /
    /// `updated_by` on the Strand projection so read-after-write sees the
    /// touch. Unknown Strand is queued for pending replay.
    pub(crate) fn apply_strand_position_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(strand_id) = operation
            .payload
            .get("strand_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_strand_id".to_owned(),
            };
        };
        let position = strand_position_from_lifecycle_payload(&operation.payload);
        let Some(strand) = self.strands.get(&strand_id) else {
            return self.queue_pending_replay(strand_id, operation, "strand_unknown");
        };
        if let Some((board_space_id, ..)) = position.as_ref()
            && let Err(reason) = self.check_space_child_scope_policy(
                board_space_id,
                strand.scope_circle_id.as_deref(),
                &strand.realm_id,
                false,
            )
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Some((_, list_space_id, _)) = position.as_ref()
            && let Err(reason) = self.check_space_child_scope_policy(
                list_space_id,
                strand.scope_circle_id.as_deref(),
                &strand.realm_id,
                false,
            )
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return self.queue_pending_replay(strand_id, operation, "strand_unknown");
        };
        strand.updated_by = Some(operation.context.sender.to_string());
        strand.updated_at = Some(now);
        let projected_state = strand.state;
        if let Some((board_space_id, list_space_id, rank)) = position {
            self.store_strand_position_relation(
                &strand_id,
                operation.realm_id.as_ref(),
                &board_space_id,
                &list_space_id,
                rank.as_deref(),
                now,
            );
        }
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: projected_state,
        }
    }

    /// Apply `ak.strand.tracks.update` server-side. State guard runs in
    /// `check_strand_tracks_transition` preflight; by the time this reducer
    /// fires, the parent Strand is known to be Active. Unknown Strand targets
    /// are queued for pending replay.
    pub(crate) fn apply_strand_track_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(strand_id) = operation
            .payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_target_ref".to_owned(),
            };
        };
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return self.queue_pending_replay(strand_id, operation, "strand_unknown");
        };
        // Defence-in-depth: even though check_strand_tracks_transition
        // gated this at the admission layer, re-check here so direct
        // reducer callers (tests / replay paths that bypass HTTP) still
        // see the spec invariant enforced.
        if strand.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "strand_not_active".to_owned(),
            };
        }
        match apply_strand_tracks_update_to_map(&strand.tracks, &operation.payload) {
            Ok(tracks) if tracks.is_empty() => {
                return ProjectionEffect::Rejected {
                    reason: "strand_tracks_empty".to_owned(),
                };
            }
            Ok(tracks) => {
                if let Err(reason) = validate_primary_track_transition(&strand.tracks, &tracks) {
                    return ProjectionEffect::Rejected {
                        reason: reason.to_owned(),
                    };
                }
                strand.tracks = tracks;
            }
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        }
        strand.updated_by = Some(operation.context.sender.to_string());
        strand.updated_at = Some(now);
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: strand.state,
        }
    }

    /// Apply `ak.strand.stage.set` — the only wire path that mutates the
    /// Strand business-progression axis (`common-fields.md` §5.3, spec
    /// `strand-and-message.md` §3.2).
    ///
    /// v1 registers no per-Realm workflow-profile carrier, so the core reducer
    /// imposes **no direction** between the eight stage values: `planned ->
    /// done` and `done -> in_progress` are equally admissible (§5.3.3). The
    /// enforced invariants are exactly the physical-lifecycle guards (also run
    /// as a read-only preflight so admission fails closed with 412), the
    /// reducer-derived `stage_changed_at`, and the same-value no-op. Unknown
    /// Strand is queued for pending replay, matching the other strand
    /// reducers' causal/backfill tolerance.
    pub(crate) fn apply_strand_stage_set(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Ok(payload) = operation.typed_payload::<arkret_wire::event_spec::StrandStageSet>()
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let strand_id = payload.strand_id.to_string();
        let Some(stage) = object_stage_from_wire_value(&payload.stage) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return self.queue_pending_replay(strand_id, operation, "strand_unknown");
        };
        // §5.3.3 rule 1 then rule 2: a physically terminal object reports
        // `strand_already_terminal`, a merely archived one `strand_not_active`.
        if strand.state.is_terminal() {
            return ProjectionEffect::Rejected {
                reason: "strand_already_terminal".to_owned(),
            };
        }
        if strand.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "strand_not_active".to_owned(),
            };
        }
        if strand.stage.as_ref() == Some(&stage) {
            // §5.3.3 rule 4 — an idempotent same-value self-transition is
            // accepted but records no change: neither `stage_changed_at` nor
            // the audit columns move.
            return ProjectionEffect::StrandLifecycle {
                strand_id,
                new_state: strand.state,
            };
        }
        strand.stage = Some(stage);
        // §5.3.3 rule 3 — any actor-supplied `stage_changed_at` is ignored; the
        // triggering event's `created_at` is the only source.
        strand.stage_changed_at = Some(now);
        strand.updated_by = Some(operation.context.sender.to_string());
        strand.updated_at = Some(now);
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: strand.state,
        }
    }
}

fn patch_touches_calendar_schedule(patch: &serde_json::Map<String, Value>) -> bool {
    patch.keys().any(|path| {
        path == "metadata"
            || path == "encrypted_metadata"
            || path == "metadata.fields"
            || path == "metadata.fields.calendar"
            || path.starts_with("metadata.fields.calendar.")
    })
}

struct StrandNarrativePost {
    content: Option<Value>,
    encrypted_content: Option<Value>,
    tracks: BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
}

/// Patch the frozen narrative cache so Synthesis paths remain distinct from
/// the top-level Description. Whole-value Topic state belongs to the native
/// canonical Strand current; this compatibility cache does not carry it.
fn apply_strand_narrative_patch(
    strand: &StrandProjection,
    patch: &serde_json::Map<String, Value>,
) -> Result<StrandNarrativePost, &'static str> {
    if patch.keys().any(|path| {
        (path == "tracks" || path.starts_with("tracks."))
            && !matches!(
                path.as_str(),
                "tracks.synthesis.content" | "tracks.synthesis.encrypted_content"
            )
    }) {
        return Err("strand_patch_invalid");
    }
    let mut metadata = serde_json::Map::new();
    metadata.insert("title".to_owned(), Value::String(strand.title.clone()));
    if let Some(summary) = &strand.summary {
        metadata.insert("summary".to_owned(), Value::String(summary.clone()));
    }
    metadata.insert(
        "fields".to_owned(),
        serde_json::to_value(&strand.fields).map_err(|_| "strand_projection_invalid")?,
    );
    let mut pre = serde_json::Map::new();
    pre.insert("metadata".to_owned(), Value::Object(metadata));
    pre.insert(
        "tracks".to_owned(),
        serde_json::to_value(&strand.tracks).map_err(|_| "strand_projection_invalid")?,
    );
    if let Some(content) = &strand.content {
        pre.insert("content".to_owned(), content.clone());
    }
    if let Some(encrypted_content) = &strand.encrypted_content {
        pre.insert("encrypted_content".to_owned(), encrypted_content.clone());
    }

    let typed_patch =
        serde_json::from_value::<arkret_wire::patch::Patch>(Value::Object(patch.clone()))
            .map_err(|_| "strand_patch_invalid")?;
    typed_patch.validate().map_err(|_| "strand_patch_invalid")?;
    let mut narrative_patch = arkret_wire::patch::Patch::new();
    for (path, op) in typed_patch.iter() {
        if path != "topic" {
            narrative_patch
                .insert_op(path.clone(), op.clone())
                .map_err(|_| "strand_patch_invalid")?;
        }
    }
    let pre = Value::Object(pre);
    let post = if narrative_patch.is_empty() {
        pre
    } else {
        narrative_patch
            .apply_for_typed_target(&pre, &strand.strand_id)
            .map_err(|_| "strand_patch_invalid")?
    };
    let post_object = post.as_object().ok_or("strand_projection_invalid")?;
    let content = post_object.get("content").cloned();
    let encrypted_content = post_object.get("encrypted_content").cloned();
    if content.is_some() && encrypted_content.is_some() {
        return Err("strand_description_content_conflict");
    }
    let tracks = serde_json::from_value::<
        BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    >(
        post_object
            .get("tracks")
            .cloned()
            .ok_or("strand_tracks_empty")?,
    )
    .map_err(|_| "strand_tracks_invalid")?;
    validate_strand_tracks(&tracks)?;
    validate_track_content_surfaces(&tracks)?;

    let before_synthesis = strand_track_content_snapshot_for(&strand.tracks, "synthesis");
    let after_synthesis = strand_track_content_snapshot_for(&tracks, "synthesis");
    if before_synthesis != after_synthesis {
        let before_active = strand
            .tracks
            .get("synthesis")
            .is_none_or(|track| track.enabled.unwrap_or(true));
        let after_active = tracks
            .get("synthesis")
            .is_none_or(|track| track.enabled.unwrap_or(true));
        if !before_active || !after_active {
            return Err("track_disabled");
        }
    }

    Ok(StrandNarrativePost {
        content,
        encrypted_content,
        tracks,
    })
}

fn validate_track_content_surfaces(
    tracks: &BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
) -> Result<(), &'static str> {
    for (track_name, track) in tracks {
        if track.content.is_some() && track.encrypted_content.is_some() {
            return Err("strand_track_content_conflict");
        }
        if track_name == "discussion"
            && (track.content.is_some() || track.encrypted_content.is_some())
        {
            return Err("discussion_content_forbidden");
        }
    }
    Ok(())
}

fn strand_track_content_snapshot_for(
    tracks: &BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    track_name: &str,
) -> (Option<Value>, Option<Value>) {
    tracks.get(track_name).map_or((None, None), |track| {
        (
            track
                .content
                .as_ref()
                .and_then(|value| serde_json::to_value(value).ok()),
            track
                .encrypted_content
                .as_ref()
                .and_then(|value| serde_json::to_value(value).ok()),
        )
    })
}

fn strand_track_content_snapshot(
    tracks: &BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
) -> BTreeMap<String, (Option<Value>, Option<Value>)> {
    tracks
        .keys()
        .filter_map(|name| {
            let body = strand_track_content_snapshot_for(tracks, name);
            (body.0.is_some() || body.1.is_some()).then(|| (name.clone(), body))
        })
        .collect()
}

fn strand_tracks_from_object(
    object: &serde_json::Map<String, Value>,
) -> Result<
    BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    &'static str,
> {
    let Some(tracks_value) = object.get("tracks") else {
        return Ok(crate::reducer::projections::default_strand_tracks());
    };
    let tracks = serde_json::from_value::<
        BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    >(tracks_value.clone())
    .map_err(|_| "strand_tracks_invalid")?;
    validate_strand_tracks(&tracks)?;
    if tracks.is_empty() {
        return Err("strand_tracks_empty");
    }
    Ok(tracks)
}

fn apply_strand_tracks_update_to_map(
    current: &BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    payload: &Value,
) -> Result<
    BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    &'static str,
> {
    let patch = payload
        .get("patch")
        .and_then(Value::as_object)
        .filter(|patch| !patch.is_empty())
        .ok_or("strand_tracks_update_requires_patch")?;
    for path in patch.keys() {
        if matches!(
            path.as_str(),
            "tracks.synthesis.content"
                | "tracks.synthesis.encrypted_content"
                | "tracks.discussion.content"
                | "tracks.discussion.encrypted_content"
        ) {
            return Err("strand_tracks_content_forbidden");
        }
        let segments = path.split('.').collect::<Vec<_>>();
        let allowed = match segments.as_slice() {
            [
                "tracks",
                "discussion" | "synthesis",
                "enabled" | "is_primary" | "profile",
            ] => true,
            ["tracks", "discussion" | "synthesis", "metadata", rest @ ..] => {
                rest.iter().all(|part| {
                    !part.is_empty()
                        && part.len() <= 64
                        && part.as_bytes()[0].is_ascii_lowercase()
                        && part.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                })
            }
            _ => false,
        };
        if !allowed {
            return Err("strand_tracks_patch_invalid");
        }
    }
    let typed_patch =
        serde_json::from_value::<arkret_wire::patch::Patch>(Value::Object(patch.clone()))
            .map_err(|_| "strand_tracks_patch_invalid")?;
    let pre = serde_json::json!({"tracks": current});
    let post = typed_patch
        .apply(&pre)
        .map_err(|_| "strand_tracks_patch_invalid")?;
    let tracks = serde_json::from_value::<
        BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    >(post.get("tracks").cloned().ok_or("strand_tracks_empty")?)
    .map_err(|_| "strand_tracks_invalid")?;
    validate_strand_tracks(&tracks)?;
    if strand_track_content_snapshot(current) != strand_track_content_snapshot(&tracks) {
        return Err("strand_tracks_content_forbidden");
    }
    Ok(tracks)
}

fn validate_strand_tracks(
    tracks: &BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
) -> Result<(), &'static str> {
    for track_id in tracks.keys() {
        arkret_models_collaboration::objects::profiles::validate_strand_track_name(track_id)
            .map_err(|_| "strand_track_name_invalid")?;
    }
    arkret_models_collaboration::objects::profiles::resolve_primary_track(tracks, None)
        .map_err(map_primary_track_error)?;
    Ok(())
}

fn validate_primary_track_transition(
    previous: &BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    next: &BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
) -> Result<(), &'static str> {
    arkret_models_collaboration::objects::profiles::validate_primary_track_transition(
        previous, next, None,
    )
    .map_err(map_primary_track_error)
}

fn map_primary_track_error(error: arkret_wire::WireError) -> &'static str {
    let message = error.to_string();
    if message.contains("track_disabled") {
        "track_disabled"
    } else {
        "primary_track_required"
    }
}

/// `schema_refs` as written on a create payload object.
fn strand_schema_refs(object: &serde_json::Map<String, Value>) -> Vec<String> {
    object
        .get("schema_refs")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `schema_refs` written by a patch, when the patch touches it at all.
fn patched_schema_refs(patch: &serde_json::Map<String, Value>) -> Option<Vec<String>> {
    let entry = patch.get("schema_refs")?;
    if entry.get("$op").and_then(Value::as_str) == Some("unset") {
        return Some(Vec::new());
    }
    let values = entry.get("value").unwrap_or(entry).as_array()?;
    Some(
        values
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
    )
}

#[cfg(test)]
mod track_configuration_tests {
    use super::*;

    #[test]
    fn configuration_rejects_ancestor_replacement_and_preserves_body() {
        let current = serde_json::from_value(serde_json::json!({
            "discussion": {"enabled": true, "is_primary": true, "profile": "discussion"},
            "synthesis": {"enabled": true, "is_primary": false, "profile": "synthesis", "content": {"kind": "ak.content.text", "body": "Protected"}}
        })).unwrap();
        for path in [
            "tracks",
            "tracks.synthesis",
            "tracks.synthesis.template",
            "tracks.synthesis.metadata.Bad",
        ] {
            let payload = serde_json::json!({"patch": {path: {"$op": "set", "value": {}}}});
            assert_eq!(
                apply_strand_tracks_update_to_map(&current, &payload),
                Err("strand_tracks_patch_invalid")
            );
        }
        let next = apply_strand_tracks_update_to_map(&current, &serde_json::json!({"patch": {"tracks.synthesis.metadata.label": {"$op": "set", "value": "Summary"}}})).unwrap();
        assert_eq!(
            strand_track_content_snapshot(&current),
            strand_track_content_snapshot(&next)
        );
        assert_eq!(
            serde_json::to_value(&next).unwrap()["synthesis"]["metadata"]["label"],
            "Summary"
        );
    }
}
