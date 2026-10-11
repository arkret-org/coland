use arkret_models_collaboration::events_payloads::{
    RelationCreatePayload, RelationTombstonePayload, RelationUpdatePayload,
};
use arkret_models_collaboration::objects::relation::{
    RelationEndpoint, RelationPrimaryConflictDomain,
};

use super::*;

impl ProjectionState {
    fn missing_relation_endpoint(
        &self,
        from_ref: Option<&str>,
        to_ref: Option<&str>,
    ) -> Option<String> {
        for endpoint in [from_ref, to_ref].into_iter().flatten() {
            if relation_endpoint_needs_projection(endpoint) && !self.projected_ref_exists(endpoint)
            {
                return Some(endpoint.to_owned());
            }
        }
        None
    }

    pub(crate) fn apply_relation_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        if let Err(reason) = self.check_relation_invariants(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let payload =
            match serde_json::from_value::<RelationCreatePayload>(operation.payload.clone()) {
                Ok(payload) => payload,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };
        let relation = &payload.relation;
        let relation_id =
            arkret_identifiers::RelationId::from_event_id(&operation.context.event_id).to_string();
        if let Some(existing) = self.relations.get(&relation_id) {
            return ProjectionEffect::RelationCreated(existing.clone());
        }
        let domain_key = relation_primary_domain_key(&payload.primary_conflict_domain);
        let current_id = self
            .relation_current
            .get(&(operation.realm_id.to_string(), domain_key.clone()));
        match current_id {
            None => {}
            Some(current_id)
                if self
                    .relations
                    .get(current_id)
                    .is_some_and(|relation| relation.state == "tombstoned") => {}
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::FAILED_PRECONDITION.to_owned(),
                };
            }
        }
        let relation_kind = relation.relation_kind.as_str().to_owned();
        let from_ref = Some(relation.from_ref.clone());
        let to_ref = Some(relation.to_ref.clone());
        if let Some(target_ref) = self.missing_relation_endpoint(
            from_ref.as_ref().and_then(RelationEndpoint::as_object_ref),
            to_ref.as_ref().and_then(RelationEndpoint::as_object_ref),
        ) {
            return self.queue_pending_replay(target_ref, operation, "relation_endpoint_unknown");
        }
        let fields = relation.fields.clone();
        let scope_circle_id = relation.scope_circle_id.as_ref().map(ToString::to_string);
        let source_event_id = Some(operation.context.event_id.to_string());
        let source_event_digest = Some(relation_event_digest(operation));

        let state = ColandRelationState {
            relation_id: relation_id.clone(),
            realm_id: operation.realm_id.to_string(),
            relation_kind,
            scope_circle_id,
            from_ref,
            to_ref,
            rank: relation.rank.clone(),
            fields,
            state: "active".to_owned(),
            source_event_id,
            source_event_digest,
            created_at: now,
            updated_at: now,
        };
        self.relations.insert(relation_id.clone(), state);
        self.relation_current.insert(
            (operation.realm_id.to_string(), domain_key.clone()),
            relation_id.clone(),
        );
        // The reducer input does not carry its accepting RealmCommit. Do not
        // retain a prior exact revision after a live mutation; startup (or an
        // authority-row refresh) installs authoritative metadata.
        self.relation_current_metadata
            .remove(&(operation.realm_id.to_string(), domain_key));
        ProjectionEffect::RelationCreated(
            self.relations
                .get(&relation_id)
                .cloned()
                .expect("relation state inserted"),
        )
    }

    /// Resolve the home Realm of a structural-relation endpoint from the local
    /// object projections. Returns `None` when the object is not locally
    /// projected (out-of-order replication), so the cross-Realm check cannot
    /// fire — consistent with the reducer's general out-of-order tolerance.
    fn resolve_object_realm(&self, ref_id: &str) -> Option<&str> {
        if let Some(strand) = self.strands.get(ref_id) {
            return Some(strand.realm_id.as_str());
        }
        if let Some(space) = self.space_containers.get(ref_id) {
            return Some(space.realm_id.as_str());
        }
        if let Some(morph) = self.morphs.get(ref_id) {
            return Some(morph.realm_id.as_str());
        }
        None
    }

    fn resolve_object_scope_circle_id(&self, ref_id: &str) -> Option<&str> {
        if let Some(strand) = self.strands.get(ref_id) {
            return strand.scope_circle_id.as_deref();
        }
        if let Some(space) = self.space_containers.get(ref_id) {
            return space.scope_circle_id.as_deref();
        }
        if let Some(morph) = self.morphs.get(ref_id) {
            return morph.scope_circle_id.as_deref();
        }
        if let Some(relation) = self.relations.get(ref_id) {
            return relation.scope_circle_id.as_deref();
        }
        None
    }

    fn relation_endpoint_scope_floor(
        &self,
        relation: &Value,
        relation_kind: &str,
    ) -> Result<Option<String>, &'static str> {
        if !matches!(
            relation_kind,
            "contains" | "belongs_to" | "confidential_discussion_of" | "assigned_to"
        ) {
            return Ok(None);
        }
        let endpoints = [relation.get("from_ref"), relation.get("to_ref")];
        let mut floor: Option<String> = None;
        for endpoint in endpoints.into_iter().flatten().filter_map(Value::as_str) {
            let Some(scope_circle_id) = self.resolve_object_scope_circle_id(endpoint) else {
                continue;
            };
            if let Some(previous) = floor.as_deref()
                && previous != scope_circle_id
            {
                return Err("relation_scope_endpoint_mismatch");
            }
            floor = Some(scope_circle_id.to_owned());
        }
        Ok(floor)
    }

    fn check_relation_effective_scope(
        &self,
        realm_id: &str,
        relation: &Value,
        relation_kind: &str,
    ) -> Result<(), &'static str> {
        let scope_circle_id = relation_scope_circle_id(relation);
        if relation_kind == "confidential_discussion_of" && scope_circle_id.is_none() {
            return Err("relation_scope_circle_id_required");
        }
        if let Some(scope_circle_id) = scope_circle_id.as_deref() {
            self.validate_scope_circle_id(scope_circle_id, realm_id)?;
        }
        if let Some(endpoint_scope) = self.relation_endpoint_scope_floor(relation, relation_kind)?
            && scope_circle_id.as_deref() != Some(endpoint_scope.as_str())
        {
            return Err("relation_scope_wider_than_endpoint");
        }
        Ok(())
    }

    /// `relation.md` §4 (line 149) — structural `contains` / `belongs_to`
    /// Relations MUST NOT cross Realm boundaries: the reducer resolves the
    /// endpoints and rejects with `cross_realm_structural_relation` when a
    /// locally-known endpoint sits in a Realm other than the Relation's. Weak
    /// reference kinds (`references` / `mentions` / `derived_from` / …) MAY
    /// cross Realm and are not checked here (they take the §4.3 two-sided
    /// capability path with projection-time `ReferenceProjectionState`).
    pub fn check_relation_cross_realm(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::RelationCreate)
        {
            return Ok(());
        }
        let payload = serde_json::from_value::<RelationCreatePayload>(operation.payload.clone())
            .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
        let relation_kind = payload.relation.relation_kind.as_str();
        let relation_realm = operation.realm_id.as_str();
        let endpoints = [&payload.relation.from_ref, &payload.relation.to_ref];
        let endpoint_realms = endpoints
            .into_iter()
            .filter_map(RelationEndpoint::as_object_ref)
            .filter_map(|endpoint| self.resolve_object_realm(endpoint))
            .collect::<Vec<_>>();
        arkret_models_collaboration::objects::relation::validate_structural_relation_same_realm(
            relation_kind,
            relation_realm,
            endpoint_realms,
        )
    }

    /// The single stateful admission rule for direct `ak.relation.*` writes on
    /// a derived edge (`relation.md` §3.2).
    ///
    /// `relation_direct_write_reject_reason` is the SDK's one expression of the
    /// rule: `watches` (truth source `ak.component.strand.watch.v1`, write path
    /// `ak.strand.watch.set`) is always derived, and `contains` is derived only
    /// in the container shape identified by a Space `from_ref` (`ak:space:…`).
    /// A `Strand -> Strand` `contains` stays a directly-writable weak relation
    /// (§3.2) and is not blocked.
    fn check_relation_direct_write(
        relation_kind: &str,
        from_ref: Option<&str>,
    ) -> Result<(), &'static str> {
        arkret_models_collaboration::objects::relation::validate_relation_direct_write(
            relation_kind,
            from_ref,
        )
    }

    /// The sole stateful admission gate for `ak.relation.create` / `.update` /
    /// `.tombstone`. Submit calls it before any persistent effect; the reducer
    /// apply paths re-call the same function defensively. There is deliberately
    /// no second parser of relation fields anywhere else: the HTTP layer only
    /// checks the stateless `effective_scope` forbidden field.
    pub fn check_relation_invariants(&self, operation: &Operation) -> Result<(), &'static str> {
        let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
            return Ok(());
        };

        if kind == arkret_wire::EventKind::RelationCreate {
            let payload =
                serde_json::from_value::<RelationCreatePayload>(operation.payload.clone())
                    .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            let relation = serde_json::to_value(&payload.relation)
                .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            let relation_kind = payload.relation.relation_kind.as_str();
            Self::check_relation_direct_write(
                relation_kind,
                payload.relation.from_ref.as_object_ref(),
            )?;
            validate_relation_endpoint_shape(&relation, relation_kind)?;
            self.check_relation_cross_realm(operation)?;
            self.check_relation_effective_scope(
                operation.realm_id.as_str(),
                &relation,
                relation_kind,
            )?;
            return Ok(());
        }

        if kind == arkret_wire::EventKind::RelationUpdate {
            let payload =
                serde_json::from_value::<RelationUpdatePayload>(operation.payload.clone())
                    .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            let relation_id = payload.relation_id.as_str();
            let patch = relation_update_patch(&operation.payload);
            if let Some(patch) = patch {
                validate_patch_semantic_safety(patch, Some("relation"))?;
            }
            let Some(relation) = self.relations.get(relation_id) else {
                return Err(arkret_wire::ErrorCode::FAILED_PRECONDITION);
            };
            if !relation.is_active()
                || !relation_primary_domain_matches(&payload.primary_conflict_domain, relation)
                || self
                    .relation_current
                    .get(&(
                        operation.realm_id.to_string(),
                        relation_primary_domain_key(&payload.primary_conflict_domain),
                    ))
                    .map(String::as_str)
                    != Some(relation_id)
            {
                return Err(arkret_wire::ErrorCode::FAILED_PRECONDITION);
            }
            // The stored Relation decides first: an update that only touches
            // `fields` still MUST NOT land on an edge the derived projection
            // owns.
            Self::check_relation_direct_write(
                relation.relation_kind.as_str(),
                relation.from_object_ref(),
            )?;
            // Identity is create-locked by the typed payload. The mutable
            // scope still has to satisfy the endpoint scope floor.
            let mut patched = relation.clone();
            if let Some(patch) = patch {
                apply_relation_patch(&mut patched, patch);
            }
            Self::check_relation_direct_write(
                patched.relation_kind.as_str(),
                patched.from_object_ref(),
            )?;
            let relation_kind = patched.relation_kind.clone();
            validate_relation_endpoint_shape(
                &relation_scope_check_object(&patched),
                &relation_kind,
            )?;
            self.check_relation_effective_scope(
                operation.realm_id.as_str(),
                &relation_scope_check_object(&patched),
                &relation_kind,
            )?;
            return Ok(());
        }

        if kind == arkret_wire::EventKind::RelationTombstone {
            let payload =
                serde_json::from_value::<RelationTombstonePayload>(operation.payload.clone())
                    .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            let relation_id = payload.relation_id.as_str();
            let Some(relation) = self.relations.get(relation_id) else {
                return Err(arkret_wire::ErrorCode::FAILED_PRECONDITION);
            };
            if !relation.is_active()
                || !relation_primary_domain_matches(&payload.primary_conflict_domain, relation)
                || self
                    .relation_current
                    .get(&(
                        operation.realm_id.to_string(),
                        relation_primary_domain_key(&payload.primary_conflict_domain),
                    ))
                    .map(String::as_str)
                    != Some(relation_id)
            {
                return Err(arkret_wire::ErrorCode::FAILED_PRECONDITION);
            }
            Self::check_relation_direct_write(
                relation.relation_kind.as_str(),
                relation.from_object_ref(),
            )?;
        }
        Ok(())
    }

    pub(crate) fn apply_relation_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        let Ok(payload) =
            serde_json::from_value::<RelationUpdatePayload>(operation.payload.clone())
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let relation_id = payload.relation_id.to_string();
        if relation_id.is_empty() {
            return ProjectionEffect::Ignored;
        }
        if let Err(reason) = self.check_relation_invariants(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        // Patch-merge on the existing relation. If the relation does not yet
        // exist locally (out-of-order replication), retain the update for
        // pending replay when the create is backfilled.
        let Some(existing_relation) = self.relations.get(&relation_id) else {
            return self.queue_pending_replay(relation_id, operation, "relation_unknown");
        };
        let patch = relation_update_patch(&operation.payload).cloned();
        let mut candidate_relation = existing_relation.clone();
        if let Some(patch) = &patch {
            apply_relation_patch(&mut candidate_relation, patch);
        }
        let relation = self
            .relations
            .get_mut(&relation_id)
            .expect("relation state exists after immutable lookup");
        if let Some(patch) = &patch {
            apply_relation_patch(relation, patch);
        }
        relation.updated_at = now;
        self.relation_current_metadata.remove(&(
            operation.realm_id.to_string(),
            relation_primary_domain_key(&payload.primary_conflict_domain),
        ));
        ProjectionEffect::RelationUpdated(
            self.relations
                .get(&relation_id)
                .cloned()
                .expect("relation state exists"),
        )
    }

    pub(crate) fn apply_relation_delete(&mut self, operation: &Operation) -> ProjectionEffect {
        let Ok(payload) =
            serde_json::from_value::<RelationTombstonePayload>(operation.payload.clone())
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let relation_id = payload.relation_id.to_string();

        if relation_id.is_empty() {
            return ProjectionEffect::Ignored;
        }
        if let Err(reason) = self.check_relation_invariants(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let Some(relation) = self.relations.get_mut(&relation_id) else {
            return self.queue_pending_replay(relation_id, operation, "relation_unknown");
        };
        {
            relation.state = "tombstoned".to_owned();
            relation.updated_at = operation.created_at;
        }
        self.relation_current_metadata.remove(&(
            operation.realm_id.to_string(),
            relation_primary_domain_key(&payload.primary_conflict_domain),
        ));
        ProjectionEffect::RelationDeleted { relation_id }
    }
}

/// The `relation` object a `relation_create_payload` carries.
fn relation_scope_circle_id(relation: &Value) -> Option<String> {
    relation
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:circle:"))
        .map(ToOwned::to_owned)
}

/// The `ak.schema.patch.v1` document an `ak.relation.update` carries. It is the
/// only expression of change the payload schema admits.
fn relation_update_patch(payload: &Value) -> Option<&serde_json::Map<String, Value>> {
    payload.get("patch").and_then(Value::as_object)
}

fn validate_relation_endpoint_shape(relation: &Value, kind: &str) -> Result<(), &'static str> {
    let parse = |name: &str| {
        relation
            .get(name)
            .cloned()
            .ok_or("relation_endpoint_invalid")
            .and_then(|value| {
                serde_json::from_value::<RelationEndpoint>(value)
                    .map_err(|_| "relation_endpoint_invalid")
            })
    };
    let from = parse("from_ref")?;
    let to = parse("to_ref")?;
    if kind == "assigned_to"
        && (to.as_actor_id().is_none()
            || !from
                .as_object_ref()
                .is_some_and(|value| value.starts_with("ak:strand:")))
    {
        return Err("relation_endpoint_invalid");
    }
    Ok(())
}

/// Apply an `ak.schema.patch.v1` patch to a materialized Relation.
///
/// Identity paths are excluded by the typed payload. Only
/// `scope_circle_id`, `rank`, and edge metadata under `fields` are mutable.
fn apply_relation_patch(
    relation: &mut ColandRelationState,
    patch: &serde_json::Map<String, Value>,
) {
    if let Some(scope_circle_id) = patch_string_value(patch, "scope_circle_id") {
        relation.scope_circle_id = scope_circle_id.filter(|value| value.starts_with("ak:circle:"));
    }
    if let Some(rank) = patch_string_value(patch, "rank") {
        relation.rank = rank;
    }
    apply_morph_fields_patch(&mut relation.fields, patch);
}

fn relation_primary_domain_key(domain: &RelationPrimaryConflictDomain) -> String {
    arkret_canonical::canonical_json_string(domain)
        .expect("validated Relation primary conflict domain canonicalizes")
}

fn relation_primary_domain_matches(
    domain: &RelationPrimaryConflictDomain,
    relation: &ColandRelationState,
) -> bool {
    domain.relation_kind.as_str() == relation.relation_kind
        && Some(&domain.from_ref) == relation.from_ref.as_ref()
        && match domain.domain_kind {
            arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomainKind::Tuple => {
                domain.to_ref.as_ref() == relation.to_ref.as_ref()
            }
            arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomainKind::From => {
                domain.to_ref.is_none()
            }
        }
}

/// Render a materialized Relation into the `{from_ref, to_ref,
/// scope_circle_id}` object shape `check_relation_effective_scope` reads, so
/// the create path and the post-patch update path share one scope check.
fn relation_scope_check_object(relation: &ColandRelationState) -> Value {
    let mut object = serde_json::Map::new();
    if let Some(from_ref) = &relation.from_ref {
        object.insert(
            "from_ref".to_owned(),
            serde_json::to_value(from_ref).expect("typed Relation endpoint serializes"),
        );
    }
    if let Some(to_ref) = &relation.to_ref {
        object.insert(
            "to_ref".to_owned(),
            serde_json::to_value(to_ref).expect("typed Relation endpoint serializes"),
        );
    }
    if let Some(scope_circle_id) = &relation.scope_circle_id {
        object.insert(
            "scope_circle_id".to_owned(),
            Value::String(scope_circle_id.clone()),
        );
    }
    Value::Object(object)
}

/// Whether this endpoint names a projected object whose existence the reducer
/// must resolve. Only a canonical typed id can: a value that is not a valid id
/// of one of these kinds never resolves to a projection row.
fn relation_endpoint_needs_projection(endpoint: &str) -> bool {
    arkret_identifiers::SpaceId::new(endpoint).is_ok()
        || arkret_identifiers::StrandId::new(endpoint).is_ok()
        || arkret_identifiers::MorphId::new(endpoint).is_ok()
        || arkret_identifiers::RelationId::new(endpoint).is_ok()
        || arkret_identifiers::EventId::new(endpoint).is_ok()
        || arkret_identifiers::MessageId::new(endpoint).is_ok()
}

fn relation_event_digest(operation: &Operation) -> String {
    operation.context.canonical_event_digest.to_string()
}

#[cfg(test)]
mod relation_primary_domain_tests {
    use serde_json::{Value, json};

    use super::*;

    const REALM: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const FROM: &str = "ak:realm:AaI4Pi7YjaMfo9_Oldm1_7Gl7z-mO6uU0oL8ZWvRl8uZ";
    const TO: &str = "ak:realm:ATu1E_hCvaxzpXDswPMlN3ypwETWAa7O994Etg387rA6";
    const REVISION_COMMIT: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

    fn domain() -> Value {
        json!({
            "domain_kind": "tuple",
            "relation_kind": "references",
            "from_ref": FROM,
            "to_ref": TO
        })
    }

    fn operation(kind: arkret_wire::EventKind, suffix: &str, payload: Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{suffix}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM.to_owned()).unwrap(),
            kind.as_str(),
            payload,
        )
    }

    fn create(suffix: &str, expected_revision: Value) -> Operation {
        operation(
            arkret_wire::EventKind::RelationCreate,
            suffix,
            json!({
                "primary_conflict_domain": domain(),
                "expected_revision": expected_revision,
                "relation": {
                    "relation_kind": "references",
                    "from_ref": FROM,
                    "to_ref": TO,
                    "rank": "A1",
                    "fields": {"label": format!("original-{suffix}")}
                }
            }),
        )
    }

    fn revision(position: u64) -> Value {
        json!({"commit_id": REVISION_COMMIT, "stream_position": position})
    }

    #[test]
    fn active_primary_domain_rejects_second_create_without_review_state() {
        let mut projection = ProjectionState::default();
        let now = chrono::Utc::now();
        let first = create("000000000001", Value::Null);
        let first_id =
            arkret_identifiers::RelationId::from_event_id(&first.context.event_id).to_string();
        assert!(matches!(
            projection.apply_relation_create(&first, now),
            ProjectionEffect::RelationCreated(_)
        ));

        let second = create("000000000002", Value::Null);
        assert!(matches!(
            projection.apply_relation_create(&second, now),
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_wire::ErrorCode::FAILED_PRECONDITION
        ));
        assert_eq!(projection.relations.len(), 1);
        assert_eq!(projection.relations[&first_id].state, "active");
    }

    #[test]
    fn corrupt_current_domain_rejects_create() {
        let now = chrono::Utc::now();
        let candidate = create("000000000011", Value::Null);
        let payload =
            serde_json::from_value::<RelationCreatePayload>(candidate.payload.clone()).unwrap();
        let key = (
            REALM.to_owned(),
            relation_primary_domain_key(&payload.primary_conflict_domain),
        );

        let mut missing_row = ProjectionState::default();
        missing_row
            .relation_current
            .insert(key.clone(), "ak:relation:missing".to_owned());
        assert!(matches!(
            missing_row.apply_relation_create(&candidate, now),
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_wire::ErrorCode::FAILED_PRECONDITION
        ));
        assert!(missing_row.relations.is_empty());

        let mut legacy = ProjectionState::default();
        let first = create("000000000012", Value::Null);
        assert_ne!(first.context.event_id, candidate.context.event_id);
        let first_id =
            arkret_identifiers::RelationId::from_event_id(&first.context.event_id).to_string();
        legacy.apply_relation_create(&first, now);
        legacy.relations.get_mut(&first_id).unwrap().state = "invalid_state".to_owned();
        assert!(matches!(
            legacy.apply_relation_create(&candidate, now),
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_wire::ErrorCode::FAILED_PRECONDITION
        ));
        assert_eq!(legacy.relations.len(), 1);
    }

    #[test]
    fn missing_current_domain_index_rejects_update_and_tombstone_without_mutation() {
        let mut projection = ProjectionState::default();
        let now = chrono::Utc::now();
        let create = create("000000000003", Value::Null);
        let relation_id =
            arkret_identifiers::RelationId::from_event_id(&create.context.event_id).to_string();
        projection.apply_relation_create(&create, now);
        projection.relation_current.clear();
        let before = projection.relations[&relation_id].clone();

        let update = operation(
            arkret_wire::EventKind::RelationUpdate,
            "000000000004",
            json!({
                "primary_conflict_domain": domain(),
                "expected_revision": revision(1),
                "patch": {"fields.label": "changed"},
                "relation_id": relation_id
            }),
        );
        assert!(matches!(
            projection.apply_relation_update(&update, now, &ServerHlc::new("relation-test")),
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_wire::ErrorCode::FAILED_PRECONDITION
        ));

        let tombstone = operation(
            arkret_wire::EventKind::RelationTombstone,
            "000000000005",
            json!({
                "primary_conflict_domain": domain(),
                "expected_revision": revision(1),
                "relation_id": relation_id
            }),
        );
        assert!(matches!(
            projection.apply_relation_delete(&tombstone),
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_wire::ErrorCode::FAILED_PRECONDITION
        ));
        let after = &projection.relations[&relation_id];
        assert_eq!(after.fields, before.fields);
        assert_eq!(after.state, before.state);
        assert_eq!(after.updated_at, before.updated_at);
    }

    #[test]
    fn missing_relation_rejects_update_and_tombstone() {
        let projection = ProjectionState::default();
        let missing_id = "ak:relation:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4";
        for operation in [
            operation(
                arkret_wire::EventKind::RelationUpdate,
                "000000000009",
                json!({
                    "primary_conflict_domain": domain(),
                    "expected_revision": revision(1),
                    "patch": {"fields.label": "changed"},
                    "relation_id": missing_id
                }),
            ),
            operation(
                arkret_wire::EventKind::RelationTombstone,
                "000000000010",
                json!({
                    "primary_conflict_domain": domain(),
                    "expected_revision": revision(1),
                    "relation_id": missing_id
                }),
            ),
        ] {
            assert_eq!(
                projection.check_relation_invariants(&operation),
                Err(arkret_wire::ErrorCode::FAILED_PRECONDITION)
            );
        }
        assert!(projection.relations.is_empty());
        assert!(projection.relation_current.is_empty());
    }

    #[test]
    fn tombstoned_domain_can_create_new_event_derived_relation_id() {
        let mut projection = ProjectionState::default();
        let now = chrono::Utc::now();
        let first = create("000000000006", Value::Null);
        let first_id =
            arkret_identifiers::RelationId::from_event_id(&first.context.event_id).to_string();
        projection.apply_relation_create(&first, now);
        let tombstone = operation(
            arkret_wire::EventKind::RelationTombstone,
            "000000000007",
            json!({
                "primary_conflict_domain": domain(),
                "expected_revision": revision(1),
                "relation_id": first_id
            }),
        );
        assert!(matches!(
            projection.apply_relation_delete(&tombstone),
            ProjectionEffect::RelationDeleted { .. }
        ));

        let replacement = create("000000000008", revision(2));
        let replacement_id =
            arkret_identifiers::RelationId::from_event_id(&replacement.context.event_id)
                .to_string();
        assert!(matches!(
            projection.apply_relation_create(&replacement, now),
            ProjectionEffect::RelationCreated(_)
        ));
        assert_ne!(replacement_id, first_id);
        assert_eq!(projection.relations[&first_id].state, "tombstoned");
        assert_eq!(projection.relations[&replacement_id].state, "active");
    }
}

#[cfg(test)]
mod relation_endpoint_typing_tests {
    use super::*;

    const EVENT_A: &str = "ak:event:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D";
    const STRAND: &str = "ak:strand:ATXlnYLuNA5AB7Pide0IGeEtDJ6YeQ19_FUbKXtjQhum";

    #[test]
    fn only_canonical_endpoints_are_resolved_against_projections() {
        assert!(relation_endpoint_needs_projection(EVENT_A));
        assert!(relation_endpoint_needs_projection(STRAND));
        assert!(!relation_endpoint_needs_projection("ak:event:not-a-token"));
        assert!(!relation_endpoint_needs_projection("ak:strand:main"));
    }
}
