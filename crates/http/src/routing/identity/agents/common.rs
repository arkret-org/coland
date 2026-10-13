#[cfg(test)]
use arkret_wire::CapabilityActionId;

use super::*;

/// Narrow internal execution context used only after the caller has authenticated
/// the deployment S2S credential. Bind the exact controller Account here; the
/// handler still validates its ownership against the authoritative Agent record.
pub(super) async fn controller_service_session(
    controller_account: &arkret_wire::AccountId,
    device_id: &str,
    state: &AppState,
) -> Result<SessionRecord, AppError> {
    if controller_account.station_id != state.service_core_id() {
        return Err(AppError::capability_denied(
            "delegated pairing controller must belong to this Station",
        ));
    }
    let account = state
        .identities()
        .account(controller_account)
        .await
        .map_err(|error| AppError::internal(format!("controller account lookup failed: {error}")))?
        .ok_or_else(|| AppError::unauthenticated("controller account no longer exists"))?;
    if &account.account_id != controller_account
        || account.principal_id != controller_account.principal_id
    {
        return Err(AppError::unauthenticated(
            "delegated pairing must bind the exact stored controller Account",
        ));
    }
    Ok(SessionRecord {
        token_hash: format!("agent-pair-commit:{}", controller_account.principal_id),
        account_pk: Some(account.pk),
        actor: controller_account.principal_id.to_string(),
        endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
            device_id: device_id.to_owned(),
        },
        audience: state.service_id().clone(),
        session_public_key: None,
        session_grant: None,
        expires_at: now() + chrono::Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    })
}

pub(super) fn validate_agent_id(value: &str) -> Result<(), AppError> {
    arkret_wire::DidCoreId::new(value.to_owned())
        .map(|_| ())
        .map_err(|_| AppError::param_invalid("agent_id must be a Core DidCoreId"))
}

pub(super) fn ensure_agent_record_controller(
    record: &AgentPrincipalRecord,
    agent_id: &str,
    session: &SessionRecord,
) -> Result<(), AppError> {
    if record.id != agent_id {
        return Err(AppError::capability_denied(
            "agent principal record does not match the requested principal",
        ));
    }
    if record.controller_principal_id.trim().is_empty() {
        return Err(AppError::capability_denied(
            "agent principal has no controller binding",
        ));
    }
    if record.controller_principal_id != session.actor {
        return Err(AppError::capability_denied(
            "agent principal is not controlled by the authenticated session",
        ));
    }
    if !agent_record_is_materialized(record) {
        return Err(AppError::capability_denied(
            "Agent provisioning has not completed its DID/PCR bootstrap binding",
        ));
    }
    Ok(())
}

pub(super) fn agent_record_is_materialized(record: &AgentPrincipalRecord) -> bool {
    record
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs.get("did_binding_accepted"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) fn agent_runtime_scope_error(
    reason: arkret_wire::ReasonCode,
    message: impl Into<String>,
) -> AppError {
    crate::app_error!(FailedPrecondition, message).with_reason_code(reason.as_str())
}

fn validate_registered_agent_scope_actions(
    scope: &AgentKeyScope,
    layer: arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer,
) -> Result<(), AppError> {
    if let Some(action) = scope.actions.iter().find(|action| {
        arkret_wire::ServiceOperationId::from_wire(action).is_none()
            && arkret_schema::capability_action(action).is_none()
    }) {
        let reason = match layer {
            arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer::Provision => {
                arkret_wire::ReasonCode::AgentProvisionScopeMigrationRequired
            }
            arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer::KeyAuthorization => {
                arkret_wire::ReasonCode::AgentKeyScopeReauthorizationRequired
            }
            arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer::Session => {
                arkret_wire::ReasonCode::AgentSessionScopeRefreshRequired
            }
        };
        return Err(agent_runtime_scope_error(
            reason,
            format!("Agent {layer:?} scope contains unregistered action {action}"),
        ));
    }
    Ok(())
}

fn map_agent_runtime_deficiency(
    deficiency: arkret_schema::agent_runtime_scope::AgentRuntimeScopeDeficiency,
) -> AppError {
    agent_runtime_scope_error(
        deficiency.reason,
        format!(
            "Agent {:?} scope omits mandatory runtime operations: {}",
            deficiency.layer,
            deficiency.missing_operations.join(", ")
        ),
    )
}

/// Validate a proposed immutable Agent provision ceiling before reservation.
pub(super) fn validate_agent_runtime_provision_scope(
    provision_scope: &AgentKeyScope,
) -> Result<(), AppError> {
    use arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer;

    validate_registered_agent_scope_actions(provision_scope, AgentRuntimeScopeLayer::Provision)?;
    let deficiency = arkret_schema::agent_runtime_scope::assess_agent_runtime_provision_scope(
        &provision_scope.actions,
    )
    .map_err(|_| {
        agent_runtime_scope_error(
            arkret_wire::ReasonCode::AgentProvisionScopeMigrationRequired,
            "generated Agent runtime provision registry is inconsistent",
        )
    })?;
    deficiency.map_or(Ok(()), |value| Err(map_agent_runtime_deficiency(value)))
}

/// Validate a proposed key ceiling against the immutable provision selection.
pub(super) fn validate_agent_runtime_key_scopes(
    provision_scope: &AgentKeyScope,
    key_scope: &AgentKeyScope,
) -> Result<(), AppError> {
    use arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer;

    validate_agent_runtime_provision_scope(provision_scope)?;
    validate_registered_agent_scope_actions(key_scope, AgentRuntimeScopeLayer::KeyAuthorization)?;
    let deficiency = arkret_schema::agent_runtime_scope::assess_agent_runtime_key_scopes(
        &provision_scope.actions,
        &key_scope.actions,
    )
    .map_err(|_| {
        agent_runtime_scope_error(
            arkret_wire::ReasonCode::AgentKeyScopeReauthorizationRequired,
            "generated Agent runtime key registry is inconsistent",
        )
    })?;
    deficiency.map_or(Ok(()), |value| Err(map_agent_runtime_deficiency(value)))
}

pub(super) async fn require_agent_controller(
    state: &AppState,
    session: &SessionRecord,
    agent_id: &str,
) -> Result<AgentPrincipalRecord, AppError> {
    validate_agent_id(agent_id)?;
    let record = state
        .agent_pairings()
        .agent(agent_id)
        .await
        .map_err(|err| AppError::internal(format!("agent controller lookup failed: {err}")))?
        .ok_or_else(|| AppError::capability_denied("agent principal has no controller binding"))?;
    ensure_agent_record_controller(&record, agent_id, session)?;
    Ok(record)
}

fn requested_scope_actions(record: &AgentPrincipalRecord) -> BTreeSet<&str> {
    record
        .requested_scope
        .as_ref()
        .and_then(|scope| scope.get("actions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn is_content_scope_kind(kind: Option<&str>) -> bool {
    matches!(
        kind,
        Some(
            "realm"
                | "space"
                | "circle"
                | "strand"
                | "message"
                | "morph"
                | "object"
                | "relation"
                | "view"
                | "event"
                | "actor"
                | "schema"
                | "policy"
                | "invite"
                | "notification"
                | "read_cursor"
                | "blob"
        )
    )
}

fn scope_resource_ref(resource: &Value) -> Option<&Value> {
    resource
        .get("resource_ref")
        .or_else(|| resource.get("space_id"))
        .or_else(|| resource.get("circle_id"))
        .or_else(|| resource.get("strand_id"))
        .or_else(|| resource.get("message_id"))
        .or_else(|| resource.get("morph_id"))
        .or_else(|| resource.get("object_ref"))
        .or_else(|| resource.get("relation_id"))
        .or_else(|| resource.get("view_id"))
        .or_else(|| resource.get("event_id"))
        .or_else(|| resource.get("actor_id"))
        .or_else(|| resource.get("policy_id"))
        .or_else(|| resource.get("invite_id"))
        .or_else(|| resource.get("blob_ref"))
}

fn scope_resource_selector_covers(ceiling: &Value, resource: &Value) -> bool {
    let ceiling_kind = ceiling.get("kind").and_then(Value::as_str);
    let resource_kind = resource.get("kind").and_then(Value::as_str);
    let kind_covers = ceiling_kind == resource_kind
        || (ceiling_kind == Some("realm") && is_content_scope_kind(resource_kind));
    if !kind_covers {
        return false;
    }
    if ceiling
        .get("realm_id")
        .is_some_and(|value| resource.get("realm_id") != Some(value))
    {
        return false;
    }
    match ceiling_kind {
        Some("operation") => ceiling
            .get("operation")
            .is_none_or(|value| resource.get("operation") == Some(value)),
        Some("service") => ceiling
            .get("service_id")
            .is_none_or(|value| resource.get("service_id") == Some(value)),
        Some("schema") => ceiling
            .get("schema_ref")
            .is_none_or(|value| resource.get("schema_ref") == Some(value)),
        _ => scope_resource_ref(ceiling)
            .is_none_or(|value| scope_resource_ref(resource) == Some(value)),
    }
}

fn scope_resources_within_requested_scope(requested_scope: &Value, resources: &[Value]) -> bool {
    let ceilings = requested_scope
        .get("resources")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let has_content_ceiling = ceilings
        .iter()
        .any(|ceiling| is_content_scope_kind(ceiling.get("kind").and_then(Value::as_str)));
    resources.iter().all(|resource| {
        let resource_kind = resource.get("kind").and_then(Value::as_str);
        (is_content_scope_kind(resource_kind) && !has_content_ceiling)
            || ceilings
                .iter()
                .any(|ceiling| scope_resource_selector_covers(ceiling, resource))
    })
}

fn constraints_preserve_requested_scope(requested_scope: &Value, constraints: &[Value]) -> bool {
    let mandatory = requested_scope
        .get("constraints")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    mandatory
        .iter()
        .all(|constraint| constraints.contains(constraint))
}

/// A per-key scope may narrow, but never widen, the immutable provision scope.
pub(crate) fn agent_key_scope_within_requested_scope(
    record: &AgentPrincipalRecord,
    scope: &Value,
) -> bool {
    let Some(requested_scope) = record.requested_scope.as_ref() else {
        return false;
    };
    let Some(actions) = scope.get("actions").and_then(Value::as_array) else {
        return false;
    };
    let Some(resources) = scope.get("resources").and_then(Value::as_array) else {
        return false;
    };
    let constraints = scope
        .get("constraints")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let requested_actions = requested_scope_actions(record);
    actions.iter().all(|action| {
        action
            .as_str()
            .is_some_and(|action| requested_actions.contains(action))
    }) && scope_resources_within_requested_scope(requested_scope, resources)
        && constraints_preserve_requested_scope(requested_scope, constraints)
}

/// Enforce the immutable provisioning ceiling during ordinary
/// `ak.capability.grant` Event admission.
pub(crate) fn agent_grant_within_requested_scope(
    record: &AgentPrincipalRecord,
    actions: &[String],
    resources: &[arkret_wire::resource_selector::WireResourceSelector],
    constraints: &[arkret_models_collaboration::governance::grant_constraint::GrantConstraint],
) -> bool {
    record
        .requested_scope
        .as_ref()
        .and_then(|scope| {
            serde_json::from_value::<
                arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
            >(scope.clone())
            .ok()
        })
        .is_some_and(|scope| {
            arkret_models_collaboration::agent_scope::agent_grant_scope_within_provision(
                &scope,
                actions,
                resources,
                constraints,
            )
            .unwrap_or(false)
        })
}

/// Project the DID of a verification method DID URL onto its Core
/// identity (`key-management.md` §7.4.1): the controller equals an `actor_id`
/// only after method-adapter projection. A controller that is not a DID —
/// including a core `ak:did_core:` id concatenated with a fragment — projects
/// to `None` and can never match.
pub(super) fn verification_method_principal(
    verification_method: &str,
) -> Option<arkret_identifiers::DidCoreId> {
    let did = arkret_identity::verification_method_did(verification_method).ok()?;
    arkret_wire::project_did_to_core_id(&did).ok()
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "scope tests stay adjacent to the private scope helpers"
)]
mod requested_scope_tests {
    use super::*;

    fn record_with_scope(scope: Value) -> AgentPrincipalRecord {
        let mut record = AgentPrincipalRecord::new(
            "ak:did_core:web:agent.example".to_owned(),
            "ak:did_core:web:controller.example".to_owned(),
            "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX".to_owned(),
            arkret_wire::DidUrl::new("did:web:controller.example#controller").unwrap(),
            AgentLifecycleState::Active,
            chrono::Utc::now(),
        );
        record.requested_scope = Some(scope);
        record
    }

    fn resource(value: Value) -> arkret_wire::resource_selector::WireResourceSelector {
        serde_json::from_value(value).unwrap()
    }

    fn scope(actions: &[&str]) -> AgentKeyScope {
        AgentKeyScope {
            actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            resources: Vec::new(),
            constraints: Vec::new(),
        }
    }

    #[test]
    fn unknown_scope_action_fails_closed_before_admission() {
        let error = validate_agent_runtime_provision_scope(&scope(&[
            "ak.self.events.read.future_unregistered.v1",
        ]))
        .unwrap_err();
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::AGENT_PROVISION_SCOPE_MIGRATION_REQUIRED)
        );
    }

    #[test]
    fn realm_grant_actions_cannot_exceed_provision_ceiling() {
        let record = record_with_scope(json!({
            "actions": [CapabilityActionId::MESSAGE_CREATE, CapabilityActionId::REACTION_ADD],
            "resources": []
        }));

        assert!(agent_grant_within_requested_scope(
            &record,
            &[CapabilityActionId::MESSAGE_CREATE.to_owned()],
            &[],
            &[],
        ));
        assert!(!agent_grant_within_requested_scope(
            &record,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &[],
            &[],
        ));
    }

    #[test]
    fn explicit_content_resources_narrow_later_realm_grants() {
        let record = record_with_scope(json!({
            "actions": [CapabilityActionId::EVENT_READ],
            "resources": [{
                "kind": "realm",
                "realm_id": "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX"
            }]
        }));
        assert!(agent_grant_within_requested_scope(
            &record,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &[resource(json!({
                "kind": "strand",
                "realm_id": "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX",
                "strand_id": "ak:strand:AXlnhO71nCU_y9RTHGx2TeHh9MFM1lET2qISAIeB4lI7"
            }))],
            &[]
        ));
        assert!(!agent_grant_within_requested_scope(
            &record,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &[resource(json!({
                "kind": "realm",
                "realm_id": "ak:realm:AcfJ22TN854ffqakmmJoe3b28anqpie2rFilRgurW7wC"
            }))],
            &[]
        ));

        let realm_wide_strand_ceiling = record_with_scope(json!({
            "actions": [CapabilityActionId::EVENT_READ],
            "resources": [{
                "kind": "strand",
                "realm_id": "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX"
            }]
        }));
        assert!(agent_grant_within_requested_scope(
            &realm_wide_strand_ceiling,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &[resource(json!({
                "kind": "strand",
                "realm_id": "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX",
                "strand_id": "ak:strand:AXlnhO71nCU_y9RTHGx2TeHh9MFM1lET2qISAIeB4lI7"
            }))],
            &[]
        ));

        let global_strand_ceiling = record_with_scope(json!({
            "actions": [CapabilityActionId::EVENT_READ],
            "resources": [{ "kind": "strand" }]
        }));
        assert!(agent_grant_within_requested_scope(
            &global_strand_ceiling,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &[resource(json!({
                "kind": "strand",
                "realm_id": "ak:realm:AcfJ22TN854ffqakmmJoe3b28anqpie2rFilRgurW7wC",
                "strand_id": "ak:strand:AXlnhO71nCU_y9RTHGx2TeHh9MFM1lET2qISAIeB4lI7"
            }))],
            &[]
        ));

        let circle_ceiling = record_with_scope(json!({
            "actions": [CapabilityActionId::EVENT_READ],
            "resources": [{
                "kind": "circle",
                "realm_id": "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX",
                "resource_ref": "ak:circle:AfIEekeSLx-Ai7SaUc0Xi2ia757PQNByOFKfeuSIpLNw"
            }]
        }));
        assert!(agent_grant_within_requested_scope(
            &circle_ceiling,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &[resource(json!({
                "kind": "circle",
                "realm_id": "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX",
                "circle_id": "ak:circle:AfIEekeSLx-Ai7SaUc0Xi2ia757PQNByOFKfeuSIpLNw"
            }))],
            &[]
        ));
        assert!(!agent_grant_within_requested_scope(
            &circle_ceiling,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &[resource(json!({
                "kind": "circle",
                "realm_id": "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX",
                "circle_id": "ak:circle:AcnPOZq8RRwOX2ep1JRrdBjYFCyVhwQeG8N3_N3YkArT"
            }))],
            &[]
        ));
    }

    #[test]
    fn realm_grant_must_preserve_provision_constraints() {
        let mut mandatory = arkret_models_collaboration::governance::grant_constraint::GrantConstraint::new(
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::ClaimBased,
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintEffect::Allow,
        );
        mandatory.constraint_subkind = Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind::Approval);
        mandatory.controller_approval_required = Some(true);
        let mandatory_value = serde_json::to_value(&mandatory).unwrap();
        let record = record_with_scope(json!({
            "actions": [CapabilityActionId::EVENT_READ],
            "resources": [{
                "kind": "operation",
                "operation": "ak.self.committed_event.stream.subscribe.v1"
            }],
            "constraints": [mandatory_value]
        }));
        let resources = [resource(json!({
            "kind": "strand",
            "realm_id": "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX",
            "strand_id": "ak:strand:AXlnhO71nCU_y9RTHGx2TeHh9MFM1lET2qISAIeB4lI7"
        }))];

        assert!(agent_grant_within_requested_scope(
            &record,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &resources,
            &[mandatory]
        ));
        assert!(!agent_grant_within_requested_scope(
            &record,
            &[CapabilityActionId::EVENT_READ.to_owned()],
            &resources,
            &[]
        ));
    }
}

/// Project a persisted agent_principal JSON record into the spec
/// `agent_projection` shape (`agent-operations.schema.json#/$defs/agent_projection`):
/// `{agent_id, display_name?, slug, avatar_blob_ref?, status, created_at?, updated_at?}`.
/// Coland-internal columns (`controller_principal_id`, `pairing_*`) are NOT
/// part of the protocol projection and are dropped at the wire boundary; the
/// persistence `state` column carries the `agent_status` enum value verbatim.
/// The controller lifecycle intent axis (`status`, key-management.md §3.6.1).
/// The persisted `state` column carries only the closed lifecycle enum
/// (`active | paused | deactivated`); pairing progress lives on the orthogonal
/// derived `runtime_state` axis and is never stored here.
pub(super) fn agent_lifecycle_from_record(record: &AgentPrincipalRecord) -> AgentLifecycleState {
    record.state
}

pub(super) fn projected_agent_lifecycle(
    local_intent: AgentLifecycleState,
    accepted: Option<AgentLifecycleState>,
) -> Result<AgentLifecycleState, AppError> {
    let accepted = accepted.ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "Agent accepted lifecycle is unavailable"
        )
    })?;
    Ok(match (local_intent, accepted) {
        (AgentLifecycleState::Deactivated, _) | (_, AgentLifecycleState::Deactivated) => {
            AgentLifecycleState::Deactivated
        }
        (AgentLifecycleState::Paused, _) | (_, AgentLifecycleState::Paused) => {
            AgentLifecycleState::Paused
        }
        (AgentLifecycleState::Active, AgentLifecycleState::Active) => AgentLifecycleState::Active,
    })
}

/// Whether the record carries a live (unconsumed, unexpired) pairing handle for
/// a non-terminal agent.
pub(super) fn agent_pairing_handle_live(
    record: &AgentPrincipalRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    agent_lifecycle_from_record(record) != AgentLifecycleState::Deactivated
        && agent_pairing_handle_is_open(record)
        && record
            .pairing_expires_at
            .is_some_and(|expires_at| expires_at > now)
}

/// The sole derivation of the read-only runtime readiness axis for a persisted
/// agent (key-management.md §3.6.1). `has_active_authorization` is whether the
/// reducer projection currently holds an active accepted `ak.agent.key.authorize`
/// for the agent; the open-handle fact comes from the record. Both server and
/// clients route every projection through `AgentRuntimeState::derive`.
pub(super) fn agent_runtime_state_from_record(
    record: &AgentPrincipalRecord,
    has_active_authorization: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> AgentRuntimeState {
    AgentRuntimeState::derive(
        has_active_authorization,
        agent_pairing_handle_live(record, now),
    )
}

pub(super) fn agent_projection_from_record(
    record: &AgentPrincipalRecord,
    runtime_state: AgentRuntimeState,
) -> AgentProjection {
    let lifecycle = agent_lifecycle_from_record(record);
    let (readiness_state, blockers) = match (lifecycle, runtime_state) {
        (_, AgentRuntimeState::Ready) => (AgentReadinessState::Ready, Vec::new()),
        (_, AgentRuntimeState::PendingRuntimeKey) => (
            AgentReadinessState::NotReady,
            vec![
                AgentReadinessBlocker::RuntimeKeyMissing,
                AgentReadinessBlocker::PairingOpen,
            ],
        ),
        (_, AgentRuntimeState::Replacing) => (
            AgentReadinessState::NotReady,
            vec![AgentReadinessBlocker::PairingOpen],
        ),
        (_, AgentRuntimeState::PairingExpired) => (
            AgentReadinessState::NotReady,
            vec![AgentReadinessBlocker::RuntimeKeyMissing],
        ),
    };
    let observed_at = chrono::Utc::now();
    AgentProjection {
        agent_id: arkret_wire::DidCoreId::new(record.id.clone())
            .expect("persisted Agent id is a validated core id"),
        display_name: record
            .display_name
            .clone()
            .filter(|value| !value.is_empty()),
        slug: record.agent_slug.clone().unwrap_or_default(),
        avatar_blob_ref: record
            .avatar_blob_ref
            .as_ref()
            .filter(|value| !value.is_empty())
            .and_then(|value| BlobRef::new(value.clone()).ok()),
        lifecycle,
        readiness: AgentReadiness {
            state: readiness_state,
            blockers,
        },
        presence: AgentPresence {
            state: AgentPresenceState::Unknown,
            expires_at: observed_at + chrono::Duration::seconds(30),
            refresh_after: observed_at,
        },
        created_at: Some(record.created_at),
        updated_at: Some(record.updated_at),
    }
}

/// Build the spec `agent_view` (`agent-operations.schema.json#/$defs/agent_view`)
/// from a persisted record: `{agent: <agent_projection>, status, grants[], key_state}`.
/// The `agent`/`status` pair is required. `grants` defaults empty here — the
/// `get_agent` read path overlays it from the durable capability projection so
/// the controller sees every unrevoked grant that terminal deactivation must
/// revoke.
pub(super) async fn agent_view_from_record(
    state: &AppState,
    record: &AgentPrincipalRecord,
) -> Result<AgentView, AppError> {
    let (keys, ..) = accepted_agent_key_authorization_snapshot(state, record).await?;
    let realm_id = arkret_wire::RealmId::new(record.principal_control_realm_id.clone())
        .map_err(|error| AppError::internal(format!("persisted Agent PCR is invalid: {error}")))?;
    let agent_id = arkret_wire::DidCoreId::new(record.id.clone())
        .map_err(|error| AppError::internal(format!("persisted Agent DID is invalid: {error}")))?;
    let lifecycle = state
        .authority_commits()
        .current_agent_result(
            &realm_id,
            &arkret_wire::CurrentSelector::AgentStatus { agent_id },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("accepted Agent lifecycle is unavailable: {error}"))
        })?
        .map(|entry| match entry {
            arkret_wire::TypedCurrentRow::Value { value, .. } => {
                serde_json::from_value::<AgentLifecycleState>(value).map_err(|error| {
                    AppError::internal(format!("accepted Agent lifecycle is invalid: {error}"))
                })
            }
        })
        .transpose()?;
    let mut projected_record = record.clone();
    projected_record.state = projected_agent_lifecycle(record.state, lifecycle)?;
    let record = &projected_record;
    let active_authorizations = active_agent_key_authorizations(state, keys).await?;
    let runtime_state = agent_runtime_state_from_record(
        record,
        !active_authorizations.is_empty(),
        chrono::Utc::now(),
    );
    let agent = agent_projection_from_record(record, runtime_state);
    let controller_account_id =
        crate::routing::identity::agent_pcr::agent_controller_account(state, record).await?;
    let key_state = agent_key_state_from_record(
        record,
        controller_account_id,
        active_authorizations,
        runtime_state,
    )?;
    Ok(AgentView {
        agent,
        grants: Vec::new(),
        key_state: Some(key_state),
    })
}

pub(super) fn agent_key_state_from_record(
    record: &AgentPrincipalRecord,
    controller_account_id: arkret_wire::AccountId,
    active_authorizations: Vec<
        arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState,
    >,
    runtime_state: AgentRuntimeState,
) -> Result<KeyState, AppError> {
    let runtime_bindings = record.runtime_bindings().map_err(|error| {
        AppError::internal(format!(
            "persisted Agent runtime binding state is invalid: {error}"
        ))
    })?;
    let requested_scope = record
        .requested_scope
        .clone()
        .ok_or_else(|| AppError::internal("persisted Agent requested_scope is missing"))?;
    let requested_scope = serde_json::from_value(requested_scope).map_err(|error| {
        AppError::internal(format!("persisted Agent scope is invalid: {error}"))
    })?;
    let authorized_event_ref = runtime_bindings
        .active_binding
        .as_ref()
        .map(|binding| binding.authorized_event_ref.clone());
    let authorized_verification_method = runtime_bindings
        .active_binding
        .as_ref()
        .map(|binding| binding.verification_method.clone());
    let authorized_public_key_digest = runtime_bindings
        .active_binding
        .as_ref()
        .map(|binding| binding.public_key_digest.clone());
    let signer_resolution_evidence_ref = runtime_bindings
        .active_binding
        .as_ref()
        .map(|binding| binding.signer_resolution_evidence_ref.clone());
    let current_signer_evidence = runtime_bindings.active_binding.as_ref().map(|binding| {
        arkret_models_collaboration::agent_operations::KeyStateCurrentSignerEvidence {
            signer_resolution_evidence_ref: binding.signer_resolution_evidence_ref.clone(),
            authenticated_signer_evidence: binding.current_signer_evidence.clone(),
        }
    });
    let agent_id = arkret_wire::DidCoreId::new(record.id.clone())
        .map_err(|error| AppError::internal(format!("persisted Agent DID is invalid: {error}")))?;
    if controller_account_id.principal_id.as_str() != record.controller_principal_id {
        return Err(AppError::internal(
            "persisted Agent controller account differs from its immutable principal binding",
        ));
    }
    let pairing_is_open = matches!(
        runtime_state,
        AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
    );
    let open_handle = pairing_is_open
        .then_some(runtime_bindings.open_handle.as_ref())
        .flatten()
        .ok_or_else(|| {
            AppError::internal(
                "derived Agent runtime state requires an open handle, but none is valid",
            )
        })
        .map(Some)
        .or_else(|error| {
            if pairing_is_open {
                Err(error)
            } else {
                Ok(None)
            }
        })?;
    Ok(KeyState {
        agent_id,
        controller_account_id,
        principal_control_realm_id: RealmId::new(record.principal_control_realm_id.clone())
            .map_err(|error| {
                AppError::internal(format!("persisted Agent PCR is invalid: {error}"))
            })?,
        controller_authorization_ref: record.controller_authorization_ref.clone(),
        requested_scope,
        pairing_request_id: open_handle.map(|handle| handle.pairing_request_id.clone()),
        pairing_code: open_handle.map(|handle| handle.pairing_code.clone()),
        pairing_expires_at: open_handle.map(|handle| handle.expires_at),
        approval_request_id: open_handle
            .and_then(|handle| handle.pending_runtime_key_request.as_ref())
            .and(record.approval_request_id.clone()),
        pending_runtime_key_request: open_handle
            .and_then(|handle| handle.pending_runtime_key_request.as_ref())
            .zip(record.approval_request_id.clone())
            .map(|(candidate, approval)| runtime_key_request_for_controller(candidate, approval)),
        approval_requested_at: open_handle
            .and_then(|handle| handle.pending_runtime_key_request.as_ref())
            .and(record.approval_requested_at),
        authorized_event_ref,
        authorized_verification_method,
        authorized_public_key_digest,
        active_authorizations,
        signer_resolution_evidence_ref,
        current_signer_evidence,
    })
}

async fn active_agent_key_authorizations(
    state: &AppState,
    keys: BTreeSet<(String, String)>,
) -> Result<
    Vec<arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState>,
    AppError,
> {
    let mut result = Vec::new();
    for (key_id, event_ref) in keys {
        let event = state
            .event_queries()
            .canonical_event(&event_ref)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| {
                AppError::internal("accepted Agent authorization Event is unavailable")
            })?;
        let payload: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
            serde_json::from_value(event.envelope["payload"].clone())
                .map_err(|error| AppError::internal(error.to_string()))?;
        if payload.key_id.as_str() != key_id {
            return Err(AppError::internal("accepted Agent key id mismatch"));
        }
        result.push(
            arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState {
                verification_method: payload.verification_method,
                key_id: payload.key_id,
                authorized_event_ref: EventId::new(event_ref)
                    .map_err(|error| AppError::internal(error.to_string()))?,
                expires_at: payload.expires_at,
            },
        );
    }
    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────
// AKP-0010 — agent participation policy (set / get).
//
// Stands up the cross-project HTTP contract at the same fidelity as the
// sibling agent handlers (audit-log row + typed response), but performs
// the REAL ceiling check via the shared owner validators so the
// "inner scope MUST NOT exceed the outer ceiling" invariant is enforced
// at the edge. Persistence into `agent_participation`, ceiling
// resolution from the realm/circle/strand policy projection,
// capability-grant materialization (`ak.capability.grant` / `revoke`),
// and the dispatcher mention gate are P2-impl — matching the rest of
// this surface.
// ─────────────────────────────────────────────────────────────────────
