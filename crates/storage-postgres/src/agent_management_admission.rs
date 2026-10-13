//! Management restrictions on concrete actions before grant/quota selection.
use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, Policy, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_policy::agent_management::{AgentManagementContext, evaluate_agent_management};
use arkret_wire::{AccountId, CapabilityActionId, PolicyEffect, RealmId, ServiceOperationId};
use coland_storage::{AuthorizationOperation, PersistenceError, PersistenceResult};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

/// A key/provision scope is a hard ceiling, never a content grant. The caller
/// independently verifies the scope's accepted provenance and ordinary authority.
/// Every supplied action is an actual content action, not an aggregate fallback.
pub(crate) fn require_key_scope_content_ceiling(
    scope: &arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    operation: &AuthorizationOperation<'_>,
) -> PersistenceResult<()> {
    use coland_storage::GrantEvaluation;
    if scope.resources.is_empty()
        || operation.actions.is_empty()
        || scope.actions.iter().any(|action| {
            arkret_schema::capability_action(action).is_none()
                && ServiceOperationId::from_wire(action).is_none()
        })
        || operation.actions.iter().any(|action| {
            arkret_schema::capability_action(action)
                .is_none_or(|descriptor| descriptor.event_mapping_kind == "aggregate_admin")
                || ServiceOperationId::from_wire(action).is_some()
                || !scope.actions.iter().any(|allowed| allowed == action)
        })
        || !concrete_content_target(operation.target)
    {
        return Err(unavailable(
            "Agent content scope action or target is unavailable",
        ));
    }
    let resources = scope
        .resources
        .iter()
        .map(key_scope_content_selector)
        .collect::<PersistenceResult<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let verdict = if resources.is_empty() {
        coland_storage::evaluate_constraint_ceiling(operation, &scope.constraints)
    } else {
        coland_storage::evaluate_resource_constraint_ceiling(
            operation,
            &resources,
            &scope.constraints,
        )
    };
    match verdict {
        GrantEvaluation::Allowed(_) => Ok(()),
        GrantEvaluation::Denied | GrantEvaluation::Unsatisfied | GrantEvaluation::Unnamed => {
            Err(PersistenceError::Conflict(
                "capability_denied: Agent content ceiling is not satisfied".into(),
            ))
        }
        GrantEvaluation::Quarantined | GrantEvaluation::RequiresReview => Err(unavailable(
            "Agent content ceiling requires unresolved quarantine or review evidence",
        )),
    }
}

fn concrete_content_target(target: &arkret_wire::WireResourceSelector) -> bool {
    use arkret_wire::ResourceSelectorKind as Kind;
    if target.validate().is_err() {
        return false;
    }
    match target.kind {
        Kind::Realm | Kind::Notification | Kind::ReadCursor => target.realm_id.is_some(),
        Kind::Space => target.space_id.is_some(),
        Kind::Circle => target.circle_id.is_some(),
        Kind::Strand => target.strand_id.is_some(),
        Kind::Message => target.message_id.is_some(),
        Kind::Morph => target.morph_id.is_some(),
        Kind::Object => target
            .object_ref
            .as_deref()
            .is_some_and(arkret_wire::is_object_ref),
        Kind::Relation => target.relation_id.is_some(),
        Kind::View => target.view_id.is_some(),
        Kind::Event => target.event_id.is_some(),
        Kind::Actor => target.actor_id.is_some(),
        Kind::Schema => target
            .schema_ref
            .as_ref()
            .is_some_and(|reference| !reference.is_empty()),
        Kind::Policy => target.policy_id.is_some(),
        Kind::Invite => target.invite_id.is_some(),
        Kind::Blob => target.blob_ref.is_some(),
        Kind::All => false,
    }
}

fn key_scope_content_selector(
    resource: &arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResource,
) -> PersistenceResult<Option<arkret_wire::WireResourceSelector>> {
    use arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResourceKind as ScopeKind;
    use arkret_wire::{ResourceSelectorKind as Kind, WireResourceSelector};
    if matches!(resource.kind, ScopeKind::Operation | ScopeKind::Service) {
        if resource.realm_id.is_some()
            || resource.resource_ref.is_some()
            || resource.schema_ref.is_some()
            || (resource.kind == ScopeKind::Operation
                && (resource.service_id.is_some()
                    || resource.operation.as_deref().is_some_and(|operation| {
                        ServiceOperationId::from_wire(operation).is_none()
                    })))
            || (resource.kind == ScopeKind::Service && resource.operation.is_some())
        {
            return Err(unavailable(
                "Agent service scope carries invalid content or service fields",
            ));
        }
        return Ok(None);
    }
    if resource.operation.is_some()
        || resource.service_id.is_some()
        || (resource.kind != ScopeKind::Schema && resource.schema_ref.is_some())
        || (resource.kind == ScopeKind::Schema && resource.resource_ref.is_some())
    {
        return Err(unavailable(
            "Agent content scope carries unsupported selector fields",
        ));
    }
    let kind = match resource.kind {
        ScopeKind::Realm => Kind::Realm,
        ScopeKind::Space => Kind::Space,
        ScopeKind::Circle => Kind::Circle,
        ScopeKind::Strand => Kind::Strand,
        ScopeKind::Message => Kind::Message,
        ScopeKind::Morph => Kind::Morph,
        ScopeKind::Object => Kind::Object,
        ScopeKind::Relation => Kind::Relation,
        ScopeKind::View => Kind::View,
        ScopeKind::Event => Kind::Event,
        ScopeKind::Actor => Kind::Actor,
        ScopeKind::Schema => Kind::Schema,
        ScopeKind::Policy => Kind::Policy,
        ScopeKind::Invite => Kind::Invite,
        ScopeKind::Notification => Kind::Notification,
        ScopeKind::ReadCursor => Kind::ReadCursor,
        ScopeKind::Blob => Kind::Blob,
        ScopeKind::Operation | ScopeKind::Service => unreachable!(),
    };
    // Ceiling wildcards are legal even where an actual WireResourceSelector
    // requires a concrete Realm/Actor. Do not invent facts to validate them.
    let mut selector = WireResourceSelector {
        kind,
        realm_id: resource.realm_id.clone(),
        space_id: None,
        circle_id: None,
        object_kind: None,
        object_ref: None,
        strand_id: None,
        message_id: None,
        morph_id: None,
        morph_kind: None,
        relation_kind: None,
        relation_id: None,
        view_id: None,
        event_id: None,
        actor_id: None,
        schema_ref: resource.schema_ref.clone(),
        policy_id: None,
        invite_id: None,
        blob_ref: None,
        match_scope: None,
    };
    if selector.schema_ref.as_ref().is_some_and(String::is_empty) {
        return Err(unavailable("Agent schema ceiling reference is empty"));
    }
    if let Some(reference) = resource.resource_ref.as_deref() {
        let invalid = || unavailable("Agent content ceiling reference does not match its kind");
        match resource.kind {
            ScopeKind::Realm => {
                let realm: RealmId = reference.parse().map_err(|_| invalid())?;
                if selector
                    .realm_id
                    .as_ref()
                    .is_some_and(|bound| bound != &realm)
                {
                    return Err(invalid());
                }
                selector.realm_id = Some(realm);
            }
            ScopeKind::Space => selector.space_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Circle => {
                selector.circle_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Strand => {
                selector.strand_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Message => {
                selector.message_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Morph => selector.morph_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Object if arkret_wire::is_object_ref(reference) => {
                selector.object_ref = Some(reference.to_owned())
            }
            ScopeKind::Relation => {
                selector.relation_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::View => selector.view_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Event => selector.event_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Actor => selector.actor_id = Some(reference.parse().map_err(|_| invalid())?),
            ScopeKind::Policy => {
                selector.policy_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Invite => {
                selector.invite_id = Some(reference.parse().map_err(|_| invalid())?)
            }
            ScopeKind::Blob => selector.blob_ref = Some(reference.parse().map_err(|_| invalid())?),
            // These two registered kinds narrow only by Realm. Never drop an
            // unrepresentable exact reference and accidentally widen its scope.
            ScopeKind::Notification
            | ScopeKind::ReadCursor
            | ScopeKind::Object
            | ScopeKind::Schema
            | ScopeKind::Operation
            | ScopeKind::Service => return Err(invalid()),
        }
    }
    Ok(Some(selector))
}

/// Consume the exact issuer-introspected scope details already authenticated
/// and holder-bound by the SDK. No local JWT claim or caller echo is accepted.
/// This adds ceilings only; current key, participation and ordinary grants
/// remain independent gates owned by the caller's held transaction cut.
pub(crate) fn require_session_content_ceiling(
    scopes: &[String],
    details: &serde_json::Map<String, serde_json::Value>,
    operation: &AuthorizationOperation<'_>,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    };
    use coland_storage::GrantEvaluation;
    const REQUIRED: [&str; 8] = [
        "controller_principal_id",
        "agent_key_authorization_ref",
        "realm_ids",
        "strand_ids",
        "resources",
        "constraints",
        "capability_grant_refs",
        "policy_refs",
    ];
    if REQUIRED.iter().any(|field| !details.contains_key(*field))
        || details
            .keys()
            .any(|field| !REQUIRED.contains(&field.as_str()) && field != "participations")
        || scopes.is_empty()
        || scopes.iter().any(|action| {
            arkret_schema::capability_action(action).is_none()
                && ServiceOperationId::from_wire(action).is_none()
        })
        || operation.actions.is_empty()
        || operation.actions.iter().any(|action| {
            arkret_schema::capability_action(action)
                .is_none_or(|descriptor| descriptor.event_mapping_kind == "aggregate_admin")
                || ServiceOperationId::from_wire(action).is_some()
                || !scopes.iter().any(|scope| scope == action)
        })
        || !concrete_content_target(operation.target)
    {
        return Err(unavailable(
            "Agent session content ceiling is incomplete or unknown",
        ));
    }
    serde_json::from_value::<arkret_wire::DidCoreId>(details["controller_principal_id"].clone())
        .map_err(unavailable)?;
    serde_json::from_value::<arkret_wire::EventId>(details["agent_key_authorization_ref"].clone())
        .map_err(unavailable)?;
    let realms: Vec<RealmId> =
        serde_json::from_value(details["realm_ids"].clone()).map_err(unavailable)?;
    let strands: Vec<arkret_wire::StrandId> =
        serde_json::from_value(details["strand_ids"].clone()).map_err(unavailable)?;
    if realms
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != realms.len()
        || strands
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != strands.len()
    {
        return Err(unavailable(
            "Agent session resource ceiling contains duplicates",
        ));
    }
    let resources = details["resources"]
        .as_object()
        .ok_or_else(|| unavailable("Agent session resources are not an object"))?;
    if resources.len() != 2
        || resources.get("realm_ids") != Some(&details["realm_ids"])
        || resources.get("strand_ids") != Some(&details["strand_ids"])
    {
        return Err(unavailable(
            "Agent session resources differ from immutable scope IDs",
        ));
    }
    if !realms.is_empty()
        && !operation
            .target
            .realm_id
            .as_ref()
            .is_some_and(|realm| realms.contains(realm))
    {
        return Err(PersistenceError::Conflict(
            "capability_denied: Agent session Realm ceiling differs".into(),
        ));
    }
    if !strands.is_empty() {
        let actual = operation
            .facts
            .strand_id
            .as_deref()
            .map(str::parse::<arkret_wire::StrandId>)
            .transpose()
            .map_err(unavailable)?;
        if operation
            .target
            .strand_id
            .as_ref()
            .zip(actual.as_ref())
            .is_some_and(|(a, b)| a != b)
            || !operation
                .target
                .strand_id
                .as_ref()
                .or(actual.as_ref())
                .is_some_and(|strand| strands.contains(strand))
        {
            return Err(PersistenceError::Conflict(
                "capability_denied: Agent session Strand ceiling is unknown or differs".into(),
            ));
        }
    }
    for field in ["capability_grant_refs", "policy_refs"] {
        serde_json::from_value::<Vec<String>>(details[field].clone()).map_err(unavailable)?;
    }
    if let Some(participation) = details.get("participations") {
        // Preserved and structurally validated, but never an authority source.
        // Continuous current participation remains the caller's separate gate.
        serde_json::from_value::<Vec<arkret_models_collaboration::governance::agent_participation::AgentParticipationEntry>>(participation.clone())
            .map_err(unavailable)?;
    }
    let constraints = details["constraints"]
        .as_object()
        .ok_or_else(|| unavailable("Agent session constraints are not an object"))?;
    if constraints.keys().any(|field| {
        !matches!(
            field.as_str(),
            "allowed_tracks" | "allowed_data_labels" | "allowed_endpoints" | "allowed_strand_ids"
        )
    }) {
        return Err(unavailable("Agent session constraint member is unknown"));
    }
    let strings = |field: &str| -> PersistenceResult<Vec<String>> {
        let value = constraints
            .get(field)
            .ok_or_else(|| unavailable("Agent session canonical constraint is missing"))?;
        let values: Vec<String> = serde_json::from_value(value.clone()).map_err(unavailable)?;
        if values.iter().any(String::is_empty)
            || values
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != values.len()
        {
            return Err(unavailable(
                "Agent session canonical constraint values are invalid",
            ));
        }
        Ok(values)
    };
    let mut ceiling = GrantConstraint::new(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    ceiling.allowed_tracks = strings("allowed_tracks")?;
    ceiling.allowed_data_labels = strings("allowed_data_labels")?;
    ceiling.allowed_endpoints = strings("allowed_endpoints")?;
    if let Some(ids) = constraints.get("allowed_strand_ids") {
        let ids: Vec<arkret_wire::StrandId> =
            serde_json::from_value(ids.clone()).map_err(unavailable)?;
        if ids != strands {
            return Err(unavailable(
                "Agent session Strand constraint differs from immutable resources",
            ));
        }
        // Actual target/facts were reconciled above. The existing constraint
        // evaluator also checks the same Strand ceiling against actual facts.
        ceiling.allowed_strand_ids = ids.iter().map(ToString::to_string).collect();
    }
    match coland_storage::evaluate_constraint_ceiling(operation, &[ceiling]) {
        GrantEvaluation::Allowed(_) => Ok(()),
        _ => Err(PersistenceError::Conflict(
            "capability_denied: Agent session constraints are unresolved or refuse content".into(),
        )),
    }
}

/// Resolve the continuous reading ceiling from the same authoritative snapshot.
/// Control Realms and independently founded Directs keep their own contracts.
pub(crate) async fn read_controller_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    circle: Option<&arkret_wire::CircleId>,
    actor: &arkret_wire::ActorId,
) -> PersistenceResult<Option<arkret_wire::ActorId>> {
    if !crate::committed_disclosure::ordinary_agent_read_ceiling(
        crate::account_stream_scan::realm_purpose(conn, realm).await?,
    ) {
        return Ok(None);
    }
    let at = chrono::Utc::now();
    let Some(controller) = crate::realm_authorization_cut::owned_controller_snapshot_in_connection(
        conn, realm, actor, at,
    )
    .await?
    else {
        return Ok(None);
    };
    require_member_event_read_in_connection(
        conn,
        realm,
        circle,
        controller
            .as_account_id()
            .ok_or_else(|| unavailable("controller Account is missing"))?,
        actor
            .as_account_id()
            .ok_or_else(|| unavailable("Agent Account is missing"))?,
        at,
    )
    .await?;
    Ok(Some(controller))
}

/// Canonical Event reads use the content event.read action, independently of
/// the member/history source that admits the read. This is not a delivery gate.
pub(crate) async fn require_member_event_read_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    circle: Option<&arkret_wire::CircleId>,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policy_snapshot_in_connection(
            conn, realm, circle,
        )
        .await?;
    require_member_event_read(&policies, realm, controller, agent, at)
}

fn require_member_event_read(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    // Reading an Event can disclose referenced objects and private preimages.
    // Until those scopes are resolved, narrower rules cannot prove a nonmatch.
    if policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .any(|rule| {
            rule.resources.as_ref().is_some_and(|resources| {
                resources
                    .iter()
                    .any(|resource| resource.kind != PolicyResourceKind::Realm)
            })
        })
    {
        return Err(unavailable(
            "Agent Event read resource evidence is unavailable",
        ));
    }
    let resources = [PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    let effect = evaluate_agent_management(
        Some(policies),
        &AgentManagementContext {
            realm_id: realm,
            ownership: Some((controller, agent)),
            operation: AgentPolicyOperation::Read,
            content_action: Some(
                CapabilityActionId::from_wire("ak.event.read")
                    .ok_or_else(|| unavailable("Event read action is unregistered"))?,
            ),
            resources: Some(&resources),
            at,
        },
    )
    .map_err(unavailable)?;
    match effect {
        PolicyEffect::Allow => Ok(()),
        PolicyEffect::Deny => Err(PersistenceError::Conflict(
            "capability_denied: Agent management forbids Event reading".to_owned(),
        )),
        PolicyEffect::Quarantine | PolicyEffect::RequireReview => Err(unavailable(
            "Agent Event read requires unresolved quarantine or review evidence",
        )),
    }
}

/// Complete canonical Event bytes disclose their accepted targets and newly
/// materialized objects. Scope comes from signed content, never UI ancestry.
pub(crate) fn event_content_resources(
    event: &arkret_wire::Event,
) -> PersistenceResult<Vec<PolicyResourceSelector>> {
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(event.realm_id.clone()),
        resource_ref: Some(event.realm_id.to_string()),
    }];
    let mut objects = std::collections::BTreeSet::from([event.event_id.to_string()]);
    objects.extend(arkret_schema::derived_object_ids_for_kind(
        event.kind.as_str(),
        &event.event_id,
    ));
    for key in [
        "target_ref",
        "message_id",
        "strand_id",
        "space_id",
        "circle_id",
        "relation_id",
        "view_id",
        "morph_id",
        "blob_ref",
    ] {
        let Some(reference) = event.payload.get(key).and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !arkret_wire::is_object_ref(reference) {
            return Err(unavailable("Agent content target is not canonical"));
        }
        objects.insert(reference.to_owned());
        let kind = match key {
            "strand_id" => Some(PolicyResourceKind::Strand),
            "space_id" => Some(PolicyResourceKind::Space),
            _ => None,
        };
        if let Some(kind) = kind {
            resources.push(PolicyResourceSelector {
                kind,
                realm_id: Some(event.realm_id.clone()),
                resource_ref: Some(reference.to_owned()),
            });
        }
    }
    if event.kind == arkret_wire::EventKind::MessageCreate {
        let payload: arkret_models_collaboration::events_payloads::MessageCreatePayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
                .map_err(unavailable)?;
        for reference in payload.blob_refs {
            let reference: arkret_wire::BlobRef = reference.parse().map_err(unavailable)?;
            objects.insert(reference.to_string());
        }
    }
    for reference in &objects {
        let kind = if reference.parse::<arkret_wire::StrandId>().is_ok() {
            Some(PolicyResourceKind::Strand)
        } else if reference.parse::<arkret_wire::SpaceId>().is_ok() {
            Some(PolicyResourceKind::Space)
        } else {
            None
        };
        if let Some(kind) = kind {
            let selector = PolicyResourceSelector {
                kind,
                realm_id: Some(event.realm_id.clone()),
                resource_ref: Some(reference.clone()),
            };
            if !resources.contains(&selector) {
                resources.push(selector);
            }
        }
    }
    resources.extend(objects.into_iter().map(|reference| PolicyResourceSelector {
        kind: PolicyResourceKind::Object,
        realm_id: Some(event.realm_id.clone()),
        resource_ref: Some(reference),
    }));
    Ok(resources)
}

/// Match global grant refusals against every registered canonical object target.
pub(crate) fn content_capability_targets(
    realm: &RealmId,
    resources: &[PolicyResourceSelector],
) -> Vec<arkret_wire::WireResourceSelector> {
    use arkret_wire::{ResourceSelectorKind as Kind, WireResourceSelector as Selector};
    let mut targets = vec![Selector::realm(realm.clone())];
    for resource in resources {
        let Some(reference) = resource.resource_ref.as_deref() else {
            continue;
        };
        let mut target = Selector::realm(realm.clone());
        if let Ok(id) = reference.parse::<arkret_wire::StrandId>() {
            target = Selector::strand(realm.clone(), id);
        } else if let Ok(id) = reference.parse::<arkret_wire::SpaceId>() {
            target = Selector::space(realm.clone(), id);
        } else if let Ok(id) = reference.parse::<arkret_wire::CircleId>() {
            target = Selector::circle(realm.clone(), id);
        } else if let Ok(id) = reference.parse::<arkret_wire::MessageId>() {
            target.kind = Kind::Message;
            target.message_id = Some(id);
        } else if let Ok(id) = reference.parse::<arkret_wire::EventId>() {
            target.kind = Kind::Event;
            target.event_id = Some(id);
        } else if let Ok(id) = reference.parse::<arkret_wire::RelationId>() {
            target.kind = Kind::Relation;
            target.relation_id = Some(id);
        } else if let Ok(id) = reference.parse::<arkret_wire::ViewId>() {
            target.kind = Kind::View;
            target.view_id = Some(id);
        } else if let Ok(id) = reference.parse::<arkret_wire::MorphId>() {
            target.kind = Kind::Morph;
            target.morph_id = Some(id);
        } else if let Ok(id) = reference.parse::<arkret_wire::BlobRef>() {
            target.kind = Kind::Blob;
            target.blob_ref = Some(id);
        } else if resource.kind == PolicyResourceKind::Object {
            target.kind = Kind::Object;
            target.object_ref = Some(reference.to_owned());
        } else {
            continue;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets
}

/// Registered selector identities used by a capability/management preflight.
/// Object identities are exact content targets, not UI container ancestry.
pub(crate) fn selector_content_resources(
    realm: &RealmId,
    target: &arkret_wire::WireResourceSelector,
) -> PersistenceResult<Vec<PolicyResourceSelector>> {
    target.validate().map_err(unavailable)?;
    if target.realm_id.as_ref() != Some(realm) {
        return Err(unavailable("content selector differs from its Realm"));
    }
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    for (kind, reference) in [
        (
            PolicyResourceKind::Strand,
            target.strand_id.as_ref().map(ToString::to_string),
        ),
        (
            PolicyResourceKind::Space,
            target.space_id.as_ref().map(ToString::to_string),
        ),
    ] {
        if let Some(reference) = reference {
            resources.push(PolicyResourceSelector {
                kind,
                realm_id: Some(realm.clone()),
                resource_ref: Some(reference.clone()),
            });
            resources.push(PolicyResourceSelector {
                kind: PolicyResourceKind::Object,
                realm_id: Some(realm.clone()),
                resource_ref: Some(reference),
            });
        }
    }
    for reference in [
        target.message_id.as_ref().map(ToString::to_string),
        target.event_id.as_ref().map(ToString::to_string),
        target.circle_id.as_ref().map(ToString::to_string),
        target.relation_id.as_ref().map(ToString::to_string),
        target.view_id.as_ref().map(ToString::to_string),
        target.morph_id.as_ref().map(ToString::to_string),
        target.blob_ref.as_ref().map(ToString::to_string),
        target.object_ref.clone(),
    ]
    .into_iter()
    .flatten()
    {
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(realm.clone()),
            resource_ref: Some(reference),
        });
    }
    Ok(resources)
}

/// This gate restricts an already proved content source; it never creates one.
#[expect(
    clippy::too_many_arguments,
    reason = "Content admission binds the caller, scope, action and resources on the same database cut."
)]
pub(crate) async fn require_content_snapshot_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    circle: Option<&arkret_wire::CircleId>,
    controller: &AccountId,
    agent: &AccountId,
    operation: AgentPolicyOperation,
    action: CapabilityActionId,
    resources: &[PolicyResourceSelector],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policy_snapshot_in_connection(
            conn, realm, circle,
        )
        .await?;
    let effect = evaluate_agent_management(
        Some(&policies),
        &AgentManagementContext {
            realm_id: realm,
            ownership: Some((controller, agent)),
            operation,
            content_action: Some(action),
            resources: Some(resources),
            at,
        },
    )
    .map_err(unavailable)?;
    match effect {
        PolicyEffect::Allow => Ok(()),
        PolicyEffect::Deny => Err(PersistenceError::Conflict(
            "capability_denied: Agent management refuses content disclosure".into(),
        )),
        PolicyEffect::Quarantine | PolicyEffect::RequireReview => Err(unavailable(
            "Agent content requires unresolved quarantine or review evidence",
        )),
    }
}

/// The caller has verified the prospective member's ownership. Do not read
/// an existing Agent join here: this gate precedes its first membership write.
pub(crate) async fn require_join_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
    event: &arkret_wire::Event,
    review: Option<&crate::agent_management_review::ReviewAdmission>,
) -> PersistenceResult<()> {
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
            conn, realm, None,
        )
        .await?;
    qualify_review_intent(
        require_join(&policies, realm, controller, agent, at),
        event,
        review,
    )
}

pub(crate) async fn require_circle_join_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    circle: &arkret_wire::CircleId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
            conn,
            realm,
            Some(circle),
        )
        .await?;
    // There is no Circle review carrier. A parent Realm review requirement
    // cannot be consumed by an unrelated Circle membership candidate.
    require_realm_intent(
        &policies,
        realm,
        controller,
        agent,
        at,
        AgentPolicyOperation::Join,
    )
}

fn require_join(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    require_realm_intent(
        policies,
        realm,
        controller,
        agent,
        at,
        AgentPolicyOperation::Join,
    )
}

/// Opening public intent is distinct from continuous public serving. Ownership,
/// the signed mode transition and its exact CAS are verified by the caller.
pub(crate) fn require_publish_in_connection<'a>(
    conn: &'a mut diesel_async::AsyncPgConnection,
    realm: &'a RealmId,
    controller: &'a AccountId,
    agent: &'a AccountId,
    at: chrono::DateTime<chrono::Utc>,
    event: &'a arkret_wire::Event,
    review: Option<&'a crate::agent_management_review::ReviewAdmission>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = PersistenceResult<()>> + Send + 'a>> {
    // Keep the complete Policy reader's state out of the enclosing mode/UOW
    // future, which already contains the other same-cut admission consumers.
    Box::pin(async move {
        let policies =
            crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
                conn, realm, None,
            )
            .await?;
        qualify_review_intent(
            require_realm_intent(
                &policies,
                realm,
                controller,
                agent,
                at,
                AgentPolicyOperation::Publish,
            ),
            event,
            review,
        )
    })
}

fn qualify_review_intent(
    result: PersistenceResult<()>,
    event: &arkret_wire::Event,
    review: Option<&crate::agent_management_review::ReviewAdmission>,
) -> PersistenceResult<()> {
    match result {
        Err(PersistenceError::Conflict(ref code))
            if code.starts_with("approval_required:")
                && review.is_some_and(|r| r.applies_to(event)) =>
        {
            Ok(())
        }
        other => other,
    }
}

/// Exclude only a rule whose registered operation or verified complete subject
/// proves it inapplicable. Missing/invalid selectors remain fail-closed and the
/// SDK still validates the entire Policy, including duplicate identities.
fn possibly_applicable_rule(
    rule: &arkret_models_collaboration::governance::operation_wire::PolicyRule,
    controller: &AccountId,
    agent: &AccountId,
    operations: &[AgentPolicyOperation],
) -> bool {
    use arkret_models_collaboration::governance::operation_wire::AgentPolicyTarget;
    if rule.agent_operations.as_ref().is_some_and(|registered| {
        !operations
            .iter()
            .any(|operation| registered.contains(operation))
    }) {
        return false;
    }
    match rule.agent_target.as_ref() {
        Some(AgentPolicyTarget::Controller {
            controller_account_id,
        }) => controller_account_id == controller,
        Some(AgentPolicyTarget::Agent { agent_account_id }) => agent_account_id == agent,
        Some(AgentPolicyTarget::All {}) | None => true,
    }
}

fn require_realm_intent(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
    operation: AgentPolicyOperation,
) -> PersistenceResult<()> {
    let intent = match operation {
        AgentPolicyOperation::Join => "joining",
        AgentPolicyOperation::Publish => "publishing",
        _ => return Err(unavailable("Agent Realm intent operation is unsupported")),
    };
    // Realm membership/public intent does not establish a Strand/object action.
    // Unsupported scoped evidence must not be treated as a nonmatching ban.
    if policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .any(|rule| {
            possibly_applicable_rule(rule, controller, agent, &[operation])
                && rule.resources.as_ref().is_some_and(|resources| {
                    resources
                        .iter()
                        .any(|resource| resource.kind != PolicyResourceKind::Realm)
                })
        })
    {
        return Err(unavailable(format!(
            "Agent {intent} resource evidence is unavailable"
        )));
    }
    let resources = [PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    let effect = evaluate_agent_management(
        Some(policies),
        &AgentManagementContext {
            realm_id: realm,
            ownership: Some((controller, agent)),
            operation,
            content_action: None,
            resources: Some(&resources),
            at,
        },
    )
    .map_err(unavailable)?;
    match effect {
        PolicyEffect::Allow => Ok(()),
        PolicyEffect::Deny => Err(PersistenceError::Conflict(format!(
            "capability_denied: Agent management forbids {intent}"
        ))),
        PolicyEffect::Quarantine => Err(unavailable(format!("Agent {intent} is quarantined"))),
        PolicyEffect::RequireReview => Err(PersistenceError::Conflict(format!(
            "approval_required: Agent {intent} requires current management review"
        ))),
    }
}

/// Every requested action must pass: grant admission has no alternative-action
/// semantics. The issuer's own grant/root authority is checked separately.
pub(crate) async fn require_authorization_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    actions: &[String],
    resources: &[arkret_wire::WireResourceSelector],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let domains =
        crate::policy_current_results::read_agent_management_authorization_domains_in_connection(
            conn, realm,
        )
        .await?;
    let mut resolved = Vec::new();
    let need_circle_scope = domains.iter().any(|(policy, source)| {
        matches!(source, arkret_wire::CommitStreamRef::Circle { .. })
            && !policy.not_before.is_some_and(|start| at < start)
            && !policy.expires_at.is_some_and(|end| at >= end)
            && (policy.default_effect != PolicyEffect::Allow
                || policy.rules.iter().any(|rule| {
                    possibly_applicable_rule(
                        rule,
                        controller,
                        agent,
                        &[AgentPolicyOperation::Authorize],
                    ) && rule
                        .actions
                        .as_ref()
                        .is_none_or(|named| actions.iter().any(|action| named.contains(action)))
                        && rule.effect != PolicyEffect::Allow
                }))
    });
    // Validate the complete accepted set before excluding an unrelated carrier.
    let all = domains
        .iter()
        .map(|(policy, _)| policy.clone())
        .collect::<Vec<_>>();
    let anchor = [PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    for action in actions {
        let content_action = CapabilityActionId::from_wire(action).filter(|_| {
            arkret_schema::capability_action(action)
                .is_some_and(|descriptor| descriptor.event_mapping_kind != "aggregate_admin")
        });
        evaluate_agent_management(
            Some(&all),
            &AgentManagementContext {
                realm_id: realm,
                ownership: Some((controller, agent)),
                operation: AgentPolicyOperation::Authorize,
                content_action,
                resources: Some(&anchor),
                at,
            },
        )
        .map_err(unavailable)?;
    }
    for resource in resources {
        let scope = if need_circle_scope {
            crate::policy_current_results::authorization_object_scope_in_connection(
                conn, realm, resource,
            )
            .await?
        } else {
            None
        };
        if let Some(arkret_wire::ScopeRef::Circle { circle_id, .. }) = &scope {
            if resource
                .circle_id
                .as_ref()
                .is_some_and(|claimed| claimed != circle_id)
            {
                return Err(unavailable(
                    "Agent authorization Circle differs from its accepted object",
                ));
            }
        } else if matches!(scope, Some(arkret_wire::ScopeRef::Realm { .. }))
            && resource.circle_id.is_some()
        {
            return Err(unavailable(
                "Agent authorization claims Circle for a Realm object",
            ));
        }
        resolved.push((resource.clone(), scope));
    }
    for (policy, source) in domains {
        let selected = resolved
            .iter()
            .filter(|(resource, scope)| match &source {
                arkret_wire::CommitStreamRef::Realm { realm_id } => realm_id == realm,
                arkret_wire::CommitStreamRef::Circle {
                    realm_id,
                    circle_id,
                } => {
                    realm_id == realm
                        && match scope {
                            Some(arkret_wire::ScopeRef::Realm { .. }) => false,
                            Some(arkret_wire::ScopeRef::Circle {
                                circle_id: actual, ..
                            }) => actual == circle_id,
                            Some(_) => true,
                            None => resource
                                .circle_id
                                .as_ref()
                                .is_none_or(|actual| actual == circle_id),
                        }
                }
                _ => true,
            })
            .map(|(resource, _)| resource.clone())
            .collect::<Vec<_>>();
        if !matches!(
            source,
            arkret_wire::CommitStreamRef::Realm { .. }
                | arkret_wire::CommitStreamRef::Circle { .. }
        ) {
            return Err(unavailable(
                "Agent authorization governance carrier is unavailable",
            ));
        }
        if !selected.is_empty() {
            require_authorization(
                std::slice::from_ref(&policy),
                realm,
                controller,
                agent,
                actions,
                &selected,
                at,
            )?;
        }
    }
    // Empty current is authoritative only after the full history reader above.
    require_authorization(&[], realm, controller, agent, actions, resources, at)
}

fn require_authorization(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    actions: &[String],
    resources: &[arkret_wire::WireResourceSelector],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if actions.is_empty() || resources.is_empty() {
        return Err(unavailable("Agent authorization coverage is empty"));
    }
    // Use the original SDK to validate complete Policy/ownership/action binding
    // even if every rule is irrelevant to this operation. Resource-set coverage
    // is then proved without replacing broad selectors with a fake actual target.
    let actual_resources = [PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    for resource in resources {
        resource.validate().map_err(unavailable)?;
        if resource.realm_id.as_ref() != Some(realm)
            || resource.kind == arkret_wire::ResourceSelectorKind::All
        {
            return Err(unavailable(
                "Agent authorization selector is outside its Realm",
            ));
        }
    }
    for action in actions {
        let descriptor = arkret_schema::capability_action(action)
            .ok_or_else(|| unavailable("Agent authorization action is unknown"))?;
        let content_action = if descriptor.event_mapping_kind == "aggregate_admin"
            || ServiceOperationId::from_wire(action).is_some()
        {
            None
        } else {
            Some(
                CapabilityActionId::from_wire(action)
                    .ok_or_else(|| unavailable("Agent authorization content action is unknown"))?,
            )
        };
        evaluate_agent_management(
            Some(policies),
            &AgentManagementContext {
                realm_id: realm,
                ownership: Some((controller, agent)),
                operation: AgentPolicyOperation::Authorize,
                content_action,
                resources: Some(&actual_resources),
                at,
            },
        )
        .map_err(unavailable)?;
        for policy in policies {
            if policy.not_before.is_some_and(|start| at < start)
                || policy.expires_at.is_some_and(|end| at >= end)
            {
                continue;
            }
            if content_action.is_none()
                && (policy.default_effect != PolicyEffect::Allow
                    || policy.rules.iter().any(|rule| {
                        possibly_applicable_rule(
                            rule,
                            controller,
                            agent,
                            &[AgentPolicyOperation::Authorize],
                        )
                    }))
            {
                return Err(unavailable(
                    "Agent authorization action coverage is unavailable",
                ));
            }
            for resource in resources {
                authorization_policy_covers(
                    policy,
                    realm,
                    controller,
                    agent,
                    content_action,
                    resource,
                    at,
                )?;
            }
        }
    }
    Ok(())
}

// A grant selector denotes a set of future concrete operations. These relations
// are internal proof states, not resources fabricated for the SDK evaluator.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Coverage {
    None,
    Whole,
    Part,
}

fn management_selector_coverage(
    selector: &PolicyResourceSelector,
    grant: &arkret_wire::WireResourceSelector,
    realm: &RealmId,
    action: Option<CapabilityActionId>,
) -> PersistenceResult<Coverage> {
    use arkret_wire::{ResourceMatchScope as Match, ResourceSelectorKind as Kind};
    if selector.realm_id.as_ref().is_some_and(|id| id != realm) {
        return Ok(Coverage::None);
    }
    if selector.kind == PolicyResourceKind::Service {
        return Err(unavailable(
            "Agent authorization has no Service content matcher",
        ));
    }
    if selector.kind == PolicyResourceKind::Realm {
        return Ok(
            if selector
                .resource_ref
                .as_ref()
                .is_none_or(|id| id == realm.as_str())
            {
                Coverage::Whole
            } else {
                Coverage::None
            },
        );
    }
    if selector.resource_ref.is_none()
        && matches!(
            (selector.kind, grant.kind),
            (PolicyResourceKind::Strand, Kind::Strand) | (PolicyResourceKind::Space, Kind::Space)
        )
    {
        return Ok(Coverage::Whole);
    }
    if selector.kind == PolicyResourceKind::Object
        && action.is_some_and(|action| {
            arkret_schema::capability_action(action.as_str())
                .is_some_and(|descriptor| descriptor.event_mapping_kind != "non_event_surface")
        })
    {
        // An authored Event can create a new Event/object or refer to additional
        // objects. Target-id inequality does not prove that these effects are
        // disjoint from an Object restriction on the entire promised grant.
        return Ok(Coverage::Part);
    }
    let broad = grant.kind == Kind::Realm
        || matches!(
            grant.match_scope,
            Some(Match::Subtree | Match::Children | Match::RealmWide)
        );
    let reference = match selector.kind {
        PolicyResourceKind::Strand => grant.strand_id.as_ref().map(ToString::to_string),
        PolicyResourceKind::Space => grant.space_id.as_ref().map(ToString::to_string),
        PolicyResourceKind::Object => match grant.kind {
            Kind::Strand => grant.strand_id.as_ref().map(ToString::to_string),
            Kind::Space => grant.space_id.as_ref().map(ToString::to_string),
            Kind::Circle => grant.circle_id.as_ref().map(ToString::to_string),
            Kind::Message => grant.message_id.as_ref().map(ToString::to_string),
            Kind::Morph => grant.morph_id.as_ref().map(ToString::to_string),
            Kind::Relation => grant.relation_id.as_ref().map(ToString::to_string),
            Kind::View => grant.view_id.as_ref().map(ToString::to_string),
            Kind::Event => grant.event_id.as_ref().map(ToString::to_string),
            Kind::Policy => grant.policy_id.as_ref().map(ToString::to_string),
            Kind::Invite => grant.invite_id.as_ref().map(ToString::to_string),
            Kind::Blob => grant.blob_ref.as_ref().map(ToString::to_string),
            Kind::Object => grant.object_ref.clone(),
            _ => None,
        },
        _ => None,
    };
    if let Some(actual) = reference {
        return Ok(
            if selector
                .resource_ref
                .as_ref()
                .is_none_or(|id| id == &actual)
            {
                if broad {
                    Coverage::Part
                } else {
                    Coverage::Whole
                }
            } else if broad {
                Coverage::Part
            } else {
                Coverage::None
            },
        );
    }
    // No invented containment: an unbounded Realm/Space/Strand domain can
    // intersect narrower content scopes, including objects created later.
    if broad
        || matches!(
            grant.kind,
            Kind::Space
                | Kind::Circle
                | Kind::Strand
                | Kind::Message
                | Kind::Morph
                | Kind::Object
                | Kind::Relation
                | Kind::View
                | Kind::Event
                | Kind::Policy
                | Kind::Invite
                | Kind::Blob
                | Kind::Notification
                | Kind::ReadCursor
        )
    {
        Ok(Coverage::Part)
    } else {
        Err(unavailable(
            "Agent authorization selector facts are unavailable",
        ))
    }
}

fn authorization_policy_covers(
    policy: &Policy,
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    action: Option<CapabilityActionId>,
    resource: &arkret_wire::WireResourceSelector,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if policy.not_before.is_some_and(|start| at < start)
        || policy.expires_at.is_some_and(|end| at >= end)
    {
        return Ok(());
    }
    let mut whole: Option<(i64, PolicyEffect)> = None;
    let mut partial = Vec::new();
    for rule in &policy.rules {
        if !possibly_applicable_rule(rule, controller, agent, &[AgentPolicyOperation::Authorize])
            || rule.actions.as_ref().is_some_and(|actions| {
                action.is_none_or(|action| !actions.iter().any(|id| id == action.as_str()))
            })
        {
            continue;
        }
        let relation = match &rule.resources {
            None => Coverage::Whole,
            Some(selectors) => {
                let mut relation = Coverage::None;
                for selector in selectors {
                    match management_selector_coverage(selector, resource, realm, action)? {
                        Coverage::Whole => {
                            relation = Coverage::Whole;
                            break;
                        }
                        Coverage::Part => relation = Coverage::Part,
                        Coverage::None => {}
                    }
                }
                relation
            }
        };
        match relation {
            Coverage::None => {}
            Coverage::Part => partial.push((rule.priority, rule.effect.clone())),
            Coverage::Whole => {
                whole = Some(match whole {
                    Some((priority, effect)) if priority > rule.priority => (priority, effect),
                    Some((priority, effect)) if priority == rule.priority => (
                        priority,
                        stricter_management_effect(effect, rule.effect.clone()),
                    ),
                    _ => (rule.priority, rule.effect.clone()),
                })
            }
        }
    }
    let (priority, effect) = whole.map_or(
        (
            None,
            if policy.default_effect == PolicyEffect::RequireReview {
                PolicyEffect::Deny
            } else {
                policy.default_effect.clone()
            },
        ),
        |(priority, effect)| (Some(priority), effect),
    );
    if effect != PolicyEffect::Allow {
        return Err(PersistenceError::Conflict(
            "capability_denied: Agent management forbids authorization".into(),
        ));
    }
    // A whole-domain winning allow masks strictly lower-priority restrictions.
    // A partial allow cannot prove the complement of its domain; default deny
    // therefore stays closed unless a whole-domain allow exists.
    if partial.iter().any(|(p, effect)| {
        *effect != PolicyEffect::Allow && priority.is_none_or(|winner| *p >= winner)
    }) {
        return Err(PersistenceError::Conflict(
            "capability_denied: Agent management restricts part of the authorization domain".into(),
        ));
    }
    Ok(())
}

fn stricter_management_effect(left: PolicyEffect, right: PolicyEffect) -> PolicyEffect {
    fn rank(effect: &PolicyEffect) -> u8 {
        match effect {
            PolicyEffect::Allow => 0,
            PolicyEffect::RequireReview => 1,
            PolicyEffect::Quarantine => 2,
            PolicyEffect::Deny => 3,
        }
    }
    if rank(&right) > rank(&left) {
        right
    } else {
        left
    }
}

/// Ownership and operation facts have already been resolved at the accepting cut.
/// This is not a read/delivery gate and never establishes ownership itself.
/// An empty result holds no permission path; the caller may try a separately
/// registered `.own` action, but must not admit or reserve quota for this result.
pub(crate) async fn executable_actions_in_connection<'a>(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    operation: &AuthorizationOperation<'a>,
    event: &arkret_wire::Event,
) -> PersistenceResult<Vec<&'a str>> {
    require_execution_event_scope(realm, operation, event)?;
    if crate::agent_interaction_current_results::requires_shared_public_mode(event) {
        crate::agent_interaction_current_results::require_current_public_in_connection(
            conn, realm, controller, agent,
        )
        .await?;
    }
    let fact_circle = operation
        .facts
        .circle_id
        .as_ref()
        .map(|id| id.parse::<arkret_wire::CircleId>())
        .transpose()
        .map_err(unavailable)?;
    if operation
        .target
        .circle_id
        .as_ref()
        .zip(fact_circle.as_ref())
        .is_some_and(|(target, fact)| target != fact)
    {
        return Err(unavailable("Agent management Circle facts conflict"));
    }
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
            conn,
            realm,
            operation.target.circle_id.as_ref().or(fact_circle.as_ref()),
        )
        .await?;
    executable_actions(&policies, realm, controller, agent, operation, event)
}

fn require_execution_event_scope(
    realm: &RealmId,
    operation: &AuthorizationOperation<'_>,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    if event.realm_id != *realm
        || event.scope_ref.realm_id_opt() != Some(realm)
        || (operation.actor != &event.actor_id && operation.actor != event.actual_signer())
    {
        return Err(unavailable("Agent execution differs from its signed scope"));
    }
    if let arkret_wire::ScopeRef::Circle { circle_id, .. } = &event.scope_ref
        && (operation
            .target
            .circle_id
            .as_ref()
            .is_some_and(|target| target != circle_id)
            || operation.facts.circle_id.as_deref() != Some(circle_id.as_str()))
    {
        return Err(unavailable(
            "Agent execution Circle differs from its signed scope",
        ));
    }
    Ok(())
}

fn executable_actions<'a>(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    operation: &AuthorizationOperation<'a>,
    event: &arkret_wire::Event,
) -> PersistenceResult<Vec<&'a str>> {
    require_execution_event_scope(realm, operation, event)?;
    if operation.actor.as_account_id() != Some(agent)
        || operation.target.realm_id.as_ref() != Some(realm)
    {
        return Err(unavailable(
            "Agent management operation identity is unavailable",
        ));
    }
    let gates: &[AgentPolicyOperation] =
        if crate::agent_interaction_current_results::requires_shared_public_mode(event) {
            &[AgentPolicyOperation::Execute, AgentPolicyOperation::Serve]
        } else {
            &[AgentPolicyOperation::Execute]
        };
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(realm.clone()),
        resource_ref: Some(realm.to_string()),
    }];
    for (kind, target, fact) in [
        (
            PolicyResourceKind::Strand,
            operation.target.strand_id.as_ref().map(ToString::to_string),
            operation.facts.strand_id.as_ref(),
        ),
        (
            PolicyResourceKind::Space,
            operation.target.space_id.as_ref().map(ToString::to_string),
            operation.facts.space_id.as_ref(),
        ),
    ] {
        if target
            .as_ref()
            .zip(fact)
            .is_some_and(|(target, fact)| target != fact)
        {
            return Err(unavailable("Agent management resource facts conflict"));
        }
        if let Some(id) = target.or_else(|| fact.cloned()) {
            let valid = match kind {
                PolicyResourceKind::Strand => id.parse::<arkret_wire::StrandId>().is_ok(),
                PolicyResourceKind::Space => id.parse::<arkret_wire::SpaceId>().is_ok(),
                _ => false,
            };
            if !valid {
                return Err(unavailable("Agent management resource identity is invalid"));
            }
            resources.push(PolicyResourceSelector {
                kind,
                realm_id: Some(realm.clone()),
                resource_ref: Some(id),
            });
        }
    }
    // Resolve signed object identities only for rules whose operation, subject
    // and action can actually apply. Do not demand unrelated facts before the
    // SDK has established that the rule is relevant to this concrete action.
    if policies.iter().flat_map(|p| &p.rules).any(|rule| {
        possibly_applicable_rule(rule, controller, agent, gates)
            && rule.actions.as_ref().is_none_or(|actions| {
                operation
                    .actions
                    .iter()
                    .any(|action| actions.iter().any(|named| named == action))
            })
            && rule.resources.as_ref().is_some_and(|selectors| {
                selectors
                    .iter()
                    .any(|selector| selector.kind == PolicyResourceKind::Object)
            })
    }) {
        if policies
            .iter()
            .flat_map(|p| &p.rules)
            .flat_map(|rule| rule.resources.iter().flatten())
            .any(|selector| {
                selector.kind == PolicyResourceKind::Object
                    && selector
                        .resource_ref
                        .as_ref()
                        .is_some_and(|id| !arkret_wire::is_object_ref(id))
            })
        {
            return Err(unavailable("Agent management object selector is invalid"));
        }
        for resource in selector_content_resources(realm, operation.target)?
            .into_iter()
            .chain(event_content_resources(event)?)
            .filter(|resource| resource.kind == PolicyResourceKind::Object)
        {
            if !resources.contains(&resource) {
                resources.push(resource);
            }
        }
    }
    let mut allowed = Vec::new();
    let mut aggregates = Vec::new();
    let mut concrete_count = 0;
    let mut restricted = false;
    for &token in operation.actions {
        let descriptor = arkret_schema::capability_action(token)
            .ok_or_else(|| unavailable("Agent management action mapping is unavailable"))?;
        if descriptor.event_mapping_kind == "aggregate_admin" {
            aggregates.push(token);
            continue;
        }
        concrete_count += 1;
        if ServiceOperationId::from_wire(token).is_some() {
            return Err(unavailable(
                "Agent management content action is unavailable",
            ));
        }
        let action = CapabilityActionId::from_wire(token)
            .ok_or_else(|| unavailable("Agent management content action is unknown"))?;
        if policies.iter().flat_map(|p| &p.rules).any(|rule| {
            possibly_applicable_rule(rule, controller, agent, gates)
                && rule
                    .actions
                    .as_ref()
                    .is_none_or(|actions| actions.iter().any(|named| named == action.as_str()))
                && rule.resources.as_ref().is_some_and(|resources| {
                    resources
                        .iter()
                        .any(|resource| resource.kind == PolicyResourceKind::Service)
                })
        }) {
            return Err(unavailable(
                "Agent management service resource facts are unavailable",
            ));
        }
        let gates: &[AgentPolicyOperation] =
            if crate::agent_interaction_current_results::requires_shared_public_mode(event) {
                &[AgentPolicyOperation::Execute, AgentPolicyOperation::Serve]
            } else {
                &[AgentPolicyOperation::Execute]
            };
        let mut path_allowed = true;
        for &gate in gates {
            let effect = evaluate_agent_management(
                Some(policies),
                &AgentManagementContext {
                    realm_id: realm,
                    ownership: Some((controller, agent)),
                    operation: gate,
                    content_action: Some(action),
                    resources: Some(&resources),
                    at: operation.at,
                },
            )
            .map_err(unavailable)?;
            match effect {
                PolicyEffect::Allow => {}
                PolicyEffect::Deny => path_allowed = false,
                PolicyEffect::Quarantine | PolicyEffect::RequireReview => {
                    path_allowed = false;
                    restricted = true;
                }
            }
        }
        if path_allowed {
            allowed.push(token);
        }
    }
    if concrete_count == 0 {
        return Err(unavailable(
            "Agent management concrete action mapping is unavailable",
        ));
    }
    if allowed.is_empty() && restricted {
        return Err(unavailable(
            "Agent management requires unresolved quarantine or review evidence",
        ));
    }
    // An existing aggregate grant remains a permission path only when none
    // of this operation's concrete paths were filtered by management. It is
    // never evaluated as a content action or used to bypass a restricted path.
    if allowed.len() == concrete_count {
        allowed.extend(aggregates);
    }
    Ok(allowed)
}

/// Process-only fixed MessageCreate preparation. The producer has not authored
/// a future Event, so unknown future object/service facts cannot supply an allow.
pub(crate) fn require_native_message_reply_policy(
    policies: &[Policy],
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
    target: &arkret_wire::WireResourceSelector,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let gates = [AgentPolicyOperation::Execute, AgentPolicyOperation::Serve];
    if policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .any(|rule| {
            possibly_applicable_rule(rule, controller, agent, &gates)
                && rule.actions.as_ref().is_none_or(|actions| {
                    actions
                        .iter()
                        .any(|action| action == CapabilityActionId::MessageCreate.as_str())
                })
                && rule.resources.as_ref().is_some_and(|resources| {
                    resources.iter().any(|resource| {
                        resource.kind == PolicyResourceKind::Service
                            || (resource.kind == PolicyResourceKind::Object
                                && resource.resource_ref.as_deref().is_some_and(|id| {
                                    Some(id) != target.strand_id.as_ref().map(|id| id.as_str())
                                        && Some(id)
                                            != target.circle_id.as_ref().map(|id| id.as_str())
                                }))
                    })
                })
        })
    {
        return Err(unavailable(
            "native reply has unknown future Object or provider Service resource facts",
        ));
    }
    // Strand is an existing actual Object resource; no future Message/Blob id
    // is added. A rule naming one of those unknown identities cannot match.
    let resources = selector_content_resources(realm, target)?;
    for operation in gates {
        match evaluate_agent_management(
            Some(policies),
            &AgentManagementContext {
                realm_id: realm,
                ownership: Some((controller, agent)),
                operation,
                content_action: Some(CapabilityActionId::MessageCreate),
                resources: Some(&resources),
                at,
            },
        )
        .map_err(unavailable)?
        {
            PolicyEffect::Allow => {}
            PolicyEffect::Deny => {
                return Err(PersistenceError::Conflict(
                    "capability_denied: native reply management refuses preparation".into(),
                ));
            }
            PolicyEffect::Quarantine | PolicyEffect::RequireReview => {
                return Err(unavailable(
                    "native reply needs unresolved review or quarantine evidence",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// Moving a management Policy changes both the old layer and the new layer.
/// Preserve native grant/global-refusal/quota/approval checks on both targets;
/// the original signed Event and candidate Commit are never rewritten.
pub(crate) async fn require_policy_write_with_approvals(
    cut: &crate::realm_authorization_cut::RealmAuthorizationCut,
    conn: &mut diesel_async::AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    new_target: &arkret_wire::WireResourceSelector,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    use arkret_models_collaboration::governance::operation_wire::PolicySetStatePayload;

    use crate::policy_current_results::ManagementPolicyCurrentRead;
    let mut targets = vec![new_target.clone()];
    if event.kind == arkret_wire::EventKind::PolicySet {
        let payload: PolicySetStatePayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
                .map_err(unavailable)?;
        payload.validate().map_err(unavailable)?;
        if let Some(expected) = payload.expected_revision {
            let source = arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None)
                .map_err(unavailable)?;
            let actual = crate::policy_current_results::management_policy_scope_target(
                &event.realm_id,
                &source,
            )?;
            if actual != *new_target {
                return Err(unavailable("Policy write target differs from actual scope"));
            }
            match crate::policy_current_results::read_management_policy_exact_in_connection(
                conn,
                &event.realm_id,
                &payload.policy_id,
            )
            .await?
            {
                ManagementPolicyCurrentRead::NeverWritten if expected.is_none() => {}
                ManagementPolicyCurrentRead::Present {
                    source, revision, ..
                } if expected.as_ref() == Some(&revision) => {
                    let previous = crate::policy_current_results::management_policy_scope_target(
                        &event.realm_id,
                        &source,
                    )?;
                    if !targets.contains(&previous) {
                        targets.push(previous);
                    }
                }
                _ => {
                    return Err(unavailable(
                        "Policy write has no matching current management revision",
                    ));
                }
            }
        }
    }
    let mut approvals = Vec::new();
    for target in &targets {
        approvals.extend(
            cut.require_policy_with_approvals(conn, event, commit, prepared, target)
                .await?,
        );
    }
    Ok(approvals)
}

#[cfg(test)]
mod signed_attachment_resource_tests {
    use arkret_wire::{EventKind, ScopeRef};
    use serde_json::json;

    use super::*;

    #[test]
    fn every_signed_message_blob_is_a_content_and_capability_target() {
        let blob = arkret_wire::BlobRef::from_bytes(b"signed attachment");
        let other = arkret_wire::BlobRef::from_bytes(b"second signed attachment");
        let realm: RealmId = "ak:realm:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
            .parse()
            .unwrap();
        let event_id: arkret_wire::EventId =
            "ak:event:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
                .parse()
                .unwrap();
        let strand = arkret_wire::StrandId::from_event_id(&event_id);
        let mut event = arkret_wire::test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
            json!({"strand_id":strand,"track_name":"main","blob_refs":[blob,other,blob]}),
            chrono::Utc::now(),
        )
        .unwrap();
        let resources = event_content_resources(&event).unwrap();
        let targets = content_capability_targets(&realm, &resources);
        for reference in [&blob, &other] {
            assert_eq!(
                resources
                    .iter()
                    .filter(|resource| resource.kind == PolicyResourceKind::Object
                        && resource.resource_ref.as_deref() == Some(reference.as_str()))
                    .count(),
                1
            );
            assert!(
                targets
                    .iter()
                    .any(|target| target.blob_ref.as_ref() == Some(reference))
            );
        }
        event.payload = serde_json::from_value(
            json!({"strand_id":strand,"track_name":"main","blob_refs":["not-a-blob"]}),
        )
        .unwrap();
        assert!(event_content_resources(&event).is_err());
    }
}

#[cfg(test)]
mod key_scope_content_tests {
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyScope, AgentKeyScopeResource,
    };
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraint, GrantConstraintEffect, GrantConstraintKind, GrantConstraintScope,
        GrantConstraintSubkind,
    };
    use arkret_wire::{ActorId, WireResourceSelector};
    use coland_storage::OperationFacts;
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const OTHER: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
    const STRAND: &str = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";
    const MESSAGE: &str = "ak:message:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";

    fn scope(resources: serde_json::Value) -> AgentKeyScope {
        serde_json::from_value(json!({
            "actions":["ak.message.create","ak.object.read","ak.self.committed_event.read.scan.v1"],
            "resources":resources
        }))
        .unwrap()
    }

    fn check(
        scope: &AgentKeyScope,
        target: &WireResourceSelector,
        facts: &OperationFacts,
    ) -> PersistenceResult<()> {
        let actor = ActorId::account(AccountId::new(
            "ak:did_core:web:agent.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        require_key_scope_content_ceiling(
            scope,
            &AuthorizationOperation {
                actor: &actor,
                actions: &["ak.message.create"],
                target,
                at: "2026-10-12T12:00:00.000Z".parse().unwrap(),
                facts,
            },
        )
    }

    #[test]
    fn exact_content_action_is_independent_of_service_surface() {
        let target = WireResourceSelector::strand(REALM.parse().unwrap(), STRAND.parse().unwrap());
        let facts = OperationFacts::default();
        let mut scoped =
            scope(json!([{"kind":"operation","operation":"ak.self.committed_event.read.scan.v1"}]));
        assert!(check(&scoped, &target, &facts).is_ok());
        scoped
            .actions
            .retain(|action| action != "ak.message.create");
        assert!(
            check(&scoped, &target, &facts).is_err(),
            "service scope never supplies omitted content action"
        );
        scoped.actions.push("ak.message".into());
        assert!(
            check(&scoped, &target, &facts).is_err(),
            "prefix does not supply exact action"
        );
        scoped.actions.push("ak.message.create".into());
        scoped.actions.retain(|action| action != "ak.message");
        scoped.resources[0].realm_id = Some(REALM.parse().unwrap());
        assert!(
            check(&scoped, &target, &facts).is_err(),
            "service selectors cannot carry content fields"
        );
    }

    #[test]
    fn aggregate_or_alternative_action_does_not_replace_actual_content_ceiling() {
        let target = WireResourceSelector::strand(REALM.parse().unwrap(), STRAND.parse().unwrap());
        let facts = OperationFacts::default();
        let actor = ActorId::account(AccountId::new(
            "ak:did_core:web:agent.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        let mut scoped = scope(json!([{"kind":"realm","realm_id":REALM}]));
        scoped.actions.push("ak.realm.owner".into());
        let operation = AuthorizationOperation {
            actor: &actor,
            actions: &["ak.message.create"],
            target: &target,
            at: "2026-10-12T12:00:00.000Z".parse().unwrap(),
            facts: &facts,
        };
        assert!(require_key_scope_content_ceiling(&scoped, &operation).is_ok());
        let aggregate = AuthorizationOperation {
            actions: &["ak.realm.owner"],
            ..operation
        };
        assert!(require_key_scope_content_ceiling(&scoped, &aggregate).is_err());
        let all = AuthorizationOperation {
            actions: &["ak.message.create", "ak.object.read"],
            ..operation
        };
        assert!(require_key_scope_content_ceiling(&scoped, &all).is_ok());
        scoped.actions.retain(|action| action != "ak.object.read");
        assert!(
            require_key_scope_content_ceiling(&scoped, &all).is_err(),
            "all actual content actions are mandatory"
        );
        let service = AuthorizationOperation {
            actions: &["ak.self.committed_event.read.scan.v1"],
            ..operation
        };
        assert!(require_key_scope_content_ceiling(&scoped, &service).is_err());
    }

    #[test]
    fn realm_content_selector_does_not_widen_to_other_realm() {
        let target = WireResourceSelector::strand(REALM.parse().unwrap(), STRAND.parse().unwrap());
        let facts = OperationFacts::default();
        let scoped = scope(json!([{"kind":"realm","realm_id":REALM,"resource_ref":REALM}]));
        assert!(check(&scoped, &target, &facts).is_ok());
        let other = WireResourceSelector::strand(OTHER.parse().unwrap(), STRAND.parse().unwrap());
        assert!(check(&scoped, &other, &facts).is_err());
        let conflicting = scope(json!([{"kind":"realm","realm_id":REALM,"resource_ref":OTHER}]));
        assert!(check(&conflicting, &target, &facts).is_err());
        let wildcard = scope(json!([{"kind":"strand","resource_ref":STRAND}]));
        assert!(
            check(&wildcard, &other, &facts).is_ok(),
            "omitted Realm is the registered ceiling wildcard"
        );
    }

    #[test]
    fn kind_and_ref_are_exact_even_when_target_contains_nested_scope() {
        let mut target =
            WireResourceSelector::strand(REALM.parse().unwrap(), STRAND.parse().unwrap());
        target.kind = arkret_wire::ResourceSelectorKind::Message;
        target.message_id = Some(MESSAGE.parse().unwrap());
        let facts = OperationFacts::default();
        let strand = scope(json!([{"kind":"strand","realm_id":REALM,"resource_ref":STRAND}]));
        assert!(
            check(&strand, &target, &facts).is_err(),
            "containing Strand field is not same-kind coverage"
        );
        let message = scope(json!([{"kind":"message","realm_id":REALM,"resource_ref":MESSAGE}]));
        assert!(check(&message, &target, &facts).is_ok());
        let wrong_kind = scope(json!([{"kind":"message","realm_id":REALM,"resource_ref":STRAND}]));
        assert!(check(&wrong_kind, &target, &facts).is_err());
        let object = scope(json!([{"kind":"object","realm_id":REALM,"resource_ref":MESSAGE}]));
        assert!(
            check(&object, &target, &facts).is_err(),
            "Object is not a universal content kind"
        );
        target.message_id = None;
        assert!(
            check(&message, &target, &facts).is_err(),
            "missing actual identity is unknown"
        );
    }

    #[test]
    fn all_registered_content_kinds_map_only_to_their_formal_fields() {
        let suffix = "AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";
        for (kind, field, reference) in [
            ("space", "space_id", format!("ak:space:{suffix}")),
            ("circle", "circle_id", format!("ak:circle:{suffix}")),
            ("strand", "strand_id", STRAND.into()),
            ("message", "message_id", MESSAGE.into()),
            ("morph", "morph_id", format!("ak:morph:{suffix}")),
            ("object", "object_ref", MESSAGE.into()),
            ("relation", "relation_id", format!("ak:relation:{suffix}")),
            ("view", "view_id", format!("ak:view:{suffix}")),
            ("event", "event_id", format!("ak:event:{suffix}")),
            ("actor", "actor_id", "ak:did_core:web:agent.example".into()),
            (
                "policy",
                "policy_id",
                "ak:policy:0198ff00-0000-7000-8000-000000000001".into(),
            ),
            ("invite", "invite_id", format!("ak:invite:{suffix}")),
            (
                "blob",
                "blob_ref",
                format!("ak:blob:sha256:{}", "a".repeat(64)),
            ),
        ] {
            let resource: AgentKeyScopeResource = serde_json::from_value(
                json!({"kind":kind,"realm_id":REALM,"resource_ref":reference}),
            )
            .unwrap();
            let selector = key_scope_content_selector(&resource).unwrap().unwrap();
            let value = serde_json::to_value(selector).unwrap();
            assert_eq!(value[field], reference, "{kind}");
        }
        let schema: AgentKeyScopeResource =
            serde_json::from_value(json!({"kind":"schema","schema_ref":"ak.schema.message.v1"}))
                .unwrap();
        assert_eq!(
            key_scope_content_selector(&schema)
                .unwrap()
                .unwrap()
                .schema_ref
                .as_deref(),
            Some("ak.schema.message.v1")
        );
        for kind in ["notification", "read_cursor"] {
            let resource: AgentKeyScopeResource =
                serde_json::from_value(json!({"kind":kind,"realm_id":REALM})).unwrap();
            assert!(key_scope_content_selector(&resource).unwrap().is_some());
            let unsupported: AgentKeyScopeResource = serde_json::from_value(
                json!({"kind":kind,"realm_id":REALM,"resource_ref":MESSAGE}),
            )
            .unwrap();
            assert!(key_scope_content_selector(&unsupported).is_err());
        }
        assert!(serde_json::from_value::<AgentKeyScopeResource>(json!({"kind":"*"})).is_err());
    }

    #[test]
    fn mandatory_scope_and_field_constraints_need_actual_facts() {
        let target = WireResourceSelector::strand(REALM.parse().unwrap(), STRAND.parse().unwrap());
        let mut scoped = scope(json!([{"kind":"service"}]));
        let mut constraint = GrantConstraint::new(
            GrantConstraintKind::ScopeLimitation,
            GrantConstraintEffect::Allow,
        );
        constraint.allowed_tracks = vec!["discussion".into()];
        constraint.allowed_strand_ids = vec![STRAND.into()];
        scoped.constraints.push(constraint);
        let facts = OperationFacts {
            track: Some("discussion".into()),
            ..Default::default()
        };
        assert!(check(&scoped, &target, &facts).is_ok());
        assert!(check(&scoped, &target, &OperationFacts::default()).is_err());
        let mut fields = GrantConstraint::new(
            GrantConstraintKind::FieldAccess,
            GrantConstraintEffect::Allow,
        );
        fields.allowed_write_fields = vec!["body".into()];
        scoped.constraints.push(fields);
        assert!(check(&scoped, &target, &facts).is_err());
        let actual = OperationFacts {
            write_fields: Some(vec!["body".into()]),
            ..facts
        };
        assert!(check(&scoped, &target, &actual).is_ok());
        let forbidden = OperationFacts {
            write_fields: Some(
                vec!["body", "mentions"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            ),
            ..actual
        };
        assert!(check(&scoped, &target, &forbidden).is_err());
    }

    #[test]
    fn unresolved_condition_and_matching_global_deny_cannot_be_skipped() {
        let target = WireResourceSelector::strand(REALM.parse().unwrap(), STRAND.parse().unwrap());
        let facts = OperationFacts {
            track: Some("discussion".into()),
            write_fields: Some(vec!["body".into()]),
            ..Default::default()
        };
        let mut scoped = scope(json!([{"kind":"service"}]));
        let conditional: GrantConstraint = serde_json::from_value(json!({
            "constraint_kind":"field_access", "effect":"allow", "allowed_write_fields":["body"],
            "condition":{"kind":"actor_is_assignee"}
        }))
        .unwrap();
        scoped.constraints.push(conditional);
        assert!(
            check(&scoped, &target, &facts).is_err(),
            "unavailable assignment condition cannot be discharged"
        );
        scoped.constraints.clear();
        let mut deny = GrantConstraint::new(
            GrantConstraintKind::ScopeLimitation,
            GrantConstraintEffect::Deny,
        );
        deny.denied_tracks = vec!["discussion".into()];
        scoped.constraints.push(deny);
        assert!(check(&scoped, &target, &facts).is_err());
        scoped.constraints.clear();
        assert!(check(&scoped, &target, &facts).is_ok());
    }

    #[test]
    fn unknown_authority_and_external_quota_cannot_become_allow() {
        let target = WireResourceSelector::strand(REALM.parse().unwrap(), STRAND.parse().unwrap());
        let facts = OperationFacts::default();
        let mut scoped = scope(json!([{"kind":"realm","realm_id":REALM}]));
        let mut authority = GrantConstraint::new(
            GrantConstraintKind::AuthorityControl,
            GrantConstraintEffect::Allow,
        );
        authority.constraint_subkind = Some(GrantConstraintSubkind::AppletAuthority);
        scoped.constraints.push(authority);
        assert!(check(&scoped, &target, &facts).is_err());
        scoped.constraints.clear();
        let mut quota =
            GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
        quota.constraint_subkind = Some(GrantConstraintSubkind::Rate);
        quota.constraint_scope = Some(GrantConstraintScope::PerActor);
        quota.max_operations = Some(3);
        quota.period = Some("PT1H".into());
        scoped.constraints.push(quota);
        assert!(check(&scoped, &target, &facts).is_err());
    }
}

#[cfg(test)]
mod session_content_tests {
    use arkret_wire::{ActorId, ResourceSelectorKind, WireResourceSelector};
    use coland_storage::OperationFacts;
    use serde_json::{Map, Value, json};

    use super::*;

    const REALM: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const OTHER: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
    const STRAND: &str = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";
    const MESSAGE: &str = "ak:message:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";

    fn details() -> Map<String, Value> {
        json!({"controller_principal_id":"ak:did_core:web:controller.example",
            "agent_key_authorization_ref":"ak:event:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv",
            "realm_ids":[REALM],"strand_ids":[STRAND],"resources":{"realm_ids":[REALM],"strand_ids":[STRAND]},
            "constraints":{"allowed_tracks":["discussion"],"allowed_data_labels":[],"allowed_endpoints":[],"allowed_strand_ids":[STRAND]},
            "capability_grant_refs":[],"policy_refs":[]}).as_object().unwrap().clone()
    }

    fn target(realm: &str) -> WireResourceSelector {
        let mut target =
            WireResourceSelector::strand(realm.parse().unwrap(), STRAND.parse().unwrap());
        target.kind = ResourceSelectorKind::Message;
        target.message_id = Some(MESSAGE.parse().unwrap());
        target
    }

    fn check(
        scopes: &[String],
        details: &Map<String, Value>,
        target: &WireResourceSelector,
        facts: &OperationFacts,
    ) -> PersistenceResult<()> {
        let actor = ActorId::account(AccountId::new(
            "ak:did_core:web:agent.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        require_session_content_ceiling(
            scopes,
            details,
            &AuthorizationOperation {
                actor: &actor,
                actions: &["ak.message.create"],
                target,
                at: "2026-10-12T12:00:00.000Z".parse().unwrap(),
                facts,
            },
        )
    }

    fn scopes() -> Vec<String> {
        vec![
            "ak.message.create".into(),
            "ak.self.committed_event.read.scan.v1".into(),
        ]
    }
    fn facts() -> OperationFacts {
        OperationFacts {
            track: Some("discussion".into()),
            ..Default::default()
        }
    }

    #[test]
    fn issuer_scope_is_exact_and_bound_to_actual_realm_and_strand() {
        let details = details();
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_ok());
        assert!(check(&scopes(), &details, &target(OTHER), &facts()).is_err());
        assert!(
            check(
                &["ak.self.committed_event.read.scan.v1".into()],
                &details,
                &target(REALM),
                &facts()
            )
            .is_err()
        );
        let mut absent = target(REALM);
        absent.strand_id = None;
        assert!(check(&scopes(), &details, &absent, &facts()).is_err());
        let actual = OperationFacts {
            strand_id: Some(STRAND.into()),
            ..facts()
        };
        assert!(check(&scopes(), &details, &absent, &actual).is_ok());
        let conflicting = OperationFacts {
            strand_id: Some("ak:strand:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5".into()),
            ..facts()
        };
        assert!(check(&scopes(), &details, &target(REALM), &conflicting).is_err());
    }

    #[test]
    fn immutable_resource_and_constraint_summaries_cannot_disagree() {
        let mut details = details();
        details["resources"]["realm_ids"] = json!([OTHER]);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
        details = self::details();
        details["constraints"]["allowed_strand_ids"] = json!([]);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
        details = self::details();
        details["resources"]["invented"] = json!([]);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
        details = self::details();
        details["realm_ids"] = json!([REALM, REALM]);
        details["resources"]["realm_ids"] = json!([REALM, REALM]);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
    }

    #[test]
    fn track_and_external_label_endpoint_ceilings_fail_closed() {
        let mut details = details();
        assert!(
            check(
                &scopes(),
                &details,
                &target(REALM),
                &OperationFacts::default()
            )
            .is_err()
        );
        let wrong = OperationFacts {
            track: Some("task".into()),
            ..Default::default()
        };
        assert!(check(&scopes(), &details, &target(REALM), &wrong).is_err());
        details["constraints"]["allowed_data_labels"] = json!(["private"]);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
        details["constraints"]["allowed_data_labels"] = json!([]);
        details["constraints"]["allowed_endpoints"] = json!(["https://agent.example"]);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
    }

    #[test]
    fn canonical_closed_fields_reject_legacy_alias_and_unknown_members() {
        let mut details = details();
        details["constraints"]
            .as_object_mut()
            .unwrap()
            .remove("allowed_data_labels");
        details["constraints"]["allowed_data_classes"] = json!([]);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
        details = self::details();
        details["resources"]
            .as_object_mut()
            .unwrap()
            .remove("realm_ids");
        details["resources"]["realm_refs"] = json!([REALM]);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
        details = self::details();
        details.insert("caller_override".into(), json!({}));
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
        details = self::details();
        details["constraints"]["unknown"] = json!(true);
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
        details = self::details();
        details.remove("controller_principal_id");
        assert!(check(&scopes(), &details, &target(REALM), &facts()).is_err());
    }
}
