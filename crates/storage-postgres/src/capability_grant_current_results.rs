use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, CapabilityGrantStatus, CapabilitySubject,
    GrantConstraintEffect, GrantConstraintKind, IssuerAuthorityRef,
};
use arkret_wire::{
    ActorId, CommitStreamRef, CommittedEventRef, CurrentRevision, EventId, GrantId, RealmCommitId,
    RealmId, WireResourceSelector,
};
use coland_storage::{ActorRealmAuthorization, resource_selector_covers};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, CapabilityGrantCurrentResultRecord,
    CapabilityGrantCurrentResultStore, CapabilityGrantCurrentStatus, Jsonb, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, async_trait, pg_conn, sql_query,
};

pub struct PgCapabilityGrantCurrentResultStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
pub(crate) struct CapabilityGrantCurrentResultReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    grant_id: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Text)]
    current_event_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = Jsonb)]
    current_stream_ref: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
pub(crate) struct RealmAuthorityRootReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    controller_epoch: i64,
    #[diesel(sql_type = BigInt)]
    authority_generation: i64,
    #[diesel(sql_type = Text)]
    authority_event_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealmAuthorityRootCurrent {
    pub(crate) realm_id: RealmId,
    pub(crate) controller_actor_id: ActorId,
    pub(crate) controller_epoch: u64,
    pub(crate) authority_generation: u64,
    pub(crate) authority_event_ref: EventId,
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Database(detail.into())
}

fn schema_violation(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.into())
}

/// A refusal whose detail is a registered conflict code keeps it; any other
/// reason (reserved or unregistered in the error-code registry) is a bare
/// `failed_precondition` carrying that reason only as diagnostic text.
fn conflict(detail: impl Into<String>) -> PersistenceError {
    let detail = detail.into();
    if coland_storage::ConflictCode::from_detail(&detail).is_some() {
        PersistenceError::Conflict(detail)
    } else {
        PersistenceError::Conflict(format!(
            "{}: {detail}",
            coland_storage::ConflictCode::FailedPrecondition
        ))
    }
}

fn u64_from_i64(value: i64, what: &str) -> PersistenceResult<u64> {
    u64::try_from(value).map_err(|_| corrupt(format!("stored {what} is negative")))
}

pub(crate) fn decode_authority_root(
    row: RealmAuthorityRootReadRow,
) -> PersistenceResult<RealmAuthorityRootCurrent> {
    Ok(RealmAuthorityRootCurrent {
        realm_id: RealmId::from_str(&row.realm_id).map_err(|error| {
            corrupt(format!(
                "stored authority-root Realm id is invalid: {error}"
            ))
        })?,
        controller_actor_id: serde_json::from_value(row.controller_actor_id).map_err(|error| {
            corrupt(format!(
                "stored authority-root controller is invalid: {error}"
            ))
        })?,
        controller_epoch: u64_from_i64(row.controller_epoch, "authority-root controller epoch")?,
        authority_generation: u64_from_i64(row.authority_generation, "authority-root generation")?,
        authority_event_ref: EventId::from_str(&row.authority_event_ref).map_err(|error| {
            corrupt(format!(
                "stored authority-root Event ref is invalid: {error}"
            ))
        })?,
    })
}

async fn locked_authority_root(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<RealmAuthorityRootCurrent>> {
    sql_query(
        "SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref \
         FROM realm_authority_root_current_results WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RealmAuthorityRootReadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_authority_root)
    .transpose()
}

fn safe_i64(value: u64, what: &str) -> PersistenceResult<i64> {
    i64::try_from(value)
        .map_err(|_| schema_violation(format!("{what} exceeds the JSON safe-integer range")))
}

/// Keep the Realm delegation root as a durable typed current result. This is
/// deliberately separate from `realm_authorities`, whose generation belongs
/// to governance-Station tenure and must never invalidate capability grants.
pub(crate) async fn commit_realm_authority_root_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let current = match event.kind {
        arkret_wire::EventKind::RealmCreate => {
            if locked_authority_root(conn, &event.realm_id)
                .await?
                .is_some()
            {
                return Err(conflict("realm_authority_root_conflict"));
            }
            RealmAuthorityRootCurrent {
                realm_id: event.realm_id.clone(),
                controller_actor_id: event.actor_id.clone(),
                controller_epoch: 0,
                authority_generation: 0,
                authority_event_ref: event.event_id.clone(),
            }
        }
        arkret_wire::EventKind::RealmOwnerTransfer => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload,
            >(serde_json::Value::Object(
                event.payload.clone().into_iter().collect(),
            ))
            .map_err(|error| {
                schema_violation(format!("Realm owner transfer payload is invalid: {error}"))
            })?;
            if payload.realm_id != event.realm_id {
                return Err(schema_violation(
                    "Realm owner transfer targets another Realm",
                ));
            }
            let mut current = locked_authority_root(conn, &event.realm_id)
                .await?
                .ok_or_else(|| conflict("realm_authority_root_missing"))?;
            let digest = arkret_canonical::canonical_sha256(&serde_json::json!({
                "controller_actor_id": current.controller_actor_id,
                "controller_epoch": current.controller_epoch,
                "authority_generation": current.authority_generation,
                "authority_event_ref": current.authority_event_ref,
            }))
            .map_err(PersistenceError::database)?;
            if digest.as_str() != payload.expected_state_digest.as_str() {
                return Err(conflict("realm_authority_root_conflict"));
            }
            current.controller_actor_id = payload.patch.controller_actor_id;
            current.controller_epoch = arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload::successor_controller_epoch(current.controller_epoch)
                .map_err(|_| conflict("realm_authority_root_conflict"))?;
            current
        }
        arkret_wire::EventKind::RealmAuthorityReset => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::realm::RealmAuthorityResetPayload,
            >(serde_json::Value::Object(
                event.payload.clone().into_iter().collect(),
            ))
            .map_err(|error| {
                schema_violation(format!("Realm authority reset payload is invalid: {error}"))
            })?;
            if payload.realm_id != event.realm_id {
                return Err(schema_violation(
                    "Realm authority reset targets another Realm",
                ));
            }
            let mut current = locked_authority_root(conn, &event.realm_id)
                .await?
                .ok_or_else(|| conflict("realm_authority_root_missing"))?;
            let digest = arkret_canonical::canonical_sha256(&serde_json::json!({
                "controller_actor_id": current.controller_actor_id,
                "controller_epoch": current.controller_epoch,
                "authority_generation": current.authority_generation,
                "authority_event_ref": current.authority_event_ref,
            }))
            .map_err(PersistenceError::database)?;
            if digest.as_str() != payload.expected_state_digest.as_str() {
                return Err(conflict("realm_authority_root_conflict"));
            }
            current.authority_generation = arkret_models_collaboration::events_payloads::realm::RealmAuthorityResetPayload::successor_authority_generation(current.authority_generation)
                .map_err(|_| conflict("realm_authority_root_conflict"))?;
            current.authority_event_ref = event.event_id.clone();
            current
        }
        _ => return Ok(()),
    };

    sql_query(
        "INSERT INTO realm_authority_root_current_results \
         (realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT(realm_id) DO UPDATE SET controller_actor_id=EXCLUDED.controller_actor_id, \
         controller_epoch=EXCLUDED.controller_epoch,authority_generation=EXCLUDED.authority_generation, \
         authority_event_ref=EXCLUDED.authority_event_ref,current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(current.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&current.controller_actor_id).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(safe_i64(current.controller_epoch, "controller_epoch")?)
    .bind::<BigInt, _>(safe_i64(current.authority_generation, "authority_generation")?)
    .bind::<Text, _>(current.authority_event_ref.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(safe_i64(commit.stream_position, "stream_position")?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) fn decode_row(
    row: CapabilityGrantCurrentResultReadRow,
) -> PersistenceResult<CapabilityGrantCurrentResultRecord> {
    let realm_id = RealmId::from_str(&row.realm_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant Realm id is invalid: {error}"
        ))
    })?;
    let grant_id = GrantId::from_str(&row.grant_id)
        .map_err(|error| corrupt(format!("stored Capability Grant id is invalid: {error}")))?;
    let status = CapabilityGrantCurrentStatus::from_str(&row.status)?;
    let stream_position = u64::try_from(row.current_stream_position)
        .map_err(|_| corrupt("stored Capability Grant stream position is negative"))?;
    let commit_id = RealmCommitId::from_str(&row.current_commit_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant Commit id is invalid: {error}"
        ))
    })?;
    let event_id = EventId::from_str(&row.current_event_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant source Event id is invalid: {error}"
        ))
    })?;
    let stream_ref =
        serde_json::from_value::<CommitStreamRef>(row.current_stream_ref).map_err(|error| {
            corrupt(format!(
                "stored Capability Grant stream ref is invalid: {error}"
            ))
        })?;
    let value = serde_json::from_value::<CapabilityGrant>(row.value).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant current value is invalid: {error}"
        ))
    })?;
    CapabilityGrantCurrentResultRecord::try_new(
        realm_id,
        grant_id,
        status,
        value,
        CurrentRevision {
            commit_id: commit_id.clone(),
            stream_position,
        },
        CommittedEventRef {
            event_id,
            commit_id,
            stream_ref,
            stream_position,
        },
    )
}

fn effective_not_before(grant: &CapabilityGrant) -> Option<chrono::DateTime<chrono::Utc>> {
    grant
        .constraints
        .iter()
        .filter(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
        .filter_map(|constraint| constraint.not_before)
        .max()
}

fn ordinary_authority_control(
    grant: &CapabilityGrant,
) -> Option<&arkret_models_collaboration::governance::grant_constraint::GrantConstraint> {
    grant.constraints.iter().find(|constraint| {
        constraint.constraint_kind == GrantConstraintKind::AuthorityControl
            && constraint.constraint_subkind.is_none()
    })
}

pub(crate) fn grant_is_active_at(
    grant: &CapabilityGrant,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    grant.status == CapabilityGrantStatus::Active
        && effective_not_before(grant).is_none_or(|value| value <= accepted_at)
        && coland_storage::capability_grant_expires_at(grant)
            .is_none_or(|value| value > accepted_at)
}

fn root_sort_key(root: &AuthorityRootRef) -> PersistenceResult<Vec<u8>> {
    arkret_canonical::canonical_json_bytes(root).map_err(PersistenceError::database)
}

fn sorted_unique_roots(
    roots: impl IntoIterator<Item = AuthorityRootRef>,
) -> PersistenceResult<Vec<AuthorityRootRef>> {
    let mut keyed = roots
        .into_iter()
        .map(|root| Ok((root_sort_key(&root)?, root)))
        .collect::<PersistenceResult<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    Ok(keyed.into_iter().map(|(_, root)| root).collect())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Ancestor validation keeps each authority binding and bounded traversal input explicit."
)]
pub(crate) fn validate_ancestor_graph(
    child_id: &GrantId,
    current_id: &GrantId,
    rows: &BTreeMap<GrantId, CapabilityGrant>,
    root: &RealmAuthorityRootCurrent,
    realm_id: &RealmId,
    accepted_at: chrono::DateTime<chrono::Utc>,
    visiting: &mut BTreeSet<GrantId>,
    depth: u64,
) -> PersistenceResult<()> {
    if ancestor_graph_current(
        child_id,
        current_id,
        rows,
        root,
        realm_id,
        accepted_at,
        visiting,
        depth,
        false,
    )? {
        Ok(())
    } else {
        Err(conflict("grant_revoked_upstream"))
    }
}

/// Continuity of an already accepted grant, not permission to exercise an
/// action or re-issue its profile-specific initial authority. A known closed
/// lineage is distinct from unavailable current evidence.
pub(crate) fn accepted_grant_is_current(
    grant_id: &GrantId,
    rows: &BTreeMap<GrantId, CapabilityGrant>,
    root: &RealmAuthorityRootCurrent,
    realm_id: &RealmId,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    ancestor_graph_current(
        // An accepted grant cannot be an ancestor of a new candidate here.
        // The traversal still detects all actual cycles through `visiting`.
        grant_id,
        grant_id,
        rows,
        root,
        realm_id,
        accepted_at,
        &mut BTreeSet::new(),
        0,
        true,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "The original grant cut and legacy error mapping remain explicit."
)]
fn ancestor_graph_current(
    child_id: &GrantId,
    current_id: &GrantId,
    rows: &BTreeMap<GrantId, CapabilityGrant>,
    root: &RealmAuthorityRootCurrent,
    realm_id: &RealmId,
    accepted_at: chrono::DateTime<chrono::Utc>,
    visiting: &mut BTreeSet<GrantId>,
    depth: u64,
    complete_current: bool,
) -> PersistenceResult<bool> {
    if depth > 4
        || (!complete_current && current_id == child_id)
        || !visiting.insert(current_id.clone())
    {
        return Err(conflict("authority_cycle"));
    }
    let parent = rows.get(current_id).ok_or_else(|| {
        if complete_current {
            conflict("temporarily_unavailable: accepted grant current is unavailable")
        } else {
            conflict("grant_exceeds_issuer_authority")
        }
    })?;
    require_delegable_parent(parent)?;
    if complete_current
        && (parent.realm_id.as_ref() != Some(realm_id) || parent.issuer_authority_refs.is_empty())
    {
        return Err(conflict(
            "temporarily_unavailable: accepted grant authority current is incomplete",
        ));
    }
    if parent.realm_id.as_ref() != Some(realm_id) || !grant_is_active_at(parent, accepted_at) {
        return Ok(false);
    }
    for authority_ref in &parent.issuer_authority_refs {
        match authority_ref {
            IssuerAuthorityRef::OwnedAgent { .. } => {
                return Err(conflict("authority_regrant_denied"));
            }
            IssuerAuthorityRef::RealmRoot {
                realm_id: root_realm_id,
                authority_event_ref,
                authority_generation,
            } => {
                if root_realm_id != realm_id
                    || root.realm_id != *root_realm_id
                    || root.authority_event_ref != *authority_event_ref
                    || root.authority_generation != *authority_generation
                {
                    return Ok(false);
                }
            }
            IssuerAuthorityRef::Grant { grant_id } => {
                let Some(ancestor) = rows.get(grant_id) else {
                    return if complete_current {
                        Err(conflict(
                            "temporarily_unavailable: accepted grant ancestor current is unavailable",
                        ))
                    } else {
                        Ok(false)
                    };
                };
                if !matches!(&ancestor.subject, CapabilitySubject::Actor(actor) if actor == &parent.issuer_id)
                {
                    return Err(conflict("grant_exceeds_issuer_authority"));
                }
                if !ancestor_graph_current(
                    child_id,
                    grant_id,
                    rows,
                    root,
                    realm_id,
                    accepted_at,
                    visiting,
                    depth + 1,
                    complete_current,
                )? {
                    return Ok(false);
                }
            }
        }
    }
    visiting.remove(current_id);
    Ok(true)
}

fn parent_covers(
    parent: &CapabilityGrant,
    child_action: &str,
    child_resource: &WireResourceSelector,
) -> bool {
    parent.actions.iter().any(|action| {
        arkret_policy::action_grants_authority_for(action, child_action).unwrap_or(false)
    }) && parent
        .resources
        .iter()
        .any(|resource| resource_selector_covers(resource, child_resource))
}

fn validate_parent_constraints(
    parent: &CapabilityGrant,
    child: &arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
) -> PersistenceResult<()> {
    let Some(control) = ordinary_authority_control(parent) else {
        return Err(conflict("authority_regrant_denied"));
    };
    let child_control = child.constraints.iter().find(|constraint| {
        constraint.constraint_kind == GrantConstraintKind::AuthorityControl
            && constraint.constraint_subkind.is_none()
    });
    let regrant_allowed = control.authority_regrant_allowed.unwrap_or(false);
    if control.max_authority_depth == Some(0) {
        return Err(conflict(if regrant_allowed {
            "authority_depth_exceeded"
        } else {
            "authority_regrant_denied"
        }));
    }
    if !regrant_allowed {
        if child_control.is_none_or(|child| {
            child.max_authority_depth != Some(0) || child.authority_regrant_allowed.unwrap_or(false)
        }) {
            return Err(conflict("authority_regrant_denied"));
        }
    } else if let Some(parent_depth) = control.max_authority_depth
        && child_control
            .and_then(|child| child.max_authority_depth)
            .is_none_or(|child_depth| child_depth > parent_depth.saturating_sub(1))
    {
        return Err(conflict("authority_depth_exceeded"));
    }
    if let Some(parent_expiry) = coland_storage::capability_grant_expires_at(parent) {
        let child_expiry = child
            .constraints
            .iter()
            .filter(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
            .filter_map(|constraint| constraint.expires_at)
            .min();
        if child_expiry.is_none_or(|value| value > parent_expiry) {
            return Err(conflict("authority_expiry_widening"));
        }
    }
    // A complete semantic partial-order over every constraint family belongs
    // in the policy crate. Until it is available, fail closed unless every
    // deny/require/quarantine parent constraint is preserved byte-for-byte.
    for constraint in parent.constraints.iter().filter(|constraint| {
        !matches!(
            constraint.effect,
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintEffect::Allow
        )
    }) {
        if !child.constraints.contains(constraint) {
            return Err(schema_violation("grant constraints widen parent authority"));
        }
    }
    Ok(())
}

enum CapabilityGrantCurrentMutation {
    Create {
        grant_id: GrantId,
        body: Box<arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody>,
    },
    Close {
        grant_id: GrantId,
        expected_revision: CurrentRevision,
        status: CapabilityGrantCurrentStatus,
    },
}

fn mutation_for_event(
    event: &arkret_wire::Event,
) -> PersistenceResult<Option<CapabilityGrantCurrentMutation>> {
    let invalid = |what: &str, error: serde_json::Error| {
        schema_violation(format!(
            "{what} payload violates its typed SDK contract: {error}"
        ))
    };
    let payload_value = || serde_json::Value::Object(event.payload.clone().into_iter().collect());
    match event.kind {
        arkret_wire::EventKind::CapabilityGrant => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityGrantPayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Grant", error))?;
            if payload.grant.schema != arkret_wire::SchemaId::CAPABILITY_V1
                || payload.grant.issuer_id != event.actor_id
                || payload
                    .grant
                    .realm_id
                    .as_ref()
                    .is_some_and(|realm_id| realm_id != &event.realm_id)
            {
                return Err(schema_violation(
                    "Capability Grant authoring body does not match its Event envelope",
                ));
            }
            let grant_id = GrantId::from_event_id(&event.event_id);
            Ok(Some(CapabilityGrantCurrentMutation::Create {
                grant_id,
                body: Box::new(payload.grant),
            }))
        }
        arkret_wire::EventKind::CapabilityRevoke => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityRevokePayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Revoke", error))?;
            Ok(Some(CapabilityGrantCurrentMutation::Close {
                grant_id: payload.grant_id,
                expected_revision: payload.expected_revision,
                status: CapabilityGrantCurrentStatus::Revoked,
            }))
        }
        arkret_wire::EventKind::CapabilityRelinquish => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Relinquish", error))?;
            Ok(Some(CapabilityGrantCurrentMutation::Close {
                grant_id: payload.grant_id,
                expected_revision: payload.expected_revision,
                status: CapabilityGrantCurrentStatus::Relinquished,
            }))
        }
        _ => Ok(None),
    }
}

fn revision_matches(
    current: &CapabilityGrantCurrentResultRecord,
    expected: &CurrentRevision,
) -> bool {
    current.revision == *expected
}

fn finite_global_expiry(
    constraints: &[arkret_models_collaboration::governance::grant_constraint::GrantConstraint],
) -> Option<chrono::DateTime<chrono::Utc>> {
    constraints
        .iter()
        .filter(|constraint| {
            constraint.constraint_kind == GrantConstraintKind::Temporal
                && constraint.effect == GrantConstraintEffect::Allow
                && constraint.applies_to_actions.is_empty()
                && constraint.recurrence.is_none()
        })
        .filter_map(|constraint| constraint.expires_at)
        .min()
}

/// The one `non_event_grant_authority_rules[]` row across compiled profiles
/// whose `grantable_action` is `action`.
fn non_event_grant_authority_rule(
    action: &str,
) -> PersistenceResult<Option<&'static arkret_wire::NonEventGrantAuthorityRule>> {
    let mut rules = arkret_wire::PROFILE_REQUIREMENTS
        .values()
        .flat_map(|profile| profile.non_event_grant_authority_rules.iter())
        .filter(|rule| rule.grantable_action == action);
    let rule = rules.next();
    if rules.next().is_some() {
        return Err(corrupt(format!(
            "non-event grant authority for {action} is registered more than once"
        )));
    }
    Ok(rule)
}

#[derive(QueryableByName)]
struct RegistrationCurrentRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// Enforce the registration-side bindings of a non-event grant authority rule
/// against the accepted Applet registration current result of this Realm.
async fn require_non_event_registration_binding(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    body: &arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
    rule: &arkret_wire::NonEventGrantAuthorityRule,
) -> PersistenceResult<()> {
    let exceeds = || conflict("grant_exceeds_issuer_authority");
    if rule.required_registration_event_kind != arkret_wire::event_kind_str::APPLET_REGISTRATION
        || rule.subject_binding != "registration.service_id"
        || rule.scope_binding != "grant.resource_exact_registration_scope"
        || rule.epoch_binding != "constraint.registration_epoch_exact_registration"
        || rule.requested_action_binding != "grant.action_in_registration.requested_scopes"
    {
        return Err(corrupt(format!(
            "non-event grant authority rule for {} has an unimplemented binding",
            rule.grantable_action
        )));
    }
    let wire_name = |value: serde_json::Result<serde_json::Value>| {
        value
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
    };
    let bindings = body
        .constraints
        .iter()
        .filter(|constraint| {
            wire_name(serde_json::to_value(constraint.constraint_kind)).as_deref()
                == Some(rule.required_constraint_kind)
                && constraint
                    .constraint_subkind
                    .as_ref()
                    .is_some_and(|subkind| {
                        wire_name(serde_json::to_value(subkind)).as_deref()
                            == Some(rule.required_constraint_subkind)
                    })
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return Err(exceeds());
    };
    let Some(applet_id) = binding.applet_id.as_ref() else {
        return Err(exceeds());
    };
    let registration = sql_query(
        "SELECT value FROM applet_registration_current_results          WHERE realm_id=$1 AND applet_id=$2 AND service_id=$3 FOR SHARE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(applet_id.as_str())
    .bind::<Text, _>(match binding.executed_by.as_ref() { Some(ActorId::Service { service_id }) => service_id.as_str(), _ => return Err(exceeds()) })
    .get_result::<RegistrationCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(exceeds)?;
    let registration: arkret_models_integration::AppletRegistrationPayload =
        serde_json::from_value(registration.value).map_err(PersistenceError::database)?;
    let service = ActorId::service(registration.service_id.clone());
    let subject_bound = matches!(
        &body.subject,
        CapabilitySubject::Actor(actor) if actor == &service
    );
    if !subject_bound
        || !registration
            .claimed_profiles
            .iter()
            .any(|profile| profile == rule.required_claimed_profile)
        || !registration
            .requested_scopes
            .iter()
            .any(|scope| scope == rule.grantable_action)
        || binding.registration_epoch.as_ref() != Some(&registration.registration_epoch)
        || binding.executed_by.as_ref() != Some(&service)
        || body.resources.is_empty()
        || body.resources.iter().any(|resource| {
            resource.kind == arkret_wire::ResourceSelectorKind::All
                || resource.realm_id.as_ref() != Some(&event.realm_id)
        })
    {
        return Err(exceeds());
    }
    Ok(())
}

pub(crate) async fn managed_subject_role(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    subject: &CapabilitySubject,
    issuer: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<
    Option<arkret_models_collaboration::governance::grant_constraint::ManagedActorRole>,
> {
    let CapabilitySubject::Actor(subject) = subject else {
        return Ok(None);
    };
    if subject.as_realm_actor_id().is_none() {
        return Ok(None);
    }
    let provision = crate::realm_actor_control::creation_source(conn, subject).await?;
    let (manager, _) = crate::realm_actor_control::current_source(
        conn,
        subject,
        serde_json::json!({"kind":"realm_actor_manager","actor_id":subject}),
    )
    .await?;
    let manager: arkret_models_integration::RealmActorManagerValue =
        serde_json::from_value(manager).map_err(PersistenceError::database)?;
    if issuer != &ActorId::service(manager.service_id)
        || event.applet_id.as_ref() != Some(&provision.applet_id)
    {
        return Err(conflict(
            "Realm managed subject requires its current Service issuer",
        ));
    }
    // Identity qualification reopens the Realm creation, manager and status gates.
    let mut qualification = event.clone();
    qualification.actor_id = subject.clone();
    qualification.executed_by = Some(issuer.clone());
    crate::boxed_future(|| {
        crate::managed_message_actor::require_managed_actor_in_connection(conn, &qualification, at)
    })
    .await?;
    Ok(Some(match provision.actor_role {
        arkret_models_integration::RealmActorCreatePayloadActorRole::Bot => {
            arkret_models_collaboration::governance::grant_constraint::ManagedActorRole::Bot
        }
        arkret_models_integration::RealmActorCreatePayloadActorRole::Ghost => {
            arkret_models_collaboration::governance::grant_constraint::ManagedActorRole::Ghost
        }
    }))
}

pub(crate) fn validate_managed_sources(
    parents: &[&CapabilityGrant],
    child: &arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
    role: arkret_models_collaboration::governance::grant_constraint::ManagedActorRole,
) -> PersistenceResult<()> {
    arkret_policy::grant_authority::validate_managed_service_sources(child, parents, role)
        .map_err(|error| conflict(error.to_string()))
}

fn materialize_capability_grant<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a arkret_wire::Event,
    commit: &'a arkret_wire::RealmCommit,
    grant_id: GrantId,
    body: arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = PersistenceResult<CapabilityGrant>> + Send + 'a>,
> {
    crate::boxed_future(|| materialize_capability_grant_inner(conn, event, commit, grant_id, body))
}

/// The registry's owned source is an exclusive terminal execution/read root.
/// Derivation never proves its liveness; the caller must validate accepted
/// ownership and both exact current join Events at its held admission cut.
fn owned_authority_root(
    body: &arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
) -> PersistenceResult<Option<AuthorityRootRef>> {
    use arkret_wire::CapabilityActionId as Action;
    body.validate_owned_agent_shape()
        .map_err(|error| schema_violation(error.to_string()))?;
    let [
        IssuerAuthorityRef::OwnedAgent {
            realm_id,
            controller_account_id,
            controller_join_event_id,
            agent_join_event_id,
        },
    ] = body.issuer_authority_refs.as_slice()
    else {
        return Ok(None);
    };
    if body.actions.is_empty()
        || body.resources.is_empty()
        || body.actions.iter().any(|action| {
            !matches!(
                Action::from_wire(action),
                Some(
                    Action::EventRead
                        | Action::MessageCreate
                        | Action::MessageRedactOwn
                        | Action::MessageReviseOwn
                        | Action::ObjectRead
                        | Action::ObjectReadContent
                        | Action::ObjectReadHistory
                        | Action::ObjectReadMetadata
                        | Action::ReactionAdd
                        | Action::ReactionRemove
                        | Action::StrandRead
                )
            )
        })
    {
        return Err(schema_violation(
            "owned Agent action is outside its registered terminal surface",
        ));
    }
    Ok(Some(AuthorityRootRef::OwnedAgent {
        realm_id: realm_id.clone(),
        controller_account_id: controller_account_id.clone(),
        controller_join_event_id: controller_join_event_id.clone(),
        agent_join_event_id: agent_join_event_id.clone(),
    }))
}

fn require_delegable_parent(parent: &CapabilityGrant) -> PersistenceResult<()> {
    if parent
        .issuer_authority_refs
        .iter()
        .any(|source| matches!(source, IssuerAuthorityRef::OwnedAgent { .. }))
        || parent
            .authority_root_refs
            .iter()
            .any(|root| matches!(root, AuthorityRootRef::OwnedAgent { .. }))
    {
        return Err(conflict("authority_regrant_denied"));
    }
    Ok(())
}

fn materialized_grant(
    realm_id: &RealmId,
    grant_id: GrantId,
    body: arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
    authority_depth: u64,
    authority_root_refs: Vec<AuthorityRootRef>,
) -> CapabilityGrant {
    CapabilityGrant {
        id: grant_id,
        schema: body.schema,
        realm_id: Some(realm_id.clone()),
        issuer_id: body.issuer_id,
        subject: body.subject,
        actions: body.actions,
        resources: body.resources,
        constraints: body.constraints,
        issuer_authority_refs: body.issuer_authority_refs,
        authority_depth,
        authority_root_refs,
        issued_at: body.issued_at,
        status: CapabilityGrantStatus::Active,
        updated_by: None,
        updated_at: None,
        revoked_by: None,
        revoked_at: None,
    }
}

/// Enforce the subject's immutable ceiling under the actual grant transaction.
/// Qualified encrypted custody supplies the controller disclosure. Its exact
/// accepted provision, genesis, authorization and active receipt are rechecked
/// under the same connection before evaluating any grant resource or action.
async fn require_agent_provision_ceiling_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    body: &arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
    evidence: Option<&coland_storage::VerifiedAgentScopeEvidence>,
) -> PersistenceResult<()> {
    let CapabilitySubject::Actor(subject) = &body.subject else {
        return Ok(());
    };
    let Some(account) = subject.as_account_id() else {
        return Ok(());
    };
    if !crate::realm_authorization_cut::is_owned_agent_in_connection(conn, &event.realm_id, account)
        .await?
    {
        return Ok(());
    }
    let evidence = evidence.ok_or_else(|| conflict("agent_requested_scope_commitment_invalid"))?;
    let binding = evidence.accepted_binding();
    if binding.controller_account.station_id != account.station_id
        || evidence.command().requested_scope_disclosure.agent_id != account.principal_id
        || binding.verified_at > commit.committed_at
    {
        return Err(conflict("agent_requested_scope_commitment_invalid"));
    }
    let current = crate::realm_authorization_cut::owned_source_in_connection(
        conn,
        &event.realm_id,
        subject,
        commit.committed_at,
        true,
    )
    .await
    .map_err(|_| conflict("agent_requested_scope_commitment_invalid"))?;
    if !matches!(current, Some(IssuerAuthorityRef::OwnedAgent { controller_account_id, .. })
        if controller_account_id == binding.controller_account)
    {
        return Err(conflict("agent_requested_scope_commitment_invalid"));
    }
    let authorization =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            &evidence.command().authorize_event.event,
        )
        .map_err(|error| schema_violation(error.to_string()))?;
    let endpoint = coland_storage::AgentEndpointGuard {
        pcr_realm_id: binding.pcr_genesis_ref.stream_ref.realm_id().clone(),
        agent_id: account.principal_id.clone(),
        authorization_ref: evidence.accepted_authorization_ref().clone(),
        verification_method: authorization.verification_method,
    };
    let scope = crate::account_content_delivery::provision_scope_in_connection(
        conn,
        &endpoint,
        evidence,
        &account.station_id,
    )
    .await
    .map_err(|_| conflict("agent_requested_scope_commitment_invalid"))?;
    if !arkret_models_collaboration::agent_scope::agent_grant_scope_within_provision(
        &scope,
        &body.actions,
        &body.resources,
        &body.constraints,
    )
    .map_err(|error| schema_violation(error.to_string()))?
    {
        return Err(conflict("agent_grant_exceeds_requested_scope"));
    }
    Ok(())
}

async fn materialize_capability_grant_inner(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    grant_id: GrantId,
    body: arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
) -> PersistenceResult<CapabilityGrant> {
    if body.issuer_authority_refs.is_empty() {
        return Err(schema_violation(
            "Capability Grant authority refs are empty",
        ));
    }
    body.validate_owned_agent_shape()
        .map_err(|error| schema_violation(error.to_string()))?;
    let managed_role = crate::boxed_future(|| {
        managed_subject_role(
            conn,
            event,
            &body.subject,
            &body.issuer_id,
            commit.committed_at,
        )
    })
    .await?;
    if managed_role.is_some()
        && (!matches!(body.issuer_id, ActorId::Service { .. })
            || body.issuer_authority_refs.is_empty()
            || body
                .issuer_authority_refs
                .iter()
                .any(|source| !matches!(source, IssuerAuthorityRef::Grant { .. })))
    {
        return Err(conflict(
            "managed Account authority must come from its Applet Service parent",
        ));
    }
    let child_expiry = finite_global_expiry(&body.constraints);
    if child_expiry.is_some_and(|expires_at| expires_at <= commit.committed_at) {
        return Err(conflict("grant_exceeds_issuer_authority"));
    }
    // capabilities.md section 8: grant admission never branches on the subject
    // kind. Only registry `required_constraints` add an expiry requirement, and
    // they apply to every subject alike.
    let mut registry_expiry_required = false;
    for action in &body.actions {
        let descriptor = arkret_schema::capability_action(action)
            .ok_or_else(|| schema_violation(format!("unregistered grant action {action}")))?;
        registry_expiry_required |= descriptor.required_constraints.contains(&"expires_at");
    }
    if registry_expiry_required && child_expiry.is_none() {
        return Err(conflict("grant requires a finite global expiry"));
    }

    if let CapabilitySubject::Actor(subject) = &body.subject {
        let subject_cut = crate::boxed_future(|| {
            crate::realm_authorization_cut::RealmAuthorizationCut::read(
                conn,
                &event.realm_id,
                subject,
            )
        })
        .await?;
        if let Some(controller) = crate::boxed_future(|| {
            subject_cut.owned_controller_in_connection(conn, commit.committed_at)
        })
        .await?
        {
            let controller = controller
                .as_account_id()
                .ok_or_else(|| conflict("Agent authorization controller is not an account"))?;
            let subject = subject
                .as_account_id()
                .ok_or_else(|| conflict("Agent authorization subject is not an account"))?;
            crate::boxed_future(|| {
                crate::agent_management_admission::require_authorization_in_connection(
                    conn,
                    &event.realm_id,
                    controller,
                    subject,
                    &body.actions,
                    &body.resources,
                    commit.committed_at,
                )
            })
            .await?;
        }
    }

    if let Some(owned_root) = owned_authority_root(&body)? {
        // This is the original signed Event, not a reference synthesized from
        // a principal row. Recheck the complete accepted source and current
        // controller coverage under the same transaction as the current write.
        crate::boxed_future(|| crate::realm_authorization_cut::RealmAuthorizationCut::require_owned_grant_coverage_in_connection(
            conn, event, &body, commit.committed_at,
        )).await?;
        return Ok(materialized_grant(
            &event.realm_id,
            grant_id,
            body,
            1,
            vec![owned_root],
        ));
    }

    // The Realm authority row already serializes commits, while this ordered
    // lock snapshot gives every grant dependency one deterministic database
    // basis. No process-local projection participates in admission.
    let locked_rows = sql_query(
        "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
         current_stream_position,value FROM capability_grant_current_results \
         WHERE realm_id=$1 ORDER BY grant_id ASC FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut rows = BTreeMap::new();
    for row in locked_rows {
        let record = decode_row(row)?;
        if rows.insert(record.grant_id, record.value).is_some() {
            return Err(corrupt("duplicate Capability Grant current row"));
        }
    }

    let root = locked_authority_root(conn, &event.realm_id)
        .await?
        .ok_or_else(|| conflict("realm_authority_root_missing"))?;

    let mut seen_refs = BTreeSet::new();
    let mut parent_ids = Vec::new();
    let mut roots = Vec::new();
    let mut deepest = 0_u64;
    for authority_ref in &body.issuer_authority_refs {
        let key = arkret_canonical::canonical_json_bytes(authority_ref)
            .map_err(PersistenceError::database)?;
        if !seen_refs.insert(key) {
            return Err(schema_violation(
                "Capability Grant authority refs are duplicated",
            ));
        }
        match authority_ref {
            IssuerAuthorityRef::OwnedAgent { .. } => {
                return Err(schema_violation("owned Agent source must be exclusive"));
            }
            IssuerAuthorityRef::RealmRoot {
                realm_id,
                authority_event_ref,
                authority_generation,
            } => {
                if realm_id != &event.realm_id {
                    return Err(conflict("grant_exceeds_issuer_authority"));
                }
                if root.realm_id != *realm_id
                    || root.controller_actor_id != body.issuer_id
                    || root.authority_event_ref != *authority_event_ref
                    || root.authority_generation != *authority_generation
                {
                    return Err(conflict("realm_authority_controller_mismatch"));
                }
                roots.push(AuthorityRootRef::RealmRoot {
                    realm_id: realm_id.clone(),
                    authority_event_ref: authority_event_ref.clone(),
                    authority_generation: *authority_generation,
                });
            }
            IssuerAuthorityRef::Grant {
                grant_id: parent_id,
            } => {
                let parent = rows
                    .get(parent_id)
                    .ok_or_else(|| conflict("grant_exceeds_issuer_authority"))?;
                if parent.realm_id.as_ref() != Some(&event.realm_id)
                    || !matches!(&parent.subject, CapabilitySubject::Actor(actor) if actor == &body.issuer_id)
                    || !grant_is_active_at(parent, commit.committed_at)
                {
                    return Err(conflict("grant_exceeds_issuer_authority"));
                }
                require_delegable_parent(parent)?;
                if managed_role.is_none() {
                    validate_parent_constraints(parent, &body)?;
                }
                deepest = deepest.max(parent.authority_depth);
                roots.extend(parent.authority_root_refs.iter().cloned());
                parent_ids.push(parent_id.clone());
            }
        }
    }

    if let Some(role) = managed_role {
        let parents = parent_ids.iter().map(|id| &rows[id]).collect::<Vec<_>>();
        validate_managed_sources(&parents, &body, role)?;
    }

    // capabilities.md §3.2 / §10.3: a closed upstream ancestor refuses the
    // first grant as `grant_exceeds_issuer_authority`; only a loop keeps its
    // own `authority_cycle`.
    for parent_id in &parent_ids {
        validate_ancestor_graph(
            &grant_id,
            parent_id,
            &rows,
            &root,
            &event.realm_id,
            commit.committed_at,
            &mut BTreeSet::new(),
            1,
        )
        .map_err(|error| {
            if error.conflict_code() == Some(coland_storage::ConflictCode::AuthorityCycle) {
                error
            } else {
                conflict("grant_exceeds_issuer_authority")
            }
        })?;
    }
    let authority_depth = deepest
        .checked_add(1)
        .filter(|depth| *depth <= 4)
        .ok_or_else(|| conflict("authority_depth_exceeded"))?;
    let authority_root_refs = sorted_unique_roots(roots)?;
    if authority_root_refs.is_empty() {
        return Err(conflict("grant_exceeds_issuer_authority"));
    }

    // A profile-registered non-event action is grantable only through its
    // `non_event_grant_authority_rules[]` row: the issuer must hold the rule's
    // issuer action and the grant must bind the accepted registration.
    let mut non_event_rules = BTreeMap::new();
    for action in &body.actions {
        if let Some(rule) = non_event_grant_authority_rule(action)? {
            require_non_event_registration_binding(conn, event, &body, rule).await?;
            non_event_rules.insert(action.as_str(), rule);
        }
    }

    let mut ref_contributed = vec![false; body.issuer_authority_refs.len()];
    for action in &body.actions {
        let rule = non_event_rules.get(action.as_str()).copied();
        for resource in &body.resources {
            let mut covered = false;
            for (index, authority_ref) in body.issuer_authority_refs.iter().enumerate() {
                let ref_covers = match (authority_ref, rule) {
                    (IssuerAuthorityRef::OwnedAgent { .. }, _) => false,
                    (IssuerAuthorityRef::RealmRoot { .. }, None) => {
                        arkret_policy::owner_may_grant(action).unwrap_or(false)
                    }
                    (IssuerAuthorityRef::RealmRoot { .. }, Some(rule)) => {
                        rule.issuer_owner_authority_allowed
                            && arkret_policy::owner_may_grant(rule.issuer_action).unwrap_or(false)
                    }
                    (IssuerAuthorityRef::Grant { grant_id }, None) => rows
                        .get(grant_id)
                        .is_some_and(|parent| parent_covers(parent, action, resource)),
                    (IssuerAuthorityRef::Grant { grant_id }, Some(rule)) => rows
                        .get(grant_id)
                        .is_some_and(|parent| parent_covers(parent, rule.issuer_action, resource)),
                };
                if ref_covers {
                    covered = true;
                    ref_contributed[index] = true;
                }
            }
            if !covered {
                return Err(conflict("grant_exceeds_issuer_authority"));
            }
        }
    }
    if ref_contributed.iter().any(|contributed| !contributed) {
        return Err(schema_violation(
            "Capability Grant carries a redundant authority ref",
        ));
    }

    Ok(materialized_grant(
        &event.realm_id,
        grant_id,
        body,
        authority_depth,
        authority_root_refs,
    ))
}

/// Materialize one of the four registered `capability_grant` writers inside
/// the same PostgreSQL transaction as its Event and RealmCommit.
pub(crate) fn commit_capability_grant_current_result_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a arkret_wire::Event,
    commit: &'a arkret_wire::RealmCommit,
    prepared: Option<&'a coland_storage::EventApprovalCommit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = PersistenceResult<()>> + Send + 'a>> {
    Box::pin(commit_capability_grant_current_result_inner(
        conn, event, commit, None, prepared,
    ))
}

pub(crate) fn commit_qualified_capability_grant_current_result_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a arkret_wire::Event,
    commit: &'a arkret_wire::RealmCommit,
    evidence: Option<&'a coland_storage::VerifiedAgentScopeEvidence>,
    prepared: Option<&'a coland_storage::EventApprovalCommit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = PersistenceResult<()>> + Send + 'a>> {
    Box::pin(commit_capability_grant_current_result_inner(
        conn, event, commit, evidence, prepared,
    ))
}

async fn commit_capability_grant_current_result_inner(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    evidence: Option<&coland_storage::VerifiedAgentScopeEvidence>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    let Some(mutation) = mutation_for_event(event)? else {
        return Ok(());
    };
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let grant_id = match &mutation {
        CapabilityGrantCurrentMutation::Create { grant_id, .. }
        | CapabilityGrantCurrentMutation::Close { grant_id, .. } => grant_id.clone(),
    };
    let lock_key = format!("capability-grant:{}:{}", event.realm_id, grant_id);
    // `pg_advisory_xact_lock` waits until it holds the lock (or the statement
    // fails), and returns `void`, so there is no "not acquired" result to test.
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(&lock_key)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

    let current = sql_query(
        "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
         current_stream_position,value FROM capability_grant_current_results \
         WHERE realm_id=$1 AND grant_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(grant_id.as_str())
    .get_result::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_row)
    .transpose()?;

    // Applet management is sourced by the accepted Service parent and the
    // terminal-child contract, independently of conversation membership.
    // Ordinary grant/revoke writers retain their joined-member action gate.
    let native_service = event.applet_id.is_some()
        && matches!(event.actor_id, ActorId::Service { .. })
        && event.executed_by.is_none();
    let managed_management = if native_service {
        match (&mutation, current.as_ref()) {
            (CapabilityGrantCurrentMutation::Create { body, .. }, _) => crate::boxed_future(|| {
                managed_subject_role(
                    conn,
                    event,
                    &body.subject,
                    &body.issuer_id,
                    commit.committed_at,
                )
            })
            .await?
            .is_some(),
            (
                CapabilityGrantCurrentMutation::Close {
                    status: CapabilityGrantCurrentStatus::Revoked,
                    ..
                },
                Some(target),
            ) if target.value.issuer_id == event.actor_id => crate::boxed_future(|| {
                managed_subject_role(
                    conn,
                    event,
                    &target.value.subject,
                    &target.value.issuer_id,
                    commit.committed_at,
                )
            })
            .await?
            .is_some(),
            _ => false,
        }
    } else {
        false
    };
    let cut = if event.kind == arkret_wire::EventKind::CapabilityRelinquish || managed_management {
        crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &event.realm_id,
            &event.actor_id,
        )
        .await?
        .require_open_lifecycle(event)?;
        None
    } else {
        Some(
            crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
                conn, event, commit, prepared,
            )
            .await?,
        )
    };

    if let CapabilityGrantCurrentMutation::Create { body, .. } = &mutation {
        crate::boxed_future(|| {
            require_agent_provision_ceiling_in_connection(conn, event, commit, body, evidence)
        })
        .await?;
    }
    let (status, value) = match (mutation, current.as_ref()) {
        (CapabilityGrantCurrentMutation::Create { grant_id, body }, None) => (
            CapabilityGrantCurrentStatus::Active,
            materialize_capability_grant(conn, event, commit, grant_id, *body).await?,
        ),
        (CapabilityGrantCurrentMutation::Create { .. }, Some(_)) => {
            return Err(conflict(
                "failed_precondition: Capability Grant current result already exists",
            ));
        }
        (
            CapabilityGrantCurrentMutation::Close {
                grant_id,
                expected_revision,
                status,
            },
            Some(current),
        ) => {
            // capabilities.md §10.4 target guards: revoke by the target's
            // issuer or the current root controller of its own Realm;
            // relinquish by its subject only.
            match status {
                CapabilityGrantCurrentStatus::Revoked => {
                    let root_controller = cut
                        .as_ref()
                        .is_some_and(crate::realm_authorization_cut::RealmAuthorizationCut::actor_is_root_controller);
                    if current.value.issuer_id != event.actor_id && !root_controller {
                        return Err(conflict(
                            "capability_denied: the actor is neither the grant issuer nor the Realm root controller",
                        ));
                    }
                }
                CapabilityGrantCurrentStatus::Relinquished => {
                    if !matches!(&current.value.subject, CapabilitySubject::Actor(subject) if subject == &event.actor_id)
                    {
                        return Err(conflict("grant_relinquish_not_subject"));
                    }
                }
                CapabilityGrantCurrentStatus::Active => {}
            }
            if current.status != CapabilityGrantCurrentStatus::Active
                || !revision_matches(current, &expected_revision)
            {
                return Err(conflict(
                    "cas_conflict: Capability Grant current revision does not match",
                ));
            }
            let mut value = current.value.clone();
            if value.id != grant_id
                || value.realm_id.as_ref() != Some(&event.realm_id)
                || value.status != CapabilityGrantStatus::Active
            {
                return Err(corrupt(
                    "stored Capability Grant current value disagrees with its authoritative row",
                ));
            }
            value.status = status.grant_status();
            match status {
                CapabilityGrantCurrentStatus::Revoked => {
                    value.revoked_by = Some(event.actor_id.clone());
                    value.revoked_at = Some(event.created_at);
                }
                CapabilityGrantCurrentStatus::Relinquished => {
                    value.updated_by = Some(event.actor_id.clone());
                    value.updated_at = Some(event.created_at);
                }
                CapabilityGrantCurrentStatus::Active => unreachable!("close cannot remain active"),
            }
            (status, value)
        }
        (CapabilityGrantCurrentMutation::Close { .. }, None) => {
            return Err(conflict(
                "failed_precondition: Capability Grant current result does not exist",
            ));
        }
    };

    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::Internal(
            "Capability Grant stream position exceeds PostgreSQL BIGINT".to_owned(),
        )
    })?;
    let stream_ref =
        serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
    if current.is_none() {
        crate::applet_current_results::retain_service_grant_source(conn, &event.realm_id, &value)
            .await?;
    }
    let value = serde_json::to_value(&value).map_err(PersistenceError::database)?;
    sql_query(
        "INSERT INTO capability_grant_current_results \
         (realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
          current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT(realm_id,grant_id) DO UPDATE SET \
           status=EXCLUDED.status,current_event_id=EXCLUDED.current_event_id, \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_ref=EXCLUDED.current_stream_ref, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(grant_id.as_str())
    .bind::<Text, _>(status.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Jsonb, _>(&stream_ref)
    .bind::<BigInt, _>(stream_position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[async_trait]
impl CapabilityGrantCurrentResultStore for PgCapabilityGrantCurrentResultStore {
    async fn get(
        &self,
        realm_id: &RealmId,
        grant_id: &GrantId,
    ) -> PersistenceResult<Option<CapabilityGrantCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value \
             FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(grant_id.as_str())
        .get_result::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_row)
        .transpose()
    }

    async fn snapshot_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value \
             FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(decode_row)
        .collect()
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value \
             FROM capability_grant_current_results ORDER BY realm_id ASC,grant_id ASC",
        )
        .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(decode_row)
        .collect()
    }

    async fn active_for_subject(
        &self,
        subject: &ActorId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>> {
        let subject = serde_json::to_value(subject).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value \
             FROM capability_grant_current_results WHERE status='active' AND value->'subject'=$1 \
             ORDER BY realm_id ASC,grant_id ASC",
        )
        .bind::<Jsonb, _>(&subject)
        .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(decode_row)
        .collect()
    }

    async fn actor_authorization(
        &self,
        realm_id: &RealmId,
        actor: &ActorId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActorRealmAuthorization> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<ActorRealmAuthorization, PgTransactionError, _>(async |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *conn)
                .await?;
            let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read_accepted(
                conn, realm_id, actor,
            )
            .await?;
            Ok(cut
                .bounded_actor_authorization_in_connection(conn, at)
                .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn agent_session_authority(
        &self,
        request: &coland_storage::AgentSessionAuthorityRequest,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::AgentSessionAuthorityOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *conn)
                .await?;
            Ok(crate::agent_session_authority::read(conn, request, at).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn seed_test_realm_root(
        &self,
        realm_id: &RealmId,
        controller: &ActorId,
    ) -> PersistenceResult<()> {
        let authority_event_ref = EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(format!("fixture-root:{realm_id}").as_bytes()),
        );
        let commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("fixture-root-commit:{realm_id}").as_bytes(),
        ));
        let controller = serde_json::to_value(controller).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO realm_authority_root_current_results \
             (realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,\
              current_commit_id,current_stream_position,updated_at) \
             VALUES($1,$2,0,0,$3,$4,0,now()) \
             ON CONFLICT(realm_id) DO UPDATE SET controller_actor_id=EXCLUDED.controller_actor_id",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Jsonb, _>(&controller)
        .bind::<Text, _>(authority_event_ref.as_str())
        .bind::<Text, _>(commit_id.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn seed_test_grant(
        &self,
        grant: &coland_storage::TestCapabilityGrant,
    ) -> PersistenceResult<GrantId> {
        let mut conn = pg_conn(&self.pool).await?;
        let root = sql_query(
            "SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,\
             authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(grant.realm_id.as_str())
        .get_result::<RealmAuthorityRootReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)
        .and_then(decode_authority_root)?;
        let event_id = EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(uuid::Uuid::new_v4().as_bytes()),
        );
        let grant_id = GrantId::from_event_id(&event_id);
        let commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            event_id.as_str().as_bytes(),
        ));
        let root_ref = IssuerAuthorityRef::RealmRoot {
            realm_id: grant.realm_id.clone(),
            authority_event_ref: root.authority_event_ref.clone(),
            authority_generation: root.authority_generation,
        };
        let value = CapabilityGrant {
            id: grant_id.clone(),
            schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
            realm_id: Some(grant.realm_id.clone()),
            issuer_id: root.controller_actor_id.clone(),
            subject: CapabilitySubject::Actor(grant.subject.clone()),
            actions: grant.actions.clone(),
            resources: grant.resources.clone(),
            constraints: grant.constraints.clone(),
            issuer_authority_refs: vec![root_ref],
            authority_depth: 1,
            authority_root_refs: vec![AuthorityRootRef::RealmRoot {
                realm_id: grant.realm_id.clone(),
                authority_event_ref: root.authority_event_ref,
                authority_generation: root.authority_generation,
            }],
            issued_at: chrono::Utc::now(),
            status: CapabilityGrantStatus::Active,
            updated_by: None,
            updated_at: None,
            revoked_by: None,
            revoked_at: None,
        };
        let value = serde_json::to_value(&value).map_err(PersistenceError::database)?;
        let stream_ref = serde_json::to_value(CommitStreamRef::Realm {
            realm_id: grant.realm_id.clone(),
        })
        .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO capability_grant_current_results \
             (realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
              current_stream_position,value,updated_at) \
             VALUES($1,$2,'active',$3,$4,$5,0,$6,now())",
        )
        .bind::<Text, _>(grant.realm_id.as_str())
        .bind::<Text, _>(grant_id.as_str())
        .bind::<Text, _>(event_id.as_str())
        .bind::<Text, _>(commit_id.as_str())
        .bind::<Jsonb, _>(&stream_ref)
        .bind::<Jsonb, _>(&value)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(grant_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn seed_test_grant_status(
        &self,
        realm_id: &RealmId,
        grant_id: &GrantId,
        status: CapabilityGrantCurrentStatus,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE capability_grant_current_results \
             SET status=$3,value=jsonb_set(value,'{status}',to_jsonb($3::text)) \
             WHERE realm_id=$1 AND grant_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(grant_id.as_str())
        .bind::<Text, _>(status.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
    const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

    fn selector(value: serde_json::Value) -> WireResourceSelector {
        serde_json::from_value(value).expect("valid selector")
    }

    fn owned_body() -> arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
        let controller = arkret_wire::AccountId::new(
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        );
        let agent = arkret_wire::AccountId::new(
            "ak:did_core:web:agent.example".parse().unwrap(),
            controller.station_id.clone(),
        );
        serde_json::from_value(serde_json::json!({
            "schema":"ak.schema.capability.v1", "realm_id":REALM_ID,
            "issuer_id":ActorId::account(controller.clone()), "subject":ActorId::account(agent),
            "actions":["ak.message.create"], "resources":[{"kind":"realm","realm_id":REALM_ID}],
            "constraints":[{"constraint_kind":"authority_control","effect":"allow","max_authority_depth":0,"authority_regrant_allowed":false}],
            "issuer_authority_refs":[{"kind":"owned_agent","realm_id":REALM_ID,
                "controller_account_id":controller,
                "controller_join_event_id":EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[61;32]),
                "agent_join_event_id":EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[62;32])}],
            "issued_at":"2026-10-12T00:00:00.000Z"
        })).unwrap()
    }

    #[test]
    fn owned_materializer_derives_exact_terminal_root_and_preserves_constraints() {
        let body = owned_body();
        let root = owned_authority_root(&body).unwrap().unwrap();
        let IssuerAuthorityRef::OwnedAgent {
            realm_id,
            controller_account_id,
            controller_join_event_id,
            agent_join_event_id,
        } = &body.issuer_authority_refs[0]
        else {
            unreachable!()
        };
        assert_eq!(
            root,
            AuthorityRootRef::OwnedAgent {
                realm_id: realm_id.clone(),
                controller_account_id: controller_account_id.clone(),
                controller_join_event_id: controller_join_event_id.clone(),
                agent_join_event_id: agent_join_event_id.clone(),
            }
        );
        let grant = materialized_grant(
            realm_id,
            GRANT_ID.parse().unwrap(),
            body.clone(),
            1,
            vec![root],
        );
        assert_eq!(grant.authority_depth, 1);
        assert_eq!(grant.issuer_authority_refs, body.issuer_authority_refs);
        assert_eq!(grant.constraints, body.constraints);
        assert_eq!(
            serde_json::to_value(&grant.subject).unwrap(),
            serde_json::to_value(&body.subject).unwrap()
        );
        assert_eq!(grant.status, CapabilityGrantStatus::Active);
    }

    #[test]
    fn owned_materializer_rejects_admin_service_unknown_and_mixed_sources() {
        let mut body = owned_body();
        for action in [
            "ak.event.read",
            "ak.message.create",
            "ak.message.redact.own",
            "ak.message.revise.own",
            "ak.object.read",
            "ak.object.read_content",
            "ak.object.read_history",
            "ak.object.read_metadata",
            "ak.reaction.add",
            "ak.reaction.remove",
            "ak.strand.read",
        ] {
            body.actions = vec![action.to_owned()];
            assert!(owned_authority_root(&body).unwrap().is_some(), "{action}");
        }
        for action in [
            "ak.capability.grant",
            "ak.agent.key.authorize",
            "ak.message.redact.any",
            "ak.admin",
            "ak.self.events.command.submit.v1",
            "ak.unknown",
        ] {
            body.actions = vec![action.to_owned()];
            assert!(owned_authority_root(&body).is_err(), "{action}");
        }
        body = owned_body();
        body.issuer_authority_refs.push(IssuerAuthorityRef::Grant {
            grant_id: GRANT_ID.parse().unwrap(),
        });
        assert!(owned_authority_root(&body).is_err());
        body = owned_body();
        body.constraints.clear();
        assert!(owned_authority_root(&body).is_err());
        body = owned_body();
        body.issuer_id = ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:other-station.example".parse().unwrap(),
        ));
        assert!(owned_authority_root(&body).is_err());
    }

    #[test]
    fn owned_parent_cannot_regrant_even_with_forged_control_or_only_owned_root() {
        let body = owned_body();
        let root = owned_authority_root(&body).unwrap().unwrap();
        let realm = body.realm_id.as_ref().unwrap();
        let mut parent = materialized_grant(
            realm,
            GRANT_ID.parse().unwrap(),
            body.clone(),
            1,
            vec![root],
        );
        parent.constraints[0].max_authority_depth = Some(4);
        parent.constraints[0].authority_regrant_allowed = Some(true);
        let refusal = require_delegable_parent(&parent).unwrap_err();
        assert_eq!(
            refusal.conflict_code(),
            Some(coland_storage::ConflictCode::FailedPrecondition)
        );
        assert!(refusal.to_string().contains("authority_regrant_denied"));
        parent.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
            grant_id: GrantId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [63; 32],
            )),
        }];
        let refusal = require_delegable_parent(&parent).unwrap_err();
        assert_eq!(
            refusal.conflict_code(),
            Some(coland_storage::ConflictCode::FailedPrecondition)
        );
        assert!(refusal.to_string().contains("authority_regrant_denied"));
    }

    #[test]
    fn durable_ceiling_selector_match_is_narrowing_only() {
        let realm = selector(serde_json::json!({"kind":"realm","realm_id":REALM_ID}));
        let exact_realm = selector(serde_json::json!({"kind":"realm","realm_id":REALM_ID}));
        let other_realm = selector(serde_json::json!({
            "kind":"realm",
            "realm_id":"ak:realm:ASm71QhtF54BxHBvRFcIhmLfPFYTrXhTcLnVAEMmqZ5t"
        }));
        assert!(resource_selector_covers(&realm, &exact_realm));
        assert!(!resource_selector_covers(&realm, &other_realm));

        let any_strand = selector(serde_json::json!({"kind":"strand","realm_id":REALM_ID}));
        let exact_strand = selector(serde_json::json!({
            "kind":"strand",
            "realm_id":REALM_ID,
            // A Strand id retypes its creating Event's id.
            "strand_id":arkret_wire::StrandId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x51; 32],
            )),
        }));
        assert!(resource_selector_covers(&any_strand, &exact_strand));
        assert!(!resource_selector_covers(&exact_strand, &any_strand));
    }

    fn row(status: &str) -> CapabilityGrantCurrentResultReadRow {
        CapabilityGrantCurrentResultReadRow {
            realm_id: REALM_ID.to_owned(),
            grant_id: GRANT_ID.to_owned(),
            status: status.to_owned(),
            current_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x44; 32],
            )
            .to_string(),
            current_commit_id: COMMIT_ID.to_owned(),
            current_stream_ref: serde_json::json!({"kind":"realm","realm_id":REALM_ID}),
            current_stream_position: 7,
            value: grant_value(status),
        }
    }

    fn grant_value(status: &str) -> serde_json::Value {
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        serde_json::json!({
            "id": GRANT_ID,
            "schema": "ak.schema.capability.v1",
            "realm_id": REALM_ID,
            "issuer_id": actor,
            "subject": actor,
            "actions": ["ak.message.create"],
            "resources": [{"kind":"realm", "realm_id":REALM_ID}],
            "issuer_authority_refs": [{
                "kind":"grant",
                "grant_id":"ak:grant:AU1_A5a8MMz_OdxEleQlWPFn-ljdJteaJv3ZZ9APkcrZ"
            }],
            "authority_depth": 2,
            "authority_root_refs": [{
                "kind":"realm_root",
                "realm_id":REALM_ID,
                "authority_event_ref":EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x55; 32],
                ),
                "authority_generation":0
            }],
            "issued_at": "2026-09-21T00:00:00.000Z",
            "status": status
        })
    }

    #[test]
    fn accepted_continuity_distinguishes_closed_initial_authority_from_unknown_current() {
        let realm: RealmId = REALM_ID.parse().unwrap();
        let id: GrantId = GRANT_ID.parse().unwrap();
        let at = "2026-10-17T00:00:00.000Z".parse().unwrap();
        let mut grant: CapabilityGrant = serde_json::from_value(grant_value("active")).unwrap();
        let root = RealmAuthorityRootCurrent {
            realm_id: realm.clone(),
            controller_actor_id: grant.issuer_id.clone(),
            controller_epoch: 0,
            authority_generation: 0,
            authority_event_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x55; 32],
            ),
        };
        grant.actions = vec!["ak.applet.bot.provision".into()];
        grant.subject = CapabilitySubject::Actor(ActorId::service(
            "ak:did_core:web:applet.example".parse().unwrap(),
        ));
        grant.authority_depth = 1;
        assert!(!arkret_policy::owner_may_grant("ak.applet.bot.provision").unwrap());
        grant.issuer_authority_refs = vec![IssuerAuthorityRef::RealmRoot {
            realm_id: realm.clone(),
            authority_event_ref: root.authority_event_ref.clone(),
            authority_generation: 0,
        }];
        let mut grants = BTreeMap::from([(id.clone(), grant.clone())]);
        // Initial issuer qualification is already accepted. Current continuity
        // must neither re-issue nor erase that profile-specific source.
        assert!(accepted_grant_is_current(&id, &grants, &root, &realm, at).unwrap());
        grants.get_mut(&id).unwrap().status = CapabilityGrantStatus::Revoked;
        assert!(!accepted_grant_is_current(&id, &grants, &root, &realm, at).unwrap());
        grants.insert(id.clone(), grant.clone());
        let mut changed_root = root.clone();
        changed_root.authority_generation = 1;
        assert!(!accepted_grant_is_current(&id, &grants, &changed_root, &realm, at).unwrap());
        assert_eq!(
            accepted_grant_is_current(&id, &BTreeMap::new(), &root, &realm, at)
                .unwrap_err()
                .conflict_code(),
            Some(coland_storage::ConflictCode::TemporarilyUnavailable)
        );
        let missing = GrantId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x56; 32],
        ));
        grants.get_mut(&id).unwrap().issuer_authority_refs =
            vec![IssuerAuthorityRef::Grant { grant_id: missing }];
        assert_eq!(
            accepted_grant_is_current(&id, &grants, &root, &realm, at)
                .unwrap_err()
                .conflict_code(),
            Some(coland_storage::ConflictCode::TemporarilyUnavailable)
        );
        grants.get_mut(&id).unwrap().issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
            grant_id: id.clone(),
        }];
        assert!(accepted_grant_is_current(&id, &grants, &root, &realm, at).is_err());
    }

    #[test]
    fn reader_returns_value_and_exact_commit_revision_from_one_row() {
        let record = decode_row(row("active")).unwrap();
        assert_eq!(record.status, CapabilityGrantCurrentStatus::Active);
        assert_eq!(record.value.id.as_str(), GRANT_ID);
        assert_eq!(record.revision.commit_id.as_str(), COMMIT_ID);
        assert_eq!(record.revision.stream_position, 7);
    }

    #[test]
    fn reader_rejects_lifecycle_or_identity_drift() {
        let mut lifecycle = row("active");
        lifecycle.value["status"] = serde_json::json!("revoked");
        assert!(matches!(
            decode_row(lifecycle),
            Err(PersistenceError::Database(_))
        ));

        let mut identity = row("active");
        identity.value["realm_id"] =
            serde_json::json!("ak:realm:ASm71QhtF54BxHBvRFcIhmLfPFYTrXhTcLnVAEMmqZ5t");
        assert!(matches!(
            decode_row(identity),
            Err(PersistenceError::Database(_))
        ));
    }

    #[test]
    fn reader_rejects_non_commit_revision_material() {
        let mut invalid_commit = row("active");
        invalid_commit.current_commit_id =
            "ak:event:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4".to_owned();
        assert!(matches!(
            decode_row(invalid_commit),
            Err(PersistenceError::Database(_))
        ));

        let mut negative_position = row("active");
        negative_position.current_stream_position = -1;
        assert!(matches!(
            decode_row(negative_position),
            Err(PersistenceError::Database(_))
        ));
    }
}
