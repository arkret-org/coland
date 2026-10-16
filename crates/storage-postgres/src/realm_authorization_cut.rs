//! Same-cut authorization of capability-gated Realm Events.
//!
//! The governing Station decides whether an Event's actor may author its kind
//! from four Realm-stream typed current results read inside the accepting
//! transaction: `realm_authority_root`, every `capability_grant` of the Realm,
//! `realm_policy_bundle` and the actor's own `member_state`
//! (`authz/event-auth-state-resolution.md` §1, `authz/capabilities.md` §18).
//!
//! [`authorize_capability_gated_event_with_approvals`] first takes the Realm
//! authority row lock. Every writer of those four families commits on the Realm
//! stream through the same row, so the verdict and the Commit it gates are one
//! cut: a grant revoked before this transaction took the lock is observed here,
//! and one revoked after it cannot commit until this transaction has ended.
//! The in-process reducer projection is never an input.
//!
//! The authorizing actions of a kind are exactly the capability actions whose
//! registered `target_event_kinds` list it; there is no second per-kind list.
//! The current root controller holds the effective `ak.realm.owner` aggregate
//! (`authz/capabilities.md` §3.2) and therefore every kind that aggregate
//! lists; any other actor needs an active Capability Grant naming one of the
//! authorizing actions on a selector covering the Realm, with an intact issuer
//! chain. Membership is a required input, never an authorization source.
//!
//! Every grant is judged by [`coland_storage::evaluate_grants`], the single
//! constraint evaluator (`authz/constraint-schema.md` §15.4); a hard quota a
//! satisfied grant owes is reserved on the quota authority inside the same
//! transaction ([`crate::capability_quota`]), so the reservation commits or
//! rolls back with the Event it admits.
//!
//! An action whose registry row lists `required_evaluator_checks` is never
//! sufficient on its own: only a kind-specific caller that discharges those
//! checks may count it. The one such check decided here is
//! `actor_eq_target_author` of the `.own` Message actions
//! ([`RealmAuthorizationCut::require_authored_target_in_connection`]).
//!
//! The Realm authority row lock taken first is the one dependency lock of the
//! cut. Every writer of the root, grant, policy bundle and member rows, and of
//! the Realm's terminal lifecycle, commits on the Realm stream through that
//! row (`authz/capabilities.md` §3.2), so a concurrent change of any of them
//! either committed before the lock was granted and is read here, or waits
//! for this transaction and is decided against its result.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, GrantConstraintEffect, GrantConstraintKind,
    IssuerAuthorityRef,
};
use arkret_wire::{
    ActorId, CapabilityActionId, CurrentRevision, EventKind, GrantId, RealmId, StrandId,
    WireResourceSelector,
};
use coland_storage::{
    ActorRealmAuthorization, AuthorizationOperation, EffectiveActorGrant, GrantEvaluation,
    OperationFacts, evaluate_grants,
};

use super::{
    AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};
use crate::capability_grant_current_results::{
    CapabilityGrantCurrentResultReadRow, RealmAuthorityRootCurrent, RealmAuthorityRootReadRow,
    decode_authority_root, decode_row, grant_is_active_at, validate_ancestor_graph,
};
use crate::direct_conversation_admission::ProfileAuthority;

/// The value members of the closed `realm-profile.schema.json` object, the
/// `schema` discriminator excepted (`models/realm-and-space.md` section 2.3.A:
/// `title`, `summary` and `avatar_blob_ref` are carried only by
/// `ak.realm.profile`).
const REALM_PROFILE_VALUE_FIELDS: [&str; 3] = ["title", "summary", "avatar_blob_ref"];

#[derive(QueryableByName)]
struct PolicyBundleRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct MembershipRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

#[derive(QueryableByName)]
struct LifecycleRow {
    #[diesel(sql_type = Text)]
    kind: String,
}

#[derive(QueryableByName)]
struct LockedAuthorityRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

fn capability_denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

/// Classification survives missing lifecycle/current projections and binds the
/// complete AccountId. It grants no membership or current controller authority.
pub(crate) async fn is_owned_agent_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    account: &arkret_wire::AccountId,
) -> PersistenceResult<bool> {
    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        present: bool,
    }
    let actor = ActorId::account(account.clone());
    Ok(sql_query(
        "SELECT EXISTS(SELECT 1 FROM agent_provisioning_current_results p \
         JOIN pcr_genesis_units g ON g.realm_id=p.realm_id \
         WHERE p.agent_id=$1 AND g.station_id=$2) \
         OR EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.state='committed' AND e.kind='ak.agent.provision' \
           AND e.envelope->'payload'->>'agent_id'=$1 \
           AND e.envelope->'actor_id'->'account_id'->>'station_id'=$2 \
           AND c.realm_id=e.realm_id \
           AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',e.realm_id)) \
         OR EXISTS(SELECT 1 FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
         JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE m.realm_id=$3 AND m.member_id=$4 \
           AND e.envelope->'payload' ? 'agent_controller_binding') AS present",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(actor.to_string())
    .get_result::<Present>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present)
}

/// Verified current ownership shared by action and member-read admission.
/// The caller holds the Realm lock or one repeatable-read visibility cut.
pub(crate) async fn owned_controller_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<ActorId>> {
    Box::pin(read_owned_controller_in_connection(
        conn, realm_id, actor, at, true,
    ))
    .await
}

/// Read ownership without admission locks from one repeatable-read snapshot.
pub(crate) async fn owned_controller_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<ActorId>> {
    read_owned_controller_in_connection(conn, realm_id, actor, at, false).await
}

async fn read_owned_controller_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
    lock: bool,
) -> PersistenceResult<Option<ActorId>> {
    let Some(agent) = actor.as_account_id() else {
        return Ok(None);
    };
    // Classification is accepted ownership material, never a profile label.
    // A broken/removed binding must not turn a known Agent into a human.
    let known = is_owned_agent_in_connection(conn, realm_id, agent).await?;
    if !known {
        return Ok(None);
    }
    let controller = if lock {
        crate::agent_interaction_current_results::controller_in_connection(
            conn, realm_id, agent, at,
        )
        .await?
    } else {
        crate::agent_interaction_current_results::controller_snapshot_in_connection(
            conn, realm_id, agent, at,
        )
        .await?
    }
    .ok_or_else(|| capability_denied("owned Agent current controller binding is unavailable"))?;
    let nested = is_owned_agent_in_connection(conn, realm_id, &controller).await?;
    if nested {
        return Err(capability_denied(
            "an Agent cannot supply another Agent's controller authority",
        ));
    }
    let account = sql_query(format!(
        "SELECT 'active' AS membership FROM accounts WHERE principal_id=$1 AND station_id=$2{}",
        if lock { " FOR SHARE" } else { "" }
    ))
    .bind::<Text, _>(controller.principal_id.as_str())
    .bind::<Text, _>(controller.station_id.as_str())
    .get_result::<MembershipRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    // Native Account identity is established by accepted PCR genesis, not by
    // the optional product account projection. Lock an existing projection so
    // its lifecycle writer remains serialized with this operation.
    if account.is_none() {
        #[derive(QueryableByName)]
        struct IdentityRow {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            present: bool,
        }
        let accepted = sql_query("SELECT EXISTS(SELECT 1 FROM principal_resolutions r JOIN pcr_genesis_units g ON g.realm_id=r.pcr_realm_id AND g.principal_id=r.principal_id AND g.station_id=r.station_id WHERE r.principal_id=$1 AND r.station_id=$2) AS present")
            .bind::<Text, _>(controller.principal_id.as_str())
            .bind::<Text, _>(controller.station_id.as_str())
            .get_result::<IdentityRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
        if !accepted {
            return Err(capability_denied(
                "owned Agent controller identity is unavailable",
            ));
        }
    }
    let lifecycle = sql_query("SELECT l.state AS membership FROM account_lifecycle l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2")
        .bind::<Text,_>(controller.principal_id.as_str())
        .bind::<Text,_>(controller.station_id.as_str())
        .get_result::<MembershipRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if lifecycle.is_some_and(|row| row.membership != "active") {
        return Err(capability_denied(
            "owned Agent controller account is not active",
        ));
    }
    Ok(Some(ActorId::account(controller)))
}

/// Resolve the immutable owned source from the two accepted current joins.
/// The caller fixes the transaction cut; no cached reference establishes liveness.
pub(crate) async fn owned_source_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
    lock: bool,
) -> PersistenceResult<Option<IssuerAuthorityRef>> {
    let Some(controller) =
        read_owned_controller_in_connection(conn, realm, agent, at, lock).await?
    else {
        return Ok(None);
    };
    #[derive(QueryableByName)]
    struct JoinRow {
        #[diesel(sql_type = Text)]
        member_id: String,
        #[diesel(sql_type = Jsonb)]
        envelope: serde_json::Value,
    }
    let members = vec![controller.to_string(), agent.to_string()];
    let rows = sql_query(format!(
        "SELECT m.member_id,e.envelope FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
         JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE m.realm_id=$1 AND m.member_id=ANY($2) AND m.membership='join' \
           AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) \
           AND e.realm_id=$1 AND e.scope_ref=c.stream_ref \
           AND c.commit_json->>'event_ref'=e.envelope->>'event_id' \
         ORDER BY m.member_id{}",
        if lock { " FOR SHARE OF m" } else { "" }
    ))
    .bind::<Text, _>(realm.as_str())
    .bind::<super::Array<Text>, _>(&members)
    .load::<JoinRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut joins = BTreeMap::new();
    for row in rows {
        let event: arkret_wire::Event =
            serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
        let joined_member = match event.kind {
            EventKind::MemberState => {
                let member: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)
                        .map_err(PersistenceError::database)?)
                        .map_err(PersistenceError::database)?;
                member
                    .to_value()
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                (member.membership
                    == arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join)
                    .then_some(member.member_id)
            }
            EventKind::InviteAccept if row.member_id == controller.to_string() => {
                let accept: arkret_models_collaboration::governance::membership_invite::InviteAcceptPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)
                        .map_err(PersistenceError::database)?)
                        .map_err(PersistenceError::database)?;
                accept
                    .validate_actor(&event.actor_id)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                event
                    .actor_id
                    .as_account_id()
                    .map(|_| event.actor_id.clone())
            }
            _ => None,
        };
        if event.realm_id != *realm
            || joined_member.as_ref().map(ToString::to_string).as_deref()
                != Some(row.member_id.as_str())
            || joins.insert(row.member_id, event).is_some()
        {
            return Err(capability_denied(
                "owned source current join is inconsistent",
            ));
        }
    }
    let controller_join = joins
        .get(&controller.to_string())
        .ok_or_else(|| capability_denied("owned source controller join is unavailable"))?;
    let agent_join = joins
        .get(&agent.to_string())
        .ok_or_else(|| capability_denied("owned source Agent join is unavailable"))?;
    let binding: arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding =
        serde_json::from_value(agent_join.payload.get("agent_controller_binding")
            .cloned().ok_or_else(|| capability_denied("owned source binding is unavailable"))?)
            .map_err(PersistenceError::database)?;
    let controller_account_id = controller
        .as_account_id()
        .ok_or_else(|| capability_denied("owned source controller is not an account"))?;
    if binding.controller_account_id != *controller_account_id
        || binding.controller_membership_generation_ref != controller_join.event_id
        || binding.controller_terminal_event_ref.is_some()
    {
        return Err(capability_denied("owned source join generation differs"));
    }
    Ok(Some(IssuerAuthorityRef::OwnedAgent {
        realm_id: realm.clone(),
        controller_account_id: controller_account_id.clone(),
        controller_join_event_id: controller_join.event_id.clone(),
        agent_join_event_id: agent_join.event_id.clone(),
    }))
}

/// Resolve the actual native scope of a confirmed selector. Navigation ancestry
/// and caller-supplied context are never authority or private Circle evidence.
async fn confirmed_resource_scope(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    target: &WireResourceSelector,
) -> PersistenceResult<Option<arkret_wire::ScopeRef>> {
    use arkret_wire::{ResourceSelectorKind as Kind, ScopeRef};
    target
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if target.realm_id.as_ref() != Some(realm) || target.match_scope.is_some() {
        return Ok(None);
    }
    match target.kind {
        Kind::Realm => Ok(Some(ScopeRef::Realm {
            realm_id: realm.clone(),
        })),
        Kind::Circle => Ok(target.circle_id.as_ref().map(|circle_id| ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle_id.clone(),
        })),
        Kind::Space => {
            let Some(id) = target.space_id.as_ref() else {
                return Ok(None);
            };
            let row = sql_query("SELECT s.value FROM space_current_results s JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id AND c.stream_position=s.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE s.realm_id=$1 AND s.space_id=$2")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(id.as_str()).get_result::<PolicyBundleRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            let Some(row) = row else { return Ok(None) };
            let space: arkret_models_collaboration::objects::space::Space =
                serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if space.id.as_ref() != Some(id) || space.realm_id != *realm {
                return Ok(None);
            }
            Ok(Some(match space.scope_circle_id {
                Some(circle_id) => ScopeRef::Circle {
                    realm_id: realm.clone(),
                    circle_id,
                },
                None => ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
            }))
        }
        Kind::Strand => {
            let Some(id) = target.strand_id.as_ref() else {
                return Ok(None);
            };
            let row = sql_query("SELECT s.value FROM strand_current_results s JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id AND c.stream_position=s.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE s.realm_id=$1 AND s.strand_id=$2")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(id.as_str()).get_result::<PolicyBundleRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            let Some(row) = row else { return Ok(None) };
            let strand: arkret_models_collaboration::objects::strand::Strand =
                serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if strand.id.as_ref() != Some(id) || strand.realm_id != *realm {
                return Ok(None);
            }
            Ok(Some(match strand.scope_circle_id {
                Some(circle_id) => ScopeRef::Circle {
                    realm_id: realm.clone(),
                    circle_id,
                },
                None => ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
            }))
        }
        Kind::Message | Kind::Event => {
            let event_id = target
                .event_id
                .clone()
                .or_else(|| target.message_id.as_ref().map(|id| id.event_id()));
            let Some(event_id) = event_id else {
                return Ok(None);
            };
            Ok(
                crate::committed_disclosure::accepted_full_event_in_connection(conn, &event_id)
                    .await?
                    .filter(|row| row.event.realm_id == *realm)
                    .map(|row| row.event.scope_ref),
            )
        }
        _ => Ok(None),
    }
}

async fn scope_member_readable(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    scope: &arkret_wire::ScopeRef,
    actor: &ActorId,
) -> PersistenceResult<bool> {
    Ok(match scope {
        arkret_wire::ScopeRef::Realm { realm_id } if realm_id == realm => {
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm, actor)
                .await?
                .is_some()
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == realm => crate::account_stream_scan::caller_circle_floor_in_connection(
            conn, realm, circle_id, actor,
        )
        .await?
        .is_some(),
        _ => false,
    })
}

/// Read-only native capability/Policy preflight. Actual admission still proves
/// the signed operation, key/session ceiling, fields, approvals and quota.
pub(crate) async fn owned_agent_authorization_check_in_connection(
    conn: &mut AsyncPgConnection,
    caller: &ActorId,
    request: &arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody,
) -> PersistenceResult<
    Option<arkret_models_collaboration::governance::authorization::AuthzCheckOutcome>,
> {
    use arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation;
    use arkret_wire::{AuthzDecision, PolicyEffect};
    let Some(target) = request.resource.as_ref() else {
        return Ok(None);
    };
    let Some(realm) = target.realm_id.as_ref() else {
        return Ok(None);
    };
    let source =
        owned_source_in_connection(conn, realm, &request.actor_id, chrono::Utc::now(), true)
            .await?
            .ok_or_else(|| capability_denied("current owned Agent source is unavailable"))?;
    let IssuerAuthorityRef::OwnedAgent {
        controller_account_id,
        ..
    } = &source
    else {
        return Err(capability_denied("owned source is unavailable"));
    };
    let controller = ActorId::account(controller_account_id.clone());
    if caller != &controller && caller != &request.actor_id {
        return Err(capability_denied("authorization subject is unavailable"));
    }
    let Some(agent) = request.actor_id.as_account_id() else {
        return Err(capability_denied("Agent account is unavailable"));
    };
    let at = chrono::Utc::now();
    let agent_cut = RealmAuthorizationCut::read(conn, realm, &request.actor_id).await?;
    let owner_cut = RealmAuthorizationCut::read(conn, realm, &controller).await?;
    let scope = confirmed_resource_scope(conn, realm, target).await?;
    let action = CapabilityActionId::from_wire(&request.action);
    let mut decision = AuthzDecision::HardDeny;
    let mut matched_grants = Vec::new();
    if let (Some(scope), Some(action), Some(descriptor)) = (
        &scope,
        action,
        arkret_schema::capability_action(&request.action),
    ) && agent_cut.actor_is_joined()
        && owner_cut.actor_is_joined()
        && scope_member_readable(conn, realm, scope, &request.actor_id).await?
        && scope_member_readable(conn, realm, scope, &controller).await?
    {
        let facts = OperationFacts {
            strand_id: target.strand_id.as_ref().map(ToString::to_string),
            circle_id: match scope {
                arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
                _ => None,
            },
            track: (action == CapabilityActionId::MessageCreate)
                .then(|| DISCUSSION_TRACK.to_owned()),
            ..OperationFacts::default()
        };
        let actions = [request.action.as_str()];
        let operation = AuthorizationOperation {
            actor: &request.actor_id,
            actions: &actions,
            target,
            at,
            facts: &facts,
        };
        let agent_grants = agent_cut
            .effective_grants_with_owned_source(at, Some(source.clone()))
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        let owner_grants = owner_cut
            .effective_grants(at)
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        let circle = match scope {
            arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
            _ => None,
        };
        let resources =
            crate::agent_management_admission::selector_content_resources(realm, target)?;
        let policies =
            crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
                conn, realm, circle,
            )
            .await?;
        let effect = arkret_policy::agent_management::evaluate_agent_management(
            Some(&policies),
            &arkret_policy::agent_management::AgentManagementContext {
                realm_id: realm,
                ownership: Some((controller_account_id, agent)),
                operation: if descriptor.event_mapping_kind == "non_event_surface" {
                    AgentPolicyOperation::Read
                } else {
                    AgentPolicyOperation::Execute
                },
                content_action: Some(action),
                resources: Some(&resources),
                at,
            },
        )
        .map_err(capability_denied)?;
        let owner_covers = owner_cut.actor_is_root_controller()
            && arkret_policy::owner_may_author_action(&request.action).unwrap_or(false);
        let evaluation = coland_storage::evaluate_controller_bounded_grants(
            &operation,
            &agent_grants,
            &controller,
            &owner_grants,
            &[],
            owner_covers,
        );
        let membership_read = descriptor.event_mapping_kind == "non_event_surface"
            && matches!(
                action,
                CapabilityActionId::EventRead
                    | CapabilityActionId::StrandRead
                    | CapabilityActionId::ObjectRead
                    | CapabilityActionId::ObjectReadContent
                    | CapabilityActionId::ObjectReadHistory
                    | CapabilityActionId::ObjectReadMetadata
            )
            && !evaluate_grants(&operation, agent_grants.iter().copied()).is_refusal()
            && !evaluate_grants(
                &AuthorizationOperation {
                    actor: &controller,
                    ..operation
                },
                owner_grants.iter().copied(),
            )
            .is_refusal();
        decision = match (effect, &evaluation) {
            (PolicyEffect::Deny, _) | (_, GrantEvaluation::Denied) => AuthzDecision::HardDeny,
            (PolicyEffect::Quarantine, _) | (_, GrantEvaluation::Quarantined) => {
                AuthzDecision::Quarantine
            }
            (PolicyEffect::RequireReview, _) | (_, GrantEvaluation::RequiresReview) => {
                AuthzDecision::RequireReview
            }
            _ if descriptor.required_evaluator_checks.is_empty()
                && (membership_read || !evaluation.unreserved().is_empty()) =>
            {
                AuthzDecision::Allow
            }
            _ => AuthzDecision::HardDeny,
        };
        if decision == AuthzDecision::Allow {
            matched_grants = evaluation.unreserved().iter().map(|grant| serde_json::json!({"grant_id":grant.id,"subject":grant.subject,"actions":grant.actions,"resources":grant.resources})).collect();
        }
    }
    Ok(Some(
        arkret_models_collaboration::governance::authorization::AuthzCheckOutcome {
            decision: decision.clone(),
            matched_grants,
            applied_constraints: Vec::new(),
            policy_results: vec![
                serde_json::json!({"actor_id":request.actor_id,"action":request.action,"resource":request.resource,"reason_detail":"owned_agent_current_capability_and_management", "evaluated_at":arkret_canonical::format_timestamp_canonical(at)}),
            ],
            missing_proofs: Vec::new(),
            checkpoint: None,
            freshness_state: Some(arkret_wire::FreshnessState::Fresh),
            last_known_checkpoint_age_ms: None,
            authority_status: Some(arkret_wire::AuthorityStatus::Fresh),
            cache_expires_at: None,
            reason_code: (decision != AuthzDecision::Allow)
                .then(|| arkret_wire::ReasonCode::from_wire("capability_denied")),
            retry_after_ms: None,
            obligations: Vec::new(),
        },
    ))
}

/// The four authorization inputs of one actor in one Realm, read at one cut.
pub(crate) struct RealmAuthorizationCut {
    realm_id: RealmId,
    actor: ActorId,
    root: Option<RealmAuthorityRootCurrent>,
    grants: BTreeMap<GrantId, CapabilityGrant>,
    revisions: BTreeMap<GrantId, CurrentRevision>,
    policy_bundle: Option<RealmPolicyBundlePayload>,
    actor_membership: Option<String>,
    lifecycle: RealmLifecycleGates,
    /// The Direct Conversation profile's verdict for the Event this cut was
    /// read for (`contact-and-direct-conversation.md` §8.3/§8.4). `Profile`
    /// means the profile's evaluator or phase mask authorized the Event; no
    /// grant or owner aggregation may substitute it, and none is counted.
    direct_conversation: Option<ProfileAuthority>,
    /// Narrow delegated Service admission to the signed authorization_ref.
    selected_grant: Option<GrantId>,
    native_operation: Option<WireResourceSelector>,
}

impl RealmAuthorizationCut {
    /// Read-only consumers may use a complete verified member-Station cut.
    /// Event admission continues to use the local authority's native rows.
    pub(crate) async fn read_accepted(
        conn: &mut AsyncPgConnection,
        realm_id: &RealmId,
        actor: &ActorId,
    ) -> PersistenceResult<Self> {
        let mut cut = Self::read(conn, realm_id, actor).await?;
        if cut.root.is_some() {
            return Ok(cut);
        }
        let rows = crate::replica_authorization::authorization_evidence(conn, realm_id)
            .await?
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "temporarily_unavailable: complete accepted authorization cut unavailable"
                        .into(),
                )
            })?;
        cut.grants.clear();
        cut.revisions.clear();
        for row in rows {
            let arkret_wire::TypedCurrentRow::Value {
                selector,
                revision,
                value,
                ..
            } = row;
            match selector {
                arkret_wire::CurrentSelector::RealmAuthorityRoot => {
                    let root: arkret_wire::RealmAuthorityRootValue =
                        serde_json::from_value(value).map_err(PersistenceError::database)?;
                    cut.root = Some(RealmAuthorityRootCurrent {
                        realm_id: realm_id.clone(),
                        controller_actor_id: root.controller_actor_id,
                        controller_epoch: root.controller_epoch,
                        authority_generation: root.authority_generation,
                        authority_event_ref: root.authority_event_ref,
                    });
                }
                arkret_wire::CurrentSelector::RealmPolicyBundle => {
                    cut.policy_bundle =
                        Some(serde_json::from_value(value).map_err(PersistenceError::database)?);
                }
                arkret_wire::CurrentSelector::CapabilityGrant { grant_id } => {
                    let grant: CapabilityGrant =
                        serde_json::from_value(value).map_err(PersistenceError::database)?;
                    if grant.id != grant_id || grant.realm_id.as_ref() != Some(realm_id) {
                        return Err(PersistenceError::SchemaViolation(
                            "accepted grant identity mismatch".into(),
                        ));
                    }
                    cut.revisions.insert(grant_id.clone(), revision);
                    cut.grants.insert(grant_id, grant);
                }
                _ => unreachable!("authorization evidence is selector-restricted"),
            }
        }
        Ok(cut)
    }

    pub(crate) fn time_sources_unchanged(
        &self,
        checked_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        now >= checked_at
            && self.grants.values().all(|grant| {
                grant_is_active_at(grant, checked_at) == grant_is_active_at(grant, now)
            })
    }

    pub(crate) fn permits_unreserved_current_actions(
        &self,
        actions: &[&str],
        target: &WireResourceSelector,
        at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let facts = OperationFacts::default();
        let evaluation = self.evaluate(actions, target, &facts, at);
        !evaluation.is_refusal()
            && (self.actor_is_root_controller() || !evaluation.unreserved().is_empty())
    }

    /// Read the cut on `conn`. The caller fixes the cut: either it holds the
    /// Realm authority row lock inside the accepting transaction, or it reads
    /// inside one REPEATABLE READ snapshot.
    pub(crate) async fn read(
        conn: &mut AsyncPgConnection,
        realm_id: &RealmId,
        actor: &ActorId,
    ) -> PersistenceResult<Self> {
        let root = sql_query(
            "SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,\
             authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<RealmAuthorityRootReadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_authority_root)
        .transpose()?;
        let stored = sql_query(
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
             current_stream_position,value FROM capability_grant_current_results \
             WHERE realm_id=$1 ORDER BY grant_id ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut grants = BTreeMap::new();
        let mut revisions = BTreeMap::new();
        for row in stored {
            let record = decode_row(row)?;
            revisions.insert(record.grant_id.clone(), record.revision);
            grants.insert(record.grant_id, record.value);
        }
        let policy_bundle =
            sql_query("SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1")
                .bind::<Text, _>(realm_id.as_str())
                .get_result::<PolicyBundleRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .map(|row| {
                    serde_json::from_value::<RealmPolicyBundlePayload>(row.value).map_err(|error| {
                        PersistenceError::Database(format!(
                            "stored realm_policy_bundle current value is invalid: {error}"
                        ))
                    })
                })
                .transpose()?;
        let member_id = actor.to_string();
        let actor_membership = sql_query(
            "SELECT membership FROM member_state_current_results \
             WHERE realm_id=$1 AND member_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&member_id)
        .get_result::<MembershipRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| row.membership);
        let lifecycle = RealmLifecycleGates::read(conn, realm_id).await?;
        Ok(Self {
            realm_id: realm_id.clone(),
            actor: actor.clone(),
            root,
            grants,
            revisions,
            policy_bundle,
            actor_membership,
            lifecycle,
            direct_conversation: None,
            selected_grant: None,
            native_operation: None,
        })
    }

    /// Read the cut for `event`'s actor together with the Direct
    /// Conversation profile's verdict for `event` at the same cut. A profile
    /// refusal is returned as its registered conflict.
    pub(crate) async fn read_for_event(
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<Self> {
        let mut cut = Self::read(conn, &event.realm_id, &event.actor_id).await?;
        cut.direct_conversation =
            crate::direct_conversation_admission::profile_authority_in_connection(conn, event)
                .await?;
        if event.kind == EventKind::MessageCreate
            && event.applet_id.is_some()
            && event.actor_id.as_account_id().is_some()
            && event.executed_by.is_none()
        {
            cut.native_operation = Some(cut.event_operation(event).0);
            cut.selected_grant = Some(
                event
                    .authorization_ref
                    .as_ref()
                    .ok_or_else(|| {
                        capability_denied("native Applet business has no selected terminal grant")
                    })?
                    .as_str()
                    .parse()
                    .map_err(PersistenceError::database)?,
            );
        }
        Ok(cut)
    }

    /// Whether the cut's Realm is a Direct Conversation, whose Events name
    /// their profile authority source instead of a Realm root or grant.
    pub(crate) fn is_direct_conversation(&self) -> bool {
        self.direct_conversation.is_some()
    }

    fn profile_authorized(&self) -> bool {
        self.direct_conversation == Some(ProfileAuthority::Profile)
    }

    /// Whether the actor is the current controller of the Realm authority root.
    pub(crate) fn actor_is_root_controller(&self) -> bool {
        self.root
            .as_ref()
            .is_some_and(|root| root.controller_actor_id == self.actor)
    }

    /// Whether the actor's current `member_state` is `join`.
    pub(crate) fn actor_is_joined(&self) -> bool {
        self.actor_membership.as_deref() == Some("join")
    }

    /// `constraint-schema.md` §15.4 over the actor's effective grants at `at`.
    pub(crate) fn evaluate<'a>(
        &'a self,
        actions: &'a [&'a str],
        target: &'a WireResourceSelector,
        facts: &'a OperationFacts,
        at: chrono::DateTime<chrono::Utc>,
    ) -> GrantEvaluation<'a> {
        evaluate_grants(
            &AuthorizationOperation {
                actor: &self.actor,
                actions,
                target,
                at,
                facts,
            },
            self.effective_grants(at).map(|(_, grant)| grant),
        )
    }

    /// Whether an effective grant allows one of `actions` over the whole
    /// Realm without owing a quota reservation. A caller that cannot reserve
    /// on the quota authority never counts a quota-bound grant.
    pub(crate) fn grants_cover_any(
        &self,
        actions: &[&str],
        at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let realm = WireResourceSelector::realm(self.realm_id.clone());
        !self
            .evaluate(actions, &realm, &OperationFacts::default(), at)
            .unreserved()
            .is_empty()
    }

    /// Decide inside the accepting transaction whether the actor may exercise
    /// one of `actions` on `target` for the Event `identity`. A refusal
    /// constraint of any named grant refuses; otherwise a satisfied grant owing
    /// no quota, then the owner aggregate when `owner_covers`, then the first
    /// satisfied grant whose quota reservations succeed admits the Event.
    #[expect(
        clippy::too_many_arguments,
        reason = "Atomic action admission retains authenticated actor, policy facts and authority cut inputs."
    )]
    async fn admit_actions_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        actions: &[&str],
        target: &WireResourceSelector,
        facts: &OperationFacts,
        owner_covers: bool,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActionAdmission> {
        let evaluation = self.evaluate(actions, target, facts, at);
        let operation = AuthorizationOperation {
            actor: &self.actor,
            actions,
            target,
            at,
            facts,
        };
        Box::pin(crate::boxed_future(|| {
            self.admit_evaluation_in_connection(
                conn,
                evaluation,
                owner_covers,
                event,
                &operation,
                &[],
                false,
            )
        }))
        .await
    }

    pub(crate) async fn owned_controller_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<ActorId>> {
        Box::pin(owned_controller_in_connection(
            conn,
            &self.realm_id,
            &self.actor,
            at,
        ))
        .await
    }

    async fn admit_evaluation_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        evaluation: GrantEvaluation<'_>,
        owner_covers: bool,
        event: &arkret_wire::Event,
        operation: &AuthorizationOperation<'_>,
        approvals: &[coland_storage::VerifiedGrantApproval],
        missing_grant_approvals: bool,
    ) -> PersistenceResult<ActionAdmission> {
        let controller = if self.is_direct_conversation() {
            None
        } else {
            Box::pin(self.owned_controller_in_connection(conn, operation.at)).await?
        };
        let controller_cut = match &controller {
            Some(controller) => Some(Box::pin(Self::read(conn, &self.realm_id, controller)).await?),
            None => None,
        };
        let bounded = controller_cut.is_some();
        let controller_root_covers = controller_cut.as_ref().is_some_and(|cut| {
            cut.actor_is_root_controller()
                && !operation.actions.is_empty()
                && operation
                    .actions
                    .iter()
                    .all(|action| arkret_policy::owner_may_author_action(action).unwrap_or(false))
        });
        let mut managed_actions = match &controller {
            Some(controller) => Some(
                Box::pin(
                    crate::agent_management_admission::executable_actions_in_connection(
                        conn,
                        &self.realm_id,
                        controller.as_account_id().ok_or_else(|| {
                            capability_denied("Agent controller is not an account")
                        })?,
                        self.actor
                            .as_account_id()
                            .ok_or_else(|| capability_denied("Agent is not an account"))?,
                        operation,
                        event,
                    ),
                )
                .await?,
            ),
            None => None,
        };
        // An attributed controller write can still have an Agent producer.
        // Its signed identity must retain management and global refusal gates
        // on the same concrete paths; controller attribution is not a bypass.
        let mut attributed_agent = false;
        let producer = event.actual_signer();
        if !self.is_direct_conversation()
            && producer != &self.actor
            && let Some(producer_controller) = Box::pin(owned_controller_in_connection(
                conn,
                &self.realm_id,
                producer,
                operation.at,
            ))
            .await?
        {
            if producer_controller != self.actor {
                return Err(capability_denied(
                    "Agent producer is not attributed to its current controller",
                ));
            }
            let producer_cut = Box::pin(Self::read(conn, &self.realm_id, producer)).await?;
            producer_cut.require_governed_member(&event.kind)?;
            let producer_operation = AuthorizationOperation {
                actor: producer,
                ..*operation
            };
            let source = Box::pin(owned_source_in_connection(
                conn,
                &self.realm_id,
                producer,
                operation.at,
                true,
            ))
            .await?;
            let mut producer_evaluation = coland_storage::evaluate_grants_with_verified_approvals(
                &producer_operation,
                producer_cut
                    .effective_grants_with_owned_source(operation.at, source)
                    .map(|(_, grant)| grant),
                approvals,
            );
            if matches!(producer_evaluation, GrantEvaluation::RequiresReview)
                && missing_grant_approvals
            {
                return Err(PersistenceError::Conflict(
                    "approval_required: Agent producer approval is not satisfied".into(),
                ));
            }
            if producer_evaluation.is_refusal() {
                return Err(capability_denied(
                    "current Agent producer sources refuse attributed execution",
                ));
            }
            let selected: GrantId = event
                .authorization_ref
                .as_ref()
                .ok_or_else(|| {
                    capability_denied("attributed Agent execution lacks authorization_ref")
                })?
                .as_str()
                .parse()
                .map_err(|_| {
                    capability_denied("attributed Agent execution must select a capability grant")
                })?;
            if let GrantEvaluation::Allowed(grants) = &mut producer_evaluation {
                grants.retain(|row| {
                    row.grant.id == selected && row.grant.owned_agent_issuer().is_none()
                });
                if grants.is_empty() {
                    return Err(capability_denied(
                        "selected grant does not authorize attributed Agent execution",
                    ));
                }
            } else {
                return Err(capability_denied(
                    "Agent producer holds no complete attributed execution path",
                ));
            }
            if let GrantEvaluation::Allowed(ref producer_grants) = producer_evaluation
                && !producer_grants
                    .iter()
                    .any(|grant| grant.reservations.is_empty())
            {
                let mut reserved = false;
                for grant in producer_grants {
                    if crate::capability_quota::try_reserve_in_connection(
                        conn,
                        &grant.reservations,
                        event.event_id.as_str(),
                    )
                    .await?
                    {
                        reserved = true;
                        break;
                    }
                }
                if !reserved {
                    return Err(PersistenceError::Conflict(format!(
                        "{}: Agent producer quota is exhausted",
                        coland_storage::ConflictCode::RateLimited,
                    )));
                }
            }
            let permitted = Box::pin(
                crate::agent_management_admission::executable_actions_in_connection(
                    conn,
                    &self.realm_id,
                    producer_controller.as_account_id().ok_or_else(|| {
                        capability_denied("Agent producer controller is not an account")
                    })?,
                    producer
                        .as_account_id()
                        .ok_or_else(|| capability_denied("Agent producer is not an account"))?,
                    &producer_operation,
                    event,
                ),
            )
            .await?;
            managed_actions = Some(
                managed_actions
                    .as_deref()
                    .unwrap_or(operation.actions)
                    .iter()
                    .copied()
                    .filter(|action| permitted.contains(action))
                    .collect(),
            );
            attributed_agent = true;
        }
        let managed_operation = AuthorizationOperation {
            actions: managed_actions.as_deref().unwrap_or(operation.actions),
            ..*operation
        };
        let evaluation = if let Some(controller_cut) = &controller_cut {
            controller_cut.require_governed_member(&EventKind::CapabilityGrant)?;
            let owned_source = Box::pin(owned_source_in_connection(
                conn,
                &self.realm_id,
                &self.actor,
                operation.at,
                true,
            ))
            .await?;
            let agent_grants = self
                .effective_grants_with_owned_source(operation.at, owned_source)
                .map(|(_, grant)| grant)
                .collect::<Vec<_>>();
            let controller_grants = controller_cut
                .effective_grants(operation.at)
                .map(|(_, grant)| grant)
                .collect::<Vec<_>>();
            // Filtering a forbidden allow path must not discard an existing
            // global grant deny/quarantine/review on the original operation.
            let original = coland_storage::evaluate_controller_bounded_grants(
                operation,
                &agent_grants,
                &controller_cut.actor,
                &controller_grants,
                approvals,
                controller_root_covers,
            );
            match original {
                GrantEvaluation::Denied
                | GrantEvaluation::Quarantined
                | GrantEvaluation::RequiresReview => original,
                _ => coland_storage::evaluate_controller_bounded_grants(
                    &managed_operation,
                    &agent_grants,
                    &controller_cut.actor,
                    &controller_grants,
                    approvals,
                    controller_root_covers,
                ),
            }
        } else if attributed_agent {
            match evaluation {
                GrantEvaluation::Denied
                | GrantEvaluation::Quarantined
                | GrantEvaluation::RequiresReview => evaluation,
                _ => coland_storage::evaluate_grants_with_verified_approvals(
                    &managed_operation,
                    self.effective_grants(operation.at).map(|(_, grant)| grant),
                    approvals,
                ),
            }
        } else {
            evaluation
        };
        let owner_covers = owner_covers
            && !bounded
            && (!attributed_agent
                || managed_operation
                    .actions
                    .iter()
                    .any(|action| arkret_policy::owner_may_author_action(action).unwrap_or(false)));
        // A signed reference selects the positive authority path, never the
        // global refusal set of the actual Account's effective grants.
        let evaluation = match evaluation {
            GrantEvaluation::Allowed(paths) if self.native_operation.is_some() => {
                let paths = paths
                    .into_iter()
                    .filter(|path| self.selected_grant.as_ref() == Some(&path.grant.id))
                    .collect::<Vec<_>>();
                if paths.is_empty() {
                    GrantEvaluation::Unsatisfied
                } else {
                    GrantEvaluation::Allowed(paths)
                }
            }
            other => other,
        };
        match evaluation {
            GrantEvaluation::Denied => Err(capability_denied(
                "a deny constraint of an effective grant matches the operation",
            )),
            GrantEvaluation::RequiresReview if missing_grant_approvals => {
                Err(PersistenceError::Conflict(
                    "approval_required: grant approval is not satisfied at this cut".into(),
                ))
            }
            GrantEvaluation::Quarantined | GrantEvaluation::RequiresReview => {
                Err(PersistenceError::Conflict(
                    "failed_precondition: an effective grant requires quarantine or review \
                     evidence this Station does not accept"
                        .to_owned(),
                ))
            }
            GrantEvaluation::Allowed(satisfied) => {
                if (!bounded && satisfied.iter().any(|grant| grant.reservations.is_empty()))
                    || owner_covers
                {
                    return Ok(ActionAdmission::Admitted);
                }
                for grant in &satisfied {
                    if crate::capability_quota::try_reserve_in_connection(
                        conn,
                        &grant.reservations,
                        event.event_id.as_str(),
                    )
                    .await?
                    {
                        return Ok(ActionAdmission::Admitted);
                    }
                }
                Err(PersistenceError::Conflict(format!(
                    "{}: every grant allowing the operation has exhausted its quota",
                    coland_storage::ConflictCode::RateLimited
                )))
            }
            GrantEvaluation::Unsatisfied if !owner_covers => {
                Ok(ActionAdmission::NotHeld { named: true })
            }
            GrantEvaluation::Unnamed if !owner_covers => {
                Ok(ActionAdmission::NotHeld { named: false })
            }
            GrantEvaluation::Unsatisfied | GrantEvaluation::Unnamed => {
                Ok(ActionAdmission::Admitted)
            }
        }
    }

    /// Every active grant whose subject is exactly the actor, whose temporal
    /// window contains `at`, and whose issuer chain descends intact from the
    /// current authority root. Actions, resources and non-temporal
    /// constraints are not decided here.
    pub(crate) fn effective_grants(
        &self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> impl Iterator<Item = (&GrantId, &CapabilityGrant)> + '_ {
        self.effective_grants_with_owned_source(at, None)
    }

    fn effective_grants_with_owned_source(
        &self,
        at: chrono::DateTime<chrono::Utc>,
        owned_source: Option<IssuerAuthorityRef>,
    ) -> impl Iterator<Item = (&GrantId, &CapabilityGrant)> + '_ {
        let root = self.root.as_ref();
        self.grants.iter().filter(move |(grant_id, grant)| {
            let Some(root) = root else {
                return false;
            };
            (self.native_operation.is_some() || self.selected_grant.as_ref().is_none_or(|selected| selected == *grant_id))
                && matches!(&grant.subject, CapabilitySubject::Actor(subject) if subject == &self.actor)
                && grant.realm_id.as_ref() == Some(&self.realm_id)
                && (self.native_operation.is_some() || grant_is_active_at(grant, at))
                && !grant.issuer_authority_refs.is_empty()
                && if let Some(target) = &self.native_operation {
                    arkret_policy::grant_authority::current_sources(grant,
                        CapabilityActionId::MessageCreate.as_str(), target, &self.grants, at,
                        |source| matches!(source, IssuerAuthorityRef::RealmRoot { realm_id, authority_event_ref, authority_generation }
                            if realm_id==&self.realm_id && authority_event_ref==&root.authority_event_ref
                                && authority_generation==&root.authority_generation)).is_ok()
                } else { grant
                    .issuer_authority_refs
                    .iter()
                    .all(|authority_ref| match authority_ref {
                        IssuerAuthorityRef::OwnedAgent { controller_account_id, .. } => {
                            grant.issuer_authority_refs.len() == 1
                                && owned_source.as_ref() == Some(authority_ref)
                                && grant.issuer_id.as_account_id() == Some(controller_account_id)
                                && grant.authority_depth == 1
                                && grant.authority_root_refs.len() == 1
                                && serde_json::to_value(&grant.authority_root_refs[0]).ok()
                                    == serde_json::to_value(authority_ref).ok()
                        },
                        IssuerAuthorityRef::RealmRoot {
                            realm_id: root_realm_id,
                            authority_event_ref,
                            authority_generation,
                        } => {
                            root_realm_id == &self.realm_id
                                && root.authority_event_ref == *authority_event_ref
                                && root.authority_generation == *authority_generation
                        }
                        IssuerAuthorityRef::Grant {
                            grant_id: parent_id,
                        } => {
                            self.grants.get(parent_id).is_some_and(|parent| {
                                matches!(&parent.subject, CapabilitySubject::Actor(subject) if subject == &grant.issuer_id)
                            }) && validate_ancestor_graph(
                                grant_id,
                                parent_id,
                                &self.grants,
                                root,
                                &self.realm_id,
                                at,
                                &mut std::collections::BTreeSet::new(),
                                1,
                            )
                            .is_ok()
                        }
                    }) }
        })
    }

    /// Issuing an owned source expresses current execution/read authority,
    /// not delegation authority. Quota is reserved only by actual operations.
    pub(crate) async fn require_owned_grant_coverage_in_connection(
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        body: &arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        body.validate_owned_agent_shape()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        arkret_schema::validate_event_for_submit(event)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let [
            reference @ IssuerAuthorityRef::OwnedAgent {
                controller_account_id,
                ..
            },
        ] = body.issuer_authority_refs.as_slice()
        else {
            return Err(capability_denied(
                "owned grant requires its exclusive source",
            ));
        };
        let CapabilitySubject::Actor(subject) = &body.subject else {
            return Err(capability_denied("owned grant requires an Agent Account"));
        };
        if event.executed_by.is_some()
            || event.actor_id != body.issuer_id
            || event.actor_id.as_account_id() != Some(controller_account_id)
            || owned_source_in_connection(conn, &event.realm_id, subject, at, true)
                .await?
                .as_ref()
                != Some(reference)
        {
            return Err(capability_denied(
                "owned grant exact current source differs",
            ));
        }
        let cut = Self::read(conn, &event.realm_id, &event.actor_id).await?;
        cut.require_governed_member(&EventKind::CapabilityGrant)?;
        let grants = cut
            .effective_grants(at)
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        let child_expiry = body
            .constraints
            .iter()
            .filter_map(|constraint| constraint.expires_at)
            .min();
        for action in &body.actions {
            for resource in &body.resources {
                let facts = OperationFacts::default();
                let operation = AuthorizationOperation {
                    actor: &event.actor_id,
                    actions: &[action.as_str()],
                    target: resource,
                    at,
                    facts: &facts,
                };
                if evaluate_grants(&operation, grants.iter().copied()).is_refusal() {
                    return Err(capability_denied(
                        "current controller sources refuse owned confirmation",
                    ));
                }
                let descriptor = arkret_schema::capability_action(action)
                    .ok_or_else(|| capability_denied("owned action is unavailable"))?;
                let member_read = if descriptor.event_mapping_kind == "non_event_surface"
                    && matches!(
                        CapabilityActionId::from_wire(action),
                        Some(
                            CapabilityActionId::EventRead
                                | CapabilityActionId::StrandRead
                                | CapabilityActionId::ObjectRead
                                | CapabilityActionId::ObjectReadContent
                                | CapabilityActionId::ObjectReadHistory
                                | CapabilityActionId::ObjectReadMetadata
                        )
                    ) {
                    match confirmed_resource_scope(conn, &event.realm_id, resource).await? {
                        Some(scope) => {
                            scope_member_readable(conn, &event.realm_id, &scope, &event.actor_id)
                                .await?
                        }
                        None => false,
                    }
                } else {
                    false
                };
                let owner = cut.actor_is_root_controller()
                    && arkret_policy::owner_may_author_action(action).unwrap_or(false);
                let parent = grants.iter().any(|grant| {
                    grant.actions.iter().any(|held| {
                        arkret_policy::action_covers_event_kinds(held, action).unwrap_or(false)
                    }) && grant
                        .resources
                        .iter()
                        .any(|held| coland_storage::resource_selector_covers(held, resource))
                        && coland_storage::capability_grant_expires_at(grant)
                            .is_none_or(|expiry| child_expiry.is_some_and(|child| child <= expiry))
                        && grant
                            .constraints
                            .iter()
                            .filter(|constraint| {
                                constraint.effect == GrantConstraintEffect::Allow
                                    && !matches!(
                                        constraint.constraint_kind,
                                        GrantConstraintKind::AuthorityControl
                                            | GrantConstraintKind::Quota
                                    )
                            })
                            .all(|constraint| {
                                if body.constraints.contains(constraint) {
                                    return true;
                                }
                                if constraint.constraint_kind != GrantConstraintKind::Temporal {
                                    return false;
                                }
                                let mut parent = constraint.clone();
                                parent.expires_at = None;
                                body.constraints.iter().any(|child| {
                                    let mut child = child.clone();
                                    child.expires_at = None;
                                    child == parent
                                })
                            })
                });
                if !(member_read || owner || parent) {
                    return Err(capability_denied(
                        "owned confirmation exceeds current controller coverage",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Membership is an independent read source. Matching global grant
    /// refusals still apply to the same canonical bytes and actual recipient.
    pub(crate) async fn require_membership_read_constraints_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let source =
            owned_source_in_connection(conn, &self.realm_id, &self.actor, at, false).await?;
        self.require_membership_read_constraints(event, at, source)
    }

    pub(crate) fn require_membership_read_constraints(
        &self,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
        source: Option<IssuerAuthorityRef>,
    ) -> PersistenceResult<()> {
        self.require_content_read_constraints(event, at, source, CapabilityActionId::EventRead)
    }

    pub(crate) fn require_content_read_constraints(
        &self,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
        source: Option<IssuerAuthorityRef>,
        action: CapabilityActionId,
    ) -> PersistenceResult<()> {
        self.require_content_read_constraints_with_approvals(event, at, source, action, &[])
    }

    pub(crate) fn require_content_read_constraints_with_approvals(
        &self,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
        source: Option<IssuerAuthorityRef>,
        action: CapabilityActionId,
        approvals: &[coland_storage::VerifiedGrantApproval],
    ) -> PersistenceResult<()> {
        let (content_target, mut facts) = self.event_operation(event);
        facts.write_fields = None;
        // A patch Event's author/time is not the target object's creator/time.
        // Until that accepted target is resolved, preserve unknown facts.
        facts.target_owner = None;
        facts.target_created_at = None;
        // A full envelope exposes every payload field; unknown narrower facts
        // retain the evaluator's fail-closed deny/quarantine/review semantics.
        facts.read_fields = None;
        facts.applet_id = None;
        facts.executed_by = None;
        facts.registration_epoch = None;
        let mut event_target = WireResourceSelector::realm(self.realm_id.clone());
        event_target.kind = arkret_wire::ResourceSelectorKind::Event;
        event_target.event_id = Some(event.event_id.clone());
        let grants = self
            .effective_grants_with_owned_source(at, source)
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        let resources = crate::agent_management_admission::event_content_resources(event)?;
        let mut targets = crate::agent_management_admission::content_capability_targets(
            &self.realm_id,
            &resources,
        );
        for target in [event_target, content_target] {
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
        for target in &targets {
            let operation = AuthorizationOperation {
                actor: &self.actor,
                actions: &[action.as_str()],
                target,
                at,
                facts: &facts,
            };
            if coland_storage::evaluate_grants_with_verified_approvals(
                &operation,
                grants.iter().copied(),
                approvals,
            )
            .is_refusal()
            {
                return Err(capability_denied(
                    "a current grant refuses canonical Event disclosure",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn content_scope_facts(
        &self,
        event: &arkret_wire::Event,
        action: CapabilityActionId,
    ) -> PersistenceResult<(WireResourceSelector, OperationFacts)> {
        let (mut target, mut facts) = self.event_operation(event);
        facts.write_fields = None;
        facts.target_owner = None;
        facts.target_created_at = None;
        facts.read_fields = None;
        facts.applet_id = None;
        facts.executed_by = None;
        facts.registration_epoch = None;
        if action == CapabilityActionId::EventRead {
            target = WireResourceSelector::realm(event.realm_id.clone());
            target.kind = arkret_wire::ResourceSelectorKind::Event;
            target.event_id = Some(event.event_id.clone());
        } else if event.kind == EventKind::StrandCreate {
            let id = StrandId::from_event_id(&event.event_id);
            facts.strand_id = Some(id.to_string());
            target = WireResourceSelector::strand(event.realm_id.clone(), id);
        } else if event.kind == EventKind::SpaceCreate {
            let id = arkret_wire::SpaceId::from_event_id(&event.event_id);
            facts.space_id = Some(id.to_string());
            target = WireResourceSelector::space(event.realm_id.clone(), id);
        } else if event.kind == EventKind::MessageCreate {
            target = WireResourceSelector::realm(event.realm_id.clone());
            target.kind = arkret_wire::ResourceSelectorKind::Message;
            target.message_id = Some(arkret_wire::MessageId::from_event_id(&event.event_id));
        }
        target.validate().map_err(PersistenceError::database)?;
        Ok((target, facts))
    }

    /// Qualify the exact fields of one native Morph projection. Current
    /// membership is a precondition; it does not manufacture a MorphRead grant.
    /// This registered read has no quota operation identity, so only an
    /// unreserved literal/profile path or the explicitly registered owner path
    /// can qualify it. All named global refusals still apply first.
    pub(crate) fn require_native_projection_read(
        &self,
        target: &WireResourceSelector,
        facts: &OperationFacts,
        action: CapabilityActionId,
        source: Option<IssuerAuthorityRef>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        target.validate().map_err(PersistenceError::database)?;
        if target.realm_id.as_ref() != Some(&self.realm_id)
            || self.actor_membership.as_deref() != Some("join")
            || self.lifecycle.terminal
            || facts.read_fields.is_none()
        {
            return Err(capability_denied(
                "native Morph read has no complete current target facts",
            ));
        }
        if !matches!(
            action,
            CapabilityActionId::MorphRead
                | CapabilityActionId::ObjectReadContent
                | CapabilityActionId::ObjectReadMetadata
                | CapabilityActionId::ObjectReadHistory
        ) {
            return Err(capability_denied(
                "unregistered native projection read action",
            ));
        }
        // MorphRead is not a supported OwnedAgent authority-source action.
        // Only its independent literal/explicit owner path may qualify it.
        let source = if action == CapabilityActionId::MorphRead {
            None
        } else {
            source
        };
        let operation = AuthorizationOperation {
            actor: &self.actor,
            actions: &[action.as_str()],
            target,
            facts,
            at,
        };
        let evaluation = evaluate_grants(
            &operation,
            self.effective_grants_with_owned_source(at, source)
                .map(|(_, grant)| grant),
        );
        let owner = self.actor_is_root_controller()
            && arkret_policy::owner_may_author_action(action.as_str()).unwrap_or(false);
        if evaluation.is_refusal() || (!owner && evaluation.unreserved().is_empty()) {
            return Err(capability_denied(
                "native Morph read lacks an unreserved registered action path",
            ));
        }
        Ok(())
    }

    /// Provider input reads Message content in addition to its Event envelope.
    /// Resolve positive authority only on the actual Message, while preserving
    /// the original global refusals on every known signed resource alias.
    pub(crate) fn require_unreserved_native_message_body(
        &self,
        controller: &Self,
        event: &arkret_wire::Event,
        source: &IssuerAuthorityRef,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        if event.kind != EventKind::MessageCreate
            || event.realm_id != self.realm_id
            || controller.realm_id != self.realm_id
            || !self.actor_is_joined()
            || !controller.actor_is_joined()
            || self.lifecycle.terminal
            || self.lifecycle.archived
            || self.lifecycle.frozen
            || controller.lifecycle.terminal
            || controller.lifecycle.archived
            || controller.lifecycle.frozen
        {
            return Err(capability_denied(
                "native reply body current subject is unavailable",
            ));
        }
        let IssuerAuthorityRef::OwnedAgent {
            realm_id,
            controller_account_id,
            ..
        } = source
        else {
            return Err(capability_denied("native reply body has no owned source"));
        };
        if realm_id != &self.realm_id
            || controller.actor.as_account_id() != Some(controller_account_id)
        {
            return Err(capability_denied("native reply body controller differs"));
        }
        let action = CapabilityActionId::ObjectReadContent;
        self.require_content_read_constraints(event, at, Some(source.clone()), action)?;
        controller.require_content_read_constraints(event, at, None, action)?;
        let (target, facts) = self.content_scope_facts(event, action)?;
        let operation = AuthorizationOperation {
            actor: &self.actor,
            actions: &[action.as_str()],
            target: &target,
            facts: &facts,
            at,
        };
        let agent_grants = self
            .effective_grants_with_owned_source(at, Some(source.clone()))
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        let controller_grants = controller
            .effective_grants(at)
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        let root_covers = controller.actor_is_root_controller()
            && arkret_policy::owner_may_author_action(action.as_str()).unwrap_or(false);
        let evaluation = coland_storage::evaluate_controller_bounded_grants(
            &operation,
            &agent_grants,
            &controller.actor,
            &controller_grants,
            &[],
            root_covers,
        );
        if evaluation.is_refusal() || evaluation.unreserved().is_empty() {
            return Err(capability_denied(
                "native reply body lacks independent unreserved read_content",
            ));
        }
        Ok(())
    }

    /// Fixed native reply authorization uses real MessageCreate facts without
    /// constructing a future Event or treating its incoming Event as quota identity.
    pub(crate) fn require_unreserved_native_message_reply(
        &self,
        controller: &Self,
        target: &WireResourceSelector,
        facts: &OperationFacts,
        source: &IssuerAuthorityRef,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        target.validate().map_err(PersistenceError::database)?;
        let IssuerAuthorityRef::OwnedAgent {
            realm_id,
            controller_account_id,
            ..
        } = source
        else {
            return Err(capability_denied(
                "native reply requires current owned authority",
            ));
        };
        if realm_id != &self.realm_id
            || controller.realm_id != self.realm_id
            || controller.actor.as_account_id() != Some(controller_account_id)
            || target.realm_id.as_ref() != Some(&self.realm_id)
            || target.kind != arkret_wire::ResourceSelectorKind::Strand
            || target.strand_id.as_ref().map(ToString::to_string).as_ref()
                != facts.strand_id.as_ref()
            || facts.track.as_deref() != Some(DISCUSSION_TRACK)
            || facts.object_kind.as_deref() != Some("message")
            || !self.actor_is_joined()
            || !controller.actor_is_joined()
            || self.lifecycle.terminal
            || self.lifecycle.archived
            || self.lifecycle.frozen
            || controller.lifecycle.terminal
            || controller.lifecycle.archived
            || controller.lifecycle.frozen
        {
            return Err(capability_denied(
                "native reply current subject or target is unavailable",
            ));
        }
        let operation = AuthorizationOperation {
            actor: &self.actor,
            actions: &[CapabilityActionId::MessageCreate.as_str()],
            target,
            facts,
            at,
        };
        let agent_grants = self
            .effective_grants_with_owned_source(at, Some(source.clone()))
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        let controller_grants = controller
            .effective_grants(at)
            .map(|(_, grant)| grant)
            .collect::<Vec<_>>();
        // Refusals on every known actual alias remain additive. Only the
        // canonical Strand target can supply a positive MessageCreate path.
        let resources =
            crate::agent_management_admission::selector_content_resources(&self.realm_id, target)?;
        for alias in crate::agent_management_admission::content_capability_targets(
            &self.realm_id,
            &resources,
        ) {
            let alias_operation = AuthorizationOperation {
                target: &alias,
                ..operation
            };
            if evaluate_grants(&alias_operation, agent_grants.iter().copied()).is_refusal()
                || evaluate_grants(
                    &AuthorizationOperation {
                        actor: &controller.actor,
                        ..alias_operation
                    },
                    controller_grants.iter().copied(),
                )
                .is_refusal()
            {
                return Err(capability_denied(
                    "native reply is refused on an actual resource alias",
                ));
            }
        }
        let root_covers = controller.actor_is_root_controller()
            && arkret_policy::owner_may_author_action(CapabilityActionId::MessageCreate.as_str())
                .unwrap_or(false);
        let evaluation = coland_storage::evaluate_controller_bounded_grants(
            &operation,
            &agent_grants,
            &controller.actor,
            &controller_grants,
            &[],
            root_covers,
        );
        if evaluation.is_refusal() || evaluation.unreserved().is_empty() {
            return Err(capability_denied(
                "native reply lacks a complete unreserved controller-bounded path",
            ));
        }
        Ok(())
    }

    /// Resolve current Strand scope under the same held Realm authority row.
    pub(crate) async fn native_message_reply_target_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        scope: &arkret_wire::ScopeRef,
        strand: &StrandId,
        controller: &Self,
        caller: &ActorId,
    ) -> PersistenceResult<(WireResourceSelector, OperationFacts)> {
        let mut target = WireResourceSelector::strand(self.realm_id.clone(), strand.clone());
        let actual_scope = confirmed_resource_scope(conn, &self.realm_id, &target)
            .await?
            .ok_or_else(|| capability_denied("native reply Strand source is unavailable"))?;
        if actual_scope != *scope
            || !matches!(
                scope,
                arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
            )
        {
            return Err(capability_denied(
                "native reply source differs from its current Strand scope",
            ));
        }
        if let arkret_wire::ScopeRef::Circle { circle_id, .. } = scope {
            #[derive(QueryableByName)]
            struct NativeCircleCurrentPresent {
                #[diesel(sql_type = diesel::sql_types::Bool)]
                present: bool,
            }
            // Same active-source join as the original Circle content writer.
            let active = sql_query(
                "SELECT EXISTS (SELECT 1 FROM circle_current_results circle \
                 JOIN realm_commits cc ON cc.commit_id=circle.current_commit_id \
                 WHERE circle.realm_id=$1 AND circle.circle_id=$2 AND circle.value->>'state'='active' \
                   AND cc.realm_id=circle.realm_id AND cc.stream_position=circle.current_stream_position \
                   AND cc.stream_ref=circle.source_stream_ref \
                   AND cc.stream_ref->>'kind'='realm' AND cc.stream_ref->>'realm_id'=circle.realm_id) AS present",
            ).bind::<Text,_>(self.realm_id.as_str()).bind::<Text,_>(circle_id.as_str())
                .get_result::<NativeCircleCurrentPresent>(&mut *conn).await.map_err(PersistenceError::database)?;
            if !active.present {
                return Err(capability_denied(
                    "native reply Circle current is not active",
                ));
            }
            target.circle_id = Some(circle_id.clone());
        }
        for actor in [&self.actor, &controller.actor, caller] {
            if !scope_member_readable(conn, &self.realm_id, scope, actor).await? {
                return Err(capability_denied(
                    "native reply current scope membership is unavailable",
                ));
            }
        }
        crate::message_revision_current_results::require_active_discussion_strand(
            conn,
            &self.realm_id,
            strand,
            scope,
        )
        .await?;
        // Future Message fields, blob refs, owner and creation time are not
        // observable yet. Preserve unknown facts rather than using the input's.
        let facts = OperationFacts {
            strand_id: Some(strand.to_string()),
            circle_id: match scope {
                arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
                _ => None,
            },
            track: Some(DISCUSSION_TRACK.into()),
            object_kind: Some("message".into()),
            ..OperationFacts::default()
        };
        Ok((target, facts))
    }

    /// The actor's authorization at `at` as a backend-neutral value: whether
    /// it is the root controller, and every effective grant with the exact
    /// revision of its current result.
    pub(crate) fn actor_authorization(
        &self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActorRealmAuthorization> {
        self.actor_authorization_with_owned_source(at, None)
    }

    fn actor_authorization_with_owned_source(
        &self,
        at: chrono::DateTime<chrono::Utc>,
        owned_source: Option<IssuerAuthorityRef>,
    ) -> PersistenceResult<ActorRealmAuthorization> {
        let grants = self
            .effective_grants_with_owned_source(at, owned_source)
            .map(|(grant_id, grant)| {
                let revision = self.revisions.get(grant_id).cloned().ok_or_else(|| {
                    PersistenceError::Database(
                        "Capability Grant current revision is missing from its cut".to_owned(),
                    )
                })?;
                Ok(EffectiveActorGrant {
                    grant: grant.clone(),
                    revision,
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        Ok(ActorRealmAuthorization {
            realm_id: self.realm_id.clone(),
            actor: self.actor.clone(),
            evaluated_at: at,
            root_controller: self.actor_is_root_controller(),
            grants,
            agent_ceiling: None,
        })
    }

    /// Read-only consumers need the same dynamic ceiling as Event admission.
    /// The enclosing snapshot fixes ownership, both members, grants and Policy.
    pub(crate) async fn bounded_actor_authorization_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActorRealmAuthorization> {
        self.bounded_actor_authorization_at_cut(conn, at, false)
            .await
    }

    pub(crate) async fn enforcing_actor_authorization_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActorRealmAuthorization> {
        self.bounded_actor_authorization_at_cut(conn, at, true)
            .await
    }

    async fn bounded_actor_authorization_at_cut(
        &self,
        conn: &mut AsyncPgConnection,
        at: chrono::DateTime<chrono::Utc>,
        lock: bool,
    ) -> PersistenceResult<ActorRealmAuthorization> {
        let mut authorization = self.actor_authorization(at)?;
        if !crate::committed_disclosure::ordinary_agent_read_ceiling(
            crate::account_stream_scan::realm_purpose(conn, &self.realm_id).await?,
        ) {
            return Ok(authorization);
        }
        let Some(controller) =
            read_owned_controller_in_connection(conn, &self.realm_id, &self.actor, at, lock)
                .await?
        else {
            return Ok(authorization);
        };
        self.require_governed_member(&EventKind::CapabilityGrant)?;
        let controller_cut = if lock {
            Self::read(conn, &self.realm_id, &controller).await?
        } else {
            Self::read_accepted(conn, &self.realm_id, &controller).await?
        };
        controller_cut.require_governed_member(&EventKind::CapabilityGrant)?;
        let owned_source =
            owned_source_in_connection(conn, &self.realm_id, &self.actor, at, lock).await?;
        authorization = self.actor_authorization_with_owned_source(at, owned_source)?;
        let policies = if lock {
            crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
                conn,
                &self.realm_id,
                None,
            )
            .await?
        } else {
            crate::policy_current_results::read_scoped_agent_management_policy_snapshot_in_connection(conn, &self.realm_id, None).await?
        };
        authorization.agent_ceiling = Some(coland_storage::AgentControllerCeiling {
            controller: Box::new(controller_cut.actor_authorization(at)?),
            management_policies: policies,
        });
        Ok(authorization)
    }

    /// The actions that authorize `kind` on their own: those without
    /// registered evaluator checks.
    fn unconditional_actions(kind: &EventKind) -> Vec<&'static str> {
        arkret_schema::capability_actions_for_event_kind(kind.as_str())
            .filter(|descriptor| descriptor.required_evaluator_checks.is_empty())
            .map(|descriptor| descriptor.action.as_str())
            .collect()
    }

    /// `realm-and-space.md` §2.6.0/§2.6.1: after a terminal Event only audit
    /// Events are admitted, and an archived or frozen Realm admits only the
    /// closed exemption set. The terminal refusal code is reserved, so it is
    /// a bare `failed_precondition`.
    /// Operation-native creations have no fabricated Event for lifecycle checks.
    pub(crate) fn require_open_business_mutation(&self) -> PersistenceResult<()> {
        if self.lifecycle.terminal || self.lifecycle.archived || self.lifecycle.frozen {
            return Err(PersistenceError::Conflict(
                "failed_precondition: Realm lifecycle refuses new business mutations".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn require_open_lifecycle(
        &self,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<()> {
        if self.lifecycle.terminal && !arkret_wire::events::kinds::is_audit_kind(&event.kind) {
            return Err(PersistenceError::Conflict(format!(
                "failed_precondition: the Realm is terminal and refuses {}",
                event.kind.as_str()
            )));
        }
        if self.lifecycle.archived || self.lifecycle.frozen {
            let payload = serde_json::Value::Object(event.payload.clone().into_iter().collect());
            if !arkret_wire::events::kinds::realm_write_gate_exempt(&event.kind, &payload) {
                return Err(PersistenceError::Conflict(format!(
                    "{}: the Realm is archived or frozen and refuses {}",
                    coland_storage::ConflictCode::RealmFrozen,
                    event.kind.as_str()
                )));
            }
        }
        Ok(())
    }

    /// The Realm has an authority root and a policy bundle at this cut and the
    /// actor is a joined member of it.
    pub(crate) fn require_governed_member(&self, kind: &EventKind) -> PersistenceResult<()> {
        if self.profile_authorized() {
            return if self.actor_is_joined() {
                Ok(())
            } else {
                Err(capability_denied(format!(
                    "{} is not a joined member of the Realm",
                    kind.as_str()
                )))
            };
        }
        if self.root.is_none() {
            return Err(PersistenceError::Conflict(
                "failed_precondition: the Realm has no authority root at this cut".to_owned(),
            ));
        }
        if self.policy_bundle.is_none() {
            return Err(PersistenceError::Conflict(
                "dependency_missing: the Realm has no policy bundle at this cut".to_owned(),
            ));
        }
        if !self.actor_is_joined() {
            return Err(capability_denied(format!(
                "{} is not a joined member of the Realm",
                kind.as_str()
            )));
        }
        Ok(())
    }

    /// The complete capability-gated verdict for `event`: the Realm has an
    /// authority root and a policy bundle, the actor is a joined member, and
    /// the actor holds an authorizing action whose constraints admit the
    /// Event, reserving any quota it owes.
    pub(crate) async fn require_event_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let kind = &event.kind;
        self.require_open_lifecycle(event)?;
        if *kind == EventKind::CapabilityRevoke && event.executed_by.is_none() {
            let payload: arkret_models_collaboration::events_payloads::CapabilityRevokePayload =
                serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if self.grants.get(&payload.grant_id).is_some_and(|grant| {
                grant
                    .owned_agent_issuer()
                    .is_some_and(|controller| event.actor_id.as_account_id() == Some(controller))
            }) {
                return Ok(());
            }
        }
        if *kind == EventKind::CapabilityGrant {
            let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
                serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if payload
                .grant
                .issuer_authority_refs
                .iter()
                .any(|source| matches!(source, IssuerAuthorityRef::OwnedAgent { .. }))
            {
                Box::pin(Self::require_owned_grant_coverage_in_connection(
                    conn,
                    event,
                    &payload.grant,
                    at,
                ))
                .await?;
                return Ok(());
            }
        }
        self.require_governed_member(kind)?;
        let root_only = arkret_schema::capability_actions_for_event_kind(kind.as_str())
            .any(|descriptor| descriptor.root_control_only);
        if root_only {
            if !self.is_direct_conversation()
                && self
                    .owned_controller_in_connection(conn, at)
                    .await?
                    .is_some()
            {
                return Err(capability_denied(
                    "owned Agent execution cannot substitute the exact Realm root controller",
                ));
            }
            return if self.actor_is_root_controller() {
                Ok(())
            } else {
                Err(capability_denied(
                    "this Event requires the exact current authority-root controller",
                ))
            };
        }
        if self.profile_authorized() {
            return Ok(());
        }
        let actions = Self::unconditional_actions(kind);
        let owner =
            self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER);
        let (target, mut facts) = self.event_operation(event);
        Box::pin(self.complete_event_facts_in_connection(conn, event, &mut facts)).await?;
        let target = self.current_event_target(event, target, &facts)?;
        match self
            .admit_actions_in_connection(conn, &actions, &target, &facts, owner, event, at)
            .await?
        {
            ActionAdmission::Admitted => Ok(()),
            ActionAdmission::NotHeld { .. } => Err(capability_denied(format!(
                "the actor holds no action authorizing {}",
                kind.as_str()
            ))),
        }
    }

    /// Revalidate the creator of an already accepted third-party Invite at the
    /// claim cut. Creation consumed its quota once; consuming that Invite does
    /// not create another invitation and must not reserve a second quota.
    pub(crate) fn require_live_invite_creator(
        &self,
        create: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        self.require_open_lifecycle(create)?;
        self.require_governed_member(&create.kind)?;
        let actions = Self::unconditional_actions(&create.kind);
        let owner =
            self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER);
        let (target, facts) = self.event_operation(create);
        match self.evaluate(&actions, &target, &facts, at) {
            GrantEvaluation::Allowed(satisfied) if !satisfied.is_empty() => Ok(()),
            GrantEvaluation::Allowed(_)
            | GrantEvaluation::Unsatisfied
            | GrantEvaluation::Unnamed
                if owner =>
            {
                Ok(())
            }
            _ => Err(capability_denied(
                "the Invite creator no longer holds its creating authority",
            )),
        }
    }

    /// Evaluate the placement grant against the actual source List resolved
    /// from durable position current, rather than an optional payload hint.
    async fn require_position_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        source: Option<&arkret_wire::SpaceId>,
        destination: &arkret_wire::SpaceId,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
    ) -> PersistenceResult<(bool, Vec<crate::approval_admission::QualifiedApproval>)> {
        let at = commit.committed_at;
        self.require_open_lifecycle(event)?;
        self.require_governed_member(&event.kind)?;
        if self.profile_authorized() {
            return Ok((false, Vec::new()));
        }
        let actions = Self::unconditional_actions(&event.kind);
        let owner =
            self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER);
        let (target, mut facts) = self.event_operation(event);
        facts.from_container_id = source.map(ToString::to_string);
        facts.to_container_id = Some(destination.to_string());
        if matches!(
            self.evaluate(&actions, &target, &facts, at),
            GrantEvaluation::Denied | GrantEvaluation::Quarantined
        ) {
            self.admit_actions_in_connection(conn, &actions, &target, &facts, owner, event, at)
                .await?;
        }
        let action = if event.kind == EventKind::StrandReorder {
            CapabilityActionId::StrandReorder
        } else {
            CapabilityActionId::StrandMove
        };
        let (discharges, mut approved, missing_approvals, mut other_dependencies) =
            if self.needs_grant_approval_preparation(&actions, &target, prepared) {
                crate::boxed_future(|| {
                    self.prepare_operation_grant_approvals(
                        conn, event, commit, prepared, &target, &facts, &actions,
                    )
                })
                .await?
            } else {
                (Vec::new(), Vec::new(), false, Vec::new())
            };
        let owned_source = if self.has_owned_actor_grants() {
            crate::boxed_future(|| {
                owned_source_in_connection(conn, &self.realm_id, &self.actor, at, true)
            })
            .await?
        } else {
            None
        };
        let operation = AuthorizationOperation {
            actor: &self.actor,
            actions: &actions,
            target: &target,
            at,
            facts: &facts,
        };
        let evaluate = || {
            coland_storage::evaluate_grants_with_verified_approvals(
                &operation,
                self.effective_grants_with_owned_source(at, owned_source.clone())
                    .map(|(_, grant)| grant),
                &discharges,
            )
        };
        let mut dependencies = match evaluate() {
            GrantEvaluation::Allowed(ref grants) => grants
                .iter()
                .map(|row| row.grant.id.clone())
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        dependencies.append(&mut other_dependencies);
        approved.retain(|approval| {
            matches!(&approval.method.signature.input.approval_context,
            arkret_wire::ApprovalContext::Grant { grant_id } if dependencies.contains(grant_id))
        });
        match crate::boxed_future(|| {
            self.admit_evaluation_in_connection(
                conn,
                evaluate(),
                owner,
                event,
                &operation,
                &discharges,
                missing_approvals,
            )
        })
        .await?
        {
            ActionAdmission::Admitted => {}
            ActionAdmission::NotHeld { .. } => {
                return Err(capability_denied(format!(
                    "the actor holds no placement action authorizing {}",
                    event.kind.as_str()
                )));
            }
        };
        approved.extend(
            crate::approval_admission::require_governance(
                conn,
                event,
                commit,
                prepared,
                action,
                &target,
                &facts,
                &dependencies,
            )
            .await?,
        );
        // Only a grant that names this action and exact Strand, admits the
        // durable source/target List facts, and owes no quota reservation may
        // override the List policy. Root ownership alone does not imply it.
        let override_allowed=evaluate()
            .unreserved()
            .iter()
            .any(|grant| {
                let wip_allow = |constraint: &&arkret_models_collaboration::governance::grant_constraint::GrantConstraint| {
                    constraint.constraint_kind == GrantConstraintKind::ScopeLimitation
                        && constraint.effect == GrantConstraintEffect::Allow
                };
                grant
                    .constraints
                    .iter()
                    .filter(wip_allow)
                    .any(|constraint| constraint.wip_limit_override == Some(true))
                    && !grant
                        .constraints
                        .iter()
                        .filter(wip_allow)
                        .any(|constraint| constraint.wip_limit_override == Some(false))
            });
        Ok((override_allowed, approved))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Atomic approval preparation retains Event, actor and grant facts on the same connection."
    )]
    async fn prepare_grant_approvals(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        action: CapabilityActionId,
        target: &WireResourceSelector,
        facts: &OperationFacts,
    ) -> PersistenceResult<(
        Vec<coland_storage::VerifiedGrantApproval>,
        Vec<crate::approval_admission::QualifiedApproval>,
        bool,
    )> {
        let mut markers = Vec::new();
        let mut accepted = Vec::new();
        let mut missing = false;
        let owned_source = if self.has_owned_actor_grants() {
            crate::boxed_future(|| {
                owned_source_in_connection(
                    conn,
                    &self.realm_id,
                    &self.actor,
                    commit.committed_at,
                    true,
                )
            })
            .await?
        } else {
            None
        };
        for (_, grant) in self
            .effective_grants_with_owned_source(commit.committed_at, owned_source)
            .filter(|(_, grant)| {
                coland_storage::grant_names_target(grant, &[action.as_str()], target)
            })
        {
            let requirements = match crate::grant_approval_admission::require_grant_approvals(
                conn, event, commit, prepared, grant, action, target, facts,
            )
            .await
            {
                Ok(requirements) => requirements,
                Err(PersistenceError::Conflict(detail))
                    if detail.starts_with("approval_required:") =>
                {
                    missing |= grant.constraints.iter().any(|constraint| {
                        crate::grant_approval_admission::is_approval_constraint(constraint)
                            && constraint.effect == GrantConstraintEffect::RequireReview
                    });
                    continue;
                }
                Err(error) => return Err(error),
            };
            for requirement in requirements {
                markers.push(coland_storage::VerifiedGrantApproval {
                    grant_id: requirement.grant_id,
                    constraint_digest: requirement.constraint_digest,
                    action,
                });
                accepted.extend(requirement.accepted);
            }
        }
        Ok((markers, accepted, missing))
    }

    pub(crate) async fn require_policy_with_approvals(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        target: &WireResourceSelector,
    ) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
        self.require_open_lifecycle(event)?;
        self.require_governed_member(&event.kind)?;
        if self.profile_authorized() {
            return Err(capability_denied(
                "Policy is not a Direct Conversation profile operation",
            ));
        }
        let action = if event.kind == EventKind::PolicySet {
            CapabilityActionId::PolicySet
        } else {
            CapabilityActionId::PolicyAction
        };
        Box::pin(self.require_action_with_approvals(
            conn,
            event,
            commit,
            prepared,
            action,
            target,
            &OperationFacts::default(),
        ))
        .await
    }

    pub(crate) async fn require_message_create_with_approvals(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        attributed: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
    ) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
        self.require_open_lifecycle(event)?;
        self.require_governed_member(&event.kind)?;
        if self.profile_authorized() {
            self.require_event_in_connection(conn, attributed, commit.committed_at)
                .await?;
            return Ok(Vec::new());
        }
        let (target, mut facts) = self.event_operation(attributed);
        self.complete_event_facts_in_connection(conn, attributed, &mut facts)
            .await?;
        // Attribution selects the authorization cut; detached evidence always
        // binds the original producer-signed Event, including its provenance.
        Box::pin(self.require_action_with_approvals(
            conn,
            event,
            commit,
            prepared,
            CapabilityActionId::MessageCreate,
            &target,
            &facts,
        ))
        .await
    }

    /// Carry detached evidence through the ordinary writer's accepting cut.
    /// Special root and owned-Agent operations retain their exact authority
    /// rules; ordinary actions reuse the grant and governance admission.
    pub(crate) async fn require_event_with_approvals(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
    ) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
        self.require_open_lifecycle(event)?;
        let root_only = arkret_schema::capability_actions_for_event_kind(event.kind.as_str())
            .any(|descriptor| descriptor.root_control_only);
        let owned_grant = if event.kind == EventKind::CapabilityGrant {
            let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
                serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            payload
                .grant
                .issuer_authority_refs
                .iter()
                .any(|source| matches!(source, IssuerAuthorityRef::OwnedAgent { .. }))
        } else {
            false
        };
        let owned_revoke =
            if event.kind == EventKind::CapabilityRevoke && event.executed_by.is_none() {
                let payload: arkret_models_collaboration::events_payloads::CapabilityRevokePayload =
                    serde_json::from_value(
                        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                    )
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                self.grants.get(&payload.grant_id).is_some_and(|grant| {
                    grant.owned_agent_issuer().is_some_and(|controller| {
                        event.actor_id.as_account_id() == Some(controller)
                    })
                })
            } else {
                false
            };
        if root_only || owned_grant || owned_revoke || self.profile_authorized() {
            crate::boxed_future(|| {
                self.require_event_in_connection(conn, event, commit.committed_at)
            })
            .await?;
            if self.profile_authorized() {
                return Ok(Vec::new());
            }
            let action = CapabilityActionId::from_wire(event.kind.as_str())
                .ok_or_else(|| capability_denied("Exact authority action is unregistered"))?;
            let (target, mut facts) = self.event_operation(event);
            self.complete_event_facts_in_connection(conn, event, &mut facts)
                .await?;
            return crate::approval_admission::require_governance(
                conn,
                event,
                commit,
                prepared,
                action,
                &target,
                &facts,
                &[],
            )
            .await;
        }
        self.require_governed_member(&event.kind)?;
        let actions = Self::unconditional_actions(&event.kind);
        let action = CapabilityActionId::from_wire(event.kind.as_str())
            .filter(|action| actions.contains(&action.as_str()))
            .or_else(|| {
                actions
                    .iter()
                    .filter(|action| **action != CapabilityActionId::REALM_OWNER)
                    .find_map(|action| CapabilityActionId::from_wire(action))
            })
            .ok_or_else(|| capability_denied("Event has no unconditional registered action"))?;
        let (target, mut facts) = self.event_operation(event);
        self.complete_event_facts_in_connection(conn, event, &mut facts)
            .await?;
        let target = self.current_event_target(event, target, &facts)?;
        if !self.needs_grant_approval_preparation(&actions, &target, prepared) {
            crate::boxed_future(|| {
                self.require_event_in_connection(conn, event, commit.committed_at)
            })
            .await?;
            return crate::boxed_future(|| {
                crate::approval_admission::require_governance(
                    conn,
                    event,
                    commit,
                    prepared,
                    action,
                    &target,
                    &facts,
                    &[],
                )
            })
            .await;
        }
        crate::boxed_future(|| {
            self.require_selected_action_with_approvals(
                conn, event, commit, prepared, action, &target, &facts, &actions,
            )
        })
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Approval admission binds the exact Event and current resource facts on one connection."
    )]
    async fn require_action_with_approvals(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        action: CapabilityActionId,
        target: &WireResourceSelector,
        facts: &OperationFacts,
    ) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
        let actions = Self::unconditional_actions(&event.kind);
        self.require_selected_action_with_approvals(
            conn, event, commit, prepared, action, target, facts, &actions,
        )
        .await
    }

    pub(crate) async fn require_moderation_with_approvals(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        actions: &[&str],
    ) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
        self.require_open_lifecycle(event)?;
        let action = CapabilityActionId::from_wire(event.kind.as_str())
            .filter(|action| {
                matches!(
                    action,
                    CapabilityActionId::ModerationDecision
                        | CapabilityActionId::ModerationDecisionLift
                )
            })
            .ok_or_else(|| capability_denied("moderation action is unregistered"))?;
        let mut actions = actions.to_vec();
        // Realm root authority alone never creates Circle moderation rights.
        if matches!(event.scope_ref, arkret_wire::ScopeRef::Realm { .. }) {
            actions.push(CapabilityActionId::REALM_OWNER);
        }
        let (target, mut facts) = self.event_operation(event);
        self.complete_event_facts_in_connection(conn, event, &mut facts)
            .await?;
        self.require_selected_action_with_approvals(
            conn, event, commit, prepared, action, &target, &facts, &actions,
        )
        .await
    }

    pub(crate) async fn require_registered_audit_action(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        action: CapabilityActionId,
        target: &WireResourceSelector,
    ) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
        if !matches!(
            action,
            CapabilityActionId::StrandWatchSetOthers
                | CapabilityActionId::CircleMemberManage
                | CapabilityActionId::CircleMemberAddOthers
                | CapabilityActionId::AuditAccessed
                | CapabilityActionId::RealmNotificationAudit
                | CapabilityActionId::CircleAudit
        ) {
            return Err(capability_denied(
                "unregistered action in an audit transaction",
            ));
        }
        self.require_open_lifecycle(event)?;
        self.require_governed_member(&event.kind)?;
        let mut actions = vec![action.as_str()];
        if arkret_policy::owner_may_author_action(action.as_str())
            .map_err(PersistenceError::database)?
        {
            actions.push(CapabilityActionId::REALM_OWNER);
        }
        let (_, mut facts) = self.event_operation(event);
        self.complete_event_facts_in_connection(conn, event, &mut facts)
            .await?;
        let mut qualified = self
            .require_selected_action_with_approvals(
                conn, event, commit, prepared, action, target, &facts, &actions,
            )
            .await?;
        if event
            .executed_by
            .as_ref()
            .is_some_and(|producer| matches!(producer, ActorId::Service { .. }))
        {
            let id: GrantId = event
                .authorization_ref
                .as_ref()
                .ok_or_else(|| capability_denied("delegated audit lacks authorization_ref"))?
                .as_str()
                .parse()
                .map_err(PersistenceError::database)?;
            let mut service = Self::read(conn, &event.realm_id, event.actual_signer()).await?;
            let (global_markers, global_approvals, global_missing) = crate::boxed_future(|| {
                service
                    .prepare_grant_approvals(conn, event, commit, prepared, action, target, &facts)
            })
            .await?;
            let service_actions = [action.as_str()];
            let global = coland_storage::evaluate_grants_with_verified_approvals(
                &AuthorizationOperation {
                    actor: event.actual_signer(),
                    actions: &service_actions,
                    target,
                    at: commit.committed_at,
                    facts: &facts,
                },
                service
                    .effective_grants(commit.committed_at)
                    .map(|(_, grant)| grant),
                &global_markers,
            );
            if matches!(global, GrantEvaluation::RequiresReview) && global_missing {
                return Err(PersistenceError::Conflict(
                    "approval_required: Service grant approval is not satisfied".into(),
                ));
            }
            if matches!(
                global,
                GrantEvaluation::Denied
                    | GrantEvaluation::Quarantined
                    | GrantEvaluation::RequiresReview
            ) {
                return Err(capability_denied(
                    "delegated Service has an unresolved global deny, quarantine or review",
                ));
            }
            qualified.extend(global_approvals);
            service.selected_grant = Some(id);
            // Account membership/permissions and the original Service grant
            // are separate obligations. The Service does not aggregate owner
            // rights or borrow another independently granted action.
            qualified.extend(
                service
                    .require_selected_action_with_approvals(
                        conn,
                        event,
                        commit,
                        prepared,
                        action,
                        target,
                        &facts,
                        &[action.as_str()],
                    )
                    .await?,
            );
        }
        Ok(qualified)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "All contributing actors use the same accepting Event and resource cut."
    )]
    async fn prepare_operation_grant_approvals(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        target: &WireResourceSelector,
        facts: &OperationFacts,
        actions: &[&str],
    ) -> PersistenceResult<(
        Vec<coland_storage::VerifiedGrantApproval>,
        Vec<crate::approval_admission::QualifiedApproval>,
        bool,
        Vec<GrantId>,
    )> {
        let mut markers = Vec::new();
        let mut accepted = Vec::new();
        let mut missing_approvals = false;
        for candidate in actions
            .iter()
            .filter_map(|action| CapabilityActionId::from_wire(action))
        {
            let (proved, votes, missing) = crate::boxed_future(|| {
                self.prepare_grant_approvals(
                    conn, event, commit, prepared, candidate, target, facts,
                )
            })
            .await?;
            markers.extend(proved);
            accepted.extend(votes);
            missing_approvals |= missing;
        }
        let mut contributors = Vec::new();
        if let Some(controller) =
            crate::boxed_future(|| self.owned_controller_in_connection(conn, commit.committed_at))
                .await?
        {
            contributors
                .push(crate::boxed_future(|| Self::read(conn, &self.realm_id, &controller)).await?);
        }
        if event.actual_signer() != &self.actor
            && crate::boxed_future(|| {
                owned_controller_in_connection(
                    conn,
                    &self.realm_id,
                    event.actual_signer(),
                    commit.committed_at,
                )
            })
            .await?
            .as_ref()
                == Some(&self.actor)
        {
            contributors.push(
                crate::boxed_future(|| Self::read(conn, &self.realm_id, event.actual_signer()))
                    .await?,
            );
        }
        let mut dependencies = Vec::new();
        for contributor in contributors {
            for candidate in actions
                .iter()
                .filter_map(|action| CapabilityActionId::from_wire(action))
            {
                let (proved, votes, missing) = crate::boxed_future(|| {
                    contributor.prepare_grant_approvals(
                        conn, event, commit, prepared, candidate, target, facts,
                    )
                })
                .await?;
                markers.extend(proved);
                accepted.extend(votes);
                missing_approvals |= missing;
            }
            let source = crate::boxed_future(|| {
                owned_source_in_connection(
                    conn,
                    &self.realm_id,
                    &contributor.actor,
                    commit.committed_at,
                    true,
                )
            })
            .await?;
            let operation = AuthorizationOperation {
                actor: &contributor.actor,
                actions,
                target,
                at: commit.committed_at,
                facts,
            };
            if let GrantEvaluation::Allowed(grants) =
                coland_storage::evaluate_grants_with_verified_approvals(
                    &operation,
                    contributor
                        .effective_grants_with_owned_source(commit.committed_at, source)
                        .map(|(_, grant)| grant),
                    &markers,
                )
            {
                dependencies.extend(grants.iter().map(|row| row.grant.id.clone()));
            }
        }
        Ok((markers, accepted, missing_approvals, dependencies))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "One accepting cut binds action, resource, approvals and evaluator checks."
    )]
    async fn require_selected_action_with_approvals(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        action: CapabilityActionId,
        target: &WireResourceSelector,
        facts: &OperationFacts,
        actions: &[&str],
    ) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
        let (admission, mut accepted, dependencies) = crate::boxed_future(|| {
            self.admit_approved_actions_in_connection(
                conn, event, commit, prepared, target, facts, actions,
            )
        })
        .await?;
        if admission != ActionAdmission::Admitted {
            return Err(capability_denied(
                "the actor holds no action for this scope",
            ));
        }
        accepted.extend(
            crate::approval_admission::require_governance(
                conn,
                event,
                commit,
                prepared,
                action,
                target,
                facts,
                &dependencies,
            )
            .await?,
        );
        Ok(accepted)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "An accepting action set binds evidence and resource facts on one connection."
    )]
    async fn admit_approved_actions_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        target: &WireResourceSelector,
        facts: &OperationFacts,
        actions: &[&str],
    ) -> PersistenceResult<(
        ActionAdmission,
        Vec<crate::approval_admission::QualifiedApproval>,
        Vec<GrantId>,
    )> {
        let owner =
            self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER);
        if !self.needs_grant_approval_preparation(actions, target, prepared) {
            let dependencies = match self.evaluate(actions, target, facts, commit.committed_at) {
                GrantEvaluation::Allowed(grants) => {
                    grants.iter().map(|row| row.grant.id.clone()).collect()
                }
                _ => Vec::new(),
            };
            let admission = crate::boxed_future(|| {
                self.admit_actions_in_connection(
                    conn,
                    actions,
                    target,
                    facts,
                    owner,
                    event,
                    commit.committed_at,
                )
            })
            .await?;
            return Ok((admission, Vec::new(), dependencies));
        }
        if matches!(
            self.evaluate(&actions, target, facts, commit.committed_at),
            GrantEvaluation::Denied | GrantEvaluation::Quarantined
        ) {
            self.admit_actions_in_connection(
                conn,
                &actions,
                target,
                facts,
                owner,
                event,
                commit.committed_at,
            )
            .await?;
        }
        let (markers, mut accepted, missing_approvals, mut other_dependencies) =
            crate::boxed_future(|| {
                self.prepare_operation_grant_approvals(
                    conn, event, commit, prepared, target, facts, actions,
                )
            })
            .await?;
        let owned_source = if self.has_owned_actor_grants() {
            crate::boxed_future(|| {
                owned_source_in_connection(
                    conn,
                    &self.realm_id,
                    &self.actor,
                    commit.committed_at,
                    true,
                )
            })
            .await?
        } else {
            None
        };
        let operation = AuthorizationOperation {
            actor: &self.actor,
            actions,
            target,
            at: commit.committed_at,
            facts,
        };
        let evaluation = coland_storage::evaluate_grants_with_verified_approvals(
            &operation,
            self.effective_grants_with_owned_source(commit.committed_at, owned_source)
                .map(|(_, grant)| grant),
            &markers,
        );
        let mut dependencies = match &evaluation {
            GrantEvaluation::Allowed(grants) => grants
                .iter()
                .map(|row| row.grant.id.clone())
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        dependencies.append(&mut other_dependencies);
        accepted.retain(|approval| {
            matches!(&approval.method.signature.input.approval_context,
            arkret_wire::ApprovalContext::Grant { grant_id } if dependencies.contains(grant_id))
        });
        let admission = crate::boxed_future(|| {
            self.admit_evaluation_in_connection(
                conn,
                evaluation,
                owner,
                event,
                &operation,
                &markers,
                missing_approvals,
            )
        })
        .await?;
        Ok((admission, accepted, dependencies))
    }

    fn has_owned_actor_grants(&self) -> bool {
        self.grants.values().any(|grant| {
            matches!(&grant.subject, CapabilitySubject::Actor(actor) if actor==&self.actor)
                && grant.owned_agent_issuer().is_some()
        })
    }

    /// A read-only decision on the complete grant cut. With no applicable
    /// approval constraint or grant-context evidence, the ordinary evaluator
    /// already enforces every controller, refusal and quota obligation.
    fn needs_grant_approval_preparation(
        &self,
        actions: &[&str],
        target: &WireResourceSelector,
        prepared: Option<&coland_storage::EventApprovalCommit>,
    ) -> bool {
        prepared.is_some_and(|proof| {
            proof.methods.iter().any(|method| {
                matches!(
                    method.signature.input.approval_context,
                    arkret_wire::ApprovalContext::Grant { .. }
                )
            })
        }) || self.grants.values().any(|grant| {
            coland_storage::grant_names_target(grant, actions, target)
                && grant
                    .constraints
                    .iter()
                    .any(crate::grant_approval_admission::is_approval_constraint)
        })
    }

    /// The capability-gated verdict for an `event` that acts on one authored
    /// object: an unconditional action as in
    /// [`Self::require_event_in_connection`], or, when the actor authored
    /// `target`, an action whose only evaluator check is
    /// `actor_eq_target_author` on a grant whose constraints, including the
    /// self-service windows of `authz/constraint-schema.md` §14.2, admit the
    /// Event. A grant that names the action but no longer admits it is
    /// `failed_precondition`, never a capability grant.
    pub(crate) async fn require_authored_target_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        target: &AuthoredTarget<'_>,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
    ) -> PersistenceResult<()> {
        let kind = &event.kind;
        self.require_open_lifecycle(event)?;
        self.require_governed_member(kind)?;
        // The profile's participant allowlist carries only the `.own`
        // variants, so its authority reaches only the actor's own object.
        if self.profile_authorized() {
            return if target.author == &self.actor {
                Ok(())
            } else {
                Err(capability_denied(format!(
                    "{} reaches only the actor's own object in a Direct Conversation",
                    kind.as_str()
                )))
            };
        }
        let resource = self.timeline_target(event, target.strand_id.clone());
        let facts = OperationFacts {
            strand_id: Some(target.strand_id.to_string()),
            circle_id: match &event.scope_ref {
                arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
                _ => None,
            },
            object_kind: Some("message".to_owned()),
            track: Some(DISCUSSION_TRACK.to_owned()),
            target_created_at: Some(target.created_at),
            target_owner: Some(target.author.clone()),
            ..OperationFacts::default()
        };
        let actions = Self::unconditional_actions(kind);
        let (admission, accepted, dependencies) = crate::boxed_future(|| {
            self.admit_approved_actions_in_connection(
                conn, event, commit, prepared, &resource, &facts, &actions,
            )
        })
        .await?;
        if admission == ActionAdmission::Admitted {
            let action = CapabilityActionId::from_wire(kind.as_str())
                .ok_or_else(|| capability_denied("Message action is unregistered"))?;
            let mut accepted = accepted;
            accepted.extend(
                crate::approval_admission::require_governance(
                    conn,
                    event,
                    commit,
                    prepared,
                    action,
                    &resource,
                    &facts,
                    &dependencies,
                )
                .await?,
            );
            return crate::approval_admission::consume_and_audit(
                conn,
                event,
                commit,
                &accepted,
                &serde_json::json!({"authored_target_admission":true,"strand_id":target.strand_id}),
            )
            .await;
        }
        if target.author != &self.actor {
            return Err(capability_denied(format!(
                "the actor holds no action authorizing {} on another author's object",
                kind.as_str()
            )));
        }
        let own_actions = arkret_schema::capability_actions_for_event_kind(kind.as_str())
            .filter(|descriptor| {
                descriptor.required_evaluator_checks == [ACTOR_EQ_TARGET_AUTHOR].as_slice()
            })
            .map(|descriptor| descriptor.action.as_str())
            .collect::<Vec<_>>();
        let (admission, mut accepted, dependencies) = crate::boxed_future(|| {
            self.admit_approved_actions_in_connection(
                conn,
                event,
                commit,
                prepared,
                &resource,
                &facts,
                &own_actions,
            )
        })
        .await?;
        match admission {
            ActionAdmission::Admitted => {
                let action = own_actions
                    .iter()
                    .find_map(|action| CapabilityActionId::from_wire(action))
                    .ok_or_else(|| capability_denied("Own Message action is unregistered"))?;
                accepted.extend(
                    crate::approval_admission::require_governance(
                        conn,
                        event,
                        commit,
                        prepared,
                        action,
                        &resource,
                        &facts,
                        &dependencies,
                    )
                    .await?,
                );
                crate::approval_admission::consume_and_audit(conn, event, commit, &accepted,
                    &serde_json::json!({"authored_target_admission":true,"strand_id":target.strand_id})).await
            }
            ActionAdmission::NotHeld { named: true } => Err(PersistenceError::Conflict(format!(
                "failed_precondition: the self-service window of {} has elapsed",
                kind.as_str()
            ))),
            ActionAdmission::NotHeld { named: false } => Err(capability_denied(format!(
                "the actor holds no action authorizing {} on this target",
                kind.as_str()
            ))),
        }
    }

    /// The target and operation facts an Event names in its own payload.
    async fn complete_event_facts_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        facts: &mut OperationFacts,
    ) -> PersistenceResult<()> {
        if matches!(
            event.kind,
            EventKind::ReactionAdd | EventKind::ReactionRemove
        ) {
            let payload: arkret_models_collaboration::events_payloads::reaction::ReactionPayload =
                serde_json::from_value(serde_json::json!(&event.payload))
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let message = arkret_wire::MessageId::new(payload.target_ref.as_str())
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let target = crate::boxed_future(|| {
                crate::message_revision_current_results::locked_message_target(
                    conn,
                    &event.realm_id,
                    &message,
                )
            })
            .await
            .map_err(|error| match error {
                PersistenceError::NotFound(_) => PersistenceError::Conflict(
                    "dependency_missing: reaction target is not materialized at this cut".into(),
                ),
                error => error,
            })?;
            if target.scope_ref != event.scope_ref {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: reaction target differs from its signed scope".into(),
                ));
            }
            facts.object_kind = Some("message".into());
            facts.strand_id = Some(target.strand_id.to_string());
            facts.target_owner = Some(target.author);
            facts.target_created_at = Some(target.created_at);
            facts.track = Some(DISCUSSION_TRACK.into());
        }
        if event.kind == EventKind::SpaceUpdate {
            let payload: arkret_models_collaboration::events_payloads::space::SpacePatchPayload =
                serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let row = diesel::sql_query("SELECT value FROM space_current_results WHERE realm_id=$1 AND space_id=$2 FOR SHARE")
                .bind::<Text, _>(event.realm_id.as_str())
                .bind::<Text, _>(payload.space_id.as_str())
                .get_result::<PolicyBundleRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
                .ok_or_else(|| PersistenceError::Conflict("failed_precondition: Space update target is absent".to_owned()))?;
            let post = match &payload.patch {
                Some(patch) => patch
                    .apply_for_typed_target(&row.value, payload.space_id.as_str())
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
                None => row.value,
            };
            facts.space_kind = post
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
        }
        if event.applet_id.is_some() {
            let registration = crate::managed_message_actor::registration(conn, event).await?;
            facts.applet_id = Some(registration.applet_id.to_string());
            facts.executed_by = Some(
                if event.executed_by.is_none() && event.actor_id.as_account_id().is_some() {
                    let authority = crate::pcr_applet_device_authority::for_event_in_connection(
                        conn,
                        event,
                        chrono::Utc::now(),
                    )
                    .await
                    .map_err(crate::PgTransactionError::into_persistence)?
                    .ok_or_else(|| {
                        capability_denied("native Applet executor has no accepted Device producer")
                    })?;
                    if authority.source_service_id != registration.service_id
                        || authority.applet_id != registration.applet_id
                    {
                        return Err(capability_denied(
                            "native Applet executor provenance differs",
                        ));
                    }
                    event.actor_id.clone()
                } else {
                    crate::managed_message_actor::registered_executor(event, &registration)?
                },
            );
            facts.registration_epoch = Some(registration.registration_epoch.to_string());
        }
        Ok(())
    }

    pub(crate) async fn require_call_actions(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
        actions: &[&str],
    ) -> PersistenceResult<()> {
        self.require_open_lifecycle(event)?;
        self.require_governed_member(&event.kind)?;
        let (target, mut facts) = self.event_operation(event);
        self.complete_event_facts_in_connection(conn, event, &mut facts)
            .await?;
        let target = self.current_event_target(event, target, &facts)?;
        let mut approved = Vec::new();
        for action in actions {
            let registered = CapabilityActionId::from_wire(action)
                .ok_or_else(|| capability_denied("Call axis action is unregistered"))?;
            let mut alternatives = vec![*action];
            if matches!(event.scope_ref, arkret_wire::ScopeRef::Realm { .. }) {
                alternatives.push(CapabilityActionId::REALM_OWNER);
            }
            approved.extend(
                crate::boxed_future(|| {
                    self.require_selected_action_with_approvals(
                        conn,
                        event,
                        commit,
                        prepared,
                        registered,
                        &target,
                        &facts,
                        &alternatives,
                    )
                })
                .await?,
            );
        }
        crate::approval_admission::consume_and_audit(
            conn,
            event,
            commit,
            &approved,
            &serde_json::json!({"call_axes":actions,"scope_ref":event.scope_ref}),
        )
        .await
    }

    /// Native join and public Profile intent retain their original subject.
    /// The Applet action selects governance approval, never transferable authority.
    pub(crate) async fn require_managed_self_action_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        prepared: Option<&coland_storage::EventApprovalCommit>,
    ) -> PersistenceResult<()> {
        self.require_open_lifecycle(event)?;
        let (target, mut facts) = self.event_operation(event);
        self.complete_event_facts_in_connection(conn, event, &mut facts)
            .await?;
        let accepted = if event.executed_by.is_none() {
            let action = crate::applet_device_admission::action(event)?;
            crate::approval_admission::require_governance(
                conn,
                event,
                commit,
                prepared,
                action,
                &target,
                &facts,
                &[],
            )
            .await?
        } else {
            let actions = Self::unconditional_actions(&event.kind);
            let action = if event
                .payload
                .get("membership")
                .and_then(serde_json::Value::as_str)
                == Some("join")
            {
                CapabilityActionId::AppletJoin
            } else {
                CapabilityActionId::RealmAdmin
            };
            self.require_selected_action_with_approvals(
                conn, event, commit, prepared, action, &target, &facts, &actions,
            )
            .await?
        };
        crate::approval_admission::consume_and_audit(
            conn,
            event,
            commit,
            &accepted,
            &serde_json::json!({"managed_self_action_admission":true,"scope_ref":event.scope_ref}),
        )
        .await
    }

    fn timeline_target(
        &self,
        event: &arkret_wire::Event,
        strand: StrandId,
    ) -> WireResourceSelector {
        match &event.scope_ref {
            arkret_wire::ScopeRef::Circle {
                realm_id,
                circle_id,
            } if realm_id == &self.realm_id => {
                WireResourceSelector::circle(realm_id.clone(), circle_id.clone())
            }
            _ => WireResourceSelector::strand(self.realm_id.clone(), strand),
        }
    }

    fn current_event_target(
        &self,
        event: &arkret_wire::Event,
        target: WireResourceSelector,
        facts: &OperationFacts,
    ) -> PersistenceResult<WireResourceSelector> {
        if matches!(
            event.kind,
            EventKind::ReactionAdd | EventKind::ReactionRemove
        ) {
            let strand = facts
                .strand_id
                .as_deref()
                .and_then(|id| id.parse::<StrandId>().ok())
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                        "failed_precondition: reaction target Strand is unavailable".into(),
                    )
                })?;
            return Ok(self.timeline_target(event, strand));
        }
        Ok(target)
    }

    pub(crate) fn event_operation(
        &self,
        event: &arkret_wire::Event,
    ) -> (WireResourceSelector, OperationFacts) {
        let realm = match &event.scope_ref {
            arkret_wire::ScopeRef::Circle {
                realm_id,
                circle_id,
            } if realm_id == &self.realm_id => {
                WireResourceSelector::circle(realm_id.clone(), circle_id.clone())
            }
            _ => WireResourceSelector::realm(self.realm_id.clone()),
        };
        let kind = event.kind.as_str();
        let family = kind
            .strip_prefix("ak.")
            .and_then(|rest| rest.split('.').next())
            .filter(|family| {
                matches!(
                    *family,
                    "strand" | "message" | "morph" | "space" | "circle" | "relation" | "view"
                )
            })
            .map(str::to_owned);
        let payload_id = |field: &str| {
            event
                .payload
                .get(field)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let mut facts = OperationFacts {
            object_kind: family,
            strand_id: payload_id("strand_id"),
            space_id: payload_id("space_id"),
            circle_id: match &event.scope_ref {
                arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
                _ => payload_id("circle_id"),
            },
            ..OperationFacts::default()
        };
        if matches!(
            event.kind,
            EventKind::PinAdd | EventKind::PinRemove | EventKind::PinReorder
        ) && let Ok(payload) =
            arkret_models_collaboration::objects::productivity::PinAssertionPayload::from_event(
                event,
            )
        {
            let target = match payload.pin_scope() {
                arkret_wire::PinScope::Strand { id } => {
                    facts.strand_id = Some(id.to_string());
                    WireResourceSelector::strand(self.realm_id.clone(), id.clone())
                }
                arkret_wire::PinScope::Space { id } => {
                    facts.space_id = Some(id.to_string());
                    WireResourceSelector::space(self.realm_id.clone(), id.clone())
                }
                arkret_wire::PinScope::Circle { id } => {
                    WireResourceSelector::circle(self.realm_id.clone(), id.clone())
                }
                arkret_wire::PinScope::Realm { .. } => realm,
            };
            return (target, facts);
        }
        if matches!(
            event.kind,
            EventKind::StrandArchive | EventKind::StrandRestore | EventKind::StrandStageSet
        ) {
            let field = if event.kind == EventKind::StrandStageSet {
                "strand_id"
            } else {
                "target_ref"
            };
            if let Some(strand) = payload_id(field).and_then(|id| StrandId::new(id).ok()) {
                facts.strand_id = Some(strand.to_string());
                return (
                    WireResourceSelector::strand(self.realm_id.clone(), strand),
                    facts,
                );
            }
        }
        if event.kind == EventKind::StrandUpdate {
            // The patch target and touched fields are producer-bound payload
            // facts. Missing or malformed facts fail closed for constrained
            // grants; the current writer additionally validates the payload.
            if let Ok(payload) = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::strand::StrandPatchPayload,
            >(
                serde_json::to_value(&event.payload).unwrap_or(serde_json::Value::Null),
            ) {
                facts.strand_id = Some(payload.target_ref.as_str().to_owned());
                facts.write_fields = Some(
                    payload
                        .patch
                        .iter()
                        .map(|(path, _)| path.to_owned())
                        .collect(),
                );
                return (
                    WireResourceSelector::strand(self.realm_id.clone(), payload.target_ref),
                    facts,
                );
            }
        }
        if matches!(
            event.kind,
            EventKind::SpaceUpdate
                | EventKind::SpaceParent
                | EventKind::SpaceArchive
                | EventKind::SpaceRestore
                | EventKind::SpaceTombstone
        ) && let Some(space) =
            payload_id("space_id").and_then(|id| arkret_wire::SpaceId::new(id).ok())
        {
            return (
                WireResourceSelector::space(self.realm_id.clone(), space),
                facts,
            );
        }
        if event.kind == EventKind::StrandTracksUpdate {
            // event-kind-registry.json: the tracks writer selects its Strand
            // by `payload.target_ref`; the action carries no field constraint.
            if let Some(strand) = payload_id("target_ref").and_then(|id| StrandId::new(id).ok()) {
                facts.strand_id = Some(strand.to_string());
                return (
                    WireResourceSelector::strand(self.realm_id.clone(), strand),
                    facts,
                );
            }
        }
        if matches!(event.kind, EventKind::StrandMove | EventKind::StrandReorder) {
            let payload = serde_json::to_value(&event.payload).unwrap_or(serde_json::Value::Null);
            let target = if event.kind == EventKind::StrandMove {
                serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::strand::StrandMovePayload,
                >(payload)
                .map(|body| (body.strand_id, body.target_space_id))
            } else {
                serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::strand::StrandReorderPayload,
                >(payload)
                .map(|body| (body.strand_id, body.space_id))
            };
            if let Ok((strand, list)) = target {
                facts.strand_id = Some(strand.as_str().to_owned());
                facts.space_id = Some(list.as_str().to_owned());
                return (
                    WireResourceSelector::strand(self.realm_id.clone(), strand),
                    facts,
                );
            }
        }
        if event.kind == EventKind::RealmProfile {
            // `ak.realm.profile` is a complete replacement of the closed
            // `realm-profile.schema.json` value: a member the payload omits is
            // cleared. Every value member is therefore touched, so the
            // registry-required `allowed_write_fields` of `ak.realm.profile`
            // admits the write only when it covers all of them.
            facts.write_fields = Some(
                REALM_PROFILE_VALUE_FIELDS
                    .iter()
                    .map(|field| (*field).to_owned())
                    .collect(),
            );
        }
        if event.kind == EventKind::SpaceCreate {
            facts.space_kind = event
                .payload
                .get("object")
                .and_then(|object| object.get("kind"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
        }
        if event.kind == EventKind::RsvpSet {
            facts.object_kind = Some("strand".to_owned());
            facts.strand_id = payload_id("event_ref");
            if let Some(strand_id) = facts
                .strand_id
                .as_deref()
                .and_then(|value| value.parse::<StrandId>().ok())
            {
                return (
                    WireResourceSelector::strand(self.realm_id.clone(), strand_id),
                    facts,
                );
            }
        }
        if event.kind == EventKind::StrandWatchSet
            && let Some(strand_id) = facts
                .strand_id
                .as_deref()
                .and_then(|value| value.parse::<StrandId>().ok())
        {
            return (
                WireResourceSelector::strand(self.realm_id.clone(), strand_id),
                facts,
            );
        }
        if event.kind == EventKind::MessageCreate {
            facts.track = Some(DISCUSSION_TRACK.to_owned());
            if let Some(strand_id) = facts
                .strand_id
                .as_deref()
                .and_then(|value| value.parse::<StrandId>().ok())
            {
                return (self.timeline_target(event, strand_id), facts);
            }
        }
        (realm, facts)
    }
}

/// The lifecycle gates of `realm-and-space.md` §2.6.0/§2.6.1, folded from the
/// Realm's committed lifecycle Events in stream order. Every one of them
/// commits on the Realm stream under the authority row lock, so the fold read
/// after that lock is the cut's own.
#[derive(Clone, Copy, Debug, Default)]
struct RealmLifecycleGates {
    archived: bool,
    frozen: bool,
    terminal: bool,
}

impl RealmLifecycleGates {
    async fn read(conn: &mut AsyncPgConnection, realm_id: &RealmId) -> PersistenceResult<Self> {
        let events = sql_query(
            "SELECT e.kind FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
             WHERE e.realm_id=$1 AND c.realm_id=e.realm_id AND e.state='committed' \
               AND e.kind IN ('ak.realm.archive','ak.realm.restore','ak.realm.freeze',\
                              'ak.realm.unfreeze','ak.realm.tombstone','ak.realm.destroy') \
             ORDER BY c.stream_position ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<LifecycleRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut gates = Self::default();
        for event in events {
            match event.kind.as_str() {
                arkret_wire::CapabilityActionId::REALM_ARCHIVE => gates.archived = true,
                arkret_wire::event_kind_str::REALM_RESTORE => gates.archived = false,
                arkret_wire::CapabilityActionId::REALM_FREEZE => gates.frozen = true,
                arkret_wire::event_kind_str::REALM_UNFREEZE => gates.frozen = false,
                _ => gates.terminal = true,
            }
        }
        Ok(gates)
    }
}

/// Enforce lifecycle fences under the already locked governance authority.
/// This runs before every fresh Commit, including non-HTTP writers.
pub(crate) async fn prepare_commit_lifecycle_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    if event.kind == EventKind::RealmDestroy {
        return Err(PersistenceError::Conflict(
            "failed_precondition: v1 has no registered destructive confirmation carrier".to_owned(),
        ));
    }
    let gates = RealmLifecycleGates::read(conn, &event.realm_id).await?;
    if gates.terminal && !arkret_wire::events::kinds::is_audit_kind(&event.kind) {
        return Err(PersistenceError::Conflict(
            "failed_precondition: the Realm is terminal".to_owned(),
        ));
    }
    let payload = serde_json::Value::Object(event.payload.clone().into_iter().collect());
    if (gates.archived || gates.frozen)
        && !arkret_wire::events::kinds::realm_write_gate_exempt(&event.kind, &payload)
    {
        return Err(PersistenceError::Conflict(
            "realm_frozen: the Realm is archived or frozen".to_owned(),
        ));
    }
    if !matches!(
        event.kind,
        EventKind::RealmTombstone
            | EventKind::RealmArchive
            | EventKind::RealmRestore
            | EventKind::RealmFreeze
            | EventKind::RealmUnfreeze
    ) {
        return Ok(Vec::new());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let cut = RealmAuthorizationCut::read_for_event(conn, event).await?;
    let approved =
        crate::boxed_future(|| cut.require_event_with_approvals(conn, event, commit, prepared))
            .await?;
    if event.kind == EventKind::RealmTombstone {
        let typed: arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload =
            serde_json::from_value(payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if typed.successor_realm_id == event.realm_id {
            return Err(PersistenceError::Conflict(
                "failed_precondition: successor must differ from the terminating Realm".to_owned(),
            ));
        }
    }
    Ok(approved)
}

/// The track every Message belongs to (`authz/constraint-schema.md` §6.1).
const DISCUSSION_TRACK: &str = "discussion";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionAdmission {
    Admitted,
    /// No grant admits the operation; `named` when some grant names it.
    NotHeld {
        named: bool,
    },
}

const ACTOR_EQ_TARGET_AUTHOR: &str = "actor_eq_target_author";

/// The author and creation time of the object a `.own` action targets.
pub(crate) struct AuthoredTarget<'a> {
    pub(crate) author: &'a ActorId,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) strand_id: &'a StrandId,
}

/// Take the Realm authority row lock for the accepting transaction. The lock
/// is re-entrant inside one transaction, so a caller that already installed
/// the Commit holds it already and this only proves it.
pub(crate) async fn lock_realm_authorization_cut(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<()> {
    sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<LockedAuthorityRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .filter(|row| row.realm_id == realm_id.as_str())
        .map(|_| ())
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "stale_authority: the Realm has no current governance authority".to_owned(),
            )
        })
}

/// First admission consumes evidence inside the same transaction as the
/// business current and outbox. Replica reducers never call this entry point.
pub(crate) fn authorize_capability_gated_event_with_approvals<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a arkret_wire::Event,
    commit: &'a arkret_wire::RealmCommit,
    prepared: Option<&'a coland_storage::EventApprovalCommit>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = PersistenceResult<RealmAuthorizationCut>> + Send + 'a>,
> {
    Box::pin(async move {
        lock_realm_authorization_cut(conn, &event.realm_id).await?;
        let cut = RealmAuthorizationCut::read_for_event(conn, event).await?;
        let approved =
            Box::pin(cut.require_event_with_approvals(conn, event, commit, prepared)).await?;
        crate::approval_admission::consume_and_audit(
            conn,
            event,
            commit,
            &approved,
            &serde_json::json!({"event_admission":true,"scope_ref":event.scope_ref}),
        )
        .await?;
        Ok(cut)
    })
}

type MessageCreateAuthorizationFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = PersistenceResult<(
                    RealmAuthorizationCut,
                    Vec<crate::approval_admission::QualifiedApproval>,
                )>,
            > + Send
            + 'a,
    >,
>;

pub(crate) fn authorize_message_create_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a arkret_wire::Event,
    attributed: &'a arkret_wire::Event,
    commit: &'a arkret_wire::RealmCommit,
    prepared: Option<&'a coland_storage::EventApprovalCommit>,
) -> MessageCreateAuthorizationFuture<'a> {
    Box::pin(async move {
        lock_realm_authorization_cut(conn, &event.realm_id).await?;
        let cut = RealmAuthorizationCut::read_for_event(conn, attributed).await?;
        let approved = Box::pin(
            cut.require_message_create_with_approvals(conn, event, attributed, commit, prepared),
        )
        .await?;
        Ok((cut, approved))
    })
}

pub(crate) async fn authorize_strand_position_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    source: Option<&arkret_wire::SpaceId>,
    destination: &arkret_wire::SpaceId,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<(bool, Vec<crate::approval_admission::QualifiedApproval>)> {
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut = RealmAuthorizationCut::read_for_event(conn, event).await?;
    cut.require_position_in_connection(conn, event, source, destination, commit, prepared)
        .await
}

#[cfg(test)]
mod operation_fact_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn native_message_cut_uses_action_windows_and_keeps_global_refusals() {
        let realm: RealmId = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"
            .parse()
            .unwrap();
        let account = |did: &str| {
            ActorId::account(arkret_wire::AccountId::new(
                did.parse().unwrap(),
                "ak:did_core:web:station.example".parse().unwrap(),
            ))
        };
        let actor = account("ak:did_core:web:bot.example");
        let owner = account("ak:did_core:web:owner.example");
        let service = ActorId::service("ak:did_core:web:applet.example".parse().unwrap());
        let event = |seed| {
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
        };
        let root_event = event(0x70);
        let parent_id = GrantId::from_event_id(&event(0x71));
        let child_id = GrantId::from_event_id(&event(0x72));
        let root_ref = json!({"kind":"realm_root","realm_id":realm,"authority_event_ref":root_event,"authority_generation":0});
        let parent:CapabilityGrant=serde_json::from_value(json!({"id":parent_id,"schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":owner,"subject":service,"actions":["ak.message.create","ak.event.read"],"resources":[{"kind":"realm","realm_id":realm}],"constraints":[{"constraint_kind":"authority_control","effect":"allow","authority_regrant_allowed":false,"max_authority_depth":0}],"issuer_authority_refs":[root_ref],"authority_depth":1,"authority_root_refs":[root_ref],"issued_at":"2026-09-21T00:00:00.000Z","status":"active"})).unwrap();
        let mut child:CapabilityGrant=serde_json::from_value(json!({"id":child_id,"schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":service,"subject":actor,"actions":["ak.message.create","ak.event.read"],"resources":[{"kind":"realm","realm_id":realm}],"constraints":[{"constraint_kind":"temporal","effect":"allow","applies_to_actions":["ak.event.read"],"expires_at":"2026-09-22T00:00:00.000Z"}],"issuer_authority_refs":[{"kind":"grant","grant_id":parent_id}],"authority_depth":2,"authority_root_refs":[root_ref],"issued_at":"2026-09-21T00:00:00.000Z","status":"active"})).unwrap();
        let target = WireResourceSelector::realm(realm.clone());
        let at = "2026-09-23T00:00:00Z".parse().unwrap();
        assert!(!grant_is_active_at(&child, at));
        let mut cut = RealmAuthorizationCut {
            realm_id: realm.clone(),
            actor,
            root: Some(RealmAuthorityRootCurrent {
                realm_id: realm,
                controller_actor_id: owner,
                controller_epoch: 0,
                authority_generation: 0,
                authority_event_ref: root_event,
            }),
            grants: BTreeMap::from([(parent_id, parent), (child_id.clone(), child.clone())]),
            revisions: BTreeMap::new(),
            policy_bundle: None,
            actor_membership: Some("join".into()),
            lifecycle: RealmLifecycleGates::default(),
            direct_conversation: None,
            selected_grant: Some(child_id),
            native_operation: Some(target.clone()),
        };
        assert_eq!(cut.effective_grants(at).count(), 1);
        assert!(matches!(
            cut.evaluate(
                &[CapabilityActionId::MESSAGE_CREATE],
                &target,
                &OperationFacts::default(),
                at
            ),
            GrantEvaluation::Allowed(_)
        ));
        child.id = GrantId::from_event_id(&event(0x73));
        child.constraints=vec![serde_json::from_value(json!({"constraint_kind":"scope_limitation","effect":"deny","denied_strand_ids":["ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv"]})).unwrap()];
        cut.grants.insert(child.id.clone(), child);
        assert_eq!(cut.effective_grants(at).count(), 2);
        assert!(matches!(
            cut.evaluate(
                &[CapabilityActionId::MESSAGE_CREATE],
                &target,
                &OperationFacts::default(),
                at
            ),
            GrantEvaluation::Denied
        ));
    }

    #[test]
    fn readonly_positive_coverage_rechecks_recurrence_at_handoff() {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraint, GrantConstraintEffect, GrantConstraintKind, GrantConstraintRecurrence,
            GrantConstraintRecurrenceDay, GrantConstraintRecurrenceFrequency,
            GrantConstraintSubkind,
        };
        let realm: RealmId = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"
            .parse()
            .unwrap();
        let account = |principal: &str| {
            ActorId::account(arkret_wire::AccountId::new(
                principal.parse().unwrap(),
                "ak:did_core:web:station.example".parse().unwrap(),
            ))
        };
        let actor = account("ak:did_core:web:reader.example");
        let controller = account("ak:did_core:web:controller.example");
        let root_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x51; 32]);
        let root_ref = json!({"kind":"realm_root","realm_id":realm,"authority_event_ref":root_event,"authority_generation":0});
        let grant_id = GrantId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x52; 32],
        ));
        let mut grant: CapabilityGrant = serde_json::from_value(json!({
            "id":grant_id,"schema":"ak.schema.capability.v1","realm_id":realm,
            "issuer_id":controller,"subject":actor,"actions":[CapabilityActionId::POLICY_SET],
            "resources":[{"kind":"realm","realm_id":realm}],
            "issuer_authority_refs":[root_ref],"authority_depth":1,"authority_root_refs":[root_ref],
            "issued_at":"2026-09-21T00:00:00.000Z","status":"active"
        }))
        .unwrap();
        let mut temporal =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
        temporal.constraint_subkind = Some(GrantConstraintSubkind::Window);
        temporal.recurrence = Some(GrantConstraintRecurrence {
            frequency: Some(GrantConstraintRecurrenceFrequency::Weekly),
            days: vec![GrantConstraintRecurrenceDay::Mon],
            window_start: Some("09:00".to_owned()),
            window_end: Some("17:00".to_owned()),
            timezone: Some("Asia/Shanghai".to_owned()),
            ..Default::default()
        });
        grant.constraints.push(temporal);
        let cut = RealmAuthorizationCut {
            realm_id: realm.clone(),
            actor,
            root: Some(RealmAuthorityRootCurrent {
                realm_id: realm.clone(),
                controller_actor_id: controller,
                controller_epoch: 0,
                authority_generation: 0,
                authority_event_ref: root_event,
            }),
            grants: BTreeMap::from([(grant_id, grant)]),
            revisions: BTreeMap::new(),
            policy_bundle: None,
            actor_membership: Some("join".to_owned()),
            lifecycle: RealmLifecycleGates::default(),
            direct_conversation: None,
            selected_grant: None,
            native_operation: None,
        };
        let before = "2026-09-21T01:00:00Z".parse().unwrap();
        let after = "2026-09-21T09:30:00Z".parse().unwrap();
        let target = WireResourceSelector::realm(realm);
        assert!(cut.time_sources_unchanged(before, after));
        assert!(cut.permits_unreserved_current_actions(
            &[CapabilityActionId::POLICY_SET],
            &target,
            before
        ));
        assert!(!cut.permits_unreserved_current_actions(
            &[CapabilityActionId::POLICY_SET],
            &target,
            after
        ));
    }

    #[test]
    fn strand_patch_authorization_names_exact_target_and_touched_fields() {
        let realm_id =
            RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let strand_id =
            StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let actor = ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:patch-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:patch-station.example").unwrap(),
        ));
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::StrandUpdate.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id: realm_id.clone() },
            actor.clone(),
            json!({"target_ref":strand_id,"patch":{"metadata.title":{"$op":"set","value":"Title"}}}),
            arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        ).unwrap();
        let cut = RealmAuthorizationCut {
            realm_id: realm_id.clone(),
            actor,
            root: None,
            grants: BTreeMap::new(),
            revisions: BTreeMap::new(),
            policy_bundle: None,
            actor_membership: None,
            lifecycle: RealmLifecycleGates::default(),
            direct_conversation: None,
            selected_grant: None,
            native_operation: None,
        };
        let (target, facts) = cut.event_operation(&event);
        assert_eq!(
            target,
            WireResourceSelector::strand(realm_id, strand_id.clone())
        );
        assert_eq!(facts.strand_id.as_deref(), Some(strand_id.as_str()));
        assert_eq!(facts.write_fields, Some(vec!["metadata.title".to_owned()]));
        let list = arkret_wire::SpaceId::from_event_id(&event.event_id);
        let board = arkret_wire::SpaceId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x77; 32],
        ));
        for kind in [EventKind::StrandMove, EventKind::StrandReorder] {
            let mut payload = json!({"board_space_id":board,"strand_id":strand_id,"rank":"a0"});
            payload[if kind == EventKind::StrandMove {
                "target_space_id"
            } else {
                "space_id"
            }] = json!(list);
            let event = arkret_wire::test_support::raw_event_for_actor_at(
                kind.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: cut.realm_id.clone(),
                },
                cut.actor.clone(),
                payload,
                event.created_at,
            )
            .unwrap();
            let (target, facts) = cut.event_operation(&event);
            assert_eq!(
                target,
                WireResourceSelector::strand(cut.realm_id.clone(), strand_id.clone())
            );
            assert_eq!(facts.strand_id.as_deref(), Some(strand_id.as_str()));
            assert_eq!(facts.space_id.as_deref(), Some(list.as_str()));
        }
    }

    #[test]
    fn realm_profile_replacement_touches_every_profile_value_field() {
        let realm_id =
            RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let actor = ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:profile-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:profile-station.example").unwrap(),
        ));
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::RealmProfile.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor.clone(),
            json!({"schema":"ak.schema.realm_profile.v1","title":"Only a title"}),
            arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        )
        .unwrap();
        let cut = RealmAuthorizationCut {
            realm_id: realm_id.clone(),
            actor,
            root: None,
            grants: BTreeMap::new(),
            revisions: BTreeMap::new(),
            policy_bundle: None,
            actor_membership: None,
            lifecycle: RealmLifecycleGates::default(),
            direct_conversation: None,
            selected_grant: None,
            native_operation: None,
        };
        let (target, facts) = cut.event_operation(&event);
        assert_eq!(target, WireResourceSelector::realm(realm_id));
        assert_eq!(
            facts.write_fields,
            Some(vec![
                "title".to_owned(),
                "summary".to_owned(),
                "avatar_blob_ref".to_owned(),
            ])
        );
    }
}
