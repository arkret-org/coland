//! Same-cut authorization of capability-gated Realm Events.
//!
//! The governing Station decides whether an Event's actor may author its kind
//! from four Realm-stream typed current results read inside the accepting
//! transaction: `realm_authority_root`, every `capability_grant` of the Realm,
//! `realm_policy_bundle` and the actor's own `member_state`
//! (`authz/event-auth-state-resolution.md` §1, `authz/capabilities.md` §18).
//!
//! [`authorize_capability_gated_event_in_connection`] first takes the Realm
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
    read_owned_controller_in_connection(conn, realm_id, actor, at, true).await
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
    if account.is_none() {
        return Err(capability_denied(
            "owned Agent controller account is unavailable",
        ));
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
}

impl RealmAuthorizationCut {
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
        identity: &str,
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
        self.admit_evaluation_in_connection(
            conn,
            evaluation,
            owner_covers,
            identity,
            &operation,
            &[],
        )
        .await
    }

    pub(crate) async fn owned_controller_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<ActorId>> {
        owned_controller_in_connection(conn, &self.realm_id, &self.actor, at).await
    }

    async fn admit_evaluation_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        evaluation: GrantEvaluation<'_>,
        owner_covers: bool,
        identity: &str,
        operation: &AuthorizationOperation<'_>,
        approvals: &[coland_storage::VerifiedGrantApproval],
    ) -> PersistenceResult<ActionAdmission> {
        let controller = if self.is_direct_conversation() {
            None
        } else {
            self.owned_controller_in_connection(conn, operation.at)
                .await?
        };
        let controller_cut = match &controller {
            Some(controller) => Some(Self::read(conn, &self.realm_id, controller).await?),
            None => None,
        };
        let bounded = controller_cut.is_some();
        let controller_root_covers = controller_cut.as_ref().is_some_and(|cut| {
            cut.actor_is_root_controller()
                && operation.actions.contains(&CapabilityActionId::REALM_OWNER)
        });
        let managed_actions = match &controller {
            Some(controller) => Some(
                crate::agent_management_admission::executable_actions_in_connection(
                    conn,
                    &self.realm_id,
                    controller
                        .as_account_id()
                        .ok_or_else(|| capability_denied("Agent controller is not an account"))?,
                    self.actor
                        .as_account_id()
                        .ok_or_else(|| capability_denied("Agent is not an account"))?,
                    operation,
                )
                .await?,
            ),
            None => None,
        };
        let managed_operation = AuthorizationOperation {
            actions: managed_actions.as_deref().unwrap_or(operation.actions),
            ..*operation
        };
        let evaluation = if let Some(controller_cut) = &controller_cut {
            controller_cut.require_governed_member(&EventKind::CapabilityGrant)?;
            let agent_grants = self
                .effective_grants(operation.at)
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
        } else {
            evaluation
        };
        let owner_covers = owner_covers && !bounded;
        match evaluation {
            GrantEvaluation::Denied => Err(capability_denied(
                "a deny constraint of an effective grant matches the operation",
            )),
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
                        identity,
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
        let root = self.root.as_ref();
        self.grants.iter().filter(move |(grant_id, grant)| {
            let Some(root) = root else {
                return false;
            };
            matches!(&grant.subject, CapabilitySubject::Actor(subject) if subject == &self.actor)
                && grant.realm_id.as_ref() == Some(&self.realm_id)
                && grant_is_active_at(grant, at)
                && !grant.issuer_authority_refs.is_empty()
                && grant
                    .issuer_authority_refs
                    .iter()
                    .all(|authority_ref| match authority_ref {
                        IssuerAuthorityRef::OwnedAgent { .. } => false,
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
                    })
        })
    }

    /// The actor's authorization at `at` as a backend-neutral value: whether
    /// it is the root controller, and every effective grant with the exact
    /// revision of its current result.
    pub(crate) fn actor_authorization(
        &self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActorRealmAuthorization> {
        let grants = self
            .effective_grants(at)
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
        })
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
        self.complete_applet_facts_in_connection(conn, event, &mut facts)
            .await?;
        match self
            .admit_actions_in_connection(
                conn,
                &actions,
                &target,
                &facts,
                owner,
                event.event_id.as_str(),
                at,
            )
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
            self.admit_actions_in_connection(
                conn,
                &actions,
                &target,
                &facts,
                owner,
                event.event_id.as_str(),
                at,
            )
            .await?;
        }
        let action = if event.kind == EventKind::StrandReorder {
            CapabilityActionId::StrandReorder
        } else {
            CapabilityActionId::StrandMove
        };
        let (discharges, mut approved) = self
            .prepare_grant_approvals(conn, event, commit, prepared, action, &target, &facts)
            .await?;
        let evaluate = || {
            coland_storage::evaluate_grants_with_verified_approvals(
                &AuthorizationOperation {
                    actor: &self.actor,
                    actions: &actions,
                    target: &target,
                    at,
                    facts: &facts,
                },
                self.effective_grants(at).map(|(_, grant)| grant),
                &discharges,
            )
        };
        let dependencies = match evaluate() {
            GrantEvaluation::Allowed(ref grants) => grants
                .iter()
                .map(|row| row.grant.id.clone())
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        match self
            .admit_evaluation_in_connection(
                conn,
                evaluate(),
                owner,
                event.event_id.as_str(),
                &AuthorizationOperation {
                    actor: &self.actor,
                    actions: &actions,
                    target: &target,
                    at,
                    facts: &facts,
                },
                &discharges,
            )
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
    )> {
        let mut markers = Vec::new();
        let mut accepted = Vec::new();
        for (_, grant) in self
            .effective_grants(commit.committed_at)
            .filter(|(_, grant)| {
                coland_storage::grant_names_target(grant, &[action.as_str()], target)
            })
        {
            for requirement in crate::grant_approval_admission::require_grant_approvals(
                conn, event, commit, prepared, grant, action, target, facts,
            )
            .await?
            {
                markers.push(coland_storage::VerifiedGrantApproval {
                    grant_id: requirement.grant_id,
                    constraint_digest: requirement.constraint_digest,
                    action,
                });
                accepted.extend(requirement.accepted);
            }
        }
        Ok((markers, accepted))
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
        let actions = Self::unconditional_actions(&event.kind);
        let owner =
            self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER);
        let facts = OperationFacts::default();
        if matches!(
            self.evaluate(&actions, target, &facts, commit.committed_at),
            GrantEvaluation::Denied | GrantEvaluation::Quarantined
        ) {
            self.admit_actions_in_connection(
                conn,
                &actions,
                target,
                &facts,
                owner,
                event.event_id.as_str(),
                commit.committed_at,
            )
            .await?;
        }
        let (markers, mut accepted) = self
            .prepare_grant_approvals(conn, event, commit, prepared, action, target, &facts)
            .await?;
        let evaluation = coland_storage::evaluate_grants_with_verified_approvals(
            &AuthorizationOperation {
                actor: &self.actor,
                actions: &actions,
                target,
                at: commit.committed_at,
                facts: &facts,
            },
            self.effective_grants(commit.committed_at)
                .map(|(_, grant)| grant),
            &markers,
        );
        let dependencies = match &evaluation {
            GrantEvaluation::Allowed(grants) => grants
                .iter()
                .map(|row| row.grant.id.clone())
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        if self
            .admit_evaluation_in_connection(
                conn,
                evaluation,
                owner,
                event.event_id.as_str(),
                &AuthorizationOperation {
                    actor: &self.actor,
                    actions: &actions,
                    target,
                    at: commit.committed_at,
                    facts: &facts,
                },
                &markers,
            )
            .await?
            != ActionAdmission::Admitted
        {
            return Err(capability_denied(
                "the actor holds no Policy action for this scope",
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
                &facts,
                &dependencies,
            )
            .await?,
        );
        Ok(accepted)
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
        at: chrono::DateTime<chrono::Utc>,
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
        let realm = match &event.scope_ref {
            arkret_wire::ScopeRef::Circle {
                realm_id,
                circle_id,
            } if realm_id == &self.realm_id => {
                WireResourceSelector::circle(realm_id.clone(), circle_id.clone())
            }
            _ => WireResourceSelector::realm(self.realm_id.clone()),
        };
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
        let identity = event.event_id.as_str();
        let actions = Self::unconditional_actions(kind);
        let owner =
            self.actor_is_root_controller() && actions.contains(&CapabilityActionId::REALM_OWNER);
        if self
            .admit_actions_in_connection(conn, &actions, &realm, &facts, owner, identity, at)
            .await?
            == ActionAdmission::Admitted
        {
            return Ok(());
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
        match self
            .admit_actions_in_connection(conn, &own_actions, &realm, &facts, false, identity, at)
            .await?
        {
            ActionAdmission::Admitted => Ok(()),
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
    async fn complete_applet_facts_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        facts: &mut OperationFacts,
    ) -> PersistenceResult<()> {
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
            facts.executed_by = Some(crate::managed_message_actor::registered_executor(
                event,
                &registration,
            )?);
            facts.registration_epoch = Some(registration.registration_epoch.to_string());
        }
        Ok(())
    }

    /// A managed actor entering itself is not already a joined member. Its
    /// explicit action grant still owes every ordinary constraint and quota.
    pub(crate) async fn require_managed_self_membership_action_in_connection(
        &self,
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        self.require_open_lifecycle(event)?;
        let actions = Self::unconditional_actions(&event.kind);
        let (target, mut facts) = self.event_operation(event);
        self.complete_applet_facts_in_connection(conn, event, &mut facts)
            .await?;
        match self
            .admit_actions_in_connection(
                conn,
                &actions,
                &target,
                &facts,
                false,
                event.event_id.as_str(),
                at,
            )
            .await?
        {
            ActionAdmission::Admitted => Ok(()),
            ActionAdmission::NotHeld { .. } => Err(capability_denied(
                "managed membership has no explicit authorizing action",
            )),
        }
    }

    fn event_operation(
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
                return (
                    WireResourceSelector::strand(self.realm_id.clone(), strand_id),
                    facts,
                );
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
                "ak.realm.archive" => gates.archived = true,
                "ak.realm.restore" => gates.archived = false,
                "ak.realm.freeze" => gates.frozen = true,
                "ak.realm.unfreeze" => gates.frozen = false,
                _ => gates.terminal = true,
            }
        }
        Ok(gates)
    }
}

/// Enforce lifecycle fences under the already locked governance authority.
/// This runs before every fresh Commit, including non-HTTP writers.
pub(crate) async fn require_commit_lifecycle_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
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
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    authorize_capability_gated_event_in_connection(conn, event, at).await?;
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
    Ok(())
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

/// Authorize `event` as a capability-gated Realm Event at the accepting
/// transaction's cut and return that cut for kind-specific rules.
pub(crate) fn authorize_capability_gated_event_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a arkret_wire::Event,
    at: chrono::DateTime<chrono::Utc>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = PersistenceResult<RealmAuthorizationCut>> + Send + 'a>,
> {
    Box::pin(authorize_capability_gated_event_inner(conn, event, at))
}

async fn authorize_capability_gated_event_inner(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<RealmAuthorizationCut> {
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut = RealmAuthorizationCut::read_for_event(conn, event).await?;
    cut.require_event_in_connection(conn, event, at).await?;
    Ok(cut)
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
