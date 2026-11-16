// Durable adapters replay accepted originals through these shared contracts.
use std::collections::BTreeMap;

pub use coland_domain::reducer::{
    CommitStreamProjection, MorphProjection, ObjectLifecycleState, ProjectionEffect,
    ProjectionState, ServerHlc, morph_document_body,
};

use super::{
    PersistenceError, PersistenceResult, ProjectedEventOperation, ProjectionEventRecord,
    RealmMetaRecord, Value, async_trait,
};
/// Trait for Realm metadata storage operations.
#[async_trait]
pub trait RealmMetaStore: Send + Sync {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmMetaRecord>>;
    async fn put(&self, realm_id: &str, record: &RealmMetaRecord) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<(String, RealmMetaRecord)>>;
    async fn delete(&self, realm_id: &str) -> PersistenceResult<()>;
}
/// One consistent restart snapshot of registered Space and Strand typed
/// current results. These values come from RealmCommit-backed current rows,
/// never the older reducer mirror tables.
#[derive(Clone, Debug)]
pub struct ObjectCurrentSnapshot {
    pub spaces: Vec<arkret_models_collaboration::objects::space::Space>,
    pub strands: Vec<arkret_models_collaboration::objects::strand::Strand>,
}

#[async_trait]
pub trait ObjectCurrentSnapshotStore: Send + Sync {
    async fn snapshot(&self) -> PersistenceResult<ObjectCurrentSnapshot>;
}
/// Durable Circle projection store (mirror of `projection_circles` +
/// `projection_circle_members`).
///
/// Circle membership is the set the wire validator enforces
/// `Circle.members subset of Realm.members` against, so losing it on restart
/// would silently widen a Circle boundary until the log is replayed.
#[async_trait]
pub trait CircleProjectionStore: Send + Sync {
    async fn get(&self, circle_id: &str) -> PersistenceResult<Option<CircleProjectionRecord>>;
    async fn put(&self, record: &CircleProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CircleProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<CircleProjectionRecord>>;
    async fn delete(&self, circle_id: &str) -> PersistenceResult<()>;
    /// Replace the whole membership set of one Circle. Membership is a set,
    /// not a log: a row that disappeared from the reducer has to disappear
    /// here too, so a partial upsert would resurrect removed members.
    async fn put_members(
        &self,
        circle_id: &str,
        members: &[CircleMemberProjectionRecord],
    ) -> PersistenceResult<()>;
    async fn snapshot_all_members(&self) -> PersistenceResult<Vec<CircleMemberProjectionRecord>>;
}
/// Durable Morph projection store (mirror of `projection_morphs` table).
#[async_trait]
pub trait MorphProjectionStore: Send + Sync {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>>;
    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<MorphProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>>;
    async fn delete(&self, morph_id: &str) -> PersistenceResult<()>;
}

/// Authoritative current Relation value for one typed primary conflict domain.
///
/// Unlike the rebuildable in-memory relation index, this row carries the exact
/// accepting RealmCommit revision used by admission CAS. Restart hydration
/// reads this port so queries and subsequent validation observe the same
/// current value the transaction boundary serialized.
#[derive(Clone, Debug)]
pub struct RelationCurrentStateRecord {
    pub realm_id: arkret_wire::RealmId,
    pub domain_key: String,
    pub primary_conflict_domain:
        arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomain,
    pub relation: arkret_models_collaboration::objects::relation::Relation,
    pub revision: arkret_wire::CurrentRevision,
}

#[async_trait]
pub trait RelationCurrentStateStore: Send + Sync {
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RelationCurrentStateRecord>>;
}

/// Authoritative current Capability Grant value accepted by the governing
/// Station.
///
/// `value` and `revision` are one durable row and therefore one read
/// snapshot.  Consumers must never replace this revision with the in-memory
/// facet counter, the effective-list digest, or an Event id.
#[derive(Clone, Debug)]
pub struct CapabilityGrantCurrentStateRecord {
    pub realm_id: arkret_wire::RealmId,
    pub grant_id: arkret_wire::GrantId,
    pub status: CapabilityGrantCurrentStatus,
    pub value: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    pub revision: arkret_wire::CurrentRevision,
    pub source: arkret_wire::CommittedEventRef,
}

impl CapabilityGrantCurrentStateRecord {
    /// Build one backend-neutral current row and fail closed if its canonical
    /// value disagrees with the storage key or lifecycle columns.
    pub fn try_new(
        realm_id: arkret_wire::RealmId,
        grant_id: arkret_wire::GrantId,
        status: CapabilityGrantCurrentStatus,
        value: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
        revision: arkret_wire::CurrentRevision,
        source: arkret_wire::CommittedEventRef,
    ) -> PersistenceResult<Self> {
        if value.schema != arkret_wire::SchemaId::CAPABILITY_V1
            || value.id != grant_id
            || value.status != status.grant_status()
            || value
                .realm_id
                .as_ref()
                .is_some_and(|value_realm| value_realm != &realm_id)
        {
            return Err(PersistenceError::Database(
                "stored Capability Grant value does not match its row identity".to_owned(),
            ));
        }
        if source.commit_id != revision.commit_id
            || source.stream_position != revision.stream_position
            || source.stream_ref.realm_id() != &realm_id
        {
            return Err(PersistenceError::Database(
                "stored Capability Grant source does not match its revision".to_owned(),
            ));
        }
        Ok(Self {
            realm_id,
            grant_id,
            status,
            value,
            revision,
            source,
        })
    }
}

/// Closed lifecycle of the `capability_grant` current state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityGrantCurrentStatus {
    Active,
    Revoked,
    Relinquished,
}

impl CapabilityGrantCurrentStatus {
    /// The lifecycle member the canonical grant value carries for this row.
    #[must_use]
    pub const fn grant_status(
        self,
    ) -> arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus {
        use arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus;
        match self {
            Self::Active => CapabilityGrantStatus::Active,
            Self::Revoked => CapabilityGrantStatus::Revoked,
            Self::Relinquished => CapabilityGrantStatus::Relinquished,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Relinquished => "relinquished",
        }
    }
}

impl std::str::FromStr for CapabilityGrantCurrentStatus {
    type Err = PersistenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "relinquished" => Ok(Self::Relinquished),
            _ => Err(PersistenceError::Database(
                "stored Capability Grant lifecycle is invalid".to_owned(),
            )),
        }
    }
}

/// One Capability Grant effective for one exact actor, paired with the exact
/// revision of the same `capability_grant` current-state row.
#[derive(Clone, Debug)]
pub struct EffectiveActorGrant {
    pub grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    pub revision: arkret_wire::CurrentRevision,
}

/// Verifier-private current facts from one native/verified Realm cut. This
/// object is never serialized and is not an authority supplied by a caller.
#[derive(Clone, Debug)]
pub struct GrantAuthorityCut {
    realm_id: arkret_wire::RealmId,
    root: arkret_wire::RealmAuthorityRootValue,
    grants: BTreeMap<
        arkret_wire::GrantId,
        arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    >,
    revisions: BTreeMap<arkret_wire::GrantId, arkret_wire::CurrentRevision>,
}

impl GrantAuthorityCut {
    pub fn new(
        realm_id: arkret_wire::RealmId,
        root: arkret_wire::RealmAuthorityRootValue,
        grants: BTreeMap<
            arkret_wire::GrantId,
            arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
        >,
        revisions: BTreeMap<arkret_wire::GrantId, arkret_wire::CurrentRevision>,
    ) -> PersistenceResult<Self> {
        if grants.len() != revisions.len()
            || grants.iter().any(|(id, grant)| {
                &grant.id != id
                    || grant.realm_id.as_ref() != Some(&realm_id)
                    || !revisions.contains_key(id)
                    || grant.validate_authority_shape().is_err()
            })
        {
            return Err(PersistenceError::Conflict(
                "revision_unavailable: incomplete or invalid current grant cut".into(),
            ));
        }
        Ok(Self {
            realm_id,
            root,
            grants,
            revisions,
        })
    }

    fn root_current(
        &self,
        source: &arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef,
    ) -> bool {
        matches!(source, arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::RealmRoot {
            realm_id,authority_event_ref,authority_generation,
        } if realm_id==&self.realm_id && authority_event_ref==&self.root.authority_event_ref
            && authority_generation==&self.root.authority_generation)
    }
}

/// The Realm authorization inputs of one exact actor, derived from one storage
/// cut of the Realm-stream typed current results (`realm_authority_root` and
/// every `capability_grant` of the Realm).
///
/// `grants` is the selected flat disclosure/list view. Permission always uses
/// the mandatory complete `source_cut`, at the actual action and selector;
/// neither an omitted view row nor a local allow failure can erase a refusal.
/// An Agent and its verified controller share the same Arc/cut and additionally
/// retain the independent management/ownership backing.
#[derive(Clone, Debug)]
pub struct ActorRealmAuthorization {
    pub realm_id: arkret_wire::RealmId,
    pub actor: arkret_wire::ActorId,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub grants: Vec<EffectiveActorGrant>,
    source_cut: std::sync::Arc<GrantAuthorityCut>,
    owned_source:
        Option<arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef>,
    // Every subject grant, not the display/effective-list subset. Only the
    // original-fulfillment view may narrow this after live authorization.
    terminal_ids: std::collections::BTreeSet<arkret_wire::GrantId>,
    /// Verifier-private same-cut backing, never an authority or wire carrier.
    pub agent_ceiling: Option<AgentControllerCeiling>,
}

#[derive(Clone, Debug)]
pub struct AgentControllerCeiling {
    pub controller: Box<ActorRealmAuthorization>,
    pub management_policies: Vec<arkret_models_collaboration::governance::operation_wire::Policy>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthorizationLayer {
    Complete,
    GrantSources,
}

impl ActorRealmAuthorization {
    fn source_error(error: arkret_policy::grant_authority::AuthorityError) -> PersistenceError {
        let code = if error == arkret_policy::grant_authority::AuthorityError::Unproved {
            "revision_unavailable"
        } else {
            "capability_denied"
        };
        PersistenceError::Conflict(format!(
            "{code}: current grant source cannot be proved: {error}"
        ))
    }
    pub fn from_source_cut(
        actor: arkret_wire::ActorId,
        evaluated_at: chrono::DateTime<chrono::Utc>,
        source_cut: std::sync::Arc<GrantAuthorityCut>,
        view_grant_ids: Vec<arkret_wire::GrantId>,
        owned_source: Option<
            arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef,
        >,
    ) -> PersistenceResult<Self> {
        let terminal_ids=source_cut.grants.iter().filter(|(_,grant)|
            matches!(&grant.subject,arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject) if subject==&actor)
        ).map(|(id,_)|id.clone()).collect::<std::collections::BTreeSet<_>>();
        let grants = view_grant_ids
            .into_iter()
            .map(|id| {
                if !terminal_ids.contains(&id) {
                    return Err(PersistenceError::Conflict(
                        "revision_unavailable: displayed grant is not this subject's current row"
                            .into(),
                    ));
                }
                Ok(EffectiveActorGrant {
                    grant: source_cut.grants[&id].clone(),
                    revision: source_cut.revisions[&id].clone(),
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        Ok(Self {
            realm_id: source_cut.realm_id.clone(),
            actor,
            evaluated_at,
            grants,
            source_cut,
            owned_source,
            terminal_ids,
            agent_ceiling: None,
        })
    }

    pub fn source_cut(&self) -> &std::sync::Arc<GrantAuthorityCut> {
        &self.source_cut
    }

    pub fn root_controller(&self) -> bool {
        self.realm_id == self.source_cut.realm_id
            && self.actor == self.source_cut.root.controller_actor_id
    }

    fn global_active(
        &self,
        grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> bool {
        use arkret_models_collaboration::governance::grant_constraint::{
            CapabilityGrantStatus, GrantConstraintEffect, GrantConstraintKind,
        };
        let from = grant
            .constraints
            .iter()
            .filter(|constraint| {
                constraint.constraint_kind == GrantConstraintKind::Temporal
                    && constraint.effect == GrantConstraintEffect::Allow
                    && constraint.applies_to_actions.is_empty()
                    && constraint.recurrence.is_none()
            })
            .filter_map(|constraint| constraint.not_before)
            .max();
        grant.status == CapabilityGrantStatus::Active
            && from.is_none_or(|from| from <= self.evaluated_at)
            && crate::capability_grant_expires_at(grant)
                .is_none_or(|until| self.evaluated_at < until)
    }

    fn owned_current(
        &self,
        grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> bool {
        grant.owned_agent_issuer().is_some()
            && grant.issuer_authority_refs.len() == 1
            && self.owned_source.as_ref() == grant.issuer_authority_refs.first()
            && self.global_active(grant)
    }

    fn current_candidates<'a>(
        &'a self,
        action: &str,
        target: &arkret_wire::WireResourceSelector,
    ) -> PersistenceResult<
        Vec<&'a arkret_models_collaboration::governance::grant_constraint::CapabilityGrant>,
    > {
        let unbound = || {
            PersistenceError::Conflict(
                "capability_denied: actual target does not bind the current source cut".into(),
            )
        };
        target.validate().map_err(|_| unbound())?;
        let target_realm = if target.kind == arkret_wire::ResourceSelectorKind::RealmActor {
            target
                .realm_actor_id()
                .and_then(arkret_wire::ActorId::as_realm_actor_id)
                .map(|actor| &actor.realm_id)
        } else {
            target.realm_id.as_ref()
        };
        if self.realm_id != self.source_cut.realm_id
            || target_realm != Some(&self.realm_id)
            || target.kind == arkret_wire::ResourceSelectorKind::All
        {
            return Err(unbound());
        }
        let mut candidates = Vec::new();
        for id in &self.terminal_ids {
            let grant = self.source_cut.grants.get(id).ok_or_else(|| {
                PersistenceError::Conflict(
                    "revision_unavailable: current terminal row is missing".into(),
                )
            })?;
            if !matches!(&grant.subject,arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject) if subject==&self.actor)
            {
                return Err(PersistenceError::Conflict(
                    "revision_unavailable: current actor slice changed its bound subject".into(),
                ));
            }
            if !arkret_policy::grant_authority::contributes(grant, action, target) {
                continue;
            }
            if grant.owned_agent_issuer().is_some() {
                if self.owned_current(grant) {
                    candidates.push(grant);
                }
                continue;
            }
            match arkret_policy::grant_authority::current_candidate_sources(
                grant,
                action,
                target,
                &self.source_cut.grants,
                self.evaluated_at,
                |source| self.source_cut.root_current(source),
            ) {
                Ok(_) => candidates.push(grant),
                Err(arkret_policy::grant_authority::AuthorityError::Closed) => {}
                Err(error) => return Err(Self::source_error(error)),
            }
        }
        Ok(candidates)
    }

    fn positive_sources<'a>(
        &'a self,
        action: &str,
        target: &arkret_wire::WireResourceSelector,
        candidates:&[&'a arkret_models_collaboration::governance::grant_constraint::CapabilityGrant],
    ) -> PersistenceResult<
        Vec<&'a arkret_models_collaboration::governance::grant_constraint::CapabilityGrant>,
    > {
        let mut positive = Vec::new();
        for grant in candidates {
            if self.owned_current(grant) {
                if arkret_policy::grant_authority::current_action_window_is_open(
                    grant,
                    action,
                    self.evaluated_at,
                ) {
                    positive.push(*grant);
                }
                continue;
            }
            match arkret_policy::grant_authority::current_sources(
                grant,
                action,
                target,
                &self.source_cut.grants,
                self.evaluated_at,
                |source| self.source_cut.root_current(source),
            ) {
                Ok(_) => positive.push(*grant),
                Err(arkret_policy::grant_authority::AuthorityError::Closed) => {}
                Err(error) => return Err(Self::source_error(error)),
            }
        }
        Ok(positive)
    }

    /// Source qualification only, not a business permission verdict. Actual
    /// constraint/approval/quota evaluation still uses `evaluate` at admission.
    pub fn current_positive_grant_source(
        &self,
        id: &arkret_wire::GrantId,
        action: &str,
        target: &arkret_wire::WireResourceSelector,
    ) -> PersistenceResult<
        &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    > {
        self.current_positive_grant_records(action, target)?
            .into_iter()
            .find(|grant| &grant.id == id)
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "capability_denied: selected current source is closed".into(),
                )
            })
    }

    /// Source-qualified candidate records for collecting constraints before
    /// approval discharge. No business permission or reservation is implied.
    pub fn current_candidate_grant_records(
        &self,
        action: &str,
        target: &arkret_wire::WireResourceSelector,
    ) -> PersistenceResult<
        Vec<&arkret_models_collaboration::governance::grant_constraint::CapabilityGrant>,
    > {
        self.current_candidates(action, target)
    }

    /// Positive lineage/window qualification only. The caller must still
    /// evaluate business constraints/approvals and reserve any actual quota.
    pub fn current_positive_grant_records(
        &self,
        action: &str,
        target: &arkret_wire::WireResourceSelector,
    ) -> PersistenceResult<
        Vec<&arkret_models_collaboration::governance::grant_constraint::CapabilityGrant>,
    > {
        let candidates = self.current_candidates(action, target)?;
        self.positive_sources(action, target, &candidates)
    }

    /// A same-cut metadata lookup. It establishes no action permission.
    pub fn current_grant_record(
        &self,
        id: &arkret_wire::GrantId,
    ) -> Option<&arkret_models_collaboration::governance::grant_constraint::CapabilityGrant> {
        self.source_cut
            .grants
            .get(id)
            .filter(|grant| self.terminal_ids.contains(id) && self.global_active(grant)
                && matches!(&grant.subject,arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject) if subject==&self.actor))
    }

    /// Called only after live current authorization and immutable Start/audit
    /// verification. This view derives original quota identities, never new
    /// permission. Keep every ancestor fact and the shared cut intact.
    fn use_original_fulfillment_time(&mut self, at: chrono::DateTime<chrono::Utc>) {
        self.evaluated_at = at;
        self.terminal_ids
            .retain(|id| self.source_cut.grants[id].issued_at <= at);
        self.grants
            .retain(|row| self.terminal_ids.contains(&row.grant.id));
        if let Some(ceiling) = self.agent_ceiling.as_mut() {
            ceiling.controller.use_original_fulfillment_time(at);
        }
    }

    /// Derive only original reservation identities after live authorization.
    /// Never return a historical authorization view or a new permission result.
    pub fn original_quota_reservation_paths(
        &self,
        accepted_start: &arkret_wire::RealmCommit,
        actions: &[&str],
        target: &arkret_wire::WireResourceSelector,
        facts: &crate::OperationFacts,
        approvals: &[crate::VerifiedGrantApproval],
    ) -> PersistenceResult<Vec<(arkret_wire::GrantId, Vec<crate::QuotaReservation>)>> {
        let live = self.evaluate_with_approvals_checked(actions, target, facts, approvals)?;
        if accepted_start.realm_id != self.realm_id
            || accepted_start.committed_at > self.evaluated_at
            || accepted_start.validate_content_address().is_err()
            || !matches!(live, crate::GrantEvaluation::Allowed(_))
        {
            return Err(PersistenceError::Conflict("capability_denied: original fulfillment lacks current authorization or a valid accepting cut".into()));
        }
        let mut original = self.clone();
        original.use_original_fulfillment_time(accepted_start.committed_at);
        let crate::GrantEvaluation::Allowed(paths) =
            original.evaluate_with_approvals_checked(actions, target, facts, approvals)?
        else {
            return Err(PersistenceError::Conflict(
                "capability_denied: original fulfillment identities cannot be proved".into(),
            ));
        };
        Ok(paths
            .into_iter()
            .map(|path| (path.grant.id.clone(), path.reservations))
            .collect())
    }

    /// `constraint-schema.md` §15.4 over the effective grants for one
    /// operation of this actor.
    pub fn evaluate<'a>(
        &'a self,
        actions: &'a [&'a str],
        target: &'a arkret_wire::WireResourceSelector,
        facts: &'a crate::OperationFacts,
    ) -> crate::GrantEvaluation<'a> {
        self.evaluate_with_approvals(actions, target, facts, &[])
    }

    pub fn evaluate_with_approvals<'a>(
        &'a self,
        actions: &'a [&'a str],
        target: &'a arkret_wire::WireResourceSelector,
        facts: &'a crate::OperationFacts,
        approvals: &[crate::VerifiedGrantApproval],
    ) -> crate::GrantEvaluation<'a> {
        self.evaluate_with_approvals_checked(actions, target, facts, approvals)
            .unwrap_or(crate::GrantEvaluation::Denied)
    }

    pub fn evaluate_with_approvals_checked<'a>(
        &'a self,
        actions: &'a [&'a str],
        target: &'a arkret_wire::WireResourceSelector,
        facts: &'a crate::OperationFacts,
        approvals: &[crate::VerifiedGrantApproval],
    ) -> PersistenceResult<crate::GrantEvaluation<'a>> {
        self.evaluate_checked(
            actions,
            target,
            facts,
            approvals,
            AuthorizationLayer::Complete,
        )
    }

    /// Grant/controller-source layer only, for native admission that already
    /// executes its real asynchronous management policy/review gate. This
    /// does not claim that empty or caller-supplied policies were verified.
    /// Merge original-action refusals before selecting a managed positive set.
    pub fn evaluate_grant_sources_with_approvals_checked<'a>(
        &'a self,
        actions: &'a [&'a str],
        target: &'a arkret_wire::WireResourceSelector,
        facts: &'a crate::OperationFacts,
        approvals: &[crate::VerifiedGrantApproval],
    ) -> PersistenceResult<crate::GrantEvaluation<'a>> {
        self.evaluate_checked(
            actions,
            target,
            facts,
            approvals,
            AuthorizationLayer::GrantSources,
        )
    }

    fn evaluate_checked<'a>(
        &'a self,
        actions: &'a [&'a str],
        target: &'a arkret_wire::WireResourceSelector,
        facts: &'a crate::OperationFacts,
        approvals: &[crate::VerifiedGrantApproval],
        layer: AuthorizationLayer,
    ) -> PersistenceResult<crate::GrantEvaluation<'a>> {
        let mut results = Vec::new();
        // Preserve the SDK's applicability gate before splitting alternatives.
        // A non-applicable `.own` alternative is not a global deny when a
        // different registered action can authorize the operation.
        let applicable = actions
            .iter()
            .copied()
            .filter(|action| {
                self.agent_ceiling.is_none()
                    || !arkret_schema::capability_action(action).is_some_and(|descriptor| {
                        descriptor
                            .required_evaluator_checks
                            .contains(&"actor_eq_target_author")
                    })
                    || facts.target_owner.as_ref() == Some(&self.actor)
            })
            .collect::<Vec<_>>();
        if applicable.is_empty() && self.agent_ceiling.is_some() {
            return Ok(crate::GrantEvaluation::Denied);
        }
        // All matching refusal sets precede every positive-path decision.
        // Matching is pure; no reservation is consumed by either pass.
        let original = applicable
            .iter()
            .map(|action| self.evaluate_action_refusals(action, target, facts, approvals))
            .collect::<PersistenceResult<Vec<_>>>()?;
        if original
            .iter()
            .any(|result| matches!(result, crate::GrantEvaluation::Denied))
        {
            return Ok(crate::GrantEvaluation::Denied);
        }
        if original
            .iter()
            .any(|result| matches!(result, crate::GrantEvaluation::Quarantined))
        {
            return Ok(crate::GrantEvaluation::Quarantined);
        }
        if original
            .iter()
            .any(|result| matches!(result, crate::GrantEvaluation::RequiresReview))
        {
            return Ok(crate::GrantEvaluation::RequiresReview);
        }
        for action in applicable {
            let (result, source_order) =
                self.evaluate_action_positive(action, target, facts, approvals, layer)?;
            if matches!(result, crate::GrantEvaluation::Denied) {
                return Ok(result);
            }
            results.push((result, source_order));
        }
        for effect in [0, 1] {
            if results.iter().any(|(result, _)| {
                matches!(
                    (effect, result),
                    (0, crate::GrantEvaluation::Quarantined)
                        | (1, crate::GrantEvaluation::RequiresReview)
                )
            }) {
                return Ok(if effect == 0 {
                    crate::GrantEvaluation::Quarantined
                } else {
                    crate::GrantEvaluation::RequiresReview
                });
            }
        }
        let mut paths: Vec<(Option<arkret_wire::GrantId>, crate::SatisfiedGrant<'a>)> = Vec::new();
        let mut named = false;
        for (result, source_order) in results {
            match result {
                crate::GrantEvaluation::Allowed(allowed) => {
                    named = true;
                    if self.agent_ceiling.is_some() && allowed.len() != source_order.len() {
                        return Err(PersistenceError::Conflict(
                            "revision_unavailable: bounded source path identity is missing".into(),
                        ));
                    }
                    for (index, path) in allowed.into_iter().enumerate() {
                        let source = source_order.get(index).cloned().flatten();
                        if self.agent_ceiling.is_some() {
                            // Controller sources remain alternatives, even for
                            // the same Agent grant. Remove only exact duplicate
                            // source/constraint/counter/window paths.
                            if !paths.iter().any(|(existing_source, existing)| {
                                existing_source == &source
                                    && existing.grant.id == path.grant.id
                                    && existing.reservations == path.reservations
                            }) {
                                paths.push((source, path));
                            }
                            continue;
                        }
                        if let Some(existing) = paths
                            .iter_mut()
                            .find(|(_, existing)| existing.grant.id == path.grant.id)
                        {
                            if path.reservations.len() < existing.1.reservations.len() {
                                existing.1 = path;
                            }
                        } else {
                            paths.push((source, path));
                        }
                    }
                }
                crate::GrantEvaluation::Unsatisfied => named = true,
                _ => {}
            }
        }
        if self.agent_ceiling.is_some() {
            // The SDK's bounded evaluator orders original parent first.
            paths.sort_by(|(left_source, left), (right_source, right)| {
                left_source
                    .cmp(right_source)
                    .then_with(|| left.grant.id.cmp(&right.grant.id))
            });
        } else {
            // Preserve the SDK ordering: no quota first, then GrantId. The
            // number of non-empty quota directives is not a new path weight.
            paths.sort_by(|(_, left), (_, right)| {
                left.reservations
                    .is_empty()
                    .cmp(&right.reservations.is_empty())
                    .reverse()
                    .then_with(|| left.grant.id.cmp(&right.grant.id))
            });
        }
        Ok(if !paths.is_empty() {
            crate::GrantEvaluation::Allowed(paths.into_iter().map(|(_, path)| path).collect())
        } else if named {
            crate::GrantEvaluation::Unsatisfied
        } else {
            crate::GrantEvaluation::Unnamed
        })
    }

    fn evaluate_action_refusals<'a>(
        &'a self,
        action: &str,
        target: &arkret_wire::WireResourceSelector,
        facts: &crate::OperationFacts,
        approvals: &[crate::VerifiedGrantApproval],
    ) -> PersistenceResult<crate::GrantEvaluation<'a>> {
        let candidates = self.current_candidates(action, target)?;
        let operation = crate::AuthorizationOperation {
            actor: &self.actor,
            actions: &[action],
            target,
            at: self.evaluated_at,
            facts,
        };
        let Some(ceiling) = &self.agent_ceiling else {
            return Ok(crate::evaluate_grants_with_verified_approvals(
                &operation, candidates, approvals,
            ));
        };
        let controller = &ceiling.controller;
        if controller.realm_id != self.realm_id
            || controller.actor == self.actor
            || controller.agent_ceiling.is_some()
            || controller.evaluated_at != self.evaluated_at
            || !std::sync::Arc::ptr_eq(&controller.source_cut, &self.source_cut)
        {
            return Err(PersistenceError::Conflict(
                "revision_unavailable: controller and actor do not share one bound source cut"
                    .into(),
            ));
        }
        let controller_candidates = controller.current_candidates(action, target)?;
        let owner_covers = controller.root_controller()
            && (action == arkret_wire::CapabilityActionId::REALM_OWNER
                || arkret_policy::owner_may_author_action(action).unwrap_or(false));
        Ok(crate::evaluate_controller_bounded_grants(
            &operation,
            &candidates,
            &controller.actor,
            &controller_candidates,
            approvals,
            owner_covers,
        ))
    }

    fn evaluate_action_positive<'a>(
        &'a self,
        action: &str,
        target: &arkret_wire::WireResourceSelector,
        facts: &crate::OperationFacts,
        approvals: &[crate::VerifiedGrantApproval],
        layer: AuthorizationLayer,
    ) -> PersistenceResult<(
        crate::GrantEvaluation<'a>,
        Vec<Option<arkret_wire::GrantId>>,
    )> {
        let candidates = self.current_candidates(action, target)?;
        let operation = crate::AuthorizationOperation {
            actor: &self.actor,
            actions: &[action],
            target,
            at: self.evaluated_at,
            facts,
        };
        let Some(ceiling) = &self.agent_ceiling else {
            let positive = self.positive_sources(action, target, &candidates)?;
            return Ok((
                crate::evaluate_grants_with_verified_approvals(&operation, positive, approvals),
                Vec::new(),
            ));
        };
        let controller = &ceiling.controller;
        if controller.realm_id != self.realm_id
            || controller.actor == self.actor
            || controller.agent_ceiling.is_some()
            || controller.evaluated_at != self.evaluated_at
            || !std::sync::Arc::ptr_eq(&controller.source_cut, &self.source_cut)
        {
            return Err(PersistenceError::Conflict(
                "revision_unavailable: controller and actor do not share one bound source cut"
                    .into(),
            ));
        }
        let controller_candidates = controller.current_candidates(action, target)?;
        let owner_covers = controller.root_controller()
            && (action == arkret_wire::CapabilityActionId::REALM_OWNER
                || arkret_policy::owner_may_author_action(action).unwrap_or(false));
        let (Some(controller_account), Some(agent_account)) =
            (controller.actor.as_account_id(), self.actor.as_account_id())
        else {
            return Err(PersistenceError::Conflict(
                "capability_denied: controller ceiling requires complete Account actors".into(),
            ));
        };
        if layer == AuthorizationLayer::Complete {
            let managed = crate::agent_management_actions(
                &ceiling.management_policies,
                &self.realm_id,
                controller_account,
                agent_account,
                &operation,
                None,
            )?;
            if !managed.contains(&action) {
                return Ok((crate::GrantEvaluation::Unsatisfied, Vec::new()));
            }
        }
        let positive = self.positive_sources(action, target, &candidates)?;
        let controller_positive =
            controller.positive_sources(action, target, &controller_candidates)?;
        let verdict = crate::evaluate_controller_bounded_grants(
            &operation,
            &positive,
            &controller.actor,
            &controller_positive,
            approvals,
            owner_covers,
        );
        if !matches!(verdict, crate::GrantEvaluation::Allowed(_)) {
            return Ok((verdict, Vec::new()));
        }
        // Retain the SDK's real parent identity alongside each alternative.
        // These calls only derive reservation directives; none consumes quota
        // or discharges a policy. All candidate refusals were already merged.
        let mut ranked = Vec::new();
        if owner_covers
            && let crate::GrantEvaluation::Allowed(paths) =
                crate::evaluate_controller_bounded_grants(
                    &operation,
                    &positive,
                    &controller.actor,
                    &[],
                    approvals,
                    true,
                )
        {
            ranked.extend(paths.into_iter().map(|path| (None, path)));
        }
        for source in &controller_positive {
            if let crate::GrantEvaluation::Allowed(paths) =
                crate::evaluate_controller_bounded_grants(
                    &operation,
                    &positive,
                    &controller.actor,
                    &[*source],
                    approvals,
                    false,
                )
            {
                ranked.extend(
                    paths
                        .into_iter()
                        .map(|path| (Some(source.id.clone()), path)),
                );
            }
        }
        ranked.sort_by(|(left_source, left), (right_source, right)| {
            left_source
                .cmp(right_source)
                .then_with(|| left.grant.id.cmp(&right.grant.id))
        });
        let (source_order, paths) = ranked.into_iter().unzip();
        Ok((crate::GrantEvaluation::Allowed(paths), source_order))
    }

    /// The effective grant row of `grant`.
    pub fn effective(
        &self,
        grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> Option<EffectiveActorGrant> {
        self.terminal_ids.contains(&grant.id).then_some(())?;
        Some(EffectiveActorGrant {
            grant: self.source_cut.grants.get(&grant.id)?.clone(),
            revision: self.source_cut.revisions.get(&grant.id)?.clone(),
        })
    }

    /// Whether the actor holds the effective `ak.realm.owner` aggregate: it is
    /// the current root controller, or an effective grant of
    /// `ak.realm.owner` over the whole Realm allows it without owing a quota
    /// reservation (`authz/capabilities.md` §3.2).
    pub fn holds_realm_owner(&self) -> bool {
        // An Agent's root/aggregate cannot replace its concrete current ceiling.
        if self.agent_ceiling.is_some() {
            return false;
        }
        let realm = arkret_wire::WireResourceSelector::realm(self.realm_id.clone());
        self.root_controller()
            || !self
                .evaluate(
                    &[arkret_wire::CapabilityActionId::REALM_OWNER],
                    &realm,
                    &crate::OperationFacts::default(),
                )
                .unreserved()
                .is_empty()
    }
}

impl From<EffectiveActorGrant>
    for arkret_models_collaboration::governance::authorization::EffectiveCapabilityGrantView
{
    fn from(effective: EffectiveActorGrant) -> Self {
        Self {
            grant: effective.grant,
            revision: effective.revision,
        }
    }
}

#[cfg(test)]
#[path = "projection/authority_cut_tests.rs"]
mod authority_cut_tests;

/// Canonical digest of the complete effective-list rows. This binds the list
/// snapshot only; it is deliberately not a per-grant revision.
pub fn effective_capability_grant_state_digest(
    rows: &[arkret_models_collaboration::governance::authorization::EffectiveCapabilityGrantView],
) -> PersistenceResult<arkret_wire::Hash> {
    let bytes = arkret_canonical::canonical_json_bytes(rows).map_err(PersistenceError::database)?;
    arkret_wire::Hash::new(arkret_canonical::sha256_digest(&bytes))
        .map_err(PersistenceError::database)
}

#[async_trait]
pub trait CapabilityGrantCurrentStateStore: Send + Sync {
    /// Deployment-private issuer source supply from one durable current cut.
    async fn agent_session_authority(
        &self,
        _request: &crate::AgentSessionAuthorityRequest,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<crate::AgentSessionAuthorityView> {
        Err(crate::PersistenceError::Database(
            "Agent session authority source is unavailable".to_owned(),
        ))
    }

    async fn get(
        &self,
        realm_id: &arkret_wire::RealmId,
        grant_id: &arkret_wire::GrantId,
    ) -> PersistenceResult<Option<CapabilityGrantCurrentStateRecord>>;

    /// Return one statement-level snapshot of every current grant in a Realm.
    /// Effective/subject filtering belongs above this persistence boundary.
    async fn snapshot_for_realm(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentStateRecord>>;

    /// Every current grant of every Realm, ordered by Realm and grant id.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<CapabilityGrantCurrentStateRecord>>;

    /// Every `active` current grant whose subject is exactly `subject`, in
    /// any Realm. Lifecycle only: temporal windows and issuer chains are not
    /// evaluated.
    async fn active_for_subject(
        &self,
        subject: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentStateRecord>>;

    /// Read the authorization inputs of `actor` in `realm_id` from one
    /// snapshot and evaluate its effective grants at `at`.
    async fn actor_authorization(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ActorRealmAuthorization>;

    /// Fixture-only: make `controller` the Realm's current authority root
    /// controller, keeping an existing root's generation and Event ref.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    async fn seed_test_realm_root(
        &self,
        realm_id: &arkret_wire::RealmId,
        controller: &arkret_wire::ActorId,
    ) -> PersistenceResult<()>;

    /// Fixture-only: install one `active` grant issued by the Realm's current
    /// root controller under the current root, as the accepting RealmCommit
    /// would have materialized it. The Realm must already have a root.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    async fn seed_test_grant(
        &self,
        grant: &TestCapabilityGrant,
    ) -> PersistenceResult<arkret_wire::GrantId>;

    /// Fixture-only: move a seeded grant to a terminal lifecycle.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    async fn seed_test_grant_status(
        &self,
        realm_id: &arkret_wire::RealmId,
        grant_id: &arkret_wire::GrantId,
        status: CapabilityGrantCurrentStatus,
    ) -> PersistenceResult<()>;
}

/// Fixture-only description of one root-issued Capability Grant.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct TestCapabilityGrant {
    pub realm_id: arkret_wire::RealmId,
    pub subject: arkret_wire::ActorId,
    pub actions: Vec<String>,
    pub resources: Vec<arkret_wire::WireResourceSelector>,
    pub constraints:
        Vec<arkret_models_collaboration::governance::grant_constraint::GrantConstraint>,
}

#[cfg(test)]
mod capability_grant_current_state_tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
    const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

    fn subject() -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn grant(
        status: CapabilityGrantCurrentStatus,
    ) -> arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
        serde_json::from_value(serde_json::json!({
            "id": GRANT_ID,
            "schema": "ak.schema.capability.v1",
            "realm_id": REALM_ID,
            "issuer_id": subject(),
            "subject": subject(),
            "actions": ["ak.message.create"],
            "resources": [{"kind":"realm", "realm_id":REALM_ID}],
            "issuer_authority_refs": [{
                "kind":"grant",
                "grant_id":"ak:grant:AU1_A5a8MMz_OdxEleQlWPFn-ljdJteaJv3ZZ9APkcrZ"
            }],
            // Reducer-derived: a re-grant under one root controller grant.
            "authority_depth": 2,
            "authority_root_ref": {
                "kind":"realm_root",
                "realm_id":REALM_ID,
                "authority_event_ref":arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x55; 32],
                ),
                "authority_generation":"0"
            },
            "issued_at": "2026-09-21T00:00:00.000Z",
            "status": status.as_str()
        }))
        .unwrap()
    }

    fn record_with(
        status: CapabilityGrantCurrentStatus,
        value: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> PersistenceResult<CapabilityGrantCurrentStateRecord> {
        CapabilityGrantCurrentStateRecord::try_new(
            REALM_ID.parse().unwrap(),
            GRANT_ID.parse().unwrap(),
            status,
            value,
            arkret_wire::CurrentRevision {
                commit_id: COMMIT_ID.parse().unwrap(),
                stream_position: 41,
            },
            arkret_wire::CommittedEventRef {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x44; 32],
                ),
                commit_id: COMMIT_ID.parse().unwrap(),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: REALM_ID.parse().unwrap(),
                },
                stream_position: 41,
            },
        )
    }

    fn complete_record(status: CapabilityGrantCurrentStatus) -> CapabilityGrantCurrentStateRecord {
        record_with(status, grant(status)).unwrap()
    }

    #[test]
    fn value_and_exact_commit_revision_remain_one_record() {
        let record = complete_record(CapabilityGrantCurrentStatus::Active);
        assert_eq!(record.value.id.as_str(), GRANT_ID);
        assert_eq!(record.revision.commit_id.as_str(), COMMIT_ID);
        assert_eq!(record.revision.stream_position, 41);
    }

    #[test]
    fn lifecycle_mismatch_fails_closed() {
        assert!(matches!(
            record_with(
                CapabilityGrantCurrentStatus::Active,
                grant(CapabilityGrantCurrentStatus::Revoked),
            ),
            Err(PersistenceError::Database(_))
        ));
    }

    #[test]
    fn effective_row_digest_binds_the_listed_rows() {
        let active = complete_record(CapabilityGrantCurrentStatus::Active);
        let rows = vec![
            arkret_models_collaboration::governance::authorization::EffectiveCapabilityGrantView::from(
                EffectiveActorGrant {
                    grant: active.value.clone(),
                    revision: active.revision.clone(),
                },
            ),
        ];
        assert_eq!(rows[0].grant.id, active.grant_id);
        assert_eq!(rows[0].revision, active.revision);
        assert_ne!(
            effective_capability_grant_state_digest(&rows).unwrap(),
            effective_capability_grant_state_digest(&[]).unwrap()
        );
    }

    fn realm() -> arkret_wire::RealmId {
        REALM_ID.parse().unwrap()
    }

    fn authorization(
        mut grants: Vec<arkret_models_collaboration::governance::grant_constraint::CapabilityGrant>,
    ) -> ActorRealmAuthorization {
        // These constraint tests exercise directly accepted root grants. The
        // record-decoding tests above separately retain the delegated shape.
        for grant in &mut grants {
            grant.authority_depth = 1;
            let arkret_models_collaboration::governance::grant_constraint::AuthorityRootRef::RealmRoot {
                realm_id,authority_event_ref,authority_generation,
            }=&grant.authority_root_ref else { unreachable!() };
            grant.issuer_authority_refs=vec![arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::RealmRoot {
                realm_id:realm_id.clone(),authority_event_ref:authority_event_ref.clone(),authority_generation:*authority_generation,
            }];
        }
        let actor=grants.first().and_then(|grant| match &grant.subject {
            arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(actor)=>Some(actor.clone()),_=>None,
        }).unwrap_or_else(subject);
        let ids = grants
            .iter()
            .map(|grant| grant.id.clone())
            .collect::<Vec<_>>();
        let revisions = grants
            .iter()
            .map(|grant| {
                (
                    grant.id.clone(),
                    arkret_wire::CurrentRevision {
                        commit_id: COMMIT_ID.parse().unwrap(),
                        stream_position: 41,
                    },
                )
            })
            .collect();
        let cut = GrantAuthorityCut::new(
            realm(),
            arkret_wire::RealmAuthorityRootValue {
                controller_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    "ak:did_core:web:current-owner.example".parse().unwrap(),
                    "ak:did_core:web:station.example".parse().unwrap(),
                )),
                controller_epoch: 1,
                authority_generation: 0,
                authority_event_ref: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x55; 32],
                ),
            },
            grants
                .into_iter()
                .map(|grant| (grant.id.clone(), grant))
                .collect(),
            revisions,
        )
        .unwrap();
        ActorRealmAuthorization::from_source_cut(
            actor,
            chrono::Utc::now(),
            std::sync::Arc::new(cut),
            ids,
            None,
        )
        .unwrap()
    }

    fn attach_controller(
        agent: &mut ActorRealmAuthorization,
        controller: ActorRealmAuthorization,
        policies: Vec<arkret_models_collaboration::governance::operation_wire::Policy>,
    ) {
        let mut cut = (*agent.source_cut).clone();
        cut.root = controller.source_cut.root.clone();
        cut.grants.extend(controller.source_cut.grants.clone());
        cut.revisions
            .extend(controller.source_cut.revisions.clone());
        let cut = std::sync::Arc::new(cut);
        let controller = ActorRealmAuthorization::from_source_cut(
            controller.actor,
            agent.evaluated_at,
            std::sync::Arc::clone(&cut),
            controller
                .grants
                .iter()
                .map(|row| row.grant.id.clone())
                .collect(),
            controller.owned_source,
        )
        .unwrap();
        agent.source_cut = cut;
        agent.agent_ceiling = Some(AgentControllerCeiling {
            controller: Box::new(controller),
            management_policies: policies,
        });
    }

    fn set_root_controller(
        authorization: &mut ActorRealmAuthorization,
        actor: arkret_wire::ActorId,
    ) {
        let mut cut = (*authorization.source_cut).clone();
        cut.root.controller_actor_id = actor;
        cut.root.controller_epoch = cut.root.controller_epoch.checked_add(1).unwrap();
        let cut = std::sync::Arc::new(cut);
        authorization.source_cut = std::sync::Arc::clone(&cut);
        if let Some(ceiling) = authorization.agent_ceiling.as_mut() {
            ceiling.controller.source_cut = cut;
        }
    }

    fn change_source(
        authorization: &mut ActorRealmAuthorization,
        id: &arkret_wire::GrantId,
        change: impl FnOnce(
            &mut arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
        ),
    ) {
        let mut cut = (*authorization.source_cut).clone();
        change(cut.grants.get_mut(id).unwrap());
        let cut = std::sync::Arc::new(cut);
        authorization.source_cut = std::sync::Arc::clone(&cut);
        if let Some(ceiling) = authorization.agent_ceiling.as_mut() {
            ceiling.controller.source_cut = cut;
        }
    }

    fn allows(
        authorization: &ActorRealmAuthorization,
        action: &str,
        target: &arkret_wire::WireResourceSelector,
    ) -> bool {
        !authorization
            .evaluate(&[action], target, &crate::OperationFacts::default())
            .unreserved()
            .is_empty()
    }

    #[test]
    fn realm_grant_covers_contained_resources_and_only_its_actions() {
        let authorization = authorization(vec![grant(CapabilityGrantCurrentStatus::Active)]);
        let strand = arkret_wire::WireResourceSelector::strand(
            realm(),
            arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x51; 32],
            )),
        );
        assert!(allows(&authorization, "ak.message.create", &strand));
        assert!(!allows(&authorization, "ak.realm.admin", &strand));
        let other = arkret_wire::WireResourceSelector::realm(
            "ak:realm:ASm71QhtF54BxHBvRFcIhmLfPFYTrXhTcLnVAEMmqZ5t"
                .parse()
                .unwrap(),
        );
        assert!(!allows(&authorization, "ak.message.create", &other));
        assert!(!authorization.holds_realm_owner());
    }

    #[test]
    fn an_undecidable_constraint_names_the_target_but_never_allows_it() {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraint, GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind,
        };
        let mut constrained = grant(CapabilityGrantCurrentStatus::Active);
        let mut claim = GrantConstraint::new(
            GrantConstraintKind::ClaimBased,
            GrantConstraintEffect::Allow,
        );
        claim.constraint_subkind = Some(GrantConstraintSubkind::Claim);
        constrained.constraints = vec![claim];
        let authorization = authorization(vec![constrained]);
        let target = arkret_wire::WireResourceSelector::realm(realm());
        assert!(matches!(
            authorization.evaluate(
                &["ak.message.create"],
                &target,
                &crate::OperationFacts::default()
            ),
            crate::GrantEvaluation::Unsatisfied
        ));
    }

    #[test]
    fn owner_aggregate_is_the_root_controller_or_a_realm_owner_grant() {
        let mut owner = grant(CapabilityGrantCurrentStatus::Active);
        owner.actions = vec![arkret_wire::CapabilityActionId::REALM_OWNER.to_owned()];
        assert!(authorization(vec![owner]).holds_realm_owner());
        let mut root = authorization(Vec::new());
        assert!(!root.holds_realm_owner());
        let actor = root.actor.clone();
        set_root_controller(&mut root, actor);
        assert!(root.holds_realm_owner());
    }

    fn controller_authorization() -> ActorRealmAuthorization {
        let controller = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        let mut parent_grant = grant(CapabilityGrantCurrentStatus::Active);
        parent_grant.id = arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x67; 32],
        ));
        parent_grant.subject =
            arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
                controller.clone(),
            );
        authorization(vec![parent_grant])
    }

    #[test]
    fn independent_agent_grant_query_intersects_controller_rights_and_global_denies() {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
        };
        let mut agent = authorization(vec![grant(CapabilityGrantCurrentStatus::Active)]);
        let target = arkret_wire::WireResourceSelector::realm(realm());
        attach_controller(&mut agent, controller_authorization(), Vec::new());
        assert!(allows(&agent, "ak.message.create", &target));
        let mut deny =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Deny);
        deny.not_before = Some(chrono::Utc::now() - chrono::TimeDelta::minutes(1));
        deny.expires_at = Some(chrono::Utc::now() + chrono::TimeDelta::minutes(1));
        let parent_id = agent.agent_ceiling.as_ref().unwrap().controller.grants[0]
            .grant
            .id
            .clone();
        change_source(&mut agent, &parent_id, |grant| grant.constraints.push(deny));
        assert!(matches!(
            agent.evaluate(
                &["ak.message.create"],
                &target,
                &crate::OperationFacts::default()
            ),
            crate::GrantEvaluation::Denied
        ));
        change_source(&mut agent, &parent_id, |grant| {
            grant.status=arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Revoked
        });
        assert!(!allows(&agent, "ak.message.create", &target));
        let actor = agent.actor.clone();
        set_root_controller(&mut agent, actor);
        assert!(!agent.holds_realm_owner());
        assert!(!allows(&agent, "ak.message.create", &target));
    }

    #[test]
    fn agent_query_preserves_original_controller_quota_counter_and_rejects_nested_ceiling() {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraint, GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind,
        };
        let mut controller = controller_authorization();
        let parent_id = controller.grants[0].grant.id.clone();
        let mut quota =
            GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
        quota.constraint_subkind = Some(GrantConstraintSubkind::Rate);
        quota.max_operation_count = Some(1);
        quota.period = Some("PT1M".into());
        quota.constraint_scope = Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintScope::PerActor);
        change_source(&mut controller, &parent_id, |grant| {
            grant.constraints.push(quota)
        });
        let controller_actor = controller.actor.to_string();
        let mut agent = authorization(vec![grant(CapabilityGrantCurrentStatus::Active)]);
        attach_controller(&mut agent, controller, Vec::new());
        let target = arkret_wire::WireResourceSelector::realm(realm());
        let facts = crate::OperationFacts::default();
        let evaluation = agent.evaluate(&["ak.message.create"], &target, &facts);
        assert!(evaluation.unreserved().is_empty());
        let crate::GrantEvaluation::Allowed(paths) = evaluation else {
            panic!("a shared quota requires reservation, never read-only allow");
        };
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].reservations.len(), 1);
        assert_eq!(paths[0].reservations[0].grant_id, parent_id);
        let counter: Vec<String> =
            serde_json::from_str(&paths[0].reservations[0].counter_key).unwrap();
        assert!(counter.contains(&controller_actor));
        agent
            .agent_ceiling
            .as_mut()
            .unwrap()
            .controller
            .agent_ceiling = Some(AgentControllerCeiling {
            controller: Box::new(controller_authorization()),
            management_policies: Vec::new(),
        });
        assert!(!allows(&agent, "ak.message.create", &target));
    }

    #[test]
    fn filtered_write_cannot_lend_controller_owner_authority_to_a_read() {
        let mut child = grant(CapabilityGrantCurrentStatus::Active);
        child.actions.push("ak.object.read".parse().unwrap());
        let mut agent = authorization(vec![child]);
        let mut controller = controller_authorization();
        let actor = controller.actor.clone();
        set_root_controller(&mut controller, actor);
        controller.source_cut = std::sync::Arc::new(
            GrantAuthorityCut::new(
                realm(),
                controller.source_cut.root.clone(),
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .unwrap(),
        );
        controller.grants.clear();
        controller.terminal_ids.clear();
        let policy = serde_json::from_value(serde_json::json!({
            "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "schema":"ak.schema.policy.v1", "realm_id":realm(), "policy_kind":"agent",
            "rules":[{"rule_id":"no_execute", "kind":"agent", "effect":"deny",
                "priority":1, "agent_target":{"kind":"all"}, "agent_operations":["execute"]}],
            "default_effect":"allow", "created_by":controller.actor,
            "created_at":"2026-10-01T00:00:00.000Z"
        }))
        .unwrap();
        attach_controller(&mut agent, controller, vec![policy]);
        assert!(!matches!(
            agent.evaluate(
                &["ak.message.create", "ak.object.read"],
                &arkret_wire::WireResourceSelector::realm(realm()),
                &crate::OperationFacts::default()
            ),
            crate::GrantEvaluation::Allowed(_)
        ));
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorphProjectionRecord {
    pub morph_id: String,
    pub realm_id: String,
    pub scope_circle_id: Option<String>,
    pub morph_kind: String,
    pub title: Option<String>,
    pub fields: serde_json::Value,
    pub schema_refs: serde_json::Value,
    pub facets: serde_json::Value,
    pub versions: serde_json::Value,
    /// Canonical content slot; exactly one of the two is present on an active
    /// object and both are absent once `state=redacted` (common-fields.md 5.2).
    pub content: Option<serde_json::Value>,
    pub encrypted_content: Option<serde_json::Value>,
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Wire spelling of the business-progression stage, absent when the object
    /// carries no stage (`common-fields.md` §5.3).
    pub stage: Option<String>,
    /// Reducer-derived timestamp of the last real stage transition; never
    /// present without `stage`.
    pub stage_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleProjectionRecord {
    pub circle_id: String,
    pub realm_id: String,
    pub profile_ref: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub display: Value,
    pub directory_visibility: String,
    pub join_rule: String,
    pub history_access: String,
    pub encryption_profile: String,
    pub mls_group_ref: Option<String>,
    /// One of `active` / `archived` / `tombstoned` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub updated_by: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleMemberProjectionRecord {
    pub circle_id: String,
    pub actor_id: String,
    /// One of `invited` / `active` / `removed` / `banned` / `left`.
    pub state: String,
    pub invited_at: Option<chrono::DateTime<chrono::Utc>>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
/// Projection-side event log (append-only, index/debug surfaces).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionEventAppendOutcome {
    Inserted,
    AlreadyExists,
}
#[async_trait]
pub trait ProjectionEventStore: Send + Sync {
    /// Append a complete derived unit atomically. A conflict on any member
    /// rolls back every insertion; exact retries preserve the original rows.
    async fn append_batch(
        &self,
        records: Vec<ProjectionEventRecord>,
    ) -> PersistenceResult<Vec<ProjectionEventAppendOutcome>>;

    async fn append(
        &self,
        record: ProjectionEventRecord,
    ) -> PersistenceResult<ProjectionEventAppendOutcome>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>>;
    /// Return one event kind in durable acceptance order. Security-critical
    /// reducers use this during startup so hydration does not need to load the
    /// unrelated global projection log.
    async fn snapshot_kind(
        &self,
        event_kind: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>>;
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<ProjectionEventRecord>>;
    async fn get_by_operation_id(
        &self,
        operation_id: &str,
    ) -> PersistenceResult<Option<ProjectionEventRecord>>;
    async fn snapshot_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<ProjectionEventRecord>>;
    async fn snapshot_actor(&self, actor_id: &str)
    -> PersistenceResult<Vec<ProjectionEventRecord>>;
}
#[doc(hidden)]
pub fn first_string_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}
#[doc(hidden)]
pub fn object_string_field<'a>(
    operation: &'a ProjectedEventOperation,
    keys: &[&str],
) -> Option<&'a str> {
    operation
        .payload
        .get("object")
        .and_then(|object| first_string_field(object, keys))
}
#[doc(hidden)]
pub fn patch_string_field<'a>(
    operation: &'a ProjectedEventOperation,
    field: &str,
) -> Option<&'a str> {
    let patch_value = operation
        .payload
        .get("patch")
        .and_then(|patch| patch.get(field))?;
    match patch_value {
        Value::String(value) => Some(value.as_str()),
        Value::Object(op) if op.get("$op").and_then(Value::as_str) == Some("set") => {
            op.get("value").and_then(Value::as_str)
        }
        _ => None,
    }
}
