// Durable adapters replay accepted originals through these shared contracts.
pub use coland_domain::reducer::{
    CommitStreamProjection, MorphProjection, ObjectLifecycleState, ProjectionEffect,
    ProjectionState, ServerHlc, morph_document_body,
};

use super::{
    BTreeMap, PersistenceError, PersistenceResult, ProjectedEventOperation, ProjectionEventRecord,
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
// ── Projection persistence traits ─────────────────────────────────────────
// The Space/Strand mirror stores below remain available for legacy data and
// storage compatibility. Their rows are not a source for registered canonical
// reads, admission, or restart hydration; ObjectCurrentSnapshotStore owns the
// latter. Other reducer mirrors retain their existing callers.

/// Durable Space-container projection store (mirror of
/// `projection_space_containers` table).
#[async_trait]
pub trait SpaceContainerProjectionStore: Send + Sync {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>>;
    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>>;
    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()>;
}
/// Durable Strand projection store (mirror of `projection_strands` table).
#[async_trait]
pub trait StrandProjectionStore: Send + Sync {
    async fn get(&self, strand_id: &str) -> PersistenceResult<Option<StrandProjectionRecord>>;
    async fn put(&self, record: &StrandProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<StrandProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandProjectionRecord>>;
    async fn delete(&self, strand_id: &str) -> PersistenceResult<()>;
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
pub struct RelationCurrentResultRecord {
    pub realm_id: arkret_wire::RealmId,
    pub domain_key: String,
    pub primary_conflict_domain:
        arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomain,
    pub relation: arkret_models_collaboration::objects::relation::Relation,
    pub revision: arkret_wire::CurrentRevision,
}

#[async_trait]
pub trait RelationCurrentResultStore: Send + Sync {
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RelationCurrentResultRecord>>;
}

/// Authoritative current Capability Grant value accepted by the governing
/// Station.
///
/// `value` and `revision` are one durable row and therefore one read
/// snapshot.  Consumers must never replace this revision with the in-memory
/// facet counter, the effective-list digest, or an Event id.
#[derive(Clone, Debug)]
pub struct CapabilityGrantCurrentResultRecord {
    pub realm_id: arkret_wire::RealmId,
    pub grant_id: arkret_wire::GrantId,
    pub status: CapabilityGrantCurrentStatus,
    pub value: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    pub revision: arkret_wire::CurrentRevision,
    pub source: arkret_wire::CommittedEventRef,
}

impl CapabilityGrantCurrentResultRecord {
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

/// Closed lifecycle of the `capability_grant` typed current result.
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
/// revision of the same `capability_grant` current-result row.
#[derive(Clone, Debug)]
pub struct EffectiveActorGrant {
    pub grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    pub revision: arkret_wire::CurrentRevision,
}

/// The Realm authorization inputs of one exact actor, derived from one storage
/// cut of the Realm-stream typed current results (`realm_authority_root` and
/// every `capability_grant` of the Realm).
///
/// `grants` holds every active grant whose subject is exactly `actor`, whose
/// temporal window contains `evaluated_at`, and whose issuer chain descends
/// intact from the current authority root. Ordinary membership does not grant
/// actions. An Agent additionally carries verified controller/member/current
/// backing that bounds every operation of its independent grant paths.
#[derive(Clone, Debug)]
pub struct ActorRealmAuthorization {
    pub realm_id: arkret_wire::RealmId,
    pub actor: arkret_wire::ActorId,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub root_controller: bool,
    pub grants: Vec<EffectiveActorGrant>,
    /// Verifier-private same-cut backing, never an authority or wire carrier.
    pub agent_ceiling: Option<AgentControllerCeiling>,
}

#[derive(Clone, Debug)]
pub struct AgentControllerCeiling {
    pub controller: Box<ActorRealmAuthorization>,
    pub management_policies: Vec<arkret_models_collaboration::governance::operation_wire::Policy>,
}

impl ActorRealmAuthorization {
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
        let operation = crate::AuthorizationOperation {
            actor: &self.actor,
            actions,
            target,
            at: self.evaluated_at,
            facts,
        };
        let Some(ceiling) = &self.agent_ceiling else {
            return crate::evaluate_grants_with_verified_approvals(
                &operation,
                self.grants.iter().map(|effective| &effective.grant),
                approvals,
            );
        };
        let controller = &ceiling.controller;
        if controller.realm_id != self.realm_id
            || controller.actor == self.actor
            || controller.agent_ceiling.is_some()
        {
            return crate::GrantEvaluation::Unsatisfied;
        }
        let agent_grants = self.grants.iter().map(|row| &row.grant).collect::<Vec<_>>();
        let controller_grants = controller
            .grants
            .iter()
            .map(|row| &row.grant)
            .collect::<Vec<_>>();
        let owner_covers = controller.root_controller
            && actions.iter().any(|action| {
                *action == arkret_wire::CapabilityActionId::REALM_OWNER
                    || arkret_policy::owner_may_author_action(action).unwrap_or(false)
            });
        let original = crate::evaluate_controller_bounded_grants(
            &operation,
            &agent_grants,
            &controller.actor,
            &controller_grants,
            approvals,
            owner_covers,
        );
        if matches!(
            original,
            crate::GrantEvaluation::Denied
                | crate::GrantEvaluation::Quarantined
                | crate::GrantEvaluation::RequiresReview
        ) {
            return original;
        }
        let (Some(controller_account), Some(agent_account)) =
            (controller.actor.as_account_id(), self.actor.as_account_id())
        else {
            return crate::GrantEvaluation::Unsatisfied;
        };
        let Ok(managed_actions) = crate::agent_management_actions(
            &ceiling.management_policies,
            &self.realm_id,
            controller_account,
            agent_account,
            &operation,
            None,
        ) else {
            return crate::GrantEvaluation::Unsatisfied;
        };
        let managed_owner_covers = controller.root_controller
            && managed_actions.iter().any(|action| {
                *action == arkret_wire::CapabilityActionId::REALM_OWNER
                    || arkret_policy::owner_may_author_action(action).unwrap_or(false)
            });
        crate::evaluate_controller_bounded_grants(
            &crate::AuthorizationOperation {
                actions: &managed_actions,
                ..operation
            },
            &agent_grants,
            &controller.actor,
            &controller_grants,
            approvals,
            managed_owner_covers,
        )
    }

    /// The effective grant row of `grant`.
    pub fn effective(
        &self,
        grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> Option<&EffectiveActorGrant> {
        self.grants
            .iter()
            .find(|effective| effective.grant.id == grant.id)
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
        self.root_controller
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
    for arkret_models_collaboration::governance::authorization::EffectiveCapabilityGrantRow
{
    fn from(effective: EffectiveActorGrant) -> Self {
        Self {
            grant: effective.grant,
            revision: effective.revision,
        }
    }
}

/// Canonical digest of the complete effective-list rows. This binds the list
/// snapshot only; it is deliberately not a per-grant revision.
pub fn effective_capability_grant_state_digest(
    rows: &[arkret_models_collaboration::governance::authorization::EffectiveCapabilityGrantRow],
) -> PersistenceResult<arkret_wire::Hash> {
    let bytes = arkret_canonical::canonical_json_bytes(rows).map_err(PersistenceError::database)?;
    arkret_wire::Hash::new(arkret_canonical::sha256_digest(&bytes))
        .map_err(PersistenceError::database)
}

#[async_trait]
pub trait CapabilityGrantCurrentResultStore: Send + Sync {
    async fn get(
        &self,
        realm_id: &arkret_wire::RealmId,
        grant_id: &arkret_wire::GrantId,
    ) -> PersistenceResult<Option<CapabilityGrantCurrentResultRecord>>;

    /// Return one statement-level snapshot of every current grant in a Realm.
    /// Effective/subject filtering belongs above this persistence boundary.
    async fn snapshot_for_realm(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>>;

    /// Every current grant of every Realm, ordered by Realm and grant id.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>>;

    /// Every `active` current grant whose subject is exactly `subject`, in
    /// any Realm. Lifecycle only: temporal windows and issuer chains are not
    /// evaluated.
    async fn active_for_subject(
        &self,
        subject: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>>;

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
mod capability_grant_current_result_tests {
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
            "authority_root_refs": [{
                "kind":"realm_root",
                "realm_id":REALM_ID,
                "authority_event_ref":arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x55; 32],
                ),
                "authority_generation":0
            }],
            "issued_at": "2026-09-21T00:00:00.000Z",
            "status": status.as_str()
        }))
        .unwrap()
    }

    fn record_with(
        status: CapabilityGrantCurrentStatus,
        value: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    ) -> PersistenceResult<CapabilityGrantCurrentResultRecord> {
        CapabilityGrantCurrentResultRecord::try_new(
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

    fn complete_record(status: CapabilityGrantCurrentStatus) -> CapabilityGrantCurrentResultRecord {
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
            arkret_models_collaboration::governance::authorization::EffectiveCapabilityGrantRow::from(
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
        grants: Vec<arkret_models_collaboration::governance::grant_constraint::CapabilityGrant>,
    ) -> ActorRealmAuthorization {
        ActorRealmAuthorization {
            realm_id: realm(),
            actor: subject(),
            evaluated_at: chrono::Utc::now(),
            root_controller: false,
            agent_ceiling: None,
            grants: grants
                .into_iter()
                .map(|grant| EffectiveActorGrant {
                    grant,
                    revision: arkret_wire::CurrentRevision {
                        commit_id: COMMIT_ID.parse().unwrap(),
                        stream_position: 41,
                    },
                })
                .collect(),
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
        root.root_controller = true;
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
        let mut result = authorization(vec![parent_grant]);
        result.actor = controller;
        result
    }

    #[test]
    fn independent_agent_grant_query_intersects_controller_rights_and_global_denies() {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
        };
        let mut agent = authorization(vec![grant(CapabilityGrantCurrentStatus::Active)]);
        let target = arkret_wire::WireResourceSelector::realm(realm());
        agent.agent_ceiling = Some(AgentControllerCeiling {
            controller: Box::new(controller_authorization()),
            management_policies: Vec::new(),
        });
        assert!(allows(&agent, "ak.message.create", &target));
        let mut deny =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Deny);
        deny.not_before = Some(chrono::Utc::now() - chrono::TimeDelta::minutes(1));
        deny.expires_at = Some(chrono::Utc::now() + chrono::TimeDelta::minutes(1));
        agent.agent_ceiling.as_mut().unwrap().controller.grants[0]
            .grant
            .constraints
            .push(deny);
        assert!(matches!(
            agent.evaluate(
                &["ak.message.create"],
                &target,
                &crate::OperationFacts::default()
            ),
            crate::GrantEvaluation::Denied
        ));
        agent
            .agent_ceiling
            .as_mut()
            .unwrap()
            .controller
            .grants
            .clear();
        assert!(!allows(&agent, "ak.message.create", &target));
        agent.root_controller = true;
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
        quota.max_operations = Some(1);
        quota.period = Some("PT1M".into());
        quota.constraint_scope = Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintScope::PerActor);
        controller.grants[0].grant.constraints.push(quota);
        let controller_actor = controller.actor.to_string();
        let mut agent = authorization(vec![grant(CapabilityGrantCurrentStatus::Active)]);
        agent.agent_ceiling = Some(AgentControllerCeiling {
            controller: Box::new(controller),
            management_policies: Vec::new(),
        });
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
        controller.root_controller = true;
        controller.grants.clear();
        let policy = serde_json::from_value(serde_json::json!({
            "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "schema":"ak.schema.policy.v1", "realm_id":realm(), "policy_kind":"agent",
            "rules":[{"rule_id":"no_execute", "kind":"agent", "effect":"deny",
                "priority":1, "agent_target":{"kind":"all"}, "agent_operations":["execute"]}],
            "default_effect":"allow", "created_by":controller.actor,
            "created_at":"2026-10-01T00:00:00.000Z"
        }))
        .unwrap();
        agent.agent_ceiling = Some(AgentControllerCeiling {
            controller: Box::new(controller),
            management_policies: vec![policy],
        });
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
/// Wire / persistence record for a Space-container projection. Mirrors fields on
/// `reducer::SpaceContainerProjection` (state stored as the canonical `&str` form
/// of `SpaceContainerLifecycleState`) so callers can convert without pulling the
/// reducer enum into the persistence layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceContainerProjectionRecord {
    pub container_space_id: String,
    pub realm_id: String,
    pub kind: String,
    pub title: String,
    pub fields: BTreeMap<String, Value>,
    pub scope_circle_id: Option<String>,
    pub child_scope_policy: Option<String>,
    pub child_scope_policy_scope_circle_id: Option<String>,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    /// One of `active` / `archived` / `tombstoned` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct StrandProjectionRecord {
    pub strand_id: String,
    pub realm_id: String,
    pub tracks: BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    pub title: String,
    pub summary: Option<String>,
    /// Canonical content slot; exactly one of the two is present on an active
    /// object and both are absent once `state=redacted` (common-fields.md 5.2).
    pub content: Option<serde_json::Value>,
    pub encrypted_content: Option<serde_json::Value>,
    pub fields: BTreeMap<String, serde_json::Value>,
    pub schema_refs: Vec<String>,
    /// One of `active` / `archived` / `deleted` / `redacted` per spec.
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
    /// AKP-0007 — the Circle (`ak:circle:…`) this Strand is scoped to, if any.
    /// Durable so circle-scoped message visibility survives restart.
    pub scope_circle_id: Option<String>,
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
