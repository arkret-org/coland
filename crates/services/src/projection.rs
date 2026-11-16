use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::RealmId;
use chrono::{DateTime, Utc};
use coland_domain::hlc::ServerHlc;
use coland_domain::reducer::{
    ColandMembershipState, ColandRealmState, ProjectionEffect, ProjectionState,
};
use coland_storage::{PersistenceResult, PersistenceStore};
use parking_lot::{Mutex, MutexGuard};
use serde_json::Value;

use crate::hydration::{HydrationProjectionAdapter, hydrate_projections_from_persistence};

pub mod tombstone;

/// A confirmed metadata mutation is awaiting reconstruction at its exact head.
fn projection_event_ref(operation: &Operation) -> String {
    operation.context.event_id.to_string()
}

pub fn morph_document_body(fields: &BTreeMap<String, Value>) -> Option<Value> {
    coland_domain::reducer::morph_document_body(fields)
}

pub fn check_realm_link_admissible(
    projection: &ProjectionState,
    realm_id: &str,
    target_realm_id: &str,
    link_kind: &str,
    status: &str,
) -> Result<(), &'static str> {
    coland_domain::reducer::realm_links::check_realm_link_admissible(
        projection,
        realm_id,
        target_realm_id,
        link_kind,
        status,
    )
}

/// Process-local hybrid logical clock owned by the application layer.
pub struct ServiceClock {
    inner: ServerHlc,
}

impl ServiceClock {
    #[must_use]
    pub fn new(node: &str) -> Self {
        Self {
            inner: ServerHlc::new(node),
        }
    }

    #[must_use]
    pub fn now(&self) -> String {
        self.inner.now()
    }
}

impl std::ops::Deref for ServiceClock {
    type Target = ServerHlc;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Owns the process-local, fully rebuildable reducer projection.
///
/// Callers receive immutable snapshots for query use cases. Mutations remain
/// explicit application operations so HTTP code cannot lock and edit the
/// shared projection maps directly.
#[derive(Clone)]
pub struct ProjectionService {
    state: Arc<Mutex<ProjectionState>>,
    generation: Arc<AtomicU64>,
    clock: Arc<ServiceClock>,
}

#[derive(Clone, Debug)]
pub enum MlsProjectionEffect {
    KeyPackagePublished {
        keypackage_id: String,
    },
    KeyPackageClaimed {
        keypackage_id: String,
        group_id: String,
        intended_realm_id: Option<String>,
        claimed_at: i64,
    },
}

#[derive(Clone, Debug)]
pub enum ProjectionEffectView {
    Rejected {
        reason: String,
    },
    PendingReplayQueued {
        target_ref: String,
        reason: String,
    },
    Ignored,
    Mls(MlsProjectionEffect),
    RealmOrganizationProjected {
        realm_id: String,
        organization_id: arkret_wire::DidCoreId,
        relationship: String,
    },
    CallStateProjected,
    Other,
}

pub struct StagedRealmBootstrap {
    operations: Vec<Operation>,
    direct_conversation_founding: bool,
}

#[derive(Clone, Debug)]
pub struct RealmBootstrapProjectionError {
    pub operation_index: usize,
    pub reason: String,
    pub ignored: bool,
}

impl From<ProjectionEffect> for ProjectionEffectView {
    fn from(effect: ProjectionEffect) -> Self {
        match effect {
            ProjectionEffect::Rejected { reason } => Self::Rejected { reason },
            ProjectionEffect::PendingReplayQueued {
                target_ref, reason, ..
            } => Self::PendingReplayQueued { target_ref, reason },
            ProjectionEffect::Ignored => Self::Ignored,
            ProjectionEffect::Mls(effect) => Self::Mls(match effect {
                coland_domain::reducer::MlsEffect::KeyPackagePublished {
                    keypackage_id, ..
                } => MlsProjectionEffect::KeyPackagePublished { keypackage_id },
                coland_domain::reducer::MlsEffect::KeyPackageClaimed {
                    keypackage_id,
                    group_id,
                    intended_realm_id,
                    claimed_at,
                    ..
                } => MlsProjectionEffect::KeyPackageClaimed {
                    keypackage_id,
                    group_id,
                    intended_realm_id,
                    claimed_at,
                },
            }),
            ProjectionEffect::RealmOrganizationProjected {
                realm_id,
                organization_id,
                relationship,
                ..
            } => Self::RealmOrganizationProjected {
                realm_id,
                organization_id,
                relationship,
            },
            ProjectionEffect::CallStateProjected { .. } => Self::CallStateProjected,
            _ => Self::Other,
        }
    }
}

impl ProjectionService {
    /// Every live mutation invalidates an outstanding persistence rebuild.
    /// The counter and publication are observed under the same state lock;
    /// no lock is held while the rebuild awaits persistence I/O.
    fn write_state(&self) -> MutexGuard<'_, ProjectionState> {
        let state = self.state.lock();
        self.generation.fetch_add(1, Ordering::Relaxed);
        state
    }

    fn rebuild_generation(&self) -> u64 {
        let _state = self.state.lock();
        self.generation.load(Ordering::Relaxed)
    }

    fn install_rebuild(&self, generation: u64, rebuilt: ProjectionState) -> bool {
        let mut live = self.state.lock();
        if self.generation.load(Ordering::Relaxed) != generation {
            return false;
        }
        *live = rebuilt;
        self.generation.fetch_add(1, Ordering::Relaxed);
        true
    }

    #[must_use]
    pub fn new(clock_node: &str) -> Self {
        Self {
            state: Arc::new(Mutex::new(ProjectionState::new())),
            generation: Arc::new(AtomicU64::new(0)),
            clock: Arc::new(ServiceClock::new(clock_node)),
        }
    }

    pub async fn hydrate_from_persistence(
        &self,
        persistence: &dyn PersistenceStore,
        projection_adapter: &dyn HydrationProjectionAdapter,
        _realm_ids: impl IntoIterator<Item = RealmId>,
    ) -> PersistenceResult<()> {
        // Reconstruct privately, then publish only if no live writer ran
        // since the first persistence read. A moved cut requires a fresh
        // rebuild, never overwriting a concurrent bootstrap or successor.
        loop {
            let generation = self.rebuild_generation();
            let reconstructed: PersistenceResult<ProjectionState> = async {
                let mut state = ProjectionState::new();
                hydrate_projections_from_persistence(persistence, &mut state, projection_adapter)
                    .await?;
                state.replay_resolved_pending(self.clock());
                for record in persistence
                    .realm_organization_statements()
                    .snapshot_all()
                    .await?
                {
                    let key = (
                        record.realm_id.clone(),
                        record.organization_id.clone(),
                        record.relationship.clone(),
                    );
                    state.realm_organization_statements.insert(
                        key,
                        coland_domain::reducer::RealmOrganizationStatementState {
                            realm_id: record.realm_id,
                            organization_id: record.organization_id,
                            relationship: record.relationship,
                            statement_id: record.statement_id,
                            status: record.status,
                            control_scopes: record.control_scopes,
                            issued_at: record.issued_at,
                            not_before: record.not_before,
                            expires_at: record.expires_at,
                            supersedes_statement_id: record.supersedes_statement_id,
                            revokes_statement_id: record.revokes_statement_id,
                            realm_commit_ref: record.realm_commit_ref,
                            proof_digest: record.proof_digest,
                            delegation_ref: record.delegation_ref,
                            issuer_role: record.issuer_role,
                            updated_at: record.updated_at,
                        },
                    );
                }
                Ok(state)
            }
            .await;
            let state = match reconstructed {
                Ok(state) => state,
                Err(error) => {
                    // A live mutation can move the cut between durable reads
                    // before the candidate reaches its publication CAS. Its
                    // incomplete reconstruction is stale, just like a stale
                    // successful candidate; stable-cut failures remain errors.
                    if self.rebuild_generation() == generation {
                        return Err(error);
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
            };
            if self.install_rebuild(generation, state) {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    }

    /// The Realm's effective digest suite
    /// (`ak.component.realm.digest_suite.v1`). The registry projection derives
    /// `digest_of` members with it, so a Realm that transitioned to blake3 must
    /// project under blake3. Absent cell means the Realm never transitioned and
    /// still runs the protocol baseline.
    #[must_use]
    pub fn realm_digest_suite(&self, realm_id: &str) -> arkret_canonical::DigestSuite {
        self.state
            .lock()
            .realm_digest_algorithm(realm_id)
            .and_then(|algorithm| arkret_canonical::digest_suite(&algorithm).ok())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn clock(&self) -> &ServiceClock {
        &self.clock
    }

    #[must_use]
    pub fn snapshot(&self) -> ProjectionState {
        self.state.lock().clone()
    }

    /// The committed `ak.agent.action_approve` Event indexed for one complete
    /// approved Event id. The caller MUST re-read and verify that exact
    /// committed confirmation; the index is never authority by itself.
    pub fn agent_action_confirmation(
        &self,
        approved_event_id: &arkret_wire::EventId,
    ) -> Option<arkret_wire::EventId> {
        self.state
            .lock()
            .agent_action_confirmations
            .get(approved_event_id.as_str())
            .cloned()
    }

    pub fn stage_realm_bootstrap(
        &self,
        operations: &[Operation],
        direct_conversation_founding: bool,
    ) -> Result<StagedRealmBootstrap, RealmBootstrapProjectionError> {
        let mut staged = self.state.lock().clone();
        Self::apply_realm_bootstrap_to_state(
            &mut staged,
            operations,
            direct_conversation_founding,
            self.clock(),
        )?;
        Ok(StagedRealmBootstrap {
            operations: operations.to_vec(),
            direct_conversation_founding,
        })
    }

    pub(crate) fn apply_realm_bootstrap_to_state(
        state: &mut ProjectionState,
        operations: &[Operation],
        direct_conversation_founding: bool,
        clock: &ServerHlc,
    ) -> Result<(), RealmBootstrapProjectionError> {
        for (index, operation) in operations.iter().enumerate() {
            // The committed membership can reach the independent projection
            // lane before this atomic founding install. Only that exact
            // accepted Event is an idempotent replay; another membership
            // still reaches the bootstrap reducer's conflict checks.
            if operation.event_kind == arkret_wire::EventKind::MemberState
                && operation
                    .typed_payload::<arkret_wire::event_spec::MemberState>()
                    .ok()
                    .is_some_and(|payload| {
                        payload.membership == arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
                            && state
                            .member(operation.realm_id.as_str(), &payload.member_id.to_string())
                            .is_some_and(|member| {
                                member.state == "join"
                                    && member.membership_event_ref.as_deref()
                                        == Some(operation.context.event_id.as_str())
                            })
                    })
            {
                continue;
            }
            let effect = if operation.event_kind == arkret_wire::EventKind::MemberState {
                if direct_conversation_founding {
                    state.apply_validated_direct_conversation_bootstrap_membership(operation)
                } else {
                    state.apply_validated_realm_bootstrap_membership(operation)
                }
            } else {
                state.apply_projected(operation, clock)
            };
            match effect {
                ProjectionEffect::Rejected { reason } => {
                    return Err(RealmBootstrapProjectionError {
                        operation_index: index,
                        reason,
                        ignored: false,
                    });
                }
                ProjectionEffect::Ignored => {
                    return Err(RealmBootstrapProjectionError {
                        operation_index: index,
                        reason: "registered event kind was ignored".to_owned(),
                        ignored: true,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn install_staged_realm_bootstrap(
        &self,
        staged: StagedRealmBootstrap,
    ) -> Result<(), RealmBootstrapProjectionError> {
        let mut live = self.write_state();
        // A bootstrap becomes visible through two paths after its durable
        // commit: this synchronous install and the Commit projection coordinator.
        // Realm ids are derived from the create Event id, so an already
        // projected create for the staged Realm is the same immutable genesis,
        // never a first-writer-wins alias. Treat that state as an idempotent
        // install: replaying the staged unit would otherwise reject with
        // `realm_already_exists` and, more importantly, could overwrite
        // successor projections that were applied after genesis.
        if staged.operations.first().is_some_and(|operation| {
            operation.event_kind == arkret_wire::EventKind::RealmCreate
                && live.realm_create_log(operation.realm_id.as_str()).is_some()
        }) {
            if staged.direct_conversation_founding {
                // The genesis Commit can win the race against the local four
                // Event install. A visible genesis alone does not prove the
                // founder/peer joins and main Strand were projected. Force
                // durable hydration in that case, while preserving any
                // successor state when all founding facets are already here.
                for (index, operation) in staged.operations.iter().enumerate().skip(1) {
                    let present = match operation.event_kind {
                        arkret_wire::EventKind::MemberState => operation
                            .payload
                            .get("member_id")
                            .and_then(|value| {
                                serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok()
                            })
                            .is_some_and(|member| {
                                live.member(operation.realm_id.as_str(), &member.to_string())
                                    .is_some()
                            }),
                        arkret_wire::EventKind::StrandCreate => {
                            let strand =
                                arkret_wire::StrandId::from_event_id(&operation.context.event_id);
                            live.strands.contains_key(strand.as_str())
                        }
                        _ => false,
                    };
                    if !present {
                        return Err(RealmBootstrapProjectionError {
                            operation_index: index,
                            reason:
                                "confirmed Direct Conversation founding is only partially projected"
                                    .to_owned(),
                            ignored: false,
                        });
                    }
                }
            }
            return Ok(());
        }
        let mut merged = live.clone();
        Self::apply_realm_bootstrap_to_state(
            &mut merged,
            &staged.operations,
            staged.direct_conversation_founding,
            self.clock(),
        )?;
        *live = merged;
        Ok(())
    }

    pub fn install_snapshot(&self, state: ProjectionState) {
        *self.write_state() = state;
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_state(&self) -> &Arc<Mutex<ProjectionState>> {
        &self.state
    }

    /// Reduce an Operation whose Event contract declares no cell write.
    ///
    /// A kind that does declare writes fails closed here with
    /// `reducer_projection_failed`; use [`Self::apply_projected`] instead.
    pub fn apply(&self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffectView {
        self.apply_projected(operation, hlc)
    }

    pub fn apply_projected(&self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffectView {
        self.write_state().apply_projected(operation, hlc).into()
    }

    pub fn prepare_mls_keypackage_publish(
        projection: &coland_domain::reducer::mls::MlsKeyPackagePublishProjection,
    ) -> Result<crate::events::MlsKeyPackageState, &'static str> {
        coland_domain::reducer::mls::prepare_keypackage_upload_projection(projection)
            .map(key_package_record_from_projection)
    }

    pub fn retain_mls_key_package(&self, record: crate::events::MlsKeyPackageState) {
        self.write_state().mls_key_packages.insert(
            record.id.clone(),
            key_package_projection_from_record(record),
        );
    }

    pub fn mls_key_package_record(
        &self,
        keypackage_id: &str,
    ) -> Option<crate::events::MlsKeyPackageState> {
        self.state
            .lock()
            .mls_key_packages
            .get(keypackage_id)
            .cloned()
            .map(key_package_record_from_projection)
    }

    pub fn mls_key_package_records(&self) -> Vec<crate::events::MlsKeyPackageState> {
        let ids = self
            .state
            .lock()
            .mls_key_packages
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        ids.iter()
            .filter_map(|id| self.mls_key_package_record(id))
            .collect()
    }

    /// Apply an ordered formal Event aggregate to a cloned projection and
    /// return the first reducer rejection without mutating live state.
    pub fn preflight_projected_batch_rejection<'a, I>(&self, operations: I) -> Option<String>
    where
        I: IntoIterator<Item = &'a Operation>,
    {
        let mut state = self.state.lock().clone();
        for operation in operations {
            if let ProjectionEffect::Rejected { reason } =
                state.apply_projected(operation, self.clock())
            {
                return Some(reason);
            }
        }
        None
    }

    pub fn mark_key_packages_revoked(&self, keypackage_ids: &[String]) {
        let mut state = self.write_state();
        for keypackage_id in keypackage_ids {
            if let Some(row) = state.mls_key_packages.get_mut(keypackage_id)
                && row.consumed_at.is_none()
            {
                row.claimed_by = Some("revoked".to_owned());
                row.claimed_at = None;
                row.claim_expires_at_unix_ms = None;
            }
        }
    }

    pub fn mark_key_package_consumed(&self, keypackage_id: &str, consumed_at: i64) {
        if let Some(row) = self.write_state().mls_key_packages.get_mut(keypackage_id) {
            row.consumed_at = Some(consumed_at);
        }
    }

    pub fn reconcile_realm_owner(
        &self,
        realm_id: &str,
        controller_actor_id: &str,
        deleted: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> bool {
        let mut state = self.write_state();
        match state.realm_states.get_mut(realm_id) {
            Some(realm) => match realm.owner.as_deref() {
                Some(owner) if owner != controller_actor_id => false,
                Some(_) => true,
                None => {
                    realm.owner = Some(controller_actor_id.to_owned());
                    true
                }
            },
            None => {
                state.realm_states.insert(
                    realm_id.to_owned(),
                    ColandRealmState {
                        realm_id: realm_id.to_owned(),
                        owner: Some(controller_actor_id.to_owned()),
                        title: None,
                        deleted,

                        created_at,
                        updated_at,
                        trust_domain: None,
                        terminal_state: None,
                        successor_realm_id: None,
                        default_strand_id: None,
                    },
                );
                true
            }
        }
    }
}

/// Materialize the membership cascade of an already accepted invite. Used
/// by canonical restart hydration.
pub(crate) fn restore_invite_acceptance_membership(
    state: &mut ProjectionState,
    realm_id: &str,
    member: &str,
    invite_created_at: DateTime<Utc>,
    operation: &Operation,
) {
    let membership_event_ref = Some(projection_event_ref(operation));
    let key = (realm_id.to_owned(), member.to_owned());
    let previous = state.members.get(&key).cloned();
    let joined_at = previous
        .as_ref()
        .filter(|membership| membership.state == "join")
        .map(|membership| membership.joined_at)
        .unwrap_or(operation.created_at);
    state.members.insert(
        key,
        ColandMembershipState {
            member: member.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref,
            invited_at: previous
                .as_ref()
                .and_then(|membership| membership.invited_at)
                .or(Some(invite_created_at)),
            joined_at,
            updated_at: operation.created_at,
            reason: None,
        },
    );
}

fn key_package_record_from_projection(
    row: coland_domain::reducer::MlsKeyPackageProjection,
) -> crate::events::MlsKeyPackageState {
    crate::events::MlsKeyPackageState {
        id: row.id,
        keypackage_ref: row.keypackage_ref,
        keypackage_digest: row.keypackage_digest,
        owner_actor_id: row.owner_actor_id,
        effective_scope: row.effective_scope,
        actor_id: row.actor_id,
        device_id: row.device_id,
        endpoint_verification_method: row.endpoint_verification_method,
        key_package_bytes: row.key_package_bytes,
        capabilities: row.capabilities,
        capabilities_digest: row.capabilities_digest,
        last_resort: row.last_resort,
        last_resort_realm_id: row.last_resort_realm_id,
        lifetime_not_before: row.lifetime.not_before,
        lifetime_not_after: row.lifetime.not_after,
        claimed_by_mls_group_id: row.claimed_by,
        device_authorize_event_id: row.device_authorize_event_id,
        agent_key_authorize_event_id: row.agent_key_authorize_event_id,
        claimed_at: row.claimed_at,
        claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
        consumed_at: row.consumed_at,
        created_at: row.created_at,
    }
}

pub(crate) fn key_package_projection_from_record(
    row: crate::events::MlsKeyPackageState,
) -> coland_domain::reducer::MlsKeyPackageProjection {
    coland_domain::reducer::MlsKeyPackageProjection {
        id: row.id,
        keypackage_ref: row.keypackage_ref,
        keypackage_digest: row.keypackage_digest,
        owner_actor_id: row.owner_actor_id,
        effective_scope: row.effective_scope,
        actor_id: row.actor_id,
        device_id: row.device_id,
        endpoint_verification_method: row.endpoint_verification_method,
        lifetime: coland_domain::reducer::KeyPackageLifetimeProjection {
            not_before: row.lifetime_not_before,
            not_after: row.lifetime_not_after,
        },
        key_package_bytes: row.key_package_bytes,
        capabilities: row.capabilities,
        capabilities_digest: row.capabilities_digest,
        last_resort: row.last_resort,
        last_resort_realm_id: row.last_resort_realm_id,
        claimed_by: row.claimed_by_mls_group_id,
        device_authorize_event_id: row.device_authorize_event_id,
        agent_key_authorize_event_id: row.agent_key_authorize_event_id,
        claimed_at: row.claimed_at,
        claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
        consumed_at: row.consumed_at,
        created_at: row.created_at,
    }
}

#[cfg(test)]
mod projection_service_tests {
    use arkret_wire::{Did, ScopeRef, project_did_to_core_id};
    use coland_domain::reducer::facet;

    use super::*;

    fn service() -> ProjectionService {
        ProjectionService::new("projection-service-test")
    }

    #[test]
    fn persistence_rebuild_preserves_a_concurrent_projection_writer() {
        use std::sync::mpsc;
        use std::time::Duration;

        let service = Arc::new(service());
        let generation = service.rebuild_generation();
        let writer_service = Arc::clone(&service);
        let (progress_tx, progress_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            let now = Utc::now();
            progress_tx
                .send(writer_service.reconcile_realm_owner(
                    "ak:realm:concurrent-rebuild",
                    "ak:did_core:webvh:concurrent-owner",
                    false,
                    now,
                    now,
                ))
                .unwrap();
        });
        assert!(
            progress_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "a persistence rebuild must not block live projection writers"
        );
        writer.join().unwrap();
        assert!(!service.install_rebuild(generation, ProjectionState::new()));
        assert!(
            service
                .snapshot()
                .realm_states
                .contains_key("ak:realm:concurrent-rebuild")
        );
        // A fresh reconstruction may publish after including that write.
        let fresh_generation = service.rebuild_generation();
        let fresh = service.snapshot();
        assert!(service.install_rebuild(fresh_generation, fresh));
        assert!(
            service
                .snapshot()
                .realm_states
                .contains_key("ak:realm:concurrent-rebuild")
        );
    }

    #[test]
    fn concurrent_rebuilds_cannot_publish_over_an_installed_snapshot() {
        let service = service();
        let now = Utc::now();
        service.reconcile_realm_owner(
            "ak:realm:installed-rebuild",
            "ak:did_core:webvh:owner",
            false,
            now,
            now,
        );
        let generation = service.rebuild_generation();
        assert!(service.install_rebuild(generation, service.snapshot()));
        assert!(!service.install_rebuild(generation, ProjectionState::new()));
        assert!(
            service
                .snapshot()
                .realm_states
                .contains_key("ak:realm:installed-rebuild")
        );
    }

    #[test]
    fn staged_bootstrap_install_preserves_concurrent_projection_updates() {
        let service = service();
        let staged = service.stage_realm_bootstrap(&[], false).unwrap();
        let now = Utc::now();
        assert!(service.reconcile_realm_owner(
            "ak:realm:concurrent-update",
            "ak:did_core:webvh:concurrent-owner",
            false,
            now,
            now,
        ));

        service.install_staged_realm_bootstrap(staged).unwrap();

        assert!(
            service
                .snapshot()
                .realm_states
                .contains_key("ak:realm:concurrent-update"),
            "installing a staged bootstrap discarded a concurrent Realm projection"
        );
    }

    #[test]
    fn bootstrap_install_reuses_only_the_exact_independently_projected_membership() {
        let actor = project_did_to_core_id(&Did::new("did:web:alice.example").unwrap()).unwrap();
        let station =
            project_did_to_core_id(&Did::new("did:web:service.example").unwrap()).unwrap();
        let member = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor.clone(),
            station.clone(),
        ));
        let genesis = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            actor,
            station,
            serde_json::json!({"object": {"purpose": "collaboration"}}),
            Utc::now(),
        )
        .unwrap();
        let join = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::MemberState.as_str(),
            ScopeRef::Realm {
                realm_id: genesis.realm_id.clone(),
            },
            member.clone(),
            serde_json::json!({"member_id": member, "membership": "join"}),
            Utc::now(),
        )
        .unwrap();
        let operation = Operation::from_accepted_event(
            arkret_identifiers::OperationId::new(
                "ak:operation:0196419b-0000-7000-8000-000000000004",
            )
            .unwrap(),
            arkret_wire::OperationKind::Create,
            None,
            &join,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let service = service();
        let mut projection = ProjectionState::new();
        projection.restore_accepted_membership(&operation, operation.created_at);
        ProjectionService::apply_realm_bootstrap_to_state(
            &mut projection,
            std::slice::from_ref(&operation),
            false,
            service.clock(),
        )
        .unwrap();
        assert_eq!(
            projection
                .member(genesis.realm_id.as_str(), &member.to_string())
                .unwrap()
                .membership_event_ref
                .as_deref(),
            Some(join.event_id.as_str()),
        );
        let mut different = operation;
        different.context.event_id = genesis.event_id;
        let error = ProjectionService::apply_realm_bootstrap_to_state(
            &mut projection,
            &[different],
            false,
            service.clock(),
        )
        .unwrap_err();
        assert_eq!(error.reason, "out_of_order_bootstrap");
    }

    #[test]
    fn accepted_bootstrap_replay_preserves_same_realm_successor_projection() {
        let service = service();
        let actor = project_did_to_core_id(&Did::new("did:web:alice.example").unwrap()).unwrap();
        let station =
            project_did_to_core_id(&Did::new("did:web:service.example").unwrap()).unwrap();
        let genesis = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            actor,
            station,
            serde_json::json!({"object": {"purpose": "collaboration"}}),
            Utc::now(),
        )
        .unwrap();
        let realm_id = genesis.realm_id.to_string();
        let operation = Operation::from_accepted_event(
            arkret_identifiers::OperationId::new(
                "ak:operation:0196419b-0000-7000-8000-000000000001",
            )
            .unwrap(),
            arkret_wire::OperationKind::Create,
            None,
            &genesis,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        {
            let mut live = service.state.lock();
            live.set_realm_facet(
                realm_id.as_str(),
                facet::REALM_CREATE,
                serde_json::json!([realm_id]),
            );
            live.realm_join_rules
                .insert(genesis.realm_id.to_string(), "public".to_owned());
        }
        let staged = StagedRealmBootstrap {
            operations: vec![operation],
            direct_conversation_founding: false,
        };

        service.install_staged_realm_bootstrap(staged).unwrap();

        assert_eq!(
            service
                .snapshot()
                .realm_join_rules
                .get(genesis.realm_id.as_str())
                .map(String::as_str),
            Some("public"),
            "an exact bootstrap replay must not replace a concurrent successor projection",
        );
    }

    #[test]
    fn direct_conversation_genesis_alone_requires_durable_founding_repair() {
        let service = service();
        let actor =
            project_did_to_core_id(&Did::new("did:web:dm-founder.example").unwrap()).unwrap();
        let station =
            project_did_to_core_id(&Did::new("did:web:dm-station.example").unwrap()).unwrap();
        let genesis = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            actor.clone(),
            station.clone(),
            serde_json::json!({"object": {"purpose": "direct_conversation"}}),
            Utc::now(),
        )
        .unwrap();
        let founder = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor.clone(),
            station.clone(),
        ));
        let join = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::MemberState.as_str(),
            ScopeRef::Realm { realm_id: genesis.realm_id.clone() },
            founder.clone(),
            serde_json::json!({"member_id": founder, "membership": "join", "reason": "direct_conversation_bootstrap"}),
            Utc::now(),
        )
        .unwrap();
        let operation = Operation::from_accepted_event(
            arkret_identifiers::OperationId::new(
                "ak:operation:0196419b-0000-7000-8000-000000000002",
            )
            .unwrap(),
            arkret_wire::OperationKind::Create,
            None,
            &join,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        {
            let mut live = service.state.lock();
            live.set_realm_facet(
                genesis.realm_id.as_str(),
                facet::REALM_CREATE,
                serde_json::json!([genesis.realm_id.clone()]),
            );
        }
        let error = service
            .install_staged_realm_bootstrap(StagedRealmBootstrap {
                operations: vec![
                    Operation::from_accepted_event(
                        arkret_identifiers::OperationId::new(
                            "ak:operation:0196419b-0000-7000-8000-000000000003",
                        )
                        .unwrap(),
                        arkret_wire::OperationKind::Create,
                        None,
                        &genesis,
                        arkret_canonical::DigestSuite::Sha256,
                    )
                    .unwrap(),
                    operation,
                ],
                direct_conversation_founding: true,
            })
            .unwrap_err();
        assert_eq!(error.operation_index, 1);
        assert!(error.reason.contains("partially projected"));
    }
}
