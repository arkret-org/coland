//! Read-only Signal governance from covered canonical cuts, never UI mirrors.
use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::events_payloads::realm::{
    RealmAuthorityResetPayload, RealmOwnerTransferPayload, RealmPolicyBundlePayload,
};
use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, CapabilityGrantStatus, CapabilitySubject, IssuerAuthorityRef,
};
use arkret_wire::{
    ActorId, CommitStreamRef, Event, EventId, EventKind, GrantId, RealmCommit, RealmCommitId,
    RealmId, ScopeRef, SignalClass, WireResourceSelector,
};
use chrono::{DateTime, Utc};
use coland_storage::{
    AuthorizationOperation, OperationFacts, PersistenceError, PersistenceResult,
    SignalScopeAuthority, SignalScopeAuthorityQuery, evaluate_grants,
};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::capability_grant_current_results::RealmAuthorityRootCurrent;
use crate::{OptionalExtension, PgPool, PgTransactionError, pg_conn};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("Signal governance cut is unavailable: {detail}"))
}
fn denied(reason: &'static str) -> Option<SignalScopeAuthority> {
    tracing::debug!(reason, "Signal authority cut denied");
    None
}
#[derive(diesel::QueryableByName)]
struct Row {
    #[diesel(sql_type=Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    envelope: Option<serde_json::Value>,
}
#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
}

struct History {
    base: Cut,
    rows: Vec<(RealmCommit, Event)>,
    head: arkret_wire::CommitStreamHead,
}

/// Replay only a covered interval: complete genesis history, or one exact
/// verified signed snapshot followed by every covered accepted successor.
async fn history(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
    through: u64,
) -> PersistenceResult<History> {
    let key = crate::authority_commit::stream_key(stream)?;
    let rows=diesel::sql_query("SELECT c.commit_json,e.envelope FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE c.stream_key=$1 AND c.stream_position<=$2 ORDER BY c.stream_position")
        .bind::<Text,_>(&key).bind::<diesel::sql_types::BigInt,_>(i64::try_from(through).unwrap_or(i64::MAX)).load::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
    let complete_genesis = !rows.is_empty()
        && rows.iter().enumerate().all(|(position, row)| {
            row.commit_json
                .get("stream_position")
                .and_then(serde_json::Value::as_u64)
                == Some(position as u64)
                && row.envelope.is_some()
        });
    let mut base = Cut::default();
    let mut base_head = None;
    let mut base_signature = None;
    let mut base_generation = 0;
    if !complete_genesis {
        #[derive(diesel::QueryableByName)]
        struct SnapshotRow {
            #[diesel(sql_type=Jsonb)]
            snapshot_json: serde_json::Value,
        }
        let snapshots=diesel::sql_query("SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot JOIN realm_state_snapshot_issuances issued ON issued.snapshot_id=snapshot.snapshot_id WHERE snapshot.realm_id=$1 AND EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot.snapshot_json->'visible_stream_heads') h WHERE h->'stream_ref'=$2 AND (h->>'stream_position')::bigint<=$3) ORDER BY snapshot.snapshot_json->>'created_at' DESC")
            .bind::<Text,_>(stream.realm_id().as_str()).bind::<Jsonb,_>(serde_json::to_value(stream).map_err(unavailable)?).bind::<diesel::sql_types::BigInt,_>(i64::try_from(through).unwrap_or(i64::MAX)).load::<SnapshotRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mut selected = None;
        for row in snapshots {
            let snapshot: arkret_wire::RealmStateSnapshot =
                serde_json::from_value(row.snapshot_json).map_err(unavailable)?;
            let Some(head) = snapshot
                .visible_stream_heads
                .iter()
                .find(|head| head.stream_ref == *stream && head.stream_position <= through)
            else {
                continue;
            };
            if selected.as_ref().is_none_or(
                |(old, _): &(
                    arkret_wire::CommitStreamHead,
                    arkret_wire::RealmStateSnapshot,
                )| old.stream_position < head.stream_position,
            ) {
                selected = Some((head.clone(), snapshot));
            }
        }
        let (head, snapshot) = selected
            .ok_or_else(|| unavailable("no verified snapshot covers the selected source cut"))?;
        base = Cut::from_snapshot(&snapshot, stream, &head)?;
        base_generation = snapshot.governance_generation;
        base_signature = Some(snapshot.signature);
        base_head = Some(head);
    }
    let mut result = Vec::new();
    let mut previous = base_head.as_ref().map(|head| head.commit_id.clone());
    let mut position = base_head
        .as_ref()
        .map_or(0, |head| head.stream_position + 1);
    for row in rows {
        let commit: RealmCommit = serde_json::from_value(row.commit_json).map_err(unavailable)?;
        if base_head
            .as_ref()
            .is_some_and(|head| commit.stream_position <= head.stream_position)
        {
            continue;
        }
        let event: Event = serde_json::from_value(
            row.envelope
                .ok_or_else(|| unavailable("missing covered Event after snapshot"))?,
        )
        .map_err(unavailable)?;
        if commit.stream_ref != *stream
            || commit.stream_position != position
            || commit.previous_commit_ref != previous
            || commit.event_ref != event.event_id
            || commit.realm_id != event.realm_id
        {
            return Err(unavailable(
                "accepted interval is discontinuous or covers another Event",
            ));
        }
        commit.validate_shape().map_err(unavailable)?;
        event
            .verify_event_id_matches_content_with_digest_suite(
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(unavailable)?;
        previous = Some(commit.commit_id.clone());
        position += 1;
        result.push((commit, event));
    }
    let (head, head_generation, signature) = match result.last() {
        Some((commit, _)) => (
            arkret_wire::CommitStreamHead {
                stream_ref: stream.clone(),
                commit_id: commit.commit_id.clone(),
                stream_position: commit.stream_position,
            },
            commit.governance_generation,
            commit.signature.clone(),
        ),
        None => (
            base_head.ok_or_else(|| unavailable("source stream is not held"))?,
            base_generation,
            base_signature.ok_or_else(|| unavailable("source proof is absent"))?,
        ),
    };
    // A verified replica anchor above the held interval is known stale, not
    // permission to reuse the older interval.
    #[derive(diesel::QueryableByName)]
    struct Anchor {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        position: i64,
    }
    let anchor=diesel::sql_query("SELECT MAX(anchor_stream_position) AS position FROM replica_stream_anchors WHERE stream_key=$1 AND anchor_commit_id IS NOT NULL HAVING MAX(anchor_stream_position) IS NOT NULL")
        .bind::<Text,_>(&key).get_result::<Anchor>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if through == u64::MAX
        && anchor
            .is_some_and(|a| u64::try_from(a.position).map_or(true, |p| p > head.stream_position))
    {
        return Err(unavailable("known replica head exceeds held interval"));
    }
    #[derive(diesel::QueryableByName)]
    struct Authority {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        generation: i64,
        #[diesel(sql_type=diesel::sql_types::Text)]
        service_id: String,
    }
    let authority =
        diesel::sql_query("SELECT generation,service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(stream.realm_id().as_str())
            .get_result::<Authority>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
    let authority = authority.ok_or_else(|| unavailable("missing current Realm authority"))?;
    if through == u64::MAX {
        let current_generation = u64::try_from(authority.generation).map_err(unavailable)?;
        if head_generation > current_generation {
            return Err(unavailable(
                "held head exceeds current authority generation",
            ));
        }
        let method = signature
            .verification_method
            .as_str()
            .split_once('#')
            .ok_or_else(|| unavailable("head signer omits fragment"))?
            .0;
        let mut service = arkret_wire::project_did_to_core_id(
            &arkret_wire::Did::new(method.to_owned()).map_err(unavailable)?,
        )
        .map_err(unavailable)?;
        let mut generation = head_generation;
        if generation < current_generation {
            #[derive(diesel::QueryableByName)]
            struct Transition {
                #[diesel(sql_type=Jsonb)]
                handoff_json: serde_json::Value,
                #[diesel(sql_type=Nullable<Jsonb>)]
                snapshot_json: Option<serde_json::Value>,
            }
            let transitions = diesel::sql_query("SELECT h.handoff_json,s.snapshot_json FROM realm_authority_handoffs h LEFT JOIN realm_state_snapshots s ON s.snapshot_id=h.handoff_json->>'snapshot_ref' WHERE h.realm_id=$1 AND h.to_generation>$2 AND h.to_generation<=$3 ORDER BY h.to_generation")
                .bind::<Text,_>(stream.realm_id().as_str())
                .bind::<diesel::sql_types::BigInt,_>(i64::try_from(generation).map_err(unavailable)?)
                .bind::<diesel::sql_types::BigInt,_>(authority.generation)
                .load::<Transition>(&mut *conn).await.map_err(PersistenceError::database)?;
            for transition in transitions {
                let handoff: arkret_wire::RealmAuthorityHandoff =
                    serde_json::from_value(transition.handoff_json).map_err(unavailable)?;
                let snapshot: arkret_wire::RealmStateSnapshot = serde_json::from_value(
                    transition
                        .snapshot_json
                        .ok_or_else(|| unavailable("handoff manifest is not held"))?,
                )
                .map_err(unavailable)?;
                handoff.validate_shape().map_err(unavailable)?;
                crate::authority_commit::verify_snapshot_content_id(&snapshot)
                    .map_err(unavailable)?;
                let digest = arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(&snapshot.visible_stream_heads)
                        .map_err(unavailable)?,
                )
                .map_err(unavailable)?;
                if handoff.realm_id != *stream.realm_id()
                    || handoff.from_generation != generation
                    || handoff.from_service_id != service
                    || snapshot.snapshot_id != handoff.snapshot_ref
                    || snapshot.realm_id != handoff.realm_id
                    || snapshot.governance_generation != generation
                    || snapshot.signature.context
                        != arkret_wire::DetachedSignatureContext::RealmSnapshot
                    || !snapshot
                        .visible_stream_heads
                        .windows(2)
                        .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
                    || digest != handoff.final_stream_heads_digest
                    || !snapshot.visible_stream_heads.iter().any(|item| {
                        item.stream_ref == *stream
                            && item.commit_id == head.commit_id
                            && item.stream_position == head.stream_position
                    })
                {
                    return Err(unavailable(
                        "unchanged head is not covered by the accepted handoff manifest",
                    ));
                }
                generation = handoff.to_generation;
                service = handoff.to_service_id;
            }
        }
        if generation != current_generation || service.as_str() != authority.service_id {
            return Err(unavailable(
                "head is not covered by current authority lineage",
            ));
        }
    }
    Ok(History {
        base,
        rows: result,
        head,
    })
}

#[derive(Default, Clone)]
struct Cut {
    root: Option<RealmAuthorityRootCurrent>,
    snapshot_root_generation: Option<u64>,
    snapshot_root_controller: Option<ActorId>,
    policies: BTreeMap<
        arkret_wire::PolicyId,
        arkret_models_collaboration::governance::operation_wire::Policy,
    >,
    circle_states: BTreeMap<
        arkret_wire::CircleId,
        arkret_models_collaboration::governance::circle::CircleState,
    >,
    mls_current: Option<arkret_wire::MlsGroupCurrent>,
    members: BTreeMap<String, (ActorId, String)>,
    member_revisions: BTreeMap<String, arkret_wire::CurrentRevision>,
    circle_parent_joins: BTreeMap<String, arkret_wire::CurrentRevision>,
    grants: BTreeMap<GrantId, CapabilityGrant>,
    policy: Option<RealmPolicyBundlePayload>,
    terminal: bool,
    frozen: bool,
    archived: bool,
    direct: bool,
    bound: bool,
    mls: Option<EventId>,
    cipher: Option<String>,
    mls_epoch: Option<u64>,
    genesis: Option<EventId>,
    links: BTreeMap<(RealmId, String), String>,
}
impl Cut {
    fn from_snapshot(
        snapshot: &arkret_wire::RealmStateSnapshot,
        stream: &CommitStreamRef,
        head: &arkret_wire::CommitStreamHead,
    ) -> PersistenceResult<Self> {
        use arkret_wire::{CurrentSelector as S, TypedCurrentRow};
        let mut cut = Self::default();
        let mut genesis_present = false;
        if snapshot.realm_id != *stream.realm_id()
            || snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
            || !snapshot.visible_stream_heads.contains(head)
        {
            return Err(unavailable("snapshot does not bind this source head"));
        }
        let mut selectors = BTreeSet::new();
        for entry in &snapshot.current_state_entries {
            let TypedCurrentRow::Value {
                selector,
                source_stream_ref,
                revision,
                value,
            } = entry;
            if source_stream_ref != stream {
                continue;
            }
            let selector_key =
                arkret_canonical::canonical_json_string(selector).map_err(unavailable)?;
            if !selectors.insert(selector_key)
                || revision.stream_position > head.stream_position
                || (revision.stream_position == head.stream_position
                    && revision.commit_id != head.commit_id)
            {
                return Err(unavailable("snapshot row is outside its exact source cut"));
            }
            match selector {
                S::RealmGenesis => {
                    genesis_present = true;
                    let genesis: arkret_models_collaboration::events_payloads::realm::RealmGenesis =
                        serde_json::from_value(value.clone()).map_err(unavailable)?;
                    cut.direct=genesis.purpose == arkret_models_collaboration::events_payloads::realm::RealmPurpose::DirectConversation;
                }
                S::RealmAuthorityRoot => {
                    cut.snapshot_root_generation = Some(
                        value
                            .get("authority_generation")
                            .and_then(serde_json::Value::as_u64)
                            .ok_or_else(|| unavailable("snapshot root omits generation"))?,
                    );
                    let controller: ActorId = serde_json::from_value(
                        value
                            .get("controller_actor_id")
                            .cloned()
                            .ok_or_else(|| unavailable("snapshot root omits controller"))?,
                    )
                    .map_err(unavailable)?;
                    cut.snapshot_root_controller = Some(controller);
                    value
                        .get("controller_epoch")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| unavailable("snapshot root omits controller epoch"))?;
                }
                S::RealmPolicyBundle => {
                    cut.policy = Some(serde_json::from_value(value.clone()).map_err(unavailable)?)
                }
                S::MemberState { actor_id } => {
                    let current: arkret_wire::MemberStateCurrent =
                        serde_json::from_value(value.clone()).map_err(unavailable)?;
                    cut.members.insert(
                        actor_id.to_string(),
                        (
                            actor_id.clone(),
                            serde_json::to_value(current.membership)
                                .map_err(unavailable)?
                                .as_str()
                                .ok_or_else(|| unavailable("snapshot membership is not a string"))?
                                .to_owned(),
                        ),
                    );
                    cut.member_revisions
                        .insert(actor_id.to_string(), revision.clone());
                }
                S::CircleMemberState {
                    circle_id,
                    member_actor_id,
                } => {
                    if !matches!(stream,CommitStreamRef::Circle {circle_id:own,..} if own==circle_id)
                    {
                        return Err(unavailable("snapshot Circle membership source differs"));
                    }
                    let current: arkret_wire::CircleMemberStateCurrent =
                        serde_json::from_value(value.clone()).map_err(unavailable)?;
                    cut.members.insert(
                        member_actor_id.to_string(),
                        (
                            member_actor_id.clone(),
                            serde_json::to_value(current.membership)
                                .map_err(unavailable)?
                                .as_str()
                                .ok_or_else(|| unavailable("snapshot membership is not a string"))?
                                .to_owned(),
                        ),
                    );
                    if let Some(parent) = current.parent_membership_revision {
                        cut.circle_parent_joins
                            .insert(member_actor_id.to_string(), parent);
                    }
                }
                S::Circle { circle_id } => {
                    let circle: arkret_models_collaboration::governance::circle::Circle =
                        serde_json::from_value(value.clone()).map_err(unavailable)?;
                    if circle.id.as_ref() != Some(circle_id) || circle.realm_id != snapshot.realm_id
                    {
                        return Err(unavailable("snapshot Circle identity differs"));
                    }
                    cut.circle_states.insert(circle_id.clone(), circle.state);
                }
                S::Policy { policy_id } => {
                    let value: arkret_models_collaboration::governance::operation_wire::PolicySetValue = serde_json::from_value(value.clone()).map_err(unavailable)?;
                    if let arkret_models_collaboration::governance::operation_wire::PolicySetValue::Governance(policy) = value {
                        if policy.id != *policy_id || policy.realm_id.as_ref() != Some(&snapshot.realm_id) { return Err(unavailable("Signal Policy identity differs")); }
                        if policy.policy_kind == arkret_wire::PolicyKind::Agent { cut.policies.insert(policy_id.clone(), *policy); }
                    }
                }
                S::CapabilityGrant { grant_id } => {
                    let grant: CapabilityGrant =
                        serde_json::from_value(value.clone()).map_err(unavailable)?;
                    if grant.id != *grant_id || grant.realm_id.as_ref() != Some(&snapshot.realm_id)
                    {
                        return Err(unavailable("snapshot grant identity differs"));
                    }
                    cut.grants.insert(grant_id.clone(), grant);
                }
                S::MlsGroup { scope_ref } => {
                    if CommitStreamRef::from_scope(scope_ref, None).map_err(unavailable)? != *stream
                    {
                        return Err(unavailable("snapshot MLS source differs"));
                    }
                    let current: arkret_wire::MlsGroupCurrent =
                        serde_json::from_value(value.clone()).map_err(unavailable)?;
                    if current.effective_scope != *scope_ref {
                        return Err(unavailable("snapshot MLS scope differs"));
                    }
                    cut.mls = Some(current.current_mls_commit_event_ref.clone());
                    cut.genesis = Some(current.genesis_event_ref.clone());
                    cut.mls_epoch = Some(current.epoch);
                    cut.cipher = Some(current.cipher_suite.as_str().to_owned());
                    cut.mls_current = Some(current);
                }
                S::RealmArchive => {
                    cut.archived = value
                        .get("archived")
                        .and_then(serde_json::Value::as_bool)
                        .ok_or_else(|| unavailable("snapshot archive value is invalid"))?
                }
                S::RealmFreeze => {
                    cut.frozen = value
                        .get("frozen")
                        .and_then(serde_json::Value::as_bool)
                        .ok_or_else(|| unavailable("snapshot freeze value is invalid"))?
                }
                S::RealmTombstone => cut.terminal = true,
                S::DirectConversationBinding { .. } => cut.bound = true,
                _ => {}
            }
        }
        if matches!(stream, CommitStreamRef::Realm { .. })
            && (!genesis_present || cut.snapshot_root_generation.is_none() || cut.policy.is_none())
        {
            return Err(unavailable("snapshot omits Realm authority rows"));
        }
        Ok(cut)
    }
    fn apply(&mut self, commit: &RealmCommit, event: &Event) -> PersistenceResult<()> {
        if matches!(
            event.kind,
            EventKind::MemberState | EventKind::InviteAccept | EventKind::CircleMemberState
        ) && let Some(current) = self.mls_current.as_mut()
        {
            current.current_key_access_revision = current
                .current_key_access_revision
                .checked_add(1)
                .ok_or_else(|| unavailable("MLS key-access revision overflow"))?;
        }
        match event.kind {
            EventKind::RealmCreate => {
                self.root = Some(RealmAuthorityRootCurrent {
                    realm_id: event.realm_id.clone(),
                    controller_actor_id: event.actor_id.clone(),
                    controller_epoch: 0,
                    authority_generation: 0,
                    authority_event_ref: event.event_id.clone(),
                });
                self.direct = event.as_realm_create().map_err(unavailable)?.object.purpose
                    == arkret_models_collaboration::events_payloads::realm::RealmPurpose::DirectConversation;
            }
            EventKind::CircleCreate => {
                let p = event.as_circle_create().map_err(unavailable)?;
                self.circle_states.insert(
                    arkret_wire::CircleId::from_event_id(&event.event_id),
                    p.object.state,
                );
            }
            EventKind::CircleArchive | EventKind::CircleRestore | EventKind::CircleTombstone => {
                use arkret_models_collaboration::governance::circle::CircleState;
                let p = match event.kind {
                    EventKind::CircleArchive => event.as_circle_archive(),
                    EventKind::CircleRestore => event.as_circle_restore(),
                    _ => event.as_circle_tombstone(),
                }
                .map_err(unavailable)?;
                let circle =
                    arkret_wire::CircleId::new(p.target_ref.as_str()).map_err(unavailable)?;
                let state = self
                    .circle_states
                    .get_mut(&circle)
                    .ok_or_else(|| unavailable("Circle lifecycle has no create"))?;
                if *state == CircleState::Tombstoned {
                    return Err(unavailable("Circle terminal lifecycle changed"));
                }
                *state = match event.kind {
                    EventKind::CircleArchive => CircleState::Archived,
                    EventKind::CircleRestore => CircleState::Active,
                    _ => CircleState::Tombstoned,
                };
            }
            EventKind::RealmOwnerTransfer => {
                let p = event.as_realm_owner_transfer().map_err(unavailable)?;
                if self.root.is_none() && self.snapshot_root_generation.is_some() {
                    return Ok(());
                }
                let root = self
                    .root
                    .as_mut()
                    .ok_or_else(|| unavailable("root transfer without genesis"))?;
                root.controller_actor_id = p.patch.controller_actor_id;
                root.controller_epoch =
                    RealmOwnerTransferPayload::successor_controller_epoch(root.controller_epoch)
                        .map_err(unavailable)?;
            }
            EventKind::RealmAuthorityReset => {
                if self.root.is_none() {
                    let generation = self
                        .snapshot_root_generation
                        .ok_or_else(|| unavailable("root reset without genesis"))?;
                    self.snapshot_root_generation = Some(
                        RealmAuthorityResetPayload::successor_authority_generation(generation)
                            .map_err(unavailable)?,
                    );
                    self.grants.clear();
                    return Ok(());
                }
                let root = self
                    .root
                    .as_mut()
                    .ok_or_else(|| unavailable("root reset without genesis"))?;
                root.authority_generation =
                    RealmAuthorityResetPayload::successor_authority_generation(
                        root.authority_generation,
                    )
                    .map_err(unavailable)?;
                root.authority_event_ref = event.event_id.clone();
            }
            EventKind::CircleMemberState => {
                let p = event.as_circle_member_state().map_err(unavailable)?;
                p.validate().map_err(unavailable)?;
                let key = p.member_id.to_string();
                if let Some(revision) = p.parent_membership_revision {
                    self.circle_parent_joins.insert(key.clone(), revision);
                } else {
                    self.circle_parent_joins.remove(&key);
                }
                self.members
                    .insert(key, (p.member_id, p.membership.as_str().to_owned()));
            }
            EventKind::MemberState => {
                let p = event.as_member_state().map_err(unavailable)?;
                let member = p.member_id;
                use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
                let membership = match p.membership {
                    MembershipPayloadState::Join => "join",
                    MembershipPayloadState::Knock => "knock",
                    MembershipPayloadState::Leave => "leave",
                    MembershipPayloadState::Ban => "ban",
                };
                self.members
                    .insert(member.to_string(), (member.clone(), membership.to_owned()));
                self.member_revisions.insert(
                    member.to_string(),
                    arkret_wire::CurrentRevision {
                        commit_id: commit.commit_id.clone(),
                        stream_position: commit.stream_position,
                    },
                );
            }
            EventKind::InviteAccept => {
                self.members.insert(
                    event.actor_id.to_string(),
                    (event.actor_id.clone(), "join".to_owned()),
                );
                self.member_revisions.insert(
                    event.actor_id.to_string(),
                    arkret_wire::CurrentRevision {
                        commit_id: commit.commit_id.clone(),
                        stream_position: commit.stream_position,
                    },
                );
            }
            EventKind::CapabilityGrant => {
                let p = event.as_capability_grant().map_err(unavailable)?;
                let b = p.grant;
                let mut roots = Vec::new();
                let mut depth = 1;
                for reference in &b.issuer_authority_refs {
                    match reference {
                        IssuerAuthorityRef::OwnedAgent {
                            realm_id,
                            controller_account_id,
                            controller_join_event_id,
                            agent_join_event_id,
                        } => roots.push(AuthorityRootRef::OwnedAgent {
                            realm_id: realm_id.clone(),
                            controller_account_id: controller_account_id.clone(),
                            controller_join_event_id: controller_join_event_id.clone(),
                            agent_join_event_id: agent_join_event_id.clone(),
                        }),
                        IssuerAuthorityRef::RealmRoot {
                            realm_id,
                            authority_event_ref,
                            authority_generation,
                        } => roots.push(AuthorityRootRef::RealmRoot {
                            realm_id: realm_id.clone(),
                            authority_event_ref: authority_event_ref.clone(),
                            authority_generation: *authority_generation,
                        }),
                        IssuerAuthorityRef::Grant { grant_id } => {
                            let parent = self
                                .grants
                                .get(grant_id)
                                .ok_or_else(|| unavailable("accepted grant parent missing"))?;
                            depth = depth.max(parent.authority_depth + 1);
                            roots.extend(parent.authority_root_refs.clone());
                        }
                    }
                }
                let grant = CapabilityGrant {
                    id: GrantId::from_event_id(&event.event_id),
                    schema: b.schema,
                    realm_id: Some(event.realm_id.clone()),
                    issuer_id: b.issuer_id,
                    subject: b.subject,
                    actions: b.actions,
                    resources: b.resources,
                    constraints: b.constraints,
                    issuer_authority_refs: b.issuer_authority_refs,
                    authority_depth: depth,
                    authority_root_refs: roots,
                    issued_at: b.issued_at,
                    status: CapabilityGrantStatus::Active,
                    updated_by: None,
                    updated_at: None,
                    revoked_by: None,
                    revoked_at: None,
                };
                self.grants.insert(grant.id.clone(), grant);
            }
            EventKind::CapabilityRevoke => {
                let p = event.as_capability_revoke().map_err(unavailable)?;
                let grant = self
                    .grants
                    .get_mut(&p.grant_id)
                    .ok_or_else(|| unavailable("accepted revoke target missing"))?;
                grant.status = CapabilityGrantStatus::Revoked;
                grant.revoked_by = Some(event.actor_id.clone());
                grant.revoked_at = Some(event.created_at);
            }
            EventKind::CapabilityRelinquish => {
                let p = event.as_capability_relinquish().map_err(unavailable)?;
                let grant = self
                    .grants
                    .get_mut(&p.grant_id)
                    .ok_or_else(|| unavailable("accepted relinquish target missing"))?;
                grant.status = CapabilityGrantStatus::Relinquished;
                grant.updated_by = Some(event.actor_id.clone());
                grant.updated_at = Some(event.created_at);
            }
            EventKind::PolicySet => {
                let payload = event.as_policy_set().map_err(unavailable)?;
                if let arkret_models_collaboration::governance::operation_wire::PolicySetValue::Governance(policy) = payload.value {
                    if policy.policy_kind == arkret_wire::PolicyKind::Agent { self.policies.insert(policy.id.clone(), *policy); }
                }
            }
            EventKind::RealmPolicyBundle => {
                self.policy = Some(event.as_realm_policy_bundle().map_err(unavailable)?);
            }
            EventKind::RealmLink => {
                let p = event.as_realm_link().map_err(unavailable)?;
                self.links.insert(
                    (p.target_realm_id, p.link_kind.as_str().to_owned()),
                    p.status.as_str().to_owned(),
                );
            }
            EventKind::RealmArchive => self.archived = true,
            EventKind::RealmRestore => self.archived = false,
            EventKind::RealmFreeze => self.frozen = true,
            EventKind::RealmUnfreeze => self.frozen = false,
            EventKind::RealmDestroy | EventKind::RealmTombstone => self.terminal = true,
            EventKind::DirectConversationBound => self.bound = true,
            EventKind::MlsGenesis => {
                let p = event.as_mls_genesis().map_err(unavailable)?;
                p.validate().map_err(unavailable)?;
                if p.effective_scope() != &event.scope_ref
                    || p.mls_group_id().map_err(unavailable)?
                        != event
                            .scope_ref
                            .canonical_mls_group_id()
                            .map_err(unavailable)?
                {
                    return Err(unavailable("MLS genesis scope differs"));
                }
                self.mls = Some(event.event_id.clone());
                self.genesis = Some(event.event_id.clone());
                self.mls_epoch = Some(0);
                self.cipher = Some(p.cipher_suite.as_str().to_owned());
            }
            EventKind::MlsCommit => {
                let p = event.as_mls_commit().map_err(unavailable)?;
                if self.mls.as_ref() != Some(p.base_group_state_ref())
                    || self.mls_epoch != Some(p.base_epoch())
                {
                    return Err(unavailable("MLS winning interval is discontinuous"));
                }
                self.mls = Some(event.event_id.clone());
                self.mls_epoch = Some(p.next_epoch());
                // The public post-transition tree is not part of the Event.
                // A replica must refresh its signed current before delivery.
                self.mls_current = None;
            }
            _ => {}
        }
        Ok(())
    }
    fn joined(&self, actor: &ActorId) -> bool {
        self.members
            .get(&actor.to_string())
            .is_some_and(|(_, m)| m == "join")
    }
    fn permits(
        &self,
        realm: &RealmId,
        scope: &ScopeRef,
        actor: &ActorId,
        class: SignalClass,
        at: DateTime<Utc>,
    ) -> bool {
        if !self.joined(actor) || self.terminal || self.frozen || self.archived {
            return false;
        }
        if self.direct {
            // The decrypted product kind is not an outer capability selector.
            // Direct Conversation has no participant moderation action.
            return self.bound && self.members.len() == 2 && class != SignalClass::Moderation;
        }
        // Setup/session contain encrypted product actions. Only moderation
        // has a Station-visible action, evaluated through the shared grant
        // constraint evaluator and intact accepted issuer graph.
        if class != SignalClass::Moderation {
            return true;
        }
        let generation = self
            .root
            .as_ref()
            .map(|root| root.authority_generation)
            .or(self.snapshot_root_generation);
        let Some(generation) = generation else {
            return false;
        };
        let target = match scope {
            ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
            _ => return false,
        };
        let actions = [arkret_wire::CapabilityActionId::CALL_MODERATE];
        let facts = OperationFacts::default();
        let effective=self.grants.iter().filter_map(|(id,g)| {
            (matches!(&g.subject,CapabilitySubject::Actor(subject) if subject==actor)
                && crate::replica_authorization::intact_chain(id,&self.grants,realm,generation,at,&mut BTreeSet::new(),0)
                && self.root.as_ref().is_none_or(|root|g.authority_root_refs.iter().all(|reference|matches!(reference,AuthorityRootRef::RealmRoot {realm_id,authority_event_ref,authority_generation} if realm_id==realm && authority_event_ref==&root.authority_event_ref && *authority_generation==generation))))
                .then_some(g)
        });
        let result = evaluate_grants(
            &AuthorizationOperation {
                actor,
                actions: &actions,
                target: &target,
                at,
                facts: &facts,
            },
            effective,
        );
        !result.unreserved().is_empty()
    }
}
fn fold(history: &History, through: u64) -> PersistenceResult<Cut> {
    let mut cut = history.base.clone();
    for (c, e) in history
        .rows
        .iter()
        .take_while(|(c, _)| c.stream_position <= through)
    {
        cut.apply(c, e)?;
    }
    Ok(cut)
}
async fn declared_commit(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
    id: &RealmCommitId,
    sent_at: DateTime<Utc>,
) -> PersistenceResult<Option<RealmCommit>> {
    #[derive(diesel::QueryableByName)]
    struct CommitRow {
        #[diesel(sql_type=Jsonb)]
        commit_json: serde_json::Value,
    }
    let row = diesel::sql_query(
        "SELECT commit_json FROM realm_commits WHERE commit_id=$1 AND stream_key=$2",
    )
    .bind::<Text, _>(id.as_str())
    .bind::<Text, _>(crate::authority_commit::stream_key(stream)?)
    .get_result::<CommitRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(None) };
    let commit: RealmCommit = serde_json::from_value(row.commit_json).map_err(unavailable)?;
    commit.validate_shape().map_err(unavailable)?;
    Ok((commit.commit_id == *id
        && commit.stream_ref == *stream
        && commit.realm_id == *stream.realm_id()
        && commit.committed_at <= sent_at)
        .then_some(commit))
}

const PRODUCT_ACTIONS: [&str; 2] = [
    arkret_wire::CapabilityActionId::MESSAGE_STREAM_SEND,
    arkret_wire::CapabilityActionId::MESSAGE_CREATE,
];

fn qualified_chain(
    cut: &Cut,
    id: &GrantId,
    realm: &RealmId,
    at: DateTime<Utc>,
    owned: Option<&IssuerAuthorityRef>,
    visiting: &mut BTreeSet<GrantId>,
    depth: usize,
) -> bool {
    if depth > 4 || !visiting.insert(id.clone()) {
        return false;
    }
    let generation = cut
        .root
        .as_ref()
        .map(|r| r.authority_generation)
        .or(cut.snapshot_root_generation);
    let root_matches = |r: &AuthorityRootRef| match r {
        AuthorityRootRef::RealmRoot {
            realm_id,
            authority_event_ref,
            authority_generation,
        } => {
            realm_id == realm
                && Some(*authority_generation) == generation
                && cut
                    .root
                    .as_ref()
                    .is_none_or(|root| &root.authority_event_ref == authority_event_ref)
        }
        AuthorityRootRef::OwnedAgent {
            realm_id,
            controller_account_id,
            controller_join_event_id,
            agent_join_event_id,
        } => {
            matches!(owned, Some(IssuerAuthorityRef::OwnedAgent { realm_id: own_realm, controller_account_id: controller, controller_join_event_id: controller_join, agent_join_event_id: agent_join }) if realm_id == own_realm && controller_account_id == controller && controller_join_event_id == controller_join && agent_join_event_id == agent_join)
        }
    };
    let valid = cut.grants.get(id).is_some_and(|grant| {
        grant.realm_id.as_ref() == Some(realm)
        && crate::capability_grant_current_results::grant_is_active_at(grant, at)
        && !grant.issuer_authority_refs.is_empty() && !grant.authority_root_refs.is_empty()
        && grant.authority_root_refs.iter().all(root_matches)
        && grant.issuer_authority_refs.iter().all(|reference| match reference {
            IssuerAuthorityRef::OwnedAgent { .. } => depth == 0 && Some(reference) == owned && grant.authority_depth == 1,
            IssuerAuthorityRef::RealmRoot { realm_id, authority_event_ref, authority_generation } => grant.authority_root_refs.iter().any(|r| matches!(r, AuthorityRootRef::RealmRoot { realm_id: root_realm, authority_event_ref: root_event, authority_generation: root_generation } if root_realm == realm_id && root_event == authority_event_ref && root_generation == authority_generation)),
            IssuerAuthorityRef::Grant { grant_id } => cut.grants.get(grant_id).is_some_and(|parent| matches!(&parent.subject, CapabilitySubject::Actor(subject) if subject == &grant.issuer_id) && !parent.issuer_authority_refs.iter().any(|r| matches!(r, IssuerAuthorityRef::OwnedAgent { .. }))) && qualified_chain(cut, grant_id, realm, at, None, visiting, depth + 1),
        })
    });
    visiting.remove(id);
    valid
}

fn product_grants(
    cut: &Cut,
    realm: &RealmId,
    actor: &ActorId,
    at: DateTime<Utc>,
    owned: Option<&IssuerAuthorityRef>,
) -> Vec<CapabilityGrant> {
    cut.grants
        .iter()
        .filter(|(id, grant)| {
            matches!(&grant.subject, CapabilitySubject::Actor(subject) if subject == actor)
                && grant
                    .actions
                    .iter()
                    .any(|action| PRODUCT_ACTIONS.contains(&action.as_str()))
                && qualified_chain(cut, id, realm, at, owned, &mut BTreeSet::new(), 0)
        })
        .map(|(_, grant)| grant.clone())
        .collect()
}

fn product_owner_actions(historical: &Cut, current: &Cut, actor: &ActorId) -> Vec<String> {
    let controller = |cut: &Cut| {
        cut.root
            .as_ref()
            .map(|r| &r.controller_actor_id)
            .or(cut.snapshot_root_controller.as_ref())
            .cloned()
    };
    if controller(historical).as_ref() != Some(actor) || controller(current).as_ref() != Some(actor)
    {
        return Vec::new();
    }
    PRODUCT_ACTIONS
        .into_iter()
        .filter(|action| arkret_policy::owner_may_author_action(action).unwrap_or(false))
        .map(str::to_owned)
        .collect()
}

fn product_member_effective(scope: &ScopeRef, parent: &Cut, scoped: &Cut, actor: &ActorId) -> bool {
    if !parent.joined(actor) {
        return false;
    }
    if !matches!(scope, ScopeRef::Circle { .. }) {
        return true;
    }
    let key = actor.to_string();
    scoped.joined(actor)
        && parent
            .member_revisions
            .get(&key)
            .is_some_and(|revision| scoped.circle_parent_joins.get(&key) == Some(revision))
}

async fn product_material(
    conn: &mut AsyncPgConnection,
    query: &SignalScopeAuthorityQuery<'_>,
    historical_parent: &Cut,
    current_parent: &Cut,
    historical_scope: &Cut,
    current_scope: &Cut,
    current_realm_head: &arkret_wire::CommitStreamHead,
    current_scope_head: &arkret_wire::CommitStreamHead,
) -> PersistenceResult<Option<Box<arkret_models_collaboration::SignalProductAuthority>>> {
    use arkret_models_collaboration::{SignalAgentProductAuthority, SignalProductAuthority};
    let realm = query.scope.realm_id();
    let mut owned = None;
    let agent = if let Some((controller, key_scope)) = query.product_agent {
        if key_scope.actions.is_empty() || key_scope.resources.is_empty() {
            return Ok(None);
        }
        let verified = crate::realm_authorization_cut::owned_controller_snapshot_in_connection(
            conn,
            realm,
            query.sender,
            query.at,
        )
        .await?;
        let controller_actor = ActorId::account(controller.clone());
        if verified.as_ref() != Some(&controller_actor)
            || !product_member_effective(
                query.scope,
                historical_parent,
                historical_scope,
                &controller_actor,
            )
            || !product_member_effective(
                query.scope,
                current_parent,
                current_scope,
                &controller_actor,
            )
            || historical_parent
                .member_revisions
                .get(&controller_actor.to_string())
                != current_parent
                    .member_revisions
                    .get(&controller_actor.to_string())
            || historical_parent
                .member_revisions
                .get(&query.sender.to_string())
                != current_parent
                    .member_revisions
                    .get(&query.sender.to_string())
        {
            return Ok(None);
        }
        owned = crate::realm_authorization_cut::owned_source_in_connection(
            conn,
            realm,
            query.sender,
            query.at,
            false,
        )
        .await?;
        if owned.is_none() {
            return Ok(None);
        }
        let policies = |parent: &Cut, scope: &Cut| {
            let mut policies = parent.policies.values().cloned().collect::<Vec<_>>();
            if matches!(query.scope, ScopeRef::Circle { .. }) {
                policies.extend(scope.policies.values().cloned());
            }
            policies
        };
        Some(SignalAgentProductAuthority {
            controller_account_id: controller.clone(),
            controller_grants: product_grants(
                historical_parent,
                realm,
                &controller_actor,
                query.sent_at,
                None,
            ),
            current_controller_grants: product_grants(
                current_parent,
                realm,
                &controller_actor,
                query.at,
                None,
            ),
            controller_owner_actions: product_owner_actions(
                historical_parent,
                current_parent,
                &controller_actor,
            ),
            historical_management_policies: policies(historical_parent, historical_scope),
            current_management_policies: policies(current_parent, current_scope),
            key_scope: key_scope.clone(),
        })
    } else {
        None
    };
    // Direct profile permission has already been established from its accepted
    // stable pair and both independent contact permissions in this transaction.
    let direct = historical_parent.direct && current_parent.direct;
    let material = SignalProductAuthority {
        authority_commit_id: query.authority_commit_id.clone(),
        parent_realm_authority_commit_id: query.parent_realm_authority_commit_id.cloned(),
        current_realm_head: current_realm_head.clone(),
        current_scope_head: current_scope_head.clone(),
        sent_at: query.sent_at,
        grants: if direct {
            Vec::new()
        } else {
            product_grants(
                historical_parent,
                realm,
                query.sender,
                query.sent_at,
                owned.as_ref(),
            )
        },
        current_grants: if direct {
            Vec::new()
        } else {
            product_grants(
                current_parent,
                realm,
                query.sender,
                query.at,
                owned.as_ref(),
            )
        },
        owner_actions: if direct {
            Vec::new()
        } else {
            product_owner_actions(historical_parent, current_parent, query.sender)
        },
        profile_actions: if direct {
            vec![arkret_wire::CapabilityActionId::MESSAGE_CREATE.to_owned()]
        } else {
            Vec::new()
        },
        agent,
    };
    if material.agent.as_ref().is_some_and(|a| {
        a.controller_grants.len() > 64
            || a.current_controller_grants.len() > 64
            || a.historical_management_policies.len() > 64
            || a.current_management_policies.len() > 64
    }) || material.grants.len() > 64
        || material.current_grants.len() > 64
        || arkret_canonical::canonical_json_bytes(&material)
            .map_err(unavailable)?
            .len()
            > SignalProductAuthority::MAX_CANONICAL_BYTES
    {
        return Ok(None);
    }
    Ok(Some(Box::new(material)))
}

pub(crate) async fn read(
    pool: &PgPool,
    query: SignalScopeAuthorityQuery<'_>,
) -> PersistenceResult<Option<SignalScopeAuthority>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
        read_in_connection(conn, query).await.map_err(Into::into)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    query: SignalScopeAuthorityQuery<'_>,
) -> PersistenceResult<Option<SignalScopeAuthority>> {
    let SignalScopeAuthorityQuery {
        scope,
        authority_commit_id,
        parent_realm_authority_commit_id,
        sender,
        signal_class: class,
        sent_at,
        at,
        include_product_authority,
        product_agent: _,
    } = query;
    let realm = scope.realm_id();
    let stream = CommitStreamRef::from_scope(scope, None).map_err(unavailable)?;
    let Some(declared) = declared_commit(conn, &stream, authority_commit_id, sent_at).await? else {
        return Ok(denied("declared scope Commit is not held"));
    };
    let rows = history(conn, &stream, declared.stream_position).await?;
    if rows.head.commit_id != declared.commit_id
        || rows.head.stream_position != declared.stream_position
    {
        return Err(unavailable("selected historical cut is not covered"));
    }
    let historical = fold(&rows, declared.stream_position)?;
    let current_rows = history(conn, &stream, u64::MAX).await?;
    let current = fold(&current_rows, current_rows.head.stream_position)?;
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let realm_rows = history(conn, &realm_stream, u64::MAX).await?;
    let parent = fold(&realm_rows, realm_rows.head.stream_position)?;
    let parent_historical = match (scope, parent_realm_authority_commit_id) {
        (ScopeRef::Realm { .. }, None) => historical.clone(),
        (ScopeRef::Circle { .. }, Some(id)) => {
            let Some(cut) = declared_commit(conn, &realm_stream, id, sent_at).await? else {
                return Ok(denied("declared parent Commit is not held"));
            };
            let rows = history(conn, &realm_stream, cut.stream_position).await?;
            if rows.head.commit_id != cut.commit_id
                || rows.head.stream_position != cut.stream_position
            {
                return Err(unavailable("selected parent cut is not covered"));
            }
            fold(&rows, cut.stream_position)?
        }
        _ => return Ok(denied("parent cut presence differs from scope")),
    };
    if let ScopeRef::Circle { circle_id, .. } = scope {
        use arkret_models_collaboration::governance::circle::CircleState;
        if parent_historical.circle_states.get(circle_id) != Some(&CircleState::Active)
            || parent.circle_states.get(circle_id) != Some(&CircleState::Active)
        {
            return Ok(denied("historical or current Circle is not active"));
        }
    }
    if !parent.joined(sender)
        || parent.terminal
        || parent.frozen
        || parent.archived
        || !historical.joined(sender)
        || !current.joined(sender)
    {
        return Ok(denied(
            "historical or current sender membership is not active",
        ));
    }
    let circle = matches!(scope, ScopeRef::Circle { .. });
    if circle
        && (!parent_historical.joined(sender)
            || historical.circle_parent_joins.get(&sender.to_string())
                != parent_historical.member_revisions.get(&sender.to_string())
            || current.circle_parent_joins.get(&sender.to_string())
                != parent.member_revisions.get(&sender.to_string())
            || !circle_parent_join_is_current(conn, realm, &historical, sender).await?
            || !circle_parent_join_is_current(conn, realm, &current, sender).await?)
    {
        return Ok(denied("Circle parent join revision is no longer exact"));
    }
    // Scope owns membership and MLS; only the parent Realm owns grants.
    // The explicit vector of cuts avoids inventing a cross-stream order.
    let scope_class = if circle { SignalClass::Session } else { class };
    if !historical.permits(realm, scope, sender, scope_class, sent_at)
        || !current.permits(realm, scope, sender, scope_class, at)
        || !parent_historical.permits(realm, scope, sender, class, sent_at)
        || !parent.permits(realm, scope, sender, class, at)
    {
        return Ok(denied("historical or current class action is not eligible"));
    }
    if current.direct {
        let profile =
            crate::direct_conversation_admission::direct_conversation_realm_in_connection(
                conn, realm,
            )
            .await?
            .ok_or_else(|| unavailable("accepted founding source missing"))?;
        let Some(pair) = profile.pair() else {
            return Ok(None);
        };
        if pair.len() != 2
            || !pair.contains(&sender)
            || current
                .members
                .values()
                .map(|(a, _)| a.to_string())
                .collect::<BTreeSet<_>>()
                != pair.iter().map(|a| a.to_string()).collect::<BTreeSet<_>>()
        {
            return Ok(None);
        }
        if !profile.pair_grants_direct_message_snapshot(conn).await? {
            return Ok(None);
        }
    }
    let mut recipients = current
        .members
        .values()
        .filter(|(_, m)| m == "join")
        .map(|(a, _)| a.clone())
        .collect::<Vec<_>>();
    let mut eligible = Vec::new();
    for recipient in recipients {
        if crate::authority_commit::accepted_current_member_joined_in_connection(
            conn, realm, &recipient,
        )
        .await?
            && (!matches!(scope, ScopeRef::Circle { .. })
                || circle_parent_join_is_current(conn, realm, &current, &recipient).await?)
        {
            eligible.push(recipient);
        }
    }
    recipients = eligible;
    if !recipients.contains(sender) {
        return Ok(denied(
            "sender is not in the accepted current recipient set",
        ));
    }
    // Linked parent membership is authoritative only on the target's current
    // governing Station. Its sources are independently complete accepted cuts.
    if let Some(join) = parent.policy.as_ref().and_then(|p| p.join_policy.as_ref()) {
        use arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate;
        let mut source_groups = Vec::<BTreeSet<String>>::new();
        for gate in &join.gates {
            let JoinPolicyGate::ParentMembership {
                membership_source_realm_ids,
                ..
            } = gate
            else {
                continue;
            };
            let mut joined = BTreeSet::new();
            for source in membership_source_realm_ids {
                if parent
                    .links
                    .get(&(source.clone(), "join_gate_from".to_owned()))
                    .map(String::as_str)
                    != Some("active")
                {
                    return Ok(None);
                }
                #[derive(diesel::QueryableByName)]
                struct CoGoverned {
                    #[diesel(sql_type=diesel::sql_types::Bool)]
                    same: bool,
                }
                let same=diesel::sql_query("SELECT a.service_id=b.service_id AS same FROM realm_authorities a JOIN realm_authorities b ON b.realm_id=$2 WHERE a.realm_id=$1")
                    .bind::<Text,_>(realm.as_str()).bind::<Text,_>(source.as_str()).get_result::<CoGoverned>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if !same.is_some_and(|row| row.same) {
                    return Err(unavailable("parent membership authority differs"));
                }
                let source_rows = history(
                    conn,
                    &CommitStreamRef::Realm {
                        realm_id: source.clone(),
                    },
                    u64::MAX,
                )
                .await?;
                {
                    joined.extend(
                        fold(&source_rows, source_rows.head.stream_position)?
                            .members
                            .into_values()
                            .filter(|(_, m)| m == "join")
                            .map(|(a, _)| a.to_string()),
                    );
                }
            }
            source_groups.push(joined);
        }
        if !source_groups.is_empty() {
            let all = match join.combinator.as_str() {
                "all" => true,
                "any" => false,
                _ => return Err(unavailable("unknown parent membership combinator")),
            };
            recipients.retain(|actor| {
                if all {
                    source_groups
                        .iter()
                        .all(|sources| sources.contains(&actor.to_string()))
                } else {
                    source_groups
                        .iter()
                        .any(|sources| sources.contains(&actor.to_string()))
                }
            });
            if !recipients.contains(sender) {
                return Ok(None);
            }
        }
    }
    let current_mls = match current.mls_current.clone() {
        Some(current) => current,
        None => {
            let key = String::from_utf8(
                arkret_canonical::canonical_json_bytes(scope).map_err(unavailable)?,
            )
            .map_err(unavailable)?;
            let row =
                diesel::sql_query("SELECT value FROM mls_group_current_results WHERE scope_key=$1")
                    .bind::<Text, _>(&key)
                    .get_result::<ValueRow>(conn)
                    .await
                    .optional()
                    .map_err(PersistenceError::database)?;
            let Some(row) = row else {
                return Ok(denied("accepted current MLS is not held"));
            };
            serde_json::from_value(row.value).map_err(unavailable)?
        }
    };
    let Some(historical_mls_event_ref) = historical.mls.clone() else {
        return Ok(denied("declared cut predates MLS activation"));
    };
    if current.mls.as_ref() != Some(&current_mls.current_mls_commit_event_ref)
        || current.genesis.as_ref() != Some(&current_mls.genesis_event_ref)
        || current.mls_epoch != Some(current_mls.epoch)
        || current_mls.effective_scope != *scope
        || current_mls.covered_key_access_revision < current_mls.current_key_access_revision
    {
        return Ok(denied(
            "current MLS scope, epoch or key-access revision differs",
        ));
    }
    let cipher_suite = current_mls.cipher_suite.as_str().to_owned();
    if current
        .cipher
        .as_ref()
        .is_some_and(|cipher| cipher != &cipher_suite)
    {
        return Err(unavailable("MLS suite differs from its accepted genesis"));
    }
    let product_authority = if include_product_authority {
        product_material(
            conn,
            &query,
            &parent_historical,
            &parent,
            &historical,
            &current,
            &realm_rows.head,
            &current_rows.head,
        )
        .await
        .unwrap_or_else(|error| {
            tracing::debug!(%error, "Signal product material is unavailable");
            None
        })
    } else {
        None
    };
    Ok(Some(SignalScopeAuthority {
        recipient_actors: recipients,
        historical_mls_event_ref,
        current_mls,
        cipher_suite,
        current_realm_head: realm_rows.head,
        current_scope_head: current_rows.head,
        product_authority,
    }))
}

async fn circle_parent_join_is_current(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    cut: &Cut,
    actor: &ActorId,
) -> PersistenceResult<bool> {
    let Some(revision) = cut.circle_parent_joins.get(&actor.to_string()) else {
        return Ok(false);
    };
    #[derive(diesel::QueryableByName)]
    struct Present {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        present: bool,
    }
    let value = serde_json::json!({"membership":"join", "parent_membership_revision": revision});
    diesel::sql_query("SELECT circle_member_parent_join_current($1,$2,$3) AS present")
        .bind::<Text, _>(realm.as_str())
        .bind::<Text, _>(actor.to_string())
        .bind::<Jsonb, _>(value)
        .get_result::<Present>(&mut *conn)
        .await
        .map(|row| row.present)
        .map_err(PersistenceError::database)
}

pub(crate) async fn recipient_realms(
    pool: &PgPool,
    actor: &ActorId,
) -> PersistenceResult<Vec<RealmId>> {
    #[derive(diesel::QueryableByName)]
    struct RealmRow {
        #[diesel(sql_type=Text)]
        realm_id: String,
    }
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(conn).await.map_err(PersistenceError::database)?;
        let rows=diesel::sql_query("SELECT realm_id FROM member_state_current_results WHERE member_id=$1 AND membership='join' ORDER BY realm_id")
            .bind::<Text,_>(actor.to_string()).load::<RealmRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mut result=Vec::new();
        for row in rows {
            let realm=RealmId::new(row.realm_id).map_err(unavailable)?;
            if crate::authority_commit::accepted_current_member_joined_in_connection(conn,&realm,actor).await? {result.push(realm);}
        }
        Ok(result)
    }).await.map_err(PgTransactionError::into_persistence)
}

#[cfg(test)]
mod typed_replay_tests {
    use serde_json::json;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x61; 32],
        ))
    }
    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }
    fn event(kind: EventKind, payload: serde_json::Value) -> Event {
        arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id(),
            },
            ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:signal-member.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:signal-station.example").unwrap(),
            )),
            payload,
            at(),
        )
        .unwrap()
    }
    fn commit(event: &arkret_wire::Event, position: u64) -> arkret_wire::RealmCommit {
        arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
            realm_id: realm_id(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            stream_position: position,
            previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([0x09; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x61; 32],
                ),
            ),
            committed_at: at(),
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:mls-bump-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at(),
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        }
    }

    #[test]
    fn product_controller_circle_membership_cannot_expand_realm_authority() {
        let actor = event(EventKind::MemberState, json!({})).actor_id;
        let key = actor.to_string();
        let mut parent = Cut::default();
        parent
            .members
            .insert(key.clone(), (actor.clone(), "join".into()));
        let revision = arkret_wire::CurrentRevision {
            commit_id: RealmCommitId::from_digest([3; 32]),
            stream_position: 3,
        };
        parent
            .member_revisions
            .insert(key.clone(), revision.clone());
        let realm = ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let circle = ScopeRef::Circle {
            realm_id: realm_id(),
            circle_id: arkret_wire::CircleId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [4; 32],
            )),
        };
        let mut scoped = Cut::default();
        assert!(product_member_effective(&realm, &parent, &scoped, &actor));
        assert!(!product_member_effective(&circle, &parent, &scoped, &actor));
        scoped
            .members
            .insert(key.clone(), (actor.clone(), "join".into()));
        assert!(!product_member_effective(&circle, &parent, &scoped, &actor));
        scoped.circle_parent_joins.insert(key.clone(), revision);
        assert!(product_member_effective(&circle, &parent, &scoped, &actor));
        parent
            .member_revisions
            .get_mut(&key)
            .unwrap()
            .stream_position += 1;
        assert!(!product_member_effective(&circle, &parent, &scoped, &actor));
        let revision = parent.member_revisions[&key].clone();
        scoped.circle_parent_joins.insert(key.clone(), revision);
        assert!(product_member_effective(&circle, &parent, &scoped, &actor));
        scoped.members.get_mut(&key).unwrap().1 = "leave".into();
        assert!(!product_member_effective(&circle, &parent, &scoped, &actor));
        assert!(!product_member_effective(
            &realm,
            &Cut::default(),
            &scoped,
            &actor,
        ));
    }

    #[test]
    fn product_graph_requires_exact_root_parent_and_owned_join_source() {
        let actor = event(EventKind::MemberState, json!({})).actor_id;
        let id = GrantId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [7; 32],
        ));
        let root_event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [8; 32]);
        let root_ref = json!({"kind":"realm_root", "realm_id":realm_id(), "authority_event_ref":root_event, "authority_generation":0});
        let grant: CapabilityGrant = serde_json::from_value(json!({"id":id,"schema":"ak.schema.capability.v1","realm_id":realm_id(),"issuer_id":actor,"subject":actor,"actions":PRODUCT_ACTIONS,"resources":[{"kind":"realm","realm_id":realm_id()}],"issuer_authority_refs":[root_ref],"authority_root_refs":[root_ref],"authority_depth":1,"status":"active","issued_at":arkret_canonical::format_timestamp_canonical(at())})).unwrap();
        let mut cut = Cut {
            snapshot_root_generation: Some(0),
            snapshot_root_controller: Some(actor.clone()),
            ..Cut::default()
        };
        cut.grants.insert(id.clone(), grant);
        assert_eq!(
            product_grants(&cut, &realm_id(), &actor, at(), None).len(),
            1
        );
        cut.snapshot_root_generation = Some(1);
        assert!(product_grants(&cut, &realm_id(), &actor, at(), None).is_empty());
        cut.snapshot_root_generation = Some(0);
        let controller = actor.as_account_id().unwrap().clone();
        let owned = IssuerAuthorityRef::OwnedAgent {
            realm_id: realm_id(),
            controller_account_id: controller.clone(),
            controller_join_event_id: root_event.clone(),
            agent_join_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [9; 32],
            ),
        };
        let owned_root: AuthorityRootRef =
            serde_json::from_value(serde_json::to_value(&owned).unwrap()).unwrap();
        let grant = cut.grants.get_mut(&id).unwrap();
        grant.issuer_authority_refs = vec![owned.clone()];
        grant.authority_root_refs = vec![owned_root];
        assert_eq!(
            product_grants(&cut, &realm_id(), &actor, at(), Some(&owned)).len(),
            1
        );
        assert!(product_grants(&cut, &realm_id(), &actor, at(), None).is_empty());
        let wrong = IssuerAuthorityRef::OwnedAgent {
            realm_id: realm_id(),
            controller_account_id: controller,
            controller_join_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [10; 32],
            ),
            agent_join_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [9; 32],
            ),
        };
        assert!(product_grants(&cut, &realm_id(), &actor, at(), Some(&wrong)).is_empty());
        cut.grants.get_mut(&id).unwrap().status = CapabilityGrantStatus::Revoked;
        assert!(product_grants(&cut, &realm_id(), &actor, at(), Some(&owned)).is_empty());
    }

    #[test]
    fn member_replay_preserves_all_closed_states_and_commit_revision() {
        for (position, membership) in ["join", "knock", "leave", "ban"].into_iter().enumerate() {
            let actor = event(EventKind::MemberState, json!({})).actor_id;
            let event = event(
                EventKind::MemberState,
                json!({"member_id": actor, "membership": membership}),
            );
            let commit = commit(&event, position as u64 + 1);
            let mut cut = Cut::default();
            cut.apply(&commit, &event).unwrap();
            assert_eq!(cut.members[&actor.to_string()].1, membership);
            assert_eq!(
                cut.member_revisions[&actor.to_string()].commit_id,
                commit.commit_id
            );
            assert_eq!(
                cut.member_revisions[&actor.to_string()].stream_position,
                commit.stream_position
            );
            assert_eq!(cut.joined(&actor), membership == "join");
        }
    }

    #[test]
    fn malformed_member_replay_cannot_install_authority() {
        let actor = event(EventKind::MemberState, json!({})).actor_id;
        for payload in [
            json!({"member_id": actor}),
            json!({"member_id": actor, "membership": "active"}),
            json!({"member_id": actor, "membership": "join", "unexpected": true}),
        ] {
            let event = event(EventKind::MemberState, payload);
            let mut cut = Cut::default();
            assert!(cut.apply(&commit(&event, 1), &event).is_err());
            assert!(cut.members.is_empty());
            assert!(cut.member_revisions.is_empty());
        }
    }
}
