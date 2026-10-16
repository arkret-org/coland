//! One durable boundary for an accepted Event batch.
//!
//! Admission decides; this module installs. Every write an accepted Event
//! produces — the queued producer Event, its authority-signed `RealmCommit`,
//! the installed MLS successor and its recipient Welcome deliveries, the
//! business projections, the federation outbox rows, the idempotency
//! reservation, and the Applet / Agent / moderation batch effects — lands in a
//! single PostgreSQL transaction. A caller therefore observes either the
//! complete accepted operation or none of it, and a rolled-back commit leaves
//! no projection a reader could mistake for accepted state.

use coland_storage::{
    AuthorityCommitWriteOutcome, EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest,
    EventCommitUnitOfWork, PersistenceError, PersistenceResult, ids,
};
use diesel::sql_types::{Array, BigInt, Binary, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::agent_draft_pending_intents::{
    AgentDraftConsumptionLock, lock_agent_draft_consumption_source, mark_agent_draft_consumed,
};
use crate::authority_commit::{
    queue_event_in_connection, realm_state_snapshot_material_in_connection,
};
use crate::capability_grant_current_results::commit_realm_authority_root_current_result_in_connection;
use crate::device_revocations::{
    commit_revocation_in_connection, ensure_gate_allowed_in_transaction,
};
use crate::federation::enqueue_federation_outbox_in_connection;
use crate::idempotency::record_idempotency_in_connection;
use crate::projection::append_projection_batch_in_connection;
use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(Clone)]
pub struct PgEventCommitUnitOfWork {
    pool: PgPool,
}

impl PgEventCommitUnitOfWork {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(diesel::QueryableByName)]
struct AcceptedFlagRow {
    #[diesel(sql_type = Bool)]
    accepted: bool,
}

#[derive(diesel::QueryableByName)]
struct ContactMirrorCommitRow {
    #[diesel(sql_type = Text)]
    target_holder_principal_id: String,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

const MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

fn enforce_inline_snapshot_capacity(
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<()> {
    let bytes =
        arkret_canonical::canonical_json_bytes(snapshot).map_err(PersistenceError::database)?;
    if bytes.len() > MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES {
        return Err(PersistenceError::Conflict(
            "snapshot_capacity_exceeded: candidate Realm snapshot exceeds 8 MiB".to_owned(),
        ));
    }
    Ok(())
}

async fn enforce_realm_snapshot_capacity_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    verification_method: &arkret_wire::DidUrl,
    created_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let material = realm_state_snapshot_material_in_connection(conn, realm_id)
        .await?
        .ok_or_else(|| {
            PersistenceError::Internal(
                "accepted Realm has no durable authority snapshot material".to_owned(),
            )
        })?;
    let snapshot = arkret_wire::RealmStateSnapshot {
        snapshot_id: arkret_wire::RealmSnapshotId::from_digest([0; 32]),
        realm_id: material.realm_id,
        governance_generation: material.governance_generation,
        visible_stream_heads: material.visible_stream_heads,
        current_state_entries: material.current_state_entries,
        retention_and_history_floor: material.retention_and_history_floor,
        created_at: arkret_canonical::normalize_timestamp_canonical(created_at),
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmSnapshot,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: verification_method.clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            created_at: arkret_canonical::normalize_timestamp_canonical(created_at),
            sig: arkret_wire::Base64UrlString::new("A".repeat(86))
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        },
    };
    enforce_inline_snapshot_capacity(&snapshot)
}

#[cfg(test)]
mod snapshot_capacity_tests {
    use chrono::TimeZone as _;

    use super::*;

    fn snapshot(payload_bytes: usize) -> arkret_wire::RealmStateSnapshot {
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let created_at = chrono::Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        arkret_wire::RealmStateSnapshot {
            snapshot_id: arkret_wire::RealmSnapshotId::from_digest([2; 32]),
            realm_id,
            governance_generation: 0,
            visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 0,
                commit_id: arkret_wire::RealmCommitId::from_digest([3; 32]),
            }],
            current_state_entries: vec![arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::RealmProfile,
                source_stream_ref: stream_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: arkret_wire::RealmCommitId::from_digest([3; 32]),
                    stream_position: 0,
                },
                value: serde_json::json!({"payload": "x".repeat(payload_bytes)}),
            }],
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 0,
                }],
            },
            created_at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmSnapshot,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:station.example#notary-key".to_owned(),
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "00".repeat(32)))
                    .unwrap(),
                created_at,
                sig: arkret_wire::Base64UrlString::new("A".repeat(86)).unwrap(),
            },
        }
    }

    #[test]
    fn exact_snapshot_capacity_is_accepted_and_one_byte_more_is_rejected() {
        let base = arkret_canonical::canonical_json_bytes(&snapshot(0))
            .unwrap()
            .len();
        let exact_payload = MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES - base;
        let exact = snapshot(exact_payload);
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&exact)
                .unwrap()
                .len(),
            MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES
        );
        enforce_inline_snapshot_capacity(&exact).unwrap();

        let error = enforce_inline_snapshot_capacity(&snapshot(exact_payload + 1)).unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::SnapshotCapacityExceeded)
        );
    }
}

#[derive(diesel::QueryableByName)]
struct AppletNamespaceClaimRow {
    #[diesel(sql_type = Text)]
    domain: String,
    #[diesel(sql_type = Text)]
    pattern: String,
    #[diesel(sql_type = Bool)]
    exclusive: bool,
}

#[derive(diesel::QueryableByName)]
struct AppletAdmissionRecordRow {
    #[diesel(sql_type = Jsonb)]
    record: serde_json::Value,
}

#[derive(diesel::QueryableByName)]
struct RelationCurrentResultRow {
    #[diesel(sql_type = Text)]
    relation_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(diesel::QueryableByName)]
struct ParentMembershipAuthorityRow {
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(diesel::QueryableByName)]
struct ParentMembershipPolicyRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(diesel::QueryableByName)]
struct ParentMembershipLinkRow {
    #[diesel(sql_type = Text)]
    status: String,
}

#[derive(diesel::QueryableByName)]
struct ParentMembershipMemberRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

enum RelationCurrentResultMutation {
    Create(arkret_models_collaboration::events_payloads::RelationCreatePayload),
    Update(arkret_models_collaboration::events_payloads::RelationUpdatePayload),
    Tombstone(arkret_models_collaboration::events_payloads::RelationTombstonePayload),
}

fn conflict(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(detail.into())
}

fn gate_check_failed() -> PersistenceError {
    conflict("gate_check_failed")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParentMembershipCombinator {
    All,
    Any,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParentMembershipDependencies {
    combinator: ParentMembershipCombinator,
    source_groups: Vec<Vec<arkret_wire::RealmId>>,
    sources: Vec<arkret_wire::RealmId>,
}

fn parent_membership_dependencies(
    join_policy: &serde_json::Value,
) -> PersistenceResult<Option<ParentMembershipDependencies>> {
    let Some(gates) = join_policy
        .get("gates")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let mut source_groups = Vec::new();
    for gate in gates {
        if gate.get("kind").and_then(serde_json::Value::as_str) != Some("parent_membership") {
            continue;
        }
        let raw_sources = gate
            .get("membership_source_realm_ids")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(gate_check_failed)?;
        let mut group = Vec::with_capacity(raw_sources.len());
        for source in raw_sources {
            let source = source
                .as_str()
                .ok_or_else(gate_check_failed)
                .and_then(|source| {
                    arkret_wire::RealmId::new(source.to_owned()).map_err(|_| gate_check_failed())
                })?;
            group.push(source);
        }
        if group.is_empty() {
            return Err(gate_check_failed());
        }
        group.sort_by_key(arkret_wire::RealmId::token_bytes);
        group.dedup();
        source_groups.push(group);
    }
    if source_groups.is_empty() {
        return Ok(None);
    }
    let combinator = match join_policy
        .get("combinator")
        .and_then(serde_json::Value::as_str)
    {
        Some("all") => ParentMembershipCombinator::All,
        Some("any") => ParentMembershipCombinator::Any,
        _ => return Err(gate_check_failed()),
    };
    let mut sources = source_groups.iter().flatten().cloned().collect::<Vec<_>>();
    sources.sort_by_key(arkret_wire::RealmId::token_bytes);
    sources.dedup();
    Ok(Some(ParentMembershipDependencies {
        combinator,
        source_groups,
        sources,
    }))
}

fn parent_membership_gate_satisfied(
    dependencies: &ParentMembershipDependencies,
    joined_sources: &std::collections::BTreeSet<arkret_wire::RealmId>,
) -> bool {
    let group_satisfied = |group: &Vec<arkret_wire::RealmId>| {
        group.iter().any(|source| joined_sources.contains(source))
    };
    match dependencies.combinator {
        ParentMembershipCombinator::All => dependencies.source_groups.iter().all(group_satisfied),
        ParentMembershipCombinator::Any => dependencies.source_groups.iter().any(group_satisfied),
    }
}

#[cfg(test)]
mod parent_membership_tests {
    use std::collections::BTreeSet;

    use super::{parent_membership_dependencies, parent_membership_gate_satisfied};

    const SOURCE_A: &str = "ak:realm:AehJkZSB3P7C-ch-biRjD2flKZh73AhHpbhFnxWBhjo1";
    const SOURCE_B: &str = "ak:realm:AYCKiTPA1bjQa3rIKg4O1PGpeq_EXPw1fnNCfHYhPsdG";

    fn policy(combinator: &str) -> serde_json::Value {
        serde_json::json!({
            "combinator": combinator,
            "gates": [
                {
                    "kind": "parent_membership",
                    "membership_source_realm_ids": [SOURCE_A]
                },
                {
                    "kind": "parent_membership",
                    "membership_source_realm_ids": [SOURCE_B]
                }
            ]
        })
    }

    #[test]
    fn all_parent_gates_require_a_join_in_every_source_group() {
        let dependencies = parent_membership_dependencies(&policy("all"))
            .unwrap()
            .unwrap();
        let only_a = BTreeSet::from([arkret_wire::RealmId::new(SOURCE_A.to_owned()).unwrap()]);
        assert!(!parent_membership_gate_satisfied(&dependencies, &only_a));
        let both = BTreeSet::from([
            arkret_wire::RealmId::new(SOURCE_A.to_owned()).unwrap(),
            arkret_wire::RealmId::new(SOURCE_B.to_owned()).unwrap(),
        ]);
        assert!(parent_membership_gate_satisfied(&dependencies, &both));
    }

    #[test]
    fn any_parent_gate_accepts_one_joined_source_group() {
        let dependencies = parent_membership_dependencies(&policy("any"))
            .unwrap()
            .unwrap();
        let only_a = BTreeSet::from([arkret_wire::RealmId::new(SOURCE_A.to_owned()).unwrap()]);
        assert!(parent_membership_gate_satisfied(&dependencies, &only_a));
    }
}

fn member_state_mutation(
    event: &arkret_wire::Event,
) -> PersistenceResult<Option<(String, String, serde_json::Value)>> {
    let (member_id, membership, value) = match event.kind {
        arkret_wire::EventKind::MemberState => {
            let member = event.payload.get("member_id").cloned().ok_or_else(|| {
                PersistenceError::SchemaViolation("member_state omits member_id".into())
            })?;
            let member: arkret_wire::ActorId = serde_json::from_value(member).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "member_state member_id is invalid: {error}"
                ))
            })?;
            let membership = event
                .payload
                .get("membership")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation("member_state omits membership".into())
                })?;
            (
                member.to_string(),
                membership.to_owned(),
                serde_json::json!({"membership": membership}),
            )
        }
        arkret_wire::EventKind::InviteAccept => (
            event.actor_id.to_string(),
            "join".to_owned(),
            serde_json::json!({"membership":"join"}),
        ),
        _ => return Ok(None),
    };
    Ok(Some((member_id, membership, value)))
}

pub(crate) async fn advisory_lock(
    conn: &mut AsyncPgConnection,
    key: String,
) -> PersistenceResult<()> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(key)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

async fn lock_authorities_for_parent_membership(
    conn: &mut AsyncPgConnection,
    target: &arkret_wire::RealmId,
    sources: &[arkret_wire::RealmId],
    expected_target: &coland_storage::CurrentRealmAuthority,
) -> PersistenceResult<()> {
    let mut realms = sources.to_vec();
    realms.push(target.clone());
    realms.sort_by_key(arkret_wire::RealmId::token_bytes);
    realms.dedup();
    let mut service_id = None::<String>;
    for realm in realms {
        let row = sql_query(
            "SELECT generation,service_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<ParentMembershipAuthorityRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(gate_check_failed)?;
        if realm == *target
            && (u64::try_from(row.generation).ok() != Some(expected_target.generation)
                || row.service_id != expected_target.service_id.as_str())
        {
            return Err(gate_check_failed());
        }
        match service_id.as_ref() {
            Some(expected) if expected != &row.service_id => return Err(gate_check_failed()),
            None => service_id = Some(row.service_id),
            _ => {}
        }
    }
    Ok(())
}

async fn locked_member_state(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member_id: &str,
) -> PersistenceResult<Option<String>> {
    advisory_lock(
        conn,
        format!("parent-membership:member:{}:{member_id}", realm_id.as_str()),
    )
    .await?;
    sql_query(
        "SELECT membership FROM member_state_current_results \
         WHERE realm_id=$1 AND member_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member_id)
    .get_result::<ParentMembershipMemberRow>(&mut *conn)
    .await
    .optional()
    .map(|row| row.map(|row| row.membership))
    .map_err(PersistenceError::database)
}

async fn validate_parent_membership_dependencies(
    conn: &mut AsyncPgConnection,
    target: &arkret_wire::RealmId,
    dependencies: &ParentMembershipDependencies,
    member_id: Option<&str>,
    require_parent_gate: bool,
) -> PersistenceResult<()> {
    for source in &dependencies.sources {
        advisory_lock(
            conn,
            format!(
                "parent-membership:link:{}:{}:join_gate_from",
                target.as_str(),
                source.as_str()
            ),
        )
        .await?;
        let row = sql_query(
            "SELECT status FROM realm_link_current_results \
             WHERE realm_id=$1 AND target_realm_id=$2 AND link_kind='join_gate_from' FOR UPDATE",
        )
        .bind::<Text, _>(target.as_str())
        .bind::<Text, _>(source.as_str())
        .get_result::<ParentMembershipLinkRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if row.as_ref().map(|row| row.status.as_str()) != Some("active") {
            return Err(gate_check_failed());
        }
    }
    let Some(member_id) = member_id else {
        return Ok(());
    };
    let mut joined_sources = std::collections::BTreeSet::new();
    for source in &dependencies.sources {
        if locked_member_state(conn, source, member_id)
            .await?
            .as_deref()
            == Some("join")
        {
            joined_sources.insert(source.clone());
        }
    }
    let parent_gate_satisfied = parent_membership_gate_satisfied(dependencies, &joined_sources);
    if require_parent_gate && !parent_gate_satisfied {
        return Err(gate_check_failed());
    }
    Ok(())
}

/// Lock and revalidate the complete co-governed `parent_membership` cut before
/// the canonical Event is queued. Any error therefore rolls back with zero
/// Event, RealmCommit, or current-result writes.
async fn prepare_parent_membership_transaction(
    conn: &mut AsyncPgConnection,
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    let event = &request.authority_commit.event;
    if event.kind == arkret_wire::EventKind::RealmPolicyBundle {
        let Some(join_policy) = event.payload.get("join_policy") else {
            return Ok(());
        };
        let Some(dependencies) = parent_membership_dependencies(join_policy)? else {
            return Ok(());
        };
        lock_authorities_for_parent_membership(
            conn,
            &event.realm_id,
            &dependencies.sources,
            &request.authority_commit.expected_authority,
        )
        .await?;
        advisory_lock(
            conn,
            format!("parent-membership:policy:{}", event.realm_id.as_str()),
        )
        .await?;
        validate_parent_membership_dependencies(conn, &event.realm_id, &dependencies, None, false)
            .await?;
        return Ok(());
    }

    if event.kind != arkret_wire::EventKind::MemberState
        || event
            .payload
            .get("membership")
            .and_then(serde_json::Value::as_str)
            != Some("join")
    {
        if request.parent_membership_admission.is_some() {
            return Err(PersistenceError::SchemaViolation(
                "parent-membership admission plan is attached to a non-join Event".into(),
            ));
        }
        return Ok(());
    }
    let member = event
        .payload
        .get("member_id")
        .cloned()
        .ok_or_else(gate_check_failed)
        .and_then(|value| {
            serde_json::from_value::<arkret_wire::ActorId>(value).map_err(|_| gate_check_failed())
        })?
        .to_string();

    // An unlocked first read discovers the authority lock set. The later
    // advisory + row lock and digest comparison make a concurrent policy
    // change a fail-closed retry rather than a mixed transaction cut.
    let candidate =
        sql_query("SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1")
            .bind::<Text, _>(event.realm_id.as_str())
            .get_result::<ParentMembershipPolicyRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
    let candidate_join_policy = candidate
        .as_ref()
        .and_then(|row| row.value.get("join_policy"));
    let candidate_dependencies = candidate_join_policy
        .map(parent_membership_dependencies)
        .transpose()?
        .flatten();
    let Some(dependencies) = candidate_dependencies else {
        if request.parent_membership_admission.is_some() {
            return Err(gate_check_failed());
        }
        return Ok(());
    };
    lock_authorities_for_parent_membership(
        conn,
        &event.realm_id,
        &dependencies.sources,
        &request.authority_commit.expected_authority,
    )
    .await?;

    // Existing join -> join updates are not entry admissions. Recheck under
    // the same target authority and member-key locks used by the mutation.
    if locked_member_state(conn, &event.realm_id, &member)
        .await?
        .as_deref()
        == Some("join")
    {
        return Ok(());
    }
    // Normal Self Event admission has no separately trusted service plan.
    // Derive its supported parent-only plan from the actual policy discovered
    // above, then re-prove that exact policy and every dependency under locks.
    let derived_plan;
    let plan = match request.parent_membership_admission.as_ref() {
        Some(plan) => plan,
        None => {
            let join_policy = candidate_join_policy.ok_or_else(gate_check_failed)?;
            let gates = join_policy
                .get("gates")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(gate_check_failed)?;
            if gates.is_empty()
                || gates.iter().any(|gate| {
                    gate.get("kind").and_then(serde_json::Value::as_str)
                        != Some("parent_membership")
                })
            {
                return Err(gate_check_failed());
            }
            derived_plan = coland_storage::ParentMembershipAdmissionCheck {
                expected_join_policy_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(join_policy)
                        .map_err(PersistenceError::database)?,
                )
                .map_err(|_| gate_check_failed())?,
                require_joined_source: true,
            };
            &derived_plan
        }
    };
    advisory_lock(
        conn,
        format!("parent-membership:policy:{}", event.realm_id.as_str()),
    )
    .await?;
    let current = sql_query(
        "SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<ParentMembershipPolicyRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(gate_check_failed)?;
    let join_policy = current
        .value
        .get("join_policy")
        .ok_or_else(gate_check_failed)?;
    let digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(join_policy).map_err(PersistenceError::database)?,
    )
    .map_err(|_| gate_check_failed())?;
    if digest != plan.expected_join_policy_digest
        || parent_membership_dependencies(join_policy)?.as_ref() != Some(&dependencies)
    {
        return Err(gate_check_failed());
    }
    validate_parent_membership_dependencies(
        conn,
        &event.realm_id,
        &dependencies,
        Some(&member),
        plan.require_joined_source,
    )
    .await
}

fn relation_current_result_mutation(
    event: &arkret_wire::Event,
) -> PersistenceResult<Option<RelationCurrentResultMutation>> {
    let payload = serde_json::to_value(&event.payload).map_err(|error| {
        PersistenceError::Internal(format!("Relation payload serialization failed: {error}"))
    })?;
    let invalid = |error: serde_json::Error| {
        PersistenceError::SchemaViolation(format!(
            "Relation payload violates its typed SDK contract: {error}"
        ))
    };
    match event.kind {
        arkret_wire::EventKind::RelationCreate => serde_json::from_value(payload)
            .map(RelationCurrentResultMutation::Create)
            .map(Some)
            .map_err(invalid),
        arkret_wire::EventKind::RelationUpdate => serde_json::from_value(payload)
            .map(RelationCurrentResultMutation::Update)
            .map(Some)
            .map_err(invalid),
        arkret_wire::EventKind::RelationTombstone => serde_json::from_value(payload)
            .map(RelationCurrentResultMutation::Tombstone)
            .map(Some)
            .map_err(invalid),
        _ => Ok(None),
    }
}

fn relation_domain_matches_value(
    domain: &arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomain,
    relation: &arkret_models_collaboration::objects::relation::Relation,
) -> bool {
    domain.relation_kind == relation.relation_kind
        && domain.from_ref == relation.from_ref
        && match domain.domain_kind {
            arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomainKind::Tuple => {
                domain.to_ref.as_ref() == Some(&relation.to_ref)
            }
            arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomainKind::From => {
                domain.to_ref.is_none()
            }
        }
}

fn relation_revision_matches(
    row: &RelationCurrentResultRow,
    expected: &arkret_wire::CurrentRevision,
) -> bool {
    row.current_commit_id == expected.commit_id.as_str()
        && u64::try_from(row.current_stream_position).ok() == Some(expected.stream_position)
}

fn relation_current_value_for_create(
    event: &arkret_wire::Event,
    payload: arkret_models_collaboration::events_payloads::RelationCreatePayload,
    lifecycle_time: chrono::DateTime<chrono::Utc>,
) -> arkret_models_collaboration::objects::relation::Relation {
    arkret_models_collaboration::objects::relation::Relation {
        schema: arkret_models_collaboration::objects::relation::Relation::SCHEMA.to_owned(),
        id: Some(arkret_wire::RelationId::from_event_id(&event.event_id)),
        realm_id: event.realm_id.clone(),
        scope_circle_id: payload.relation.scope_circle_id,
        effective_scope: Some(event.scope_ref.clone()),
        relation_kind: payload.relation.relation_kind,
        from_ref: payload.relation.from_ref,
        to_ref: payload.relation.to_ref,
        rank: payload.relation.rank,
        fields: payload.relation.fields,
        state: Some(arkret_wire::RelationState::Active),
        state_changed_at: None,
        created_by: event.actor_id.clone(),
        created_at: lifecycle_time,
        updated_by: None,
        updated_at: None,
    }
}

/// Write the `relation` typed current of one accepted `ak.relation.*`.
///
/// `authorize` is the governing Station's admission: the same-cut capability
/// verdict, source stream, Circle author and the scope/endpoint rules of
/// `relation.md` sections 3.2 and 4.4. A verified replica fold passes `false`
/// and only replays the primary-domain CAS the authority already decided.
pub(crate) async fn commit_relation_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authorize: bool,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    let Some(mutation) = relation_current_result_mutation(event)? else {
        return Ok(());
    };
    if authorize {
        crate::relation_current_results::authorize_relation_write_in_connection(
            conn, event, commit, prepared,
        )
        .await?;
    }
    let created = matches!(mutation, RelationCurrentResultMutation::Create(_));
    let lifecycle_time = std::cmp::max(event.created_at, commit.committed_at);
    let (domain, expected_revision) = match &mutation {
        RelationCurrentResultMutation::Create(payload) => (
            payload.primary_conflict_domain.clone(),
            payload.expected_revision.clone(),
        ),
        RelationCurrentResultMutation::Update(payload) => (
            payload.primary_conflict_domain.clone(),
            Some(payload.expected_revision.clone()),
        ),
        RelationCurrentResultMutation::Tombstone(payload) => (
            payload.primary_conflict_domain.clone(),
            Some(payload.expected_revision.clone()),
        ),
    };
    let domain_key = arkret_canonical::canonical_json_string(&domain).map_err(|error| {
        PersistenceError::Internal(format!(
            "Relation primary conflict domain canonicalization failed: {error}"
        ))
    })?;
    let domain_json = serde_json::to_value(&domain).map_err(|error| {
        PersistenceError::Internal(format!(
            "Relation primary conflict domain serialization failed: {error}"
        ))
    })?;
    let lock_key = format!("relation:{}:{domain_key}", event.realm_id);
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0)) IS NULL AS accepted")
        .bind::<Text, _>(&lock_key)
        .get_result::<AcceptedFlagRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

    let current = sql_query(
        "SELECT relation_id,state,current_commit_id,current_stream_position,value \
         FROM relation_current_results WHERE realm_id=$1 AND domain_key=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&domain_key)
    .get_result::<RelationCurrentResultRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;

    let value = match (mutation, current.as_ref()) {
        (RelationCurrentResultMutation::Create(payload), None) => {
            if expected_revision.is_some() {
                return Err(conflict(
                    "failed_precondition: Relation current revision is absent",
                ));
            }
            relation_current_value_for_create(event, payload, lifecycle_time)
        }
        (RelationCurrentResultMutation::Create(payload), Some(row)) => {
            if row.state != "tombstoned"
                || expected_revision
                    .as_ref()
                    .is_none_or(|expected| !relation_revision_matches(row, expected))
            {
                return Err(conflict(
                    "failed_precondition: Relation create requires the exact tombstoned current revision",
                ));
            }
            let current: arkret_models_collaboration::objects::relation::Relation =
                serde_json::from_value(row.value.clone()).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored Relation current value is invalid: {error}"
                    ))
                })?;
            if current.id.as_ref().map(|id| id.as_str()) != Some(row.relation_id.as_str())
                || current.state.as_ref() != Some(&arkret_wire::RelationState::Tombstoned)
            {
                return Err(conflict(
                    "failed_precondition: stored Relation tombstone is inconsistent",
                ));
            }
            if !relation_domain_matches_value(&payload.primary_conflict_domain, &current) {
                return Err(PersistenceError::SchemaViolation(
                    "Relation create primary conflict domain does not match current value"
                        .to_owned(),
                ));
            }
            relation_current_value_for_create(event, payload, lifecycle_time)
        }
        (RelationCurrentResultMutation::Update(payload), Some(row)) => {
            if row.state != "active"
                || row.relation_id != payload.relation_id.as_str()
                || !relation_revision_matches(row, &payload.expected_revision)
            {
                return Err(conflict(
                    "failed_precondition: Relation update current value does not match",
                ));
            }
            let current: arkret_models_collaboration::objects::relation::Relation =
                serde_json::from_value(row.value.clone()).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored Relation current value is invalid: {error}"
                    ))
                })?;
            if current.id.as_ref().map(|id| id.as_str()) != Some(row.relation_id.as_str())
                || current.state.as_ref() != Some(&arkret_wire::RelationState::Active)
            {
                return Err(conflict(
                    "failed_precondition: stored Relation current value is inconsistent",
                ));
            }
            if !relation_domain_matches_value(&payload.primary_conflict_domain, &current) {
                return Err(PersistenceError::SchemaViolation(
                    "Relation update primary conflict domain does not match current value"
                        .to_owned(),
                ));
            }
            let mut post = payload.patch.apply(&row.value).map_err(|error| {
                PersistenceError::SchemaViolation(format!("Relation update patch failed: {error}"))
            })?;
            let object = post.as_object_mut().ok_or_else(|| {
                PersistenceError::Internal(
                    "stored Relation current value is not an object".to_owned(),
                )
            })?;
            object.insert(
                "updated_by".to_owned(),
                serde_json::to_value(&event.actor_id).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "Relation actor serialization failed: {error}"
                    ))
                })?,
            );
            // The current value carries the canonical `timestamp` form, the
            // same one the typed create and tombstone values serialize to.
            object.insert(
                "updated_at".to_owned(),
                serde_json::Value::String(arkret_canonical::format_timestamp_canonical(
                    lifecycle_time,
                )),
            );
            serde_json::from_value(post).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "Relation update produced an invalid current value: {error}"
                ))
            })?
        }
        (RelationCurrentResultMutation::Tombstone(payload), Some(row)) => {
            if row.state != "active"
                || row.relation_id != payload.relation_id.as_str()
                || !relation_revision_matches(row, &payload.expected_revision)
            {
                return Err(conflict(
                    "failed_precondition: Relation tombstone current value does not match",
                ));
            }
            let mut current: arkret_models_collaboration::objects::relation::Relation =
                serde_json::from_value(row.value.clone()).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored Relation current value is invalid: {error}"
                    ))
                })?;
            if current.id.as_ref().map(|id| id.as_str()) != Some(row.relation_id.as_str())
                || current.state.as_ref() != Some(&arkret_wire::RelationState::Active)
            {
                return Err(conflict(
                    "failed_precondition: stored Relation current value is inconsistent",
                ));
            }
            if !relation_domain_matches_value(&payload.primary_conflict_domain, &current) {
                return Err(PersistenceError::SchemaViolation(
                    "Relation tombstone primary conflict domain does not match current value"
                        .to_owned(),
                ));
            }
            current.state = Some(arkret_wire::RelationState::Tombstoned);
            current.state_changed_at = Some(lifecycle_time);
            current.updated_by = Some(event.actor_id.clone());
            current.updated_at = Some(lifecycle_time);
            current
        }
        (RelationCurrentResultMutation::Update(_), None)
        | (RelationCurrentResultMutation::Tombstone(_), None) => {
            return Err(conflict(
                "failed_precondition: Relation current value does not exist",
            ));
        }
    };
    if authorize {
        let before = match current.as_ref() {
            Some(row) if !created => Some(
                serde_json::from_value::<arkret_models_collaboration::objects::relation::Relation>(
                    row.value.clone(),
                )
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored Relation current value is invalid: {error}"
                    ))
                })?,
            ),
            _ => None,
        };
        crate::relation_current_results::require_relation_value_scope_in_connection(
            conn,
            event,
            before.as_ref(),
            &value,
            created,
        )
        .await?;
    }
    let relation_id = value.id.clone().ok_or_else(|| {
        PersistenceError::Internal("Relation current value has no derived id".to_owned())
    })?;
    let state = match value.state.as_ref() {
        Some(arkret_wire::RelationState::Active) => "active",
        Some(arkret_wire::RelationState::Tombstoned) => "tombstoned",
        None => {
            return Err(conflict(
                "failed_precondition: stored Relation current value has no lifecycle state",
            ));
        }
    };
    let value_json = serde_json::to_value(&value).map_err(|error| {
        PersistenceError::Internal(format!(
            "Relation current value serialization failed: {error}"
        ))
    })?;
    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::Internal("Relation stream position exceeds PostgreSQL BIGINT".to_owned())
    })?;
    sql_query(
        "INSERT INTO relation_current_results \
         (realm_id,domain_key,domain,relation_id,state,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT(realm_id,domain_key) DO UPDATE SET \
           domain=EXCLUDED.domain,relation_id=EXCLUDED.relation_id,state=EXCLUDED.state, \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&domain_key)
    .bind::<Jsonb, _>(&domain_json)
    .bind::<Text, _>(relation_id.as_str())
    .bind::<Text, _>(state)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(stream_position)
    .bind::<Jsonb, _>(&value_json)
    .bind::<Timestamptz, _>(lifecycle_time)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn commit_parent_membership_current_results(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::Internal(
            "current-result stream position exceeds PostgreSQL BIGINT".into(),
        )
    })?;
    let updated_at = std::cmp::max(event.created_at, commit.committed_at);
    let payload_value = serde_json::to_value(&event.payload).map_err(|error| {
        PersistenceError::Internal(format!("Event payload serialization failed: {error}"))
    })?;
    match event.kind {
        arkret_wire::EventKind::RealmPolicyBundle => {
            advisory_lock(
                conn,
                format!("parent-membership:policy:{}", event.realm_id.as_str()),
            )
            .await?;
            let bundle: arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload =
                serde_json::from_value(payload_value.clone())
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            bundle
                .validate()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let previous = sql_query("SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1 FOR UPDATE")
                .bind::<Text,_>(event.realm_id.as_str()).get_result::<ParentMembershipPolicyRow>(&mut *conn)
                .await.optional().map_err(PersistenceError::database)?;
            let previous = previous.map(|row| serde_json::from_value::<arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload>(row.value))
                .transpose().map_err(PersistenceError::database)?.map_or(0, |bundle| bundle.policy_revision);
            let expected = previous.checked_add(1).ok_or_else(|| {
                PersistenceError::Conflict(
                    "policy_revision_rollback: policy revision is exhausted".to_owned(),
                )
            })?;
            if bundle.policy_revision < expected {
                return Err(PersistenceError::Conflict(
                    "policy_revision_rollback: policy revision must advance by one".to_owned(),
                ));
            }
            if bundle.policy_revision > expected {
                return Err(PersistenceError::Conflict(
                    "policy_revision_gap: policy revision must advance by one".to_owned(),
                ));
            }
            let join_rule = sql_query("SELECT value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_join_rule' FOR SHARE")
                .bind::<Text,_>(event.realm_id.as_str()).get_result::<ParentMembershipPolicyRow>(&mut *conn)
                .await.optional().map_err(PersistenceError::database)?;
            if let Some(policy) = payload_value.get("join_policy") {
                coland_storage::validate_join_policy_payload(policy)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_owned()))?;
            }
            if join_rule
                .as_ref()
                .and_then(|row| row.value.as_str())
                .is_some_and(coland_storage::join_rule_requires_an_automatic_gate)
                && !coland_storage::join_policy_declares_an_automatic_gate(
                    payload_value.get("join_policy"),
                )
            {
                return Err(PersistenceError::Conflict(
                    "join_rule_policy_mismatch: restricted join rule requires an automatic gate"
                        .to_owned(),
                ));
            }
            let genesis = sql_query("SELECT value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_genesis' FOR SHARE")
                .bind::<Text,_>(event.realm_id.as_str()).get_result::<ParentMembershipPolicyRow>(&mut *conn)
                .await.optional().map_err(PersistenceError::database)?;
            if genesis
                .as_ref()
                .and_then(|row| row.value.get("security_class"))
                .and_then(serde_json::Value::as_str)
                == Some("high_assurance")
                && !matches!(
                    payload_value
                        .get("federation_policy")
                        .and_then(serde_json::Value::as_str),
                    Some("closed" | "restricted" | "quarantine")
                )
            {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: high assurance federation policy is invalid".to_owned(),
                ));
            }
            sql_query(
                "INSERT INTO realm_policy_bundle_current_results \
                 (realm_id,current_commit_id,current_stream_position,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5) ON CONFLICT(realm_id) DO UPDATE SET \
                 current_commit_id=EXCLUDED.current_commit_id, \
                 current_stream_position=EXCLUDED.current_stream_position, \
                 value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(stream_position)
            .bind::<Jsonb, _>(&payload_value)
            .bind::<Timestamptz, _>(updated_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        arkret_wire::EventKind::RealmLink => {
            let link =
                arkret_event_draft::EventPayloadExt::as_realm_link(event).map_err(|error| {
                    PersistenceError::SchemaViolation(format!(
                        "realm_link payload is invalid: {error}"
                    ))
                })?;
            let target_realm_id = link.target_realm_id.as_str();
            let link_kind = link.link_kind.as_str();
            let status = link.status.as_str();
            advisory_lock(
                conn,
                format!(
                    "parent-membership:link:{}:{target_realm_id}:{link_kind}",
                    event.realm_id.as_str()
                ),
            )
            .await?;
            sql_query(
                "INSERT INTO realm_link_current_results \
                 (realm_id,target_realm_id,link_kind,status,current_commit_id,current_stream_position,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8) \
                 ON CONFLICT(realm_id,target_realm_id,link_kind) DO UPDATE SET \
                 status=EXCLUDED.status,current_commit_id=EXCLUDED.current_commit_id, \
                 current_stream_position=EXCLUDED.current_stream_position, \
                 value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(target_realm_id)
            .bind::<Text, _>(link_kind)
            .bind::<Text, _>(status)
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(stream_position)
            .bind::<Jsonb, _>(&payload_value)
            .bind::<Timestamptz, _>(updated_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        arkret_wire::EventKind::MemberState | arkret_wire::EventKind::InviteAccept => {
            let Some((member_id, membership, value)) = member_state_mutation(event)? else {
                return Ok(());
            };
            locked_member_state(conn, &event.realm_id, &member_id).await?;
            sql_query(
                "INSERT INTO member_state_current_results \
                 (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,member_id) DO UPDATE SET \
                 membership=EXCLUDED.membership,current_commit_id=EXCLUDED.current_commit_id, \
                 current_stream_position=EXCLUDED.current_stream_position, \
                 value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(&member_id)
            .bind::<Text, _>(&membership)
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(stream_position)
            .bind::<Jsonb, _>(&value)
            .bind::<Timestamptz, _>(updated_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        _ => {}
    }
    Ok(())
}

/// Refuse an Applet-authored Event once its installation or managed identity is
/// fenced. The identity row is the same linearization point installation
/// revocation takes, and the exact Events a closed first install carries are
/// admitted by that aggregate rather than by the fence they are creating.
async fn ensure_applet_admission_in_transaction(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    applet_record: Option<&coland_storage::AppletRecordCommit>,
) -> PersistenceResult<()> {
    if closed_applet_install_contains_event(
        event.event_id.as_str(),
        event.applet_id.as_ref().map(arkret_wire::AppletId::as_str),
        applet_record,
    ) {
        return Ok(());
    }
    let fail = || conflict("applet_revoked");
    let grant_id = if matches!(
        event.kind,
        arkret_wire::EventKind::CapabilityRevoke | arkret_wire::EventKind::CapabilityRelinquish
    ) {
        event
            .payload
            .get("grant_id")
            .and_then(serde_json::Value::as_str)
    } else if event.applet_id.is_some() || event.kind == arkret_wire::EventKind::AppletBridgeError {
        event.authorization_ref.as_deref()
    } else {
        None
    };
    if let Some(grant_id) = grant_id {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(format!("applet-grant:{grant_id}"))
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    let Some(applet_id) = &event.applet_id else {
        return Ok(());
    };
    let scope_key = coland_storage::applet_effective_scope_key(&event.scope_ref)?;
    let install = sql_query(
        "SELECT record FROM applet_installations \
         WHERE applet_id = $1 AND effective_scope_key = $2 FOR UPDATE",
    )
    .bind::<Text, _>(applet_id.as_str())
    .bind::<Text, _>(&scope_key)
    .get_result::<AppletAdmissionRecordRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(fail)?;
    // The shared identity belongs to this hosting Station, not to the
    // remote Service which signs its terminal grants and management Events.
    let target = install
        .record
        .get("target_station_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(fail)?;
    let identity = sql_query(
        "SELECT record FROM applet_managed_identities \
         WHERE applet_id = $1 AND target_station_id = $2 FOR UPDATE",
    )
    .bind::<Text, _>(applet_id.as_str())
    .bind::<Text, _>(target)
    .get_result::<AppletAdmissionRecordRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(fail)?;
    if identity
        .record
        .get("globally_fenced_at")
        .is_some_and(|value| !value.is_null())
        || install
            .record
            .get("revoked_at")
            .is_some_and(|value| !value.is_null())
        || !matches!(
            install
                .record
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("installed" | "partially_installed")
        )
    {
        return Err(fail());
    }
    Ok(())
}

/// A first install is a closed aggregate: the Events it carries are admitted by
/// the same mutation that creates the fence, so they are not measured against
/// an installation row that does not exist yet.
fn closed_applet_install_contains_event(
    event_id: &str,
    event_applet_id: Option<&str>,
    mutation: Option<&coland_storage::AppletRecordCommit>,
) -> bool {
    let Some(mutation) = mutation.filter(|mutation| mutation.expected_record.is_none()) else {
        return false;
    };
    if event_applet_id != Some(mutation.applet_id.as_str()) {
        return false;
    }
    mutation
        .record
        .get("registration_event")
        .and_then(|event| event.get("event_id"))
        .and_then(serde_json::Value::as_str)
        == Some(event_id)
        || mutation
            .record
            .get("capability_grant_events")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|events| {
                events.iter().any(|event| {
                    event.get("event_id").and_then(serde_json::Value::as_str) == Some(event_id)
                })
            })
}

fn contact_event_ref(
    value: Option<&arkret_identifiers::EventId>,
) -> PersistenceResult<Option<Vec<u8>>> {
    value
        .map(|value| {
            ids::event_token_part_or_schema_violation(value.as_str(), "event")
                .map(|token| token.to_vec())
        })
        .transpose()
}

/// Install one committed Contact mutation, its verified request mirror, and the
/// holder-private invite policy the same command decided.
///
/// A command's completion intent is staged only after its request-slot CAS is
/// recomputed from the pair row this transaction locks at the planned
/// revision, so the signed slot transcript is exactly the accepting cut.
pub(crate) async fn commit_contact_projection(
    conn: &mut AsyncPgConnection,
    committed_ref: Option<&arkret_wire::CommittedEventRef>,
    commit: coland_storage::ContactProjectionCommit,
) -> PersistenceResult<()> {
    if let Some(intent) = commit.completion_intent.as_ref() {
        let committed_ref = committed_ref.ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "a Contact completion intent needs its accepting Commit".to_owned(),
            )
        })?;
        intent.validate_event_binding()?;
        if intent.plan.event.event_id != committed_ref.event_id {
            return Err(PersistenceError::SchemaViolation(
                "Contact delivery intent does not bind the committed Event".to_owned(),
            ));
        }
        let pre_state = match commit.expected_updated_at {
            Some(expected) => Some(
                crate::contacts::lock_pair_contact_at_in_connection(
                    conn,
                    &commit.record.requester_id,
                    &commit.record.target_id,
                    expected,
                )
                .await?
                .ok_or_else(|| conflict(commit.conflict_code.clone()))?,
            ),
            None => None,
        };
        intent.validate_slot_cas(pre_state.as_ref(), &commit.record)?;
        crate::contacts::completion::stage_in_transaction(conn, committed_ref, intent).await?;
    }
    let conflict_code = commit.conflict_code;
    let invite_policy = commit.invite_policy;
    let verified_mirror = commit.verified_mirror;
    let record = commit.record;
    let request_slot_states =
        serde_json::to_value(&record.request_slot_states).map_err(|error| {
            PersistenceError::Internal(format!(
                "cannot encode Contact request-slot states: {error}"
            ))
        })?;
    let request_receipts = serde_json::to_value(&record.request_receipts).map_err(|error| {
        PersistenceError::Internal(format!("cannot encode Contact request receipts: {error}"))
    })?;
    let request_mirror_receipts =
        serde_json::to_value(&record.request_mirror_receipts).map_err(|error| {
            PersistenceError::Internal(format!("cannot encode Contact mirror receipts: {error}"))
        })?;
    let contact_round_evidence = record
        .contact_round_evidence
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| {
            PersistenceError::Internal(format!("cannot encode Contact round evidence: {error}"))
        })?;
    let contact_round_evidence_history =
        serde_json::to_value(&record.contact_round_evidence_history).map_err(|error| {
            PersistenceError::Internal(format!(
                "cannot encode Contact round evidence history: {error}"
            ))
        })?;
    let control_outcomes = serde_json::to_value(&record.control_outcomes).map_err(|error| {
        PersistenceError::Internal(format!("cannot encode Contact control outcomes: {error}"))
    })?;
    let request_event_ref = contact_event_ref(record.request_event_ref.as_ref())?;
    let response_event_ref = contact_event_ref(record.response_event_ref.as_ref())?;
    let tombstone_event_ref = contact_event_ref(record.tombstone_event_ref.as_ref())?;

    let affected = if let Some(expected_updated_at) = commit.expected_updated_at {
        if record.updated_at <= expected_updated_at {
            return Err(conflict(conflict_code));
        }
        sql_query(
            "UPDATE contacts SET requester_id = $1, target_id = $2, \
                contact_round_id = $3, granted_to_target_scopes = $4, \
                granted_to_requester_scopes = $5, status = $6, pending_incoming_admitted = $7, request_event_ref = $8, \
                request_slot_states = $9, request_receipts = $10, request_mirror_receipts = $11, \
                contact_round_evidence = $12, contact_round_evidence_history = $13, \
                control_outcomes = $14, response_event_ref = $15, tombstone_event_ref = $16, \
                message = $17, peer_id = $18, peer_service_resolution = $19, updated_at = $20 \
             WHERE ((requester_id = $1 AND target_id = $2) OR \
                    (requester_id = $2 AND target_id = $1)) AND updated_at = $21",
        )
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Bool, _>(record.pending_incoming_admitted)
        .bind::<Nullable<Binary>, _>(request_event_ref)
        .bind::<Jsonb, _>(&request_slot_states)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&contact_round_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(response_event_ref)
        .bind::<Nullable<Binary>, _>(tombstone_event_ref)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_host_id.as_ref())
        .bind::<Nullable<Jsonb>, _>(record.peer_service_resolution.as_ref())
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(expected_updated_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
    } else {
        sql_query(
            "INSERT INTO contacts \
             (id, requester_id, target_id, contact_round_id, granted_to_target_scopes, granted_to_requester_scopes, status, pending_incoming_admitted, request_event_ref, request_slot_states, request_receipts, request_mirror_receipts, contact_round_evidence, contact_round_evidence_history, control_outcomes, response_event_ref, tombstone_event_ref, message, peer_id, peer_service_resolution, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22) \
             ON CONFLICT (requester_id, target_id) DO NOTHING",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(record.requester_id.to_string())
        .bind::<Text, _>(record.target_id.to_string())
        .bind::<Nullable<Text>, _>(record.contact_round_id.as_ref())
        .bind::<Array<Text>, _>(&record.granted_to_target_scopes)
        .bind::<Array<Text>, _>(&record.granted_to_requester_scopes)
        .bind::<Text, _>(&record.status)
        .bind::<Bool, _>(record.pending_incoming_admitted)
        .bind::<Nullable<Binary>, _>(request_event_ref)
        .bind::<Jsonb, _>(&request_slot_states)
        .bind::<Jsonb, _>(&request_receipts)
        .bind::<Jsonb, _>(&request_mirror_receipts)
        .bind::<Nullable<Jsonb>, _>(contact_round_evidence.as_ref())
        .bind::<Jsonb, _>(&contact_round_evidence_history)
        .bind::<Jsonb, _>(&control_outcomes)
        .bind::<Nullable<Binary>, _>(response_event_ref)
        .bind::<Nullable<Binary>, _>(tombstone_event_ref)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_host_id.as_ref())
        .bind::<Nullable<Jsonb>, _>(record.peer_service_resolution.as_ref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
    };
    if affected != 1 {
        return Err(conflict(conflict_code));
    }
    if let Some(mirror) = verified_mirror {
        let source_receipt = serde_json::to_value(&mirror.source_receipt).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "Contact request receipt encode failed: {error}"
            ))
        })?;
        let committed = sql_query(
            "INSERT INTO contact_verified_mirrors \
             (target_holder_principal_id, request_event_id, request_digest, canonical_event_bytes, source_receipt, issuer_id, verified_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (target_holder_principal_id, request_event_id) DO UPDATE \
             SET verified_at = contact_verified_mirrors.verified_at \
             WHERE contact_verified_mirrors.request_digest = EXCLUDED.request_digest \
               AND contact_verified_mirrors.canonical_event_bytes = EXCLUDED.canonical_event_bytes \
               AND contact_verified_mirrors.source_receipt = EXCLUDED.source_receipt \
               AND contact_verified_mirrors.issuer_id = EXCLUDED.issuer_id \
             RETURNING target_holder_principal_id",
        )
        .bind::<Text, _>(&mirror.target_holder_principal_id)
        .bind::<Text, _>(&mirror.request_event_id)
        .bind::<Text, _>(&mirror.request_digest)
        .bind::<Binary, _>(&mirror.canonical_event_bytes)
        .bind::<Jsonb, _>(&source_receipt)
        .bind::<Text, _>(&mirror.issuer_id)
        .bind::<Timestamptz, _>(mirror.verified_at)
        .get_result::<ContactMirrorCommitRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if committed
            .as_ref()
            .is_none_or(|row| row.target_holder_principal_id != mirror.target_holder_principal_id)
        {
            return Err(conflict("contact_verified_mirror_conflict"));
        }
    }
    if let Some((account_id, policy)) = invite_policy {
        crate::contacts::put_invite_receive_policy(conn, &account_id, &policy).await?;
    }
    Ok(())
}

/// Install one committed consent command's holder-private effects.
///
/// `consent-model.md` section 4.1.2 requires the eager holder-quarantine
/// invalidation to land inside the same transaction boundary as the accepted
/// revoke. The insert guard repeats admission's `(holder, consent_id)` intent
/// binding under the row lock, so a concurrent grant cannot rebind the same
/// `consent_id` between admission and commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccountDataCommitOutcome {
    Applied,
    ExactReplay,
}

/// Replace one holder-private register under the revision read frozen by
/// admission. When `source_event_id` is present, the account-data adapter also
/// verifies that the committed source Event describes this exact value and
/// publishes that source into the holder sync projection. Any conflict aborts
/// the surrounding Event transaction.
async fn commit_account_data_cas(
    conn: &mut AsyncPgConnection,
    cas: coland_storage::AccountDataCasCommit,
    source_event_id: Option<&arkret_wire::EventId>,
) -> PersistenceResult<AccountDataCommitOutcome> {
    let record = cas.record;
    match crate::accounts::compare_account_data_in_transaction(
        conn,
        &record,
        cas.expected_revision,
        source_event_id,
    )
    .await?
    {
        coland_storage::AccountDataCasResult::Applied(_) => Ok(AccountDataCommitOutcome::Applied),
        coland_storage::AccountDataCasResult::Conflict(_) => {
            let exact_replay = if let Some(event_id) = source_event_id {
                sql_query(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM account_datas d \
                         JOIN account_global_versions v \
                           ON v.actor_key=d.actor_id \
                          AND v.channel='account_data_events' \
                          AND v.item_key='event:'||d.account_data_key \
                          AND v.valid_until IS NULL \
                         WHERE d.actor_id=$1 AND d.account_data_key=$2 \
                           AND d.revision=$3 AND d.payload=$4 AND d.tombstone=$5 \
                           AND v.payload->>'source'='event' \
                           AND v.payload->'value'->>'event_id'=$6 \
                     ) AS accepted",
                )
                .bind::<Text, _>(&record.actor)
                .bind::<Text, _>(&record.account_data_key)
                .bind::<BigInt, _>(i64::try_from(record.revision).map_err(|_| {
                    PersistenceError::Internal(
                        "account data revision exceeds PostgreSQL BIGINT".to_owned(),
                    )
                })?)
                .bind::<Jsonb, _>(&record.payload)
                .bind::<Bool, _>(record.tombstone)
                .bind::<Text, _>(event_id.as_str())
                .get_result::<AcceptedFlagRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
                .accepted
            } else {
                false
            };
            if exact_replay {
                Ok(AccountDataCommitOutcome::ExactReplay)
            } else {
                Err(conflict(cas.conflict_code))
            }
        }
    }
}

#[derive(diesel::QueryableByName)]
struct PrincipalControlRealmRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

#[derive(diesel::QueryableByName)]
struct ActorPrivateLedgerRow {
    #[diesel(sql_type = Binary)]
    canonical_event_digest: Vec<u8>,
}

/// Admit one actor-private account-data Event outside any RealmCommit: exact
/// retry first, then the producer guard, then the ledger row and the holder
/// CAS it sources, all in the caller's transaction.
pub(crate) async fn admit_actor_private_account_data_in_connection(
    conn: &mut AsyncPgConnection,
    admission: &coland_storage::ActorPrivateAccountDataAdmission,
) -> PersistenceResult<coland_storage::ActorPrivateAccountDataOutcome> {
    let event = &admission.event;
    if event.kind != arkret_wire::EventKind::AccountDataSet
        || admission.cas.record.actor != event.actor_id.to_string()
        || admission.canonical_event_digest.len() != 32
    {
        return Err(PersistenceError::SchemaViolation(
            "actor-private account data admission is not bound to its Event".to_owned(),
        ));
    }
    let token = event.event_id.token_bytes().to_vec();
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("actor-private-event:{}", event.event_id))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    if let Some(existing) =
        sql_query("SELECT canonical_event_digest FROM actor_private_events WHERE id=$1")
            .bind::<Binary, _>(&token)
            .get_result::<ActorPrivateLedgerRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
    {
        return if existing.canonical_event_digest == admission.canonical_event_digest {
            Ok(coland_storage::ActorPrivateAccountDataOutcome::Replayed)
        } else {
            Err(conflict(
                "duplicate_conflict: the actor-private Event identity carries other bytes",
            ))
        };
    }
    if let Some(guard) = &admission.producer_guard {
        crate::authority_commit::check_self_producer_guard_in_connection(
            conn,
            event,
            guard,
            admission.accepted_at,
        )
        .await?;
    }
    // The holder's account data lives on its own principal-control Realm.
    let owner = event.actor_id.as_account_id().ok_or_else(|| {
        PersistenceError::SchemaViolation("account data is owned by an Account".to_owned())
    })?;
    let pcr = sql_query(
        "SELECT pcr_realm_id FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(owner.principal_id.as_str())
    .bind::<Text, _>(owner.station_id.as_str())
    .get_result::<PrincipalControlRealmRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if pcr.is_none_or(|row| row.pcr_realm_id != event.realm_id.as_str()) {
        return Err(PersistenceError::SchemaViolation(
            "the account data Event realm is not the holder's principal-control Realm".to_owned(),
        ));
    }
    sql_query(
        "INSERT INTO actor_private_events \
         (id, event_id, actor_id, kind, canonical_event_digest, envelope, outcome, accepted_at) \
         VALUES ($1,$2,$3,$4,$5,$6,NULL,$7)",
    )
    .bind::<Binary, _>(&token)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(event.actor_id.to_string())
    .bind::<Text, _>(event.kind.as_str())
    .bind::<Binary, _>(&admission.canonical_event_digest)
    .bind::<Jsonb, _>(serde_json::to_value(event).map_err(PersistenceError::database)?)
    .bind::<Timestamptz, _>(admission.accepted_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    match commit_actor_private_account_data(
        conn,
        admission.cas.clone(),
        event,
        admission.accepted_at,
    )
    .await?
    {
        AccountDataCommitOutcome::Applied => {
            Ok(coland_storage::ActorPrivateAccountDataOutcome::Applied)
        }
        // A fresh ledger row cannot already be the published source.
        AccountDataCommitOutcome::ExactReplay => Err(PersistenceError::Internal(
            "a new actor-private Event was already the published account data source".to_owned(),
        )),
    }
}

/// Install one actor-private Account Data effect. Initial Agent draft creates
/// additionally consume their Station-private proposal source under the same
/// PostgreSQL transaction and row lock. Later revisions remain ordinary
/// holder CAS writes and never consume the source again.
async fn commit_actor_private_account_data(
    conn: &mut AsyncPgConnection,
    cas: coland_storage::AccountDataCasCommit,
    event: &arkret_wire::Event,
    protocol_time: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AccountDataCommitOutcome> {
    if event.kind != arkret_wire::EventKind::AccountDataSet {
        return commit_account_data_cas(conn, cas, Some(&event.event_id)).await;
    }

    let payload: arkret_models_collaboration::events_payloads::account_data::AccountDataSetPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
            PersistenceError::Internal(format!(
                "account_data payload serialization failed: {error}"
            ))
        })?)
        .map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "account_data payload violates its typed SDK contract: {error}"
            ))
        })?;
    let expected_record_revision = cas.expected_revision.checked_add(1).ok_or_else(|| {
        PersistenceError::Conflict("cas_conflict: account data revision is exhausted".to_owned())
    })?;
    if payload.key.as_str() != cas.record.account_data_key
        || payload.expected_server_revision != cas.expected_revision
        || cas.record.revision != expected_record_revision
        || cas.record.actor != event.actor_id.to_string()
    {
        return Err(PersistenceError::SchemaViolation(
            "account_data commit does not match its signed Event payload".to_owned(),
        ));
    }

    let initial_agent_draft = payload.key.as_str().starts_with("ak.agent.draft.v1:")
        && payload.expected_server_revision == 0;
    if !initial_agent_draft {
        return commit_account_data_cas(conn, cas, Some(&event.event_id)).await;
    }
    if !payload.body.is_absent() || payload.encrypted_payload.is_none() || payload.tombstone {
        return Err(PersistenceError::SchemaViolation(
            "initial Agent draft Account Data create must carry only encrypted_payload".to_owned(),
        ));
    }

    let source_pending_event_id = payload.source_pending_event_id.as_ref().ok_or_else(|| {
        PersistenceError::SchemaViolation(
            "initial Agent draft Account Data create lacks source_pending_event_id".to_owned(),
        )
    })?;
    let controller_account_id = event.actor_id.as_account_id().ok_or_else(|| {
        PersistenceError::Conflict(
            "failed_precondition: Agent draft Account Data owner must be an Account".to_owned(),
        )
    })?;
    let source = lock_agent_draft_consumption_source(
        conn,
        controller_account_id,
        source_pending_event_id,
        &event.event_id,
        payload.key.as_str(),
        cas.record.revision,
        protocol_time,
    )
    .await?;
    let outcome = commit_account_data_cas(conn, cas, Some(&event.event_id)).await?;
    match (source, outcome) {
        (AgentDraftConsumptionLock::Available, AccountDataCommitOutcome::Applied) => {
            mark_agent_draft_consumed(
                conn,
                controller_account_id,
                source_pending_event_id,
                &event.event_id,
                payload.key.as_str(),
                1,
                protocol_time,
            )
            .await?;
            Ok(AccountDataCommitOutcome::Applied)
        }
        (AgentDraftConsumptionLock::ExactReplay, AccountDataCommitOutcome::ExactReplay) => {
            Ok(AccountDataCommitOutcome::ExactReplay)
        }
        _ => Err(PersistenceError::Conflict(
            "duplicate_conflict: Agent draft Account Data and pending source outcomes diverged"
                .to_owned(),
        )),
    }
}

/// Read the controller's current join generation and its exact active Agent
/// membership set under the Realm-wide batch admission lock. The typed current
/// value contains only `membership`; the bound generation is recovered from
/// each covering accepted join Event.
async fn cascade_membership_prestate(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    controller: &arkret_wire::AccountId,
) -> PersistenceResult<(
    arkret_wire::EventId,
    std::collections::BTreeSet<arkret_wire::ActorId>,
)> {
    #[derive(diesel::QueryableByName)]
    struct JoinedEventRow {
        #[diesel(sql_type = Jsonb)]
        envelope: serde_json::Value,
    }

    let rows = sql_query(
        "SELECT e.envelope FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id = m.current_commit_id \
         JOIN canonical_events e ON e.pk = c.event_pk \
         WHERE m.realm_id = $1 AND m.membership = 'join' \
           AND c.realm_id = m.realm_id \
           AND c.stream_position = m.current_stream_position \
           AND c.stream_ref->>'kind' = 'realm' \
           AND c.stream_ref->>'realm_id' = m.realm_id \
         FOR SHARE OF m",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<JoinedEventRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let controller_actor = arkret_wire::ActorId::account(controller.clone());
    let mut controller_generation = None;
    let mut agent_joins = Vec::new();
    for row in rows {
        let event: arkret_wire::Event = serde_json::from_value(row.envelope).map_err(|error| {
            PersistenceError::Internal(format!("current membership Event is invalid: {error}"))
        })?;
        if event.actor_id == controller_actor {
            controller_generation = Some(event.event_id.clone());
            continue;
        }
        if event.kind != arkret_wire::EventKind::MemberState {
            continue;
        }
        let payload: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
                PersistenceError::Internal(format!(
                    "current membership payload is invalid: {error}"
                ))
            })?)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "current membership payload is invalid: {error}"
                ))
            })?;
        if let Some(binding) = payload.agent_controller_binding
            && binding.controller_account_id == *controller
        {
            agent_joins.push((event.actor_id, binding.controller_membership_generation_ref));
        }
    }
    let generation = controller_generation.ok_or_else(|| {
        PersistenceError::Conflict(
            "failed_precondition: controller current membership is not join".to_owned(),
        )
    })?;
    let agents = agent_joins
        .into_iter()
        .filter_map(|(agent, bound_generation)| (bound_generation == generation).then_some(agent))
        .collect();
    Ok((generation, agents))
}

/// Freeze or complete an Agent membership cascade intent.
///
/// The cascade is a batch-level product effect: the controller transition and
/// every Agent transition it fans out to are one command unit, and the durable
/// cleanup intent is written in the same transaction as the Events that
/// justify it.
async fn stage_agent_membership_cascade(
    conn: &mut AsyncPgConnection,
    transition: Option<&coland_storage::AgentMembershipCascadeCommit>,
    events: &[EventCommitRequest],
) -> PersistenceResult<()> {
    use coland_storage::{
        AgentCleanupRecord, AgentMembershipCascadeCommit, MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS,
    };

    #[derive(diesel::QueryableByName)]
    struct AgentCleanupIntentJsonRow {
        #[diesel(sql_type = Jsonb)]
        record_json: serde_json::Value,
    }

    let Some(transition) = transition else {
        return Ok(());
    };
    let event_ids = events
        .iter()
        .map(|request| request.event.event_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    match transition {
        AgentMembershipCascadeCommit::AtomicSelfLeave {
            controller_transition_event_id,
            agent_transition_event_ids,
            expected_agent_ids,
        } => {
            if agent_transition_event_ids.is_empty()
                || agent_transition_event_ids.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS
            {
                return Err(PersistenceError::SchemaViolation(
                    "invalid atomic Agent cleanup cardinality".to_owned(),
                ));
            }
            let mut expected = agent_transition_event_ids
                .iter()
                .map(arkret_wire::EventId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if expected.len() != agent_transition_event_ids.len()
                || !expected.insert(controller_transition_event_id.as_str())
                || expected != event_ids
                || expected_agent_ids.len() != agent_transition_event_ids.len()
            {
                return Err(conflict(
                    "duplicate_conflict: atomic Agent cascade Event set mismatch",
                ));
            }
            let submitted_agent_ids = events
                .iter()
                .filter(|request| request.event.event_id != controller_transition_event_id.as_str())
                .map(|request| coland_storage::admitted_cascade_agent_id(&request.event))
                .collect::<PersistenceResult<std::collections::BTreeSet<_>>>()?;
            let expected_agent_count = expected_agent_ids.len();
            let expected_agent_ids = expected_agent_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            if submitted_agent_ids != expected_agent_ids
                || expected_agent_ids.len() != expected_agent_count
            {
                return Err(conflict(
                    "duplicate_conflict: atomic Agent cascade actor set mismatch",
                ));
            }
            let controller_event = events
                .iter()
                .find(|request| request.event.event_id == controller_transition_event_id.as_str())
                .expect("validated cascade contains the controller Event");
            let controller: arkret_wire::Event = serde_json::from_value(
                controller_event.event.envelope.clone(),
            )
            .map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "controller cascade Event is invalid: {error}"
                ))
            })?;
            let controller_account = controller.actor_id.as_account_id().ok_or_else(|| {
                PersistenceError::SchemaViolation(
                    "controller cascade actor is not an account".to_owned(),
                )
            })?;
            let (_, active_agents) =
                cascade_membership_prestate(conn, &controller.realm_id, controller_account).await?;
            if active_agents != expected_agent_ids {
                return Err(conflict(
                    "failed_precondition: atomic Agent cascade differs from the current exact set",
                ));
            }
        }
        AgentMembershipCascadeCommit::EmergencyTerminal { record } => {
            record.validate().map_err(|error| {
                PersistenceError::SchemaViolation(format!("invalid Agent cleanup intent: {error}"))
            })?;
            if event_ids
                != std::collections::BTreeSet::from([record.controller_terminal_event_id.as_str()])
            {
                return Err(conflict(
                    "duplicate_conflict: emergency terminal Event set mismatch",
                ));
            }
            let terminal = events
                .first()
                .expect("validated singleton terminal Event set");
            let typed =
                serde_json::from_value::<arkret_wire::Event>(terminal.event.envelope.clone())
                    .map_err(|error| {
                        PersistenceError::SchemaViolation(format!(
                            "emergency terminal Event is invalid: {error}"
                        ))
                    })?;
            let initiator = typed.executed_by.as_ref().unwrap_or(&typed.actor_id);
            let controller = arkret_wire::ActorId::account(record.controller_account_id.clone());
            if terminal.event.actor_id != controller.to_string()
                || terminal.event.realm_id.as_deref() != Some(record.realm_id.as_str())
                || typed.actor_id != controller
                || initiator != &record.initiator_actor_id
            {
                return Err(conflict(
                    "duplicate_conflict: emergency terminal Event does not bind cleanup intent",
                ));
            }
            let (generation, active_agents) =
                cascade_membership_prestate(conn, &record.realm_id, &record.controller_account_id)
                    .await?;
            if generation != record.controller_membership_generation_ref
                || active_agents
                    != record
                        .expected_agent_ids
                        .iter()
                        .cloned()
                        .collect::<std::collections::BTreeSet<_>>()
            {
                return Err(conflict(
                    "failed_precondition: emergency Agent cleanup intent differs from the current exact set",
                ));
            }
            let existing = sql_query(
                "SELECT record_json FROM agent_membership_cleanup_intents \
                 WHERE cleanup_intent_digest = $1 OR controller_terminal_event_id = $2 \
                 FOR UPDATE",
            )
            .bind::<Text, _>(record.cleanup_intent_digest.as_str())
            .bind::<Text, _>(record.controller_terminal_event_id.as_str())
            .get_result::<AgentCleanupIntentJsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing {
                let existing = serde_json::from_value::<AgentCleanupRecord>(existing.record_json)
                    .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored Agent cleanup intent is invalid: {error}"
                    ))
                })?;
                if existing != **record {
                    return Err(conflict(
                        "duplicate_conflict: cleanup intent digest names different content",
                    ));
                }
            } else {
                let record_json = serde_json::to_value(record).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "Agent cleanup intent encoding failed: {error}"
                    ))
                })?;
                sql_query(
                    "INSERT INTO agent_membership_cleanup_intents \
                     (cleanup_intent_digest, realm_id, controller_terminal_event_id, \
                      record_json, accepted_at, cleanup_due_at, completed_at, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, NULL, $5, $5)",
                )
                .bind::<Text, _>(record.cleanup_intent_digest.as_str())
                .bind::<Text, _>(record.realm_id.as_str())
                .bind::<Text, _>(record.controller_terminal_event_id.as_str())
                .bind::<Jsonb, _>(record_json)
                .bind::<Timestamptz, _>(record.accepted_at)
                .bind::<Timestamptz, _>(record.cleanup_due_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
        }
        AgentMembershipCascadeCommit::EmergencyCleanup {
            cleanup_intent_digest,
            controller_terminal_event_id,
            agent_transition_event_ids,
            completed_at,
        } => {
            let existing = sql_query(
                "SELECT record_json FROM agent_membership_cleanup_intents \
                 WHERE cleanup_intent_digest = $1 FOR UPDATE",
            )
            .bind::<Text, _>(cleanup_intent_digest.as_str())
            .get_result::<AgentCleanupIntentJsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| conflict("failed_precondition: Agent cleanup intent is unavailable"))?;
            let mut record = serde_json::from_value::<AgentCleanupRecord>(existing.record_json)
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored Agent cleanup intent is invalid: {error}"
                    ))
                })?;
            let submitted_event_ids = agent_transition_event_ids
                .iter()
                .map(arkret_wire::EventId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            let actor_ids = events
                .iter()
                .map(|request| coland_storage::admitted_cascade_agent_id(&request.event))
                .collect::<PersistenceResult<std::collections::BTreeSet<_>>>()?;
            let expected_actor_ids = record
                .expected_agent_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            if record.controller_terminal_event_id != *controller_terminal_event_id
                || event_ids != submitted_event_ids
                || agent_transition_event_ids.len() != record.expected_agent_ids.len()
                || actor_ids != expected_actor_ids
            {
                return Err(conflict(
                    "duplicate_conflict: emergency Agent cleanup does not match frozen intent",
                ));
            }
            if record.completed_at.is_some() {
                if record.agent_transition_event_ids.as_ref() != Some(agent_transition_event_ids) {
                    return Err(conflict(
                        "duplicate_conflict: completed Agent cleanup replay differs",
                    ));
                }
                return Ok(());
            }
            record.completed_at = Some(*completed_at);
            record.agent_transition_event_ids = Some(agent_transition_event_ids.clone());
            record.validate().map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "completed Agent cleanup is invalid: {error}"
                ))
            })?;
            let record_json = serde_json::to_value(&record).map_err(|error| {
                PersistenceError::Internal(format!(
                    "completed Agent cleanup encoding failed: {error}"
                ))
            })?;
            sql_query(
                "UPDATE agent_membership_cleanup_intents SET \
                     record_json = $2, completed_at = $3, updated_at = $3 \
                 WHERE cleanup_intent_digest = $1",
            )
            .bind::<Text, _>(cleanup_intent_digest.as_str())
            .bind::<Jsonb, _>(record_json)
            .bind::<Timestamptz, _>(*completed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
    }
    Ok(())
}

/// Consume one moderation franking replay nonce.
async fn commit_franking_replay_nonce(
    conn: &mut AsyncPgConnection,
    nonce: &coland_storage::FrankingReplayNonceCommit,
) -> PersistenceResult<()> {
    let expires_at = coland_storage::franking_replay_nonce_expires_at(nonce.consumed_at)?;
    let scope_lock = format!(
        "moderation_franking_replay_nonces.capacity.v1|{}:{}|{}:{}",
        nonce.realm_id.len(),
        nonce.realm_id,
        nonce.received_by.as_str().len(),
        nonce.received_by
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&scope_lock)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    sql_query(
        "DELETE FROM moderation_franking_replay_nonces \
         WHERE realm_id = $1 AND received_by = $2 AND expires_at <= $3",
    )
    .bind::<Text, _>(&nonce.realm_id)
    .bind::<Text, _>(nonce.received_by.as_str())
    .bind::<Timestamptz, _>(nonce.consumed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let active = sql_query(
        "SELECT COUNT(*) AS count FROM moderation_franking_replay_nonces \
         WHERE realm_id = $1 AND received_by = $2",
    )
    .bind::<Text, _>(&nonce.realm_id)
    .bind::<Text, _>(nonce.received_by.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .count;
    if active
        >= i64::try_from(coland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE)
            .expect("franking replay ledger per-scope bound fits i64")
    {
        return Err(conflict("duplicate_conflict"));
    }
    let inserted = sql_query(
        "INSERT INTO moderation_franking_replay_nonces \
         (realm_id, received_by, replay_nonce, report_event_id, consumed_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(&nonce.realm_id)
    .bind::<Text, _>(nonce.received_by.as_str())
    .bind::<Text, _>(&nonce.replay_nonce)
    .bind::<Text, _>(&nonce.report_event_id)
    .bind::<Timestamptz, _>(nonce.consumed_at)
    .bind::<Timestamptz, _>(expires_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(conflict("duplicate_conflict"));
    }
    Ok(())
}

/// Install one Applet installation aggregate: the managed-identity winner, the
/// per-scope installation record, its namespace claims, and every managed
/// authority anchor it introduces.
pub(crate) async fn commit_applet_record(
    conn: &mut AsyncPgConnection,
    mutation: coland_storage::AppletRecordCommit,
) -> PersistenceResult<()> {
    coland_storage::validate_applet_installation_record(&mutation.record)?;
    if let Some(expected) = mutation.expected_record.as_ref() {
        coland_storage::validate_applet_installation_record(expected)?;
    }
    let replacing = mutation.expected_record.is_some();
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(mutation.applet_id.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let effective_scope_key =
        coland_storage::applet_effective_scope_key_from_record(&mutation.record)?;
    if mutation
        .record
        .get("target_station_id")
        .and_then(serde_json::Value::as_str)
        != Some(mutation.identity.target_station_id.as_str())
        || coland_storage::applet_id_from_record(&mutation.record)? != mutation.applet_id.as_str()
        || coland_storage::applet_id_from_record(&mutation.identity.record)?
            != mutation.applet_id.as_str()
        || mutation
            .identity
            .record
            .get("target_station_id")
            .and_then(serde_json::Value::as_str)
            != Some(mutation.identity.target_station_id.as_str())
    {
        return Err(PersistenceError::SchemaViolation(
            "Applet identity/installation key does not match its record".to_owned(),
        ));
    }
    let identity_updated =
        if let Some(expected_identity) = mutation.identity.expected_record.as_ref() {
            if expected_identity != &mutation.identity.record {
                return Err(conflict(
                    "duplicate_conflict: Applet identity winner changed",
                ));
            }
            sql_query(
                "UPDATE applet_managed_identities SET record = record \
             WHERE applet_id = $1 AND target_station_id = $2 AND record = $3",
            )
            .bind::<Text, _>(mutation.applet_id.as_str())
            .bind::<Text, _>(mutation.identity.target_station_id.as_str())
            .bind::<Jsonb, _>(expected_identity)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
        } else {
            sql_query(
                "INSERT INTO applet_managed_identities \
             (applet_id, target_station_id, record, accepted_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (applet_id, target_station_id) DO NOTHING",
            )
            .bind::<Text, _>(mutation.applet_id.as_str())
            .bind::<Text, _>(mutation.identity.target_station_id.as_str())
            .bind::<Jsonb, _>(&mutation.identity.record)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
        };
    if identity_updated != 1 {
        return Err(conflict(
            "duplicate_conflict: Applet identity winner is not the accepted winner",
        ));
    }
    let canonical_namespaces = coland_storage::applet_namespaces_from_record(&mutation.record)?;
    if let Some(expected_record) = mutation.expected_record.as_ref()
        && canonical_namespaces != coland_storage::applet_namespaces_from_record(expected_record)?
    {
        return Err(PersistenceError::SchemaViolation(
            "Applet package.namespaces are immutable".to_owned(),
        ));
    }
    let managed_authorities = coland_storage::applet_managed_authorities_from_record(
        &mutation.identity.record,
        &mutation.record,
    )?;
    let previous_managed_authorities = mutation
        .expected_record
        .as_ref()
        .map(|record| {
            coland_storage::applet_managed_authorities_from_record(
                &mutation.identity.record,
                record,
            )
        })
        .transpose()?
        .unwrap_or_default();
    if !previous_managed_authorities.is_subset(&managed_authorities) {
        return Err(PersistenceError::SchemaViolation(
            "Applet managed authority anchors are immutable".to_owned(),
        ));
    }
    let new_managed_authorities = managed_authorities
        .difference(&previous_managed_authorities)
        .cloned()
        .collect::<Vec<_>>();
    let updated = if let Some(expected_record) = mutation.expected_record {
        sql_query(
            "UPDATE applet_installations SET record = $4, updated_at = NOW() \
             WHERE applet_id = $1 AND effective_scope_key = $2 AND record = $3 \
               AND record->>'revoked_at' IS NULL \
               AND record->>'status' IN ('installed', 'partially_installed')",
        )
        .bind::<Text, _>(mutation.applet_id.as_str())
        .bind::<Text, _>(&effective_scope_key)
        .bind::<Jsonb, _>(&expected_record)
        .bind::<Jsonb, _>(&mutation.record)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
    } else {
        sql_query(
            "INSERT INTO applet_installations (applet_id, effective_scope_key, record, updated_at) \
             VALUES ($1, $2, $3, NOW()) ON CONFLICT (applet_id, effective_scope_key) DO NOTHING",
        )
        .bind::<Text, _>(mutation.applet_id.as_str())
        .bind::<Text, _>(&effective_scope_key)
        .bind::<Jsonb, _>(&mutation.record)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
    };
    if updated != 1 {
        return Err(conflict(if replacing {
            "cas_conflict"
        } else {
            "duplicate_conflict"
        }));
    }

    let namespace_claims = [
        (
            arkret_models_integration::AppletNamespaceDomain::Actors,
            "actors",
            canonical_namespaces.actors,
        ),
        (
            arkret_models_integration::AppletNamespaceDomain::Realms,
            "realms",
            canonical_namespaces.realms,
        ),
        (
            arkret_models_integration::AppletNamespaceDomain::Handles,
            "handles",
            canonical_namespaces.handles,
        ),
    ];
    if !replacing
        && namespace_claims
            .iter()
            .any(|(_, _, claims)| !claims.is_empty())
    {
        sql_query(
            "SELECT pg_advisory_xact_lock(hashtextextended('arkret.applet.namespace.claims', 0))",
        )
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let existing = sql_query(
            "SELECT claims.domain, claims.pattern, claims.exclusive \
             FROM applet_namespace_claims claims WHERE claims.applet_id <> $1",
        )
        .bind::<Text, _>(mutation.applet_id.as_str())
        .load::<AppletNamespaceClaimRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        for (domain, domain_wire, claims) in &namespace_claims {
            for claim in claims {
                if existing.iter().any(|stored| {
                    stored.domain == *domain_wire
                        && (claim.exclusive || stored.exclusive)
                        && arkret_models_integration::namespace_patterns_overlap(
                            *domain,
                            &claim.pattern,
                            &stored.pattern,
                        )
                }) {
                    return Err(conflict("applet_namespace_conflict"));
                }
                sql_query(
                    "INSERT INTO applet_namespace_claims (applet_id, domain, pattern, exclusive) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (applet_id, domain, pattern) DO NOTHING",
                )
                .bind::<Text, _>(mutation.applet_id.as_str())
                .bind::<Text, _>(*domain_wire)
                .bind::<Text, _>(&claim.pattern)
                .bind::<Bool, _>(claim.exclusive)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
        }
    }

    for claim in new_managed_authorities {
        let inserted = sql_query(
            "INSERT INTO managed_authority_claims (actor_id, station_id, applet_id) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (actor_id, station_id) DO UPDATE SET applet_id = EXCLUDED.applet_id \
             WHERE managed_authority_claims.applet_id = EXCLUDED.applet_id",
        )
        .bind::<Text, _>(&claim.actor_id)
        .bind::<Text, _>(&claim.station_id)
        .bind::<Text, _>(mutation.applet_id.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if inserted != 1 {
            return Err(conflict("applet_managed_authority_conflict"));
        }
    }
    Ok(())
}

/// Install every write one accepted Event produces.
fn commit_one_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    request: EventCommitRequest,
    applet_record: Option<&'a coland_storage::AppletRecordCommit>,
    realm_organization_proof: Option<&'a coland_storage::RealmOrganizationProofCommit>,
    invite_claim_proof: Option<&'a coland_storage::InviteClaimProofCommit>,
    event_approvals: Option<&'a coland_storage::EventApprovalCommit>,
    outcome: &'a mut EventCommitOutcome,
    audit_unit: Option<&'a coland_storage::RegisteredAuditCommit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PgTransactionError>> + Send + 'a>>
{
    // Construct this state machine outside the batch caller's poll frame.
    Box::pin(commit_one_inner(
        conn,
        request,
        applet_record,
        realm_organization_proof,
        invite_claim_proof,
        event_approvals,
        outcome,
        audit_unit,
    ))
}

async fn commit_one_inner(
    conn: &mut AsyncPgConnection,
    request: EventCommitRequest,
    applet_record: Option<&coland_storage::AppletRecordCommit>,
    realm_organization_proof: Option<&coland_storage::RealmOrganizationProofCommit>,
    invite_claim_proof: Option<&coland_storage::InviteClaimProofCommit>,
    event_approvals: Option<&coland_storage::EventApprovalCommit>,
    outcome: &mut EventCommitOutcome,
    audit_unit: Option<&coland_storage::RegisteredAuditCommit>,
) -> Result<(), PgTransactionError> {
    if request.event.event_id != request.authority_commit.event.event_id.as_str() {
        return Err(PersistenceError::SchemaViolation(
            "canonical Event record does not match the authority transaction".to_owned(),
        )
        .into());
    }
    let event = &request.authority_commit.event;
    let mimi = event.payload.contains_key("mimi_provenance")
        || event
            .payload
            .get("provenance")
            .is_some_and(|value| value == "mimi_facade");
    if mimi
        && !matches!(
            request.self_producer_guard,
            Some(coland_storage::SelfProducerCommitGuard::MimiFacade { .. })
        )
    {
        return Err(PersistenceError::Conflict(
            "capability_denied: MIMI facade requires its verified Service producer guard".into(),
        )
        .into());
    }
    let producer_guards = usize::from(request.self_producer_guard.is_some())
        + usize::from(request.forwarded_producer_evidence.is_some())
        + usize::from(request.forwarded_agent_producer.is_some())
        + usize::from(request.applet_producer_guard.is_some());
    if producer_guards > 1 {
        return Err(PersistenceError::SchemaViolation(
            "an Event producer is either local or forwarded, never both".to_owned(),
        )
        .into());
    }

    crate::agent_management_review::lock_candidate_current_realms_in_connection(
        conn,
        event,
        event_approvals,
        request.self_producer_guard.as_ref(),
    )
    .await?;

    if matches!(
        event.scope_ref,
        arkret_wire::ScopeRef::Realm { .. }
            | arkret_wire::ScopeRef::Circle { .. }
            | arkret_wire::ScopeRef::Sidecar { .. }
    ) {
        // Shared writes acquire the Realm cut before controller or Agent producer current.
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    }

    // Only the full original accepted Event and Commit witness permits replay.
    // Return its existing outcome before current producer or policy gates;
    // do not replay projections, quotas, outbox or replace the original fact.
    // The caller's outer transaction obligations and verified transport remain.
    if crate::authority_commit::is_exact_accepted_event_replay(
        conn,
        event,
        &request.authority_commit.commit,
    )
    .await?
    {
        return Ok(());
    }

    let prepared_human = if let Some(retained) = &request.forwarded_producer_evidence {
        let core = &retained.evidence.device_projection_attestation.attestation;
        let source = &core.event_authorization;
        if crate::authority_commit::is_exact_accepted_event_replay(
            conn,
            event,
            &request.authority_commit.commit,
        )
        .await?
        {
            None
        } else {
            if crate::agent_producer_signer_keys::native_control_target_in_connection(
                conn,
                &event.realm_id,
            )
            .await?
            {
                return Err(PersistenceError::Conflict(
                    "ordinary Human source is forbidden for native control Realm".into(),
                )
                .into());
            }
            let verified = arkret_identity::account_device_signer_evidence::verify_forwarded_human_signer_fact(
                &retained.evidence, event, &core.account_id.station_id,
                &request.authority_commit.expected_authority.service_id, &source.forward_body_digest,
                event.realm_id.digest_suite_code().digest_suite(), request.authority_commit.commit.committed_at,
            ).map_err(|e| PersistenceError::Conflict(format!("forward original source failed acceptance: {e}")))?;
            let fact = verified.into_fact();
            if request
                .authority_commit
                .producer_signer_fact
                .as_ref()
                .and_then(|fact| fact.as_account_device())
                != Some(&fact)
                || retained.producer_signer_fact != fact
            {
                return Err(PersistenceError::Conflict(
                    "forward source differs from signed candidate".into(),
                )
                .into());
            }
            crate::agent_producer_signer_keys::validate_account_device_fact_binding(
                event,
                &request.authority_commit.commit,
                Some(&fact),
            )?;
            Some(fact)
        }
    } else {
        Box::pin(
            crate::agent_producer_signer_keys::validate_prepared_local_account_device_in_connection(
                conn,
                &request.authority_commit,
            ),
        )
        .await?
    };

    if let Some(guard) = request.self_producer_guard.as_ref() {
        Box::pin(
            crate::authority_commit::check_self_producer_guard_in_connection(
                conn,
                event,
                guard,
                request.authority_commit.commit.committed_at,
            ),
        )
        .await?;
    }

    if let Some(producer) = request.forwarded_agent_producer.as_ref() {
        arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
            event,
            producer.evidence(),
            &producer.account().station_id,
            request.authority_commit.commit.committed_at,
            None,
        )
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "{}: {error}",
                error
                    .error_code()
                    .unwrap_or(arkret_wire::ErrorCode::SignatureInvalid)
            ))
        })?;
    }

    let mut prepared_service = None;
    let mut service_approvals = Vec::new();
    if let Some(guard) = request.applet_producer_guard.as_ref() {
        if request.self_producer_guard.is_some() || request.forwarded_producer_evidence.is_some() {
            return Err(PersistenceError::SchemaViolation(
                "Applet Service and Human producer guards are exclusive".to_owned(),
            )
            .into());
        }
        let (fact, approvals) =
            crate::managed_message_actor::require_applet_producer_in_connection(
                conn,
                event,
                guard,
                &request.authority_commit.commit,
                event_approvals,
            )
            .await?;
        service_approvals = approvals;
        if request.authority_commit.producer_signer_fact.as_ref() != Some(&fact.clone().into()) {
            return Err(PersistenceError::Conflict(
                "Service signer source changed before acceptance".into(),
            )
            .into());
        }
        crate::agent_producer_signer_keys::validate_producer_fact_binding(
            event,
            &request.authority_commit.commit,
            request.authority_commit.producer_signer_fact.as_ref(),
        )?;
        prepared_service = Some(fact);
    } else if let Some(coland_storage::SelfProducerCommitGuard::AppletManagedDevice(guard)) =
        request.self_producer_guard.as_ref()
    {
        crate::applet_device_admission::require_installation_binding(
            conn,
            event,
            guard,
            request.authority_commit.commit.committed_at,
        )
        .await?;
    } else if event.applet_id.is_some() {
        return Err(PersistenceError::Conflict(
            "failed_precondition: Applet Event requires its exact accepted producer guard"
                .to_owned(),
        )
        .into());
    }

    if let Some(gate) = request.widget_token_gate.as_ref() {
        if request.self_producer_guard.is_none()
            && request.applet_producer_guard.is_none()
            && request.forwarded_producer_evidence.is_none()
            && request.forwarded_agent_producer.is_none()
        {
            return Err(PersistenceError::Conflict(
                "capability_denied: widget token cannot replace the original producer guard".into(),
            )
            .into());
        }
        crate::applet_widget_tokens::check_event(
            conn,
            event,
            gate,
            request.authority_commit.commit.committed_at,
        )
        .await?;
    }

    Box::pin(commit_prepared_event(
        conn,
        request,
        applet_record,
        realm_organization_proof,
        invite_claim_proof,
        event_approvals,
        outcome,
        prepared_human,
        prepared_service,
        service_approvals,
        audit_unit,
    ))
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Commit preparation retains distinct typed optional proofs within the same transaction."
)]
fn commit_prepared_event<'a>(
    conn: &'a mut AsyncPgConnection,
    request: EventCommitRequest,
    applet_record: Option<&'a coland_storage::AppletRecordCommit>,
    realm_organization_proof: Option<&'a coland_storage::RealmOrganizationProofCommit>,
    invite_claim_proof: Option<&'a coland_storage::InviteClaimProofCommit>,
    event_approvals: Option<&'a coland_storage::EventApprovalCommit>,
    outcome: &'a mut EventCommitOutcome,
    prepared_human: Option<
        arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
    >,
    prepared_service: Option<
        arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact,
    >,
    service_approvals: Vec<crate::approval_admission::QualifiedApproval>,
    audit_unit: Option<&'a coland_storage::RegisteredAuditCommit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PgTransactionError>> + Send + 'a>>
{
    Box::pin(commit_prepared_event_inner(
        conn,
        request,
        applet_record,
        realm_organization_proof,
        invite_claim_proof,
        event_approvals,
        outcome,
        prepared_human,
        prepared_service,
        service_approvals,
        audit_unit,
    ))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Atomic Event commit retains distinct typed optional proofs and mutable outcome."
)]
async fn commit_prepared_event_inner(
    conn: &mut AsyncPgConnection,
    request: EventCommitRequest,
    applet_record: Option<&coland_storage::AppletRecordCommit>,
    realm_organization_proof: Option<&coland_storage::RealmOrganizationProofCommit>,
    invite_claim_proof: Option<&coland_storage::InviteClaimProofCommit>,
    event_approvals: Option<&coland_storage::EventApprovalCommit>,
    outcome: &mut EventCommitOutcome,
    prepared_human: Option<
        arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
    >,
    prepared_service: Option<
        arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact,
    >,
    service_approvals: Vec<crate::approval_admission::QualifiedApproval>,
    audit_unit: Option<&coland_storage::RegisteredAuditCommit>,
) -> Result<(), PgTransactionError> {
    let event = &request.authority_commit.event;

    let scope_profile = if crate::applet_scope_profiles::is_profile(event) {
        let Some(coland_storage::SelfProducerCommitGuard::AppletManagedDevice(guard)) =
            request.self_producer_guard.as_ref()
        else {
            return Err(PersistenceError::Conflict(
                "actor_profile_or_accountability_unit_required".into(),
            )
            .into());
        };
        Some(
            crate::boxed_future(|| {
                crate::applet_scope_profiles::prepare(
                    conn,
                    event,
                    guard,
                    request.authority_commit.commit.committed_at,
                )
            })
            .await?,
        )
    } else {
        None
    };

    let management_review = crate::boxed_future(|| {
        crate::agent_management_review::prepare_admission_in_connection(
            conn,
            event,
            event_approvals,
            request.authority_commit.commit.committed_at,
            request.self_producer_guard.as_ref(),
        )
    })
    .await?;

    if event.kind == arkret_wire::EventKind::AgentInteractionSet {
        if !matches!(
            request.self_producer_guard,
            Some(
                coland_storage::SelfProducerCommitGuard::HumanDevice(_)
                    | coland_storage::SelfProducerCommitGuard::HumanDeviceEvidence { .. }
            )
        ) && request.forwarded_producer_evidence.is_none()
        {
            return Err(PersistenceError::Conflict(
                "capability_denied: Agent mode requires the original controller device producer"
                    .into(),
            )
            .into());
        }
        crate::boxed_future(|| {
            crate::agent_interaction_current_results::admit_in_connection(
                conn,
                event,
                &request.authority_commit.commit,
                management_review.as_ref(),
            )
        })
        .await?;
    }

    crate::boxed_future(|| {
        crate::agent_participation_admission::require_current(
            conn,
            event,
            &request.authority_commit.commit,
            &request.authority_commit.expected_authority.service_id,
            request.agent_deployment_ceiling,
        )
    })
    .await?;

    crate::boxed_future(|| {
        crate::agent_interaction_current_results::require_shared_producer_in_connection(
            conn,
            event,
            &request.authority_commit.commit,
        )
    })
    .await?;

    // contact-and-direct-conversation.md section 8.4: the profile table of a
    // Direct Conversation Realm precedes every action authority and writer.
    crate::boxed_future(|| {
        crate::direct_conversation_admission::admit_direct_conversation_event_in_connection(
            conn, event,
        )
    })
    .await?;
    crate::boxed_future(|| {
        crate::organization_moderation_gate::require_organization_join_gate_in_connection(
            conn,
            event,
            &request.authority_commit.commit,
        )
    })
    .await?;

    crate::boxed_future(|| prepare_parent_membership_transaction(conn, &request)).await?;
    crate::boxed_future(|| {
        crate::sidecar_current_results::admit_in_connection(
            conn,
            event,
            &request.authority_commit.commit,
        )
    })
    .await?;

    if let Some(selector) = request.device_revocation_gate.as_ref() {
        crate::boxed_future(|| ensure_gate_allowed_in_transaction(conn, selector)).await?;
    }
    crate::boxed_future(|| ensure_applet_admission_in_transaction(conn, event, applet_record))
        .await?;

    let policy_approvals = if let Some(target) = crate::boxed_future(|| {
        crate::policy_current_results::admit_in_connection(
            conn,
            event,
            &request.authority_commit.commit,
        )
    })
    .await?
    {
        crate::boxed_future(|| {
            crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id)
        })
        .await?;
        let cut = crate::boxed_future(|| {
            crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event)
        })
        .await?;
        crate::boxed_future(|| {
            crate::agent_management_admission::require_policy_write_with_approvals(
                &cut,
                conn,
                event,
                &request.authority_commit.commit,
                event_approvals,
                &target,
            )
        })
        .await?
    } else {
        Vec::new()
    };

    let ordinary_approvals = if matches!(
        event.kind,
        arkret_wire::EventKind::RealmLink
            | arkret_wire::EventKind::RealmSetDefaultStrand
            | arkret_wire::EventKind::RealmOwnerTransfer
            | arkret_wire::EventKind::RealmGovernanceStationChange
            | arkret_wire::EventKind::RealmAuthorityReset
    ) {
        let cut = crate::boxed_future(|| {
            crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event)
        })
        .await?;
        crate::boxed_future(|| {
            cut.require_event_with_approvals(
                conn,
                event,
                &request.authority_commit.commit,
                event_approvals,
            )
        })
        .await?
    } else {
        Vec::new()
    };

    let self_pcr_outcome = crate::boxed_future(|| {
        crate::agent_producer_signer_keys::prepare_self_pcr_outcome_in_connection(
            conn,
            event,
            &request.authority_commit.commit,
            request.self_producer_guard.as_ref(),
        )
    })
    .await?;
    queue_event_in_connection(conn, event, request.event.received_at).await?;

    if let Some(profile) = scope_profile.as_ref() {
        if profile.is_public() {
            let cut =
                crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event)
                    .await?;
            cut.require_managed_self_action_in_connection(
                conn,
                event,
                &request.authority_commit.commit,
                event_approvals,
            )
            .await?;
        }
    }
    let authority_write = if let Some(profile) = scope_profile.as_ref() {
        crate::authority_commit::commit_managed_scope_profile_in_connection(
            conn,
            &request.authority_commit,
            event_approvals,
            profile,
        )
        .await?
    } else {
        crate::authority_commit::commit_transaction_with_approvals_in_connection(
            conn,
            &request.authority_commit,
            event_approvals,
        )
        .await?
    };
    match authority_write {
        AuthorityCommitWriteOutcome::Committed => outcome.event_inserted = true,
        AuthorityCommitWriteOutcome::Duplicate => {}
        AuthorityCommitWriteOutcome::StaleAuthority(current) => {
            return Err(conflict(format!(
                "stale_authority: generation {} is current",
                current.generation
            ))
            .into());
        }
    }

    let commit = &request.authority_commit.commit;
    crate::approval_admission::validate_candidate(event, commit, event_approvals)?;
    if matches!(authority_write, AuthorityCommitWriteOutcome::Committed) {
        crate::boxed_future(|| {
            crate::circle_current_results::admit_with_audit_in_connection(
                conn,
                event,
                &request.authority_commit.commit,
                &request.authority_commit.expected_authority.service_id,
                audit_unit,
                event_approvals,
            )
        })
        .await?;
        crate::boxed_future(|| {
            crate::agent_confirmation_admission::admit_confirmation(
                conn,
                event,
                &request.authority_commit.commit,
                event_approvals,
            )
        })
        .await?;
        crate::boxed_future(|| {
            crate::member_state_admission::admit_member_state_in_connection(
                conn,
                event,
                &request.authority_commit.commit,
                management_review.as_ref(),
                event_approvals,
            )
        })
        .await?;
        if let Some(review) = management_review.as_ref() {
            crate::agent_management_review::consume_in_connection(
                conn,
                event,
                commit,
                review.methods(),
            )
            .await?;
        }
        crate::agent_confirmation_admission::require_publication(conn, event, commit).await?;
        let service_basis = serde_json::json!({"applet_producer_admission":true});
        crate::boxed_future(|| {
            crate::approval_admission::consume_and_audit(
                conn,
                event,
                commit,
                &service_approvals,
                &service_basis,
            )
        })
        .await?;
        if let Some(prepared) = self_pcr_outcome {
            crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
                conn, event, commit, prepared,
            )
            .await?;
        }
        if let Some(fact) = prepared_service.as_ref() {
            crate::agent_producer_signer_keys::retain_prepared_service_in_connection(
                conn, event, commit, fact,
            )
            .await?;
        } else if let Some(fact) = prepared_human.as_ref() {
            crate::agent_producer_signer_keys::retain_prepared_account_device_in_connection(
                conn, event, commit, fact,
            )
            .await?;
            crate::account_device_committed_evidence::retain_from_guard(
                conn,
                event,
                commit,
                fact,
                request.self_producer_guard.as_ref(),
            )
            .await?;
        } else {
            crate::agent_producer_signer_keys::retain_in_connection(
                conn,
                event,
                commit,
                request.self_producer_guard.as_ref(),
            )
            .await?;
        }

        crate::policy_current_results::commit_in_connection(conn, event, commit).await?;
        crate::agent_confirmation_admission::commit_confirmation(conn, event, commit).await?;
        crate::approval_admission::consume_and_audit(
            conn,
            event,
            commit,
            &policy_approvals,
            &serde_json::json!({"policy_admission":true}),
        )
        .await?;
        let ordinary_basis = serde_json::json!({"ordinary_governance_admission":true});
        crate::boxed_future(|| {
            crate::approval_admission::consume_and_audit(
                conn,
                event,
                commit,
                &ordinary_approvals,
                &ordinary_basis,
            )
        })
        .await?;
        if let Some(retained) = request.forwarded_producer_evidence.as_ref() {
            crate::account_device_signer_evidence::retain_forwarded_producer_evidence_in_connection(
                conn, event, commit, retained,
            )
            .await?;
        }
        if let Some(producer) = request.forwarded_agent_producer.as_ref() {
            crate::agent_producer_evidence::retain_in_connection(conn, event, commit, producer)
                .await?;
        }
        if let Some(guard @ coland_storage::SelfProducerCommitGuard::MimiFacade { .. }) =
            request.self_producer_guard.as_ref()
        {
            crate::mimi_admission::persist_mapping_receipt_in_connection(
                conn,
                event,
                guard,
                commit.committed_at,
            )
            .await?;
        }

        Box::pin(commit_event_current_results_in_connection(
            conn,
            &request,
            realm_organization_proof,
            invite_claim_proof,
            event_approvals,
            audit_unit,
        ))
        .await?;

        if !matches!(
            audit_unit,
            Some(coland_storage::RegisteredAuditCommit::Pair { .. })
        ) {
            outcome.outbox_inserted += crate::realm_fanout::plan_realm_fanout_in_connection(
                conn,
                event,
                commit,
                &request.authority_commit.expected_authority.service_id,
                request.realm_fanout_source.as_ref(),
                &request
                    .authority_commit
                    .welcomes
                    .iter()
                    .filter(|welcome| welcome.claim.is_none())
                    .map(|welcome| &welcome.delivery)
                    .collect::<Vec<_>>(),
                commit.committed_at.timestamp(),
            )
            .await?;
        }
    }

    let committed_ref = arkret_wire::CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };

    if let Some(transition) = request.device_revocation_transition.as_ref() {
        commit_revocation_in_connection(conn, transition).await?;
    }
    // An exact replay of the accepting Commit found the Contact effect
    // already installed by the first transaction.
    if let Some(commit) = request.contact_projection
        && matches!(authority_write, AuthorityCommitWriteOutcome::Committed)
    {
        commit_contact_projection(conn, Some(&committed_ref), commit).await?;
    }

    // Like the outbox count below, this reports rows this attempt wrote: an
    // exact replay finds every projection row already present.
    if !request.projections.is_empty() {
        outcome.projections_inserted +=
            append_projection_batch_in_connection(conn, request.projections)
                .await?
                .into_iter()
                .filter(|appended| {
                    *appended == coland_storage::ProjectionEventAppendOutcome::Inserted
                })
                .count();
    }
    for record in &request.outbox {
        if enqueue_federation_outbox_in_connection(conn, record).await? {
            outcome.outbox_inserted += 1;
        }
    }
    if let Some(record) = request.idempotency.as_ref() {
        if matches!(
            request.self_producer_guard,
            Some(coland_storage::SelfProducerCommitGuard::MimiFacade { .. })
        ) && event.kind == arkret_wire::EventKind::SelfModerationReport
        {
            crate::mimi_admission::record_report_idempotency_in_connection(conn, record).await?;
        } else {
            record_idempotency_in_connection(conn, record).await?;
        }
    }
    Ok(())
}

// This phase stays inside the caller's transaction and preserves writer order.
fn commit_event_current_results_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    request: &'a EventCommitRequest,
    realm_organization_proof: Option<&'a coland_storage::RealmOrganizationProofCommit>,
    invite_claim_proof: Option<&'a coland_storage::InviteClaimProofCommit>,
    event_approvals: Option<&'a coland_storage::EventApprovalCommit>,
    audit_unit: Option<&'a coland_storage::RegisteredAuditCommit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PgTransactionError>> + Send + 'a>>
{
    Box::pin(commit_event_current_results_inner(
        conn,
        request,
        realm_organization_proof,
        invite_claim_proof,
        event_approvals,
        audit_unit,
    ))
}

async fn commit_event_current_results_inner(
    conn: &mut AsyncPgConnection,
    request: &EventCommitRequest,
    realm_organization_proof: Option<&coland_storage::RealmOrganizationProofCommit>,
    invite_claim_proof: Option<&coland_storage::InviteClaimProofCommit>,
    event_approvals: Option<&coland_storage::EventApprovalCommit>,
    audit_unit: Option<&coland_storage::RegisteredAuditCommit>,
) -> Result<(), PgTransactionError> {
    Box::pin(commit_scope_current_results(
        conn,
        request,
        realm_organization_proof,
        invite_claim_proof,
        audit_unit,
        event_approvals,
    ))
    .await?;

    Box::pin(commit_object_current_results(
        conn,
        request,
        event_approvals,
    ))
    .await?;

    Box::pin(commit_content_current_results(
        conn,
        request,
        event_approvals,
    ))
    .await?;
    Ok(())
}

fn commit_scope_current_results<'a>(
    conn: &'a mut AsyncPgConnection,
    request: &'a EventCommitRequest,
    realm_organization_proof: Option<&'a coland_storage::RealmOrganizationProofCommit>,
    invite_claim_proof: Option<&'a coland_storage::InviteClaimProofCommit>,
    audit_unit: Option<&'a coland_storage::RegisteredAuditCommit>,
    prepared: Option<&'a coland_storage::EventApprovalCommit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PgTransactionError>> + Send + 'a>>
{
    Box::pin(commit_scope_current_results_inner(
        conn,
        request,
        realm_organization_proof,
        invite_claim_proof,
        audit_unit,
        prepared,
    ))
}

async fn commit_scope_current_results_inner(
    conn: &mut AsyncPgConnection,
    request: &EventCommitRequest,
    realm_organization_proof: Option<&coland_storage::RealmOrganizationProofCommit>,
    invite_claim_proof: Option<&coland_storage::InviteClaimProofCommit>,
    audit_unit: Option<&coland_storage::RegisteredAuditCommit>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> Result<(), PgTransactionError> {
    let event = &request.authority_commit.event;
    let commit = &request.authority_commit.commit;

    Box::pin(commit_realm_authority_root_current_result_in_connection(
        conn, event, commit,
    ))
    .await?;

    Box::pin(crate::realm_bootstrap_current_results::commit_realm_join_rule_authority_current_result_in_connection(conn, event, commit, prepared)).await?;

    Box::pin(crate::realm_bootstrap_current_results::commit_realm_history_access_authority_current_result_in_connection(conn, event, commit, prepared)).await?;
    Box::pin(crate::realm_bootstrap_current_results::commit_plaintext_services_authority_current_result_in_connection(conn, event, commit, prepared)).await?;

    Box::pin(crate::realm_bootstrap_current_results::commit_realm_profile_authority_current_result_in_connection(
        conn, event, commit,
     prepared)).await?;

    Box::pin(crate::realm_bootstrap_current_results::commit_read_receipt_policy_authority_current_result_in_connection(conn, event, commit, prepared)).await?;
    Box::pin(crate::realm_bootstrap_current_results::commit_preview_policy_authority_current_result_in_connection(conn, event, commit, prepared)).await?;

    Box::pin(
        crate::organization_moderation_gate::commit_realm_organization_current_result_in_connection(
            conn,
            event,
            commit,
            realm_organization_proof,
            prepared,
        ),
    )
    .await?;

    Box::pin(crate::call_state_current_results::commit_in_connection(
        conn,
        event,
        commit,
        prepared,
        request.verified_media_participant.as_ref(),
    ))
    .await?;

    Box::pin(crate::circle_current_results::commit_in_connection(
        conn, event, commit,
    ))
    .await?;

    Box::pin(
        crate::strand_watch_current_results::commit_with_audit_in_connection(
            conn, event, commit, audit_unit, prepared,
        ),
    )
    .await?;

    Box::pin(crate::agent_interaction_current_results::project_in_connection(conn, event, commit))
        .await?;

    Box::pin(crate::sidecar_current_results::commit_in_connection(
        conn, event, commit,
    ))
    .await?;

    Box::pin(crate::sidecar_exchange_controls::commit_in_connection(
        conn, event, commit, true,
    ))
    .await?;

    Box::pin(commit_relation_current_result_in_connection(
        conn, event, commit, true, prepared,
    ))
    .await?;

    Box::pin(crate::capability_grant_current_results::commit_qualified_capability_grant_current_result_in_connection(
        conn, event, commit, request.agent_grant_scope_evidence.as_ref(),
     prepared))
    .await?;
    // An accepted Invite decides its accepting actor's `leave -> join`
    // edge against the member row before that row is written.

    Box::pin(
        crate::invite_current_results::commit_invite_current_results_in_connection(
            conn,
            event,
            commit,
            invite_claim_proof,
            prepared,
        ),
    )
    .await?;
    if event.kind == arkret_wire::EventKind::RealmPolicyBundle {
        Box::pin(
            crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
                conn, event, commit, prepared,
            ),
        )
        .await?;
    }
    Ok(())
}

fn commit_object_current_results<'a>(
    conn: &'a mut AsyncPgConnection,
    request: &'a EventCommitRequest,
    event_approvals: Option<&'a coland_storage::EventApprovalCommit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PgTransactionError>> + Send + 'a>>
{
    Box::pin(commit_object_current_results_inner(
        conn,
        request,
        event_approvals,
    ))
}

async fn commit_object_current_results_inner(
    conn: &mut AsyncPgConnection,
    request: &EventCommitRequest,
    event_approvals: Option<&coland_storage::EventApprovalCommit>,
) -> Result<(), PgTransactionError> {
    let event = &request.authority_commit.event;
    let commit = &request.authority_commit.commit;
    Box::pin(commit_parent_membership_current_results(
        conn, event, commit,
    ))
    .await?;
    Box::pin(commit_schema_definition_in_connection(
        conn,
        event,
        commit,
        true,
        event_approvals,
    ))
    .await?;
    Box::pin(
        crate::mls_group_current_results::advance_key_access_revision_in_connection(
            conn, event, commit,
        ),
    )
    .await?;
    Box::pin(
        crate::mls_group_current_results::commit_mls_group_current_result_in_connection(
            conn,
            &request.authority_commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::direct_conversation_admission::commit_binding_current_result_in_connection(
            conn, event, commit,
        ),
    )
    .await?;
    Box::pin(
        crate::authority_commit::commit_mimi_room_binding_current_result_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::strand_current_results::commit_strand_create_current_result_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::strand_current_results::commit_strand_update_authority_current_result_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(crate::strand_current_results::commit_strand_tracks_update_authority_current_result_in_connection(
        conn, event, commit,
     event_approvals)).await?;
    Box::pin(
        crate::strand_current_results::commit_strand_transition_in_connection(
            conn,
            event,
            commit,
            true,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::strand_position_current_results::commit_authority_position_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::space_current_results::commit_space_create_current_results_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::space_current_results::commit_space_transition_in_connection(
            conn,
            event,
            commit,
            true,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::space_current_results::commit_space_update_in_connection(
            conn,
            event,
            commit,
            true,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::space_current_results::commit_space_parent_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::rsvp_current_results::commit_rsvp_current_result_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(crate::realm_default_strand_current_results::commit_realm_default_strand_current_result_in_connection(
        conn, event, commit,
    )).await?;
    Ok(())
}

fn commit_content_current_results<'a>(
    conn: &'a mut AsyncPgConnection,
    request: &'a EventCommitRequest,
    event_approvals: Option<&'a coland_storage::EventApprovalCommit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PgTransactionError>> + Send + 'a>>
{
    Box::pin(commit_content_current_results_inner(
        conn,
        request,
        event_approvals,
    ))
}

async fn commit_content_current_results_inner(
    conn: &mut AsyncPgConnection,
    request: &EventCommitRequest,
    event_approvals: Option<&coland_storage::EventApprovalCommit>,
) -> Result<(), PgTransactionError> {
    let event = &request.authority_commit.event;
    let commit = &request.authority_commit.commit;
    Box::pin(crate::mls_group_current_results::require_mls_send_gate_in_connection(conn, event))
        .await?;
    Box::pin(crate::member_identity_current_results::commit_in_connection(conn, event, commit))
        .await?;
    Box::pin(
        crate::message_revision_current_results::commit_message_create_current_result_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::message_revision_current_results::commit_message_revise_current_result_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::object_redaction_current_results::commit_message_redact_current_result_in_connection(
            conn,
            event,
            commit,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(
        crate::message_reactions_current_results::commit_reaction_current_result_in_connection(
            conn,
            event,
            commit,
            true,
            event_approvals,
        ),
    )
    .await?;
    Box::pin(crate::pin_current_results::commit_pin_in_connection(
        conn,
        event,
        commit,
        true,
        event_approvals,
    ))
    .await?;
    Box::pin(crate::moderation_report_current_results::commit_moderation_report_current_result_in_connection(
        conn, event, commit,
    )).await?;
    Box::pin(crate::moderation_state_current_results::commit_moderation_state_current_result_in_connection(
        conn, event, commit, event_approvals,
    )).await?;
    Box::pin(crate::moderation_franking_proof_current_results::commit_franking_current_result_in_connection(
        conn, event, commit,
    )).await?;
    Box::pin(
        crate::moderation_franking_proof_current_results::enqueue_franking_in_connection(
            conn,
            event,
            &request.authority_commit.expected_authority.service_id,
            request.event.received_at,
        ),
    )
    .await?;
    if crate::account_summary::changes_account_summary_inputs(&event.kind) {
        Box::pin(
            crate::account_summary::publish_realm_account_summary_in_connection(
                conn,
                &event.realm_id,
            ),
        )
        .await?;
    }
    Box::pin(
        crate::sidecar_authority_change_guard::after_current_writes_in_connection(conn, event),
    )
    .await?;
    Ok(())
}

async fn commit_batch_in_connection(
    conn: &mut AsyncPgConnection,
    mut request: EventBatchCommitRequest,
) -> Result<EventCommitOutcome, PgTransactionError> {
    if request.events.is_empty() {
        return Err(PersistenceError::SchemaViolation("empty event batch".to_owned()).into());
    }
    coland_storage::validate_franking_replay_nonce_commit(
        &request.events,
        request.franking_replay_nonce.as_ref(),
    )?;
    crate::registered_audit::bind_approvals(&mut request)?;
    let audit_unit = request.audit_unit.as_ref();
    if let Some(original) =
        crate::boxed_future(|| crate::registered_audit::begin_in_connection(conn, &request)).await?
    {
        return Ok(EventCommitOutcome {
            audit_outcome: Some(original),
            ..Default::default()
        });
    }
    let mut snapshot_contexts = std::collections::BTreeMap::new();
    for request in &request.events {
        snapshot_contexts.insert(
            request.authority_commit.event.realm_id.clone(),
            (
                request
                    .authority_commit
                    .commit
                    .signature
                    .verification_method
                    .clone(),
                request.authority_commit.commit.committed_at,
            ),
        );
    }
    // One Realm-wide lock makes capacity measurement part of the same
    // serialization boundary even when concurrent commits target different
    // Circle or Sidecar streams.
    for realm_id in snapshot_contexts.keys() {
        advisory_lock(conn, format!("realm-snapshot-capacity:{realm_id}")).await?;
    }
    stage_agent_membership_cascade(
        conn,
        request.agent_membership_cascade.as_ref(),
        &request.events,
    )
    .await?;

    let mut outcome = EventCommitOutcome::default();
    let audit_events = request
        .events
        .iter()
        .map(|event| event.authority_commit.clone())
        .collect::<Vec<_>>();
    for event in request.events {
        let slot_approvals = match audit_unit {
            Some(coland_storage::RegisteredAuditCommit::Pair { request, approvals }) => {
                let slot = request
                    .events
                    .iter()
                    .position(|slot| slot.event.event_id == event.authority_commit.event.event_id)
                    .ok_or_else(|| {
                        PersistenceError::SchemaViolation(
                            "audit unit contains an unrelated Event".to_owned(),
                        )
                    })?;
                approvals[slot].as_ref()
            }
            _ => request.event_approvals.as_ref(),
        };
        // Keep the per-Event admission state out of the enclosing batch future.
        Box::pin(commit_one_in_connection(
            conn,
            event,
            request.applet_record.as_ref(),
            request.realm_organization_proof.as_ref(),
            request.invite_claim_proof.as_ref(),
            slot_approvals,
            &mut outcome,
            audit_unit,
        ))
        .await?;
    }

    if let Some(nonce) = request.franking_replay_nonce.as_ref() {
        commit_franking_replay_nonce(conn, nonce).await?;
    }
    if let Some(preview) = request.applet_authoring_preview.as_ref() {
        let updated = sql_query(
            "UPDATE applet_authoring_previews SET status = 'committed', committed_at = NOW() \
             WHERE subject_key = $1 AND request_digest = $2 AND status = 'current'",
        )
        .bind::<Text, _>(&preview.subject_key)
        .bind::<Text, _>(&preview.request_digest)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if updated != 1 {
            return Err(conflict("duplicate_conflict").into());
        }
    }
    if let Some(mutation) = request.applet_record {
        commit_applet_record(conn, mutation).await?;
    }
    for (realm_id, (verification_method, created_at)) in snapshot_contexts {
        enforce_realm_snapshot_capacity_in_connection(
            conn,
            &realm_id,
            &verification_method,
            created_at,
        )
        .await?;
    }
    if let Some(unit) = audit_unit {
        outcome.audit_outcome = Some(
            crate::boxed_future(|| {
                crate::registered_audit::finish_in_connection(conn, unit, &audit_events)
            })
            .await?,
        );
    }
    Ok(outcome)
}

#[async_trait::async_trait]
impl EventCommitUnitOfWork for PgEventCommitUnitOfWork {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.commit_event_batch(EventBatchCommitRequest {
            audit_unit: None,
            events: vec![request],
            realm_organization_proof: None,
            invite_claim_proof: None,
            event_approvals: None,
            franking_replay_nonce: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        })
        .await
    }

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Box::pin(commit_batch_in_connection(conn, request)).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

#[cfg(test)]
mod agent_draft_consumption_tests {
    use coland_storage::{
        AccountDataRecord, AccountDataStore, AgentDraftPendingIntentCommit,
        AgentDraftPendingIntentRecord, AgentDraftPendingIntentState, AgentDraftPendingIntentStore,
        PersistenceError, SyncCursorStore,
    };
    use diesel::sql_types::{Binary, Jsonb, Text};
    use diesel_async::{AsyncConnection, RunQueryDsl};

    use super::*;
    use crate::agent_draft_pending_intents::commit_agent_draft_pending_intent_in_connection;

    fn hash(byte: char) -> arkret_wire::Hash {
        arkret_wire::Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn account(label: &str) -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn pending(
        controller: &arkret_wire::AccountId,
        agent_id: &arkret_wire::DidCoreId,
        draft_id: &str,
        source: &arkret_wire::Event,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AgentDraftPendingIntentCommit {
        AgentDraftPendingIntentCommit {
            record: AgentDraftPendingIntentRecord {
                controller_account_id: controller.clone(),
                agent_id: agent_id.clone(),
                draft_id: draft_id.to_owned(),
                proposed_action: "ak.message.create".to_owned(),
                target: serde_json::json!({"kind":"realm","realm_id":"ak:realm:AcQajqaKFvyDoMpqpSlBvMh0d4gheZsVPhbHaTlqXtkV"}),
                content_digest: hash('1'),
                content_handoff: Some(serde_json::json!({
                    "scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1",
                    "recipients":[{
                        "recipient_device_id":"ak:device:01964137-0000-7000-8000-000000000001",
                        "recipient_hpke_key_digest":hash('2'),
                        "enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
                        "ciphertext_digest":hash('3')
                    }]
                })),
                canonical_event_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(source).unwrap(),
                )
                .unwrap(),
                accepted_event_id: source.event_id.clone(),
                expires_at: now + chrono::TimeDelta::minutes(10),
                created_at: now,
                state: AgentDraftPendingIntentState::Available,
                consumption: None,
                expired_at: None,
            },
        }
    }

    /// The fixture principal-control Realm of `account`.
    fn pcr_realm(account: &arkret_wire::AccountId) -> arkret_wire::RealmId {
        arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(format!("fixture-pcr:{account}").as_bytes()),
        ))
    }

    /// Resolve `account` to its fixture principal-control Realm.
    async fn seed_pcr(conn: &mut AsyncPgConnection, account: &arkret_wire::AccountId) {
        sql_query(
            "INSERT INTO principal_resolutions \
             (principal_id, station_id, pcr_realm_id, genesis_event_id, current_event_id, projection, updated_at) \
             VALUES ($1,$2,$3,'fixture-genesis','fixture-current','{}'::jsonb,now()) ON CONFLICT DO NOTHING",
        )
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .bind::<Text, _>(pcr_realm(account).as_str())
        .execute(conn)
        .await
        .unwrap();
    }

    fn account_data_event(
        controller: &arkret_wire::AccountId,
        key: &str,
        source_event_id: &arkret_wire::EventId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> (arkret_wire::Event, serde_json::Value) {
        let encrypted_payload = serde_json::json!({
            "schema":"ak.schema.account_data_encrypted_value.v1",
            "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"
        });
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::AccountDataSet.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: pcr_realm(controller),
            },
            controller.principal_id.clone(),
            controller.station_id.clone(),
            serde_json::json!({
                "key": key,
                "expected_server_revision": 0,
                "encrypted_payload": encrypted_payload,
                "source_pending_event_id": source_event_id,
            }),
            now,
        )
        .unwrap();
        (event, encrypted_payload)
    }

    fn proposal_event(
        controller: &arkret_wire::AccountId,
        agent: &arkret_wire::DidCoreId,
        draft: &str,
        marker: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> arkret_wire::Event {
        let template = pending(
            controller,
            agent,
            draft,
            &arkret_wire::test_support::raw_event_at(
                "ak.agent.draft.propose",
                arkret_wire::ScopeRef::RealmGenesis,
                agent.clone(),
                controller.station_id.clone(),
                serde_json::json!({}),
                now,
            )
            .unwrap(),
            now,
        );
        let record = template.record;
        arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::AgentDraftPropose.as_str(), arkret_wire::ScopeRef::RealmGenesis,
            agent.clone(), controller.station_id.clone(),
            serde_json::json!({"draft_id":record.draft_id,"agent_id":record.agent_id,"controller_account_id":controller,
                "proposed_action":record.proposed_action,"target":record.target,"content_digest":record.content_digest,
                "content_handoff":record.content_handoff,"expires_at":arkret_canonical::format_timestamp_canonical(record.expires_at),
                "created_at":arkret_canonical::format_timestamp_canonical(now),"summary":marker}), now,
        ).unwrap()
    }

    fn cas(
        event: &arkret_wire::Event,
        key: &str,
        encrypted_payload: serde_json::Value,
    ) -> coland_storage::AccountDataCasCommit {
        coland_storage::AccountDataCasCommit {
            record: AccountDataRecord {
                actor: event.actor_id.to_string(),
                account_data_key: key.to_owned(),
                revision: 1,
                payload: encrypted_payload,
                tombstone: false,
                updated_at: event.created_at,
            },
            expected_revision: 0,
            conflict_code: "cas_conflict".to_owned(),
        }
    }

    async fn insert_private_source(
        conn: &mut AsyncPgConnection,
        event: &arkret_wire::Event,
    ) -> Result<(), PersistenceError> {
        let bytes =
            arkret_canonical::canonical_json_bytes(event).map_err(PersistenceError::database)?;
        let outcome = arkret_wire::ActorPrivateEventSubmitOutcome::AgentDraftPropose {
            accepted_event_id: event.event_id.clone(),
        };
        sql_query("INSERT INTO actor_private_events(id,event_id,actor_id,kind,canonical_event_digest,envelope,outcome,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).bind::<Text,_>(event.event_id.as_str())
            .bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(event.kind.as_str())
            .bind::<Binary,_>(arkret_canonical::sha256_bytes(&bytes).to_vec()).bind::<Jsonb,_>(serde_json::json!(event))
            .bind::<Jsonb,_>(serde_json::json!(outcome)).bind::<Timestamptz,_>(event.created_at)
            .execute(conn).await.map_err(PersistenceError::database)?;
        Ok(())
    }

    /// Admit one account-data Event through the private actor-private
    /// transaction the self operation uses, without a producer guard.
    async fn apply_account_data_in_transaction(
        conn: &mut AsyncPgConnection,
        event: arkret_wire::Event,
        mutation: coland_storage::AccountDataCasCommit,
    ) -> Result<coland_storage::ActorPrivateAccountDataOutcome, PersistenceError> {
        let admission = coland_storage::ActorPrivateAccountDataAdmission {
            canonical_event_digest: arkret_canonical::sha256_bytes(
                &arkret_canonical::canonical_json_bytes(&event).unwrap(),
            )
            .to_vec(),
            accepted_at: event.created_at,
            event,
            cas: mutation,
            producer_guard: None,
        };
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            admit_actor_private_account_data_in_connection(conn, &admission)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    #[tokio::test]
    async fn revision_one_consumes_source_and_exact_replay_is_a_noop() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let now = "2026-09-20T01:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let controller = account("draft-consume");
        let agent = arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let draft_id = "draft-001";
        let proposal = proposal_event(&controller, &agent, "draft-001", "happy", now);
        let source_event_id = proposal.event_id.clone();
        let key = arkret_models_collaboration::events_payloads::account_data::agent_draft_account_data_key(
            &agent,
            draft_id,
        )
        .unwrap();
        let mut conn = crate::pg_conn(&pool).await.unwrap();
        seed_pcr(&mut conn, &controller).await;
        insert_private_source(&mut conn, &proposal).await.unwrap();
        commit_agent_draft_pending_intent_in_connection(
            &mut conn,
            &pending(&controller, &agent, draft_id, &proposal, now),
        )
        .await
        .unwrap();
        let (event, encrypted_payload) = account_data_event(
            &controller,
            &key,
            &source_event_id,
            now + chrono::TimeDelta::minutes(1),
        );
        let mutation = cas(&event, &key, encrypted_payload.clone());
        let event_for_commit = event.clone();
        apply_account_data_in_transaction(&mut conn, event_for_commit, mutation)
            .await
            .unwrap();

        let pending_store = crate::PgAgentDraftPendingIntentStore { pool: pool.clone() };
        let consumed = pending_store
            .get_by_source_event(&controller, &source_event_id, event.created_at)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(consumed.state, AgentDraftPendingIntentState::Consumed);
        assert!(consumed.content_handoff.is_none());
        assert_eq!(
            consumed
                .consumption
                .as_ref()
                .unwrap()
                .account_data_set_event_id,
            event.event_id
        );
        assert_eq!(consumed.consumption.as_ref().unwrap().account_data_key, key);
        assert_eq!(consumed.consumption.as_ref().unwrap().accepted_revision, 1);
        let stored = crate::PgAccountDataStore { pool: pool.clone() }
            .get(&event.actor_id.to_string(), &key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.payload, encrypted_payload);

        let sync = crate::PgSyncCursorStore { pool: pool.clone() };
        let actor_key = event.actor_id.canonical_key().unwrap();
        let cut = sync.account_global_watermark().await.unwrap();
        assert_eq!(
            sync.account_global_channel_position(&actor_key, "agent_draft_pending_intents", cut,)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            sync.account_global_channel_position(&actor_key, "account_data_events", cut)
                .await
                .unwrap(),
            1
        );

        let before_replay = sync.account_global_watermark().await.unwrap();
        let replay_event = event.clone();
        let replay_mutation = cas(&replay_event, &key, stored.payload.clone());
        assert_eq!(
            apply_account_data_in_transaction(&mut conn, replay_event, replay_mutation)
                .await
                .expect("byte-identical replay returns the original outcome"),
            coland_storage::ActorPrivateAccountDataOutcome::Replayed
        );
        assert_eq!(
            sync.account_global_watermark().await.unwrap(),
            before_replay
        );

        let (second_event, second_payload) = account_data_event(
            &controller,
            &key,
            &source_event_id,
            now + chrono::TimeDelta::minutes(2),
        );
        let second_id = second_event.event_id.clone();
        let second_mutation = cas(&second_event, &key, second_payload);
        let error = apply_account_data_in_transaction(&mut conn, second_event, second_mutation)
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::DuplicateConflict)
        );
        let second_count =
            sql_query("SELECT count(*)::bigint AS count FROM actor_private_events WHERE id=$1")
                .bind::<Binary, _>(second_id.token_bytes().to_vec())
                .get_result::<CountRow>(&mut conn)
                .await
                .unwrap();
        assert_eq!(second_count.count, 0);
        assert_eq!(
            sync.account_global_watermark().await.unwrap(),
            before_replay
        );
    }

    #[tokio::test]
    async fn cas_conflict_and_foreign_controller_roll_back_without_consuming() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let now = "2026-09-20T02:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let controller = account("draft-conflict");
        let agent = arkret_wire::DidCoreId::new("ak:did_core:web:agent-conflict.example").unwrap();
        let proposal = proposal_event(&controller, &agent, "draft-conflict", "conflict", now);
        let source_event_id = proposal.event_id.clone();
        let key = arkret_models_collaboration::events_payloads::account_data::agent_draft_account_data_key(
            &agent,
            "draft-conflict",
        )
        .unwrap();
        let mut conn = crate::pg_conn(&pool).await.unwrap();
        seed_pcr(&mut conn, &controller).await;
        insert_private_source(&mut conn, &proposal).await.unwrap();
        commit_agent_draft_pending_intent_in_connection(
            &mut conn,
            &pending(&controller, &agent, "draft-conflict", &proposal, now),
        )
        .await
        .unwrap();
        let (event, encrypted_payload) = account_data_event(
            &controller,
            &key,
            &source_event_id,
            now + chrono::TimeDelta::minutes(1),
        );
        let occupied = AccountDataRecord {
            actor: event.actor_id.to_string(),
            account_data_key: key.clone(),
            revision: 1,
            payload: serde_json::json!({"occupied":true}),
            tombstone: false,
            updated_at: now,
        };
        crate::PgAccountDataStore { pool: pool.clone() }
            .compare_and_set(&occupied, 0)
            .await
            .unwrap();
        let rejected_event_id = event.event_id.clone();
        let rejected_event = event.clone();
        let mutation = cas(&event, &key, encrypted_payload);
        let error = apply_account_data_in_transaction(&mut conn, rejected_event, mutation)
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::CasConflict)
        );
        let source = crate::PgAgentDraftPendingIntentStore { pool: pool.clone() }
            .get_by_source_event(&controller, &source_event_id, event.created_at)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source.state, AgentDraftPendingIntentState::Available);
        assert!(source.content_handoff.is_some());
        assert!(source.consumption.is_none());
        let event_count =
            sql_query("SELECT count(*)::bigint AS count FROM actor_private_events WHERE id=$1")
                .bind::<Binary, _>(rejected_event_id.token_bytes().to_vec())
                .get_result::<CountRow>(&mut conn)
                .await
                .unwrap();
        assert_eq!(event_count.count, 0, "rejected source Event must roll back");
        assert_eq!(
            crate::PgAccountDataStore { pool: pool.clone() }
                .get(&event.actor_id.to_string(), &key)
                .await
                .unwrap()
                .unwrap()
                .payload,
            serde_json::json!({"occupied":true})
        );

        let foreign = account("draft-foreign");
        seed_pcr(&mut conn, &foreign).await;
        let (foreign_event, foreign_payload) = account_data_event(
            &foreign,
            &key,
            &source_event_id,
            now + chrono::TimeDelta::minutes(2),
        );
        let foreign_id = foreign_event.event_id.clone();
        let foreign_actor = foreign_event.actor_id.to_string();
        let foreign_mutation = cas(&foreign_event, &key, foreign_payload);
        let error = apply_account_data_in_transaction(&mut conn, foreign_event, foreign_mutation)
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::FailedPrecondition)
        );
        let foreign_count =
            sql_query("SELECT count(*)::bigint AS count FROM actor_private_events WHERE id=$1")
                .bind::<Binary, _>(foreign_id.token_bytes().to_vec())
                .get_result::<CountRow>(&mut conn)
                .await
                .unwrap();
        assert_eq!(foreign_count.count, 0);
        assert!(
            crate::PgAccountDataStore { pool: pool.clone() }
                .get(&foreign_actor, &key)
                .await
                .unwrap()
                .is_none()
        );

        let wrong_agent =
            arkret_wire::DidCoreId::new("ak:did_core:web:wrong-agent.example").unwrap();
        let wrong_key = arkret_models_collaboration::events_payloads::account_data::agent_draft_account_data_key(
            &wrong_agent,
            "draft-conflict",
        )
        .unwrap();
        let (wrong_key_event, wrong_key_payload) = account_data_event(
            &controller,
            &wrong_key,
            &source_event_id,
            now + chrono::TimeDelta::minutes(3),
        );
        let wrong_key_id = wrong_key_event.event_id.clone();
        let wrong_key_actor = wrong_key_event.actor_id.to_string();
        let wrong_key_mutation = cas(&wrong_key_event, &wrong_key, wrong_key_payload);
        let mut conn = crate::pg_conn(&pool).await.unwrap();
        let error =
            apply_account_data_in_transaction(&mut conn, wrong_key_event, wrong_key_mutation)
                .await
                .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::FailedPrecondition)
        );
        let wrong_key_count =
            sql_query("SELECT count(*)::bigint AS count FROM actor_private_events WHERE id=$1")
                .bind::<Binary, _>(wrong_key_id.token_bytes().to_vec())
                .get_result::<CountRow>(&mut conn)
                .await
                .unwrap();
        assert_eq!(wrong_key_count.count, 0);
        assert!(
            crate::PgAccountDataStore { pool }
                .get(&wrong_key_actor, &wrong_key)
                .await
                .unwrap()
                .is_none()
        );
    }
}

/// A schema subject is immutable after its first accepted definition.
pub(crate) async fn commit_schema_definition_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authorize: bool,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::SchemaDefine {
        return Ok(());
    }
    let value = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    arkret_schema::validate_schema_definition_payload(&value)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: arkret_models_collaboration::events_payloads::registry_state::SchemaDefineStatePayload =
        serde_json::from_value(value).map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let subject = payload
        .schema_id()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: schema definition requires its Realm authority cut".to_owned(),
        ));
    }
    if authorize {
        crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
            conn, event, commit, prepared,
        )
        .await?;
    }
    let document = serde_json::Value::Object(payload.value.clone());
    let previous = sql_query("SELECT value FROM schema_definition_current_results WHERE realm_id=$1 AND schema_id=$2 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(subject)
        .get_result::<ParentMembershipPolicyRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(previous) = previous {
        if previous.value != document {
            return Err(PersistenceError::Conflict("failed_precondition: schema definition subject is already occupied by different bytes".to_owned()));
        }
        return Ok(());
    }
    let position = i64::try_from(commit.stream_position).map_err(PersistenceError::database)?;
    sql_query("INSERT INTO schema_definition_current_results (realm_id,schema_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(subject)
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(position)
        .bind::<Jsonb,_>(&document).bind::<Timestamptz,_>(commit.committed_at)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
