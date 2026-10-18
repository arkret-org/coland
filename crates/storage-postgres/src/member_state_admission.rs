//! Same-cut admission of the Realm membership FSM.
//!
//! Two registered Event kinds move a Realm `member_state` outside the
//! bootstrap unit: an ordinary `ak.member.state` transition and the
//! `leave -> join` edge an exact `ak.invite.accept` drives
//! (`common-fields.md` §4.5, `realm-and-space.md` §2.7,
//! `governance-objects.md` §5.3). An ordinary transition is decided here,
//! inside the Event's RealmCommit transaction and before any of its writes, against the locked
//! durable member row, the Realm's typed join rule and join policy and the
//! writer's authorization from the same-cut evaluator in
//! [`crate::realm_authorization_cut`]. The in-process reducer projection is
//! never an input.
//!
//! Supported `ak.member.state` writers are the target ActorId itself and a
//! joined member holding an action that authorizes the kind at the same cut
//! (the Realm root controller through its effective `ak.realm.owner`).
//! Invite acceptance is decided with its Invite lifecycle by
//! [`crate::invite_current_results`], which reuses this module's member row
//! lock and Realm role check. Agent controller joins bind accepted ownership
//! and the controller's exact joined generation. Circle and Strand scoped
//! membership and join policies
//! whose proof gates need a same-cut re-evaluation stay closed.

use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_types::{Bool, Jsonb, Text};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

use crate::realm_authorization_cut::{RealmAuthorizationCut, lock_realm_authorization_cut};

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(diesel::QueryableByName)]
struct CurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct MembershipRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

#[derive(diesel::QueryableByName)]
struct ControllerJoinRow {
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    event_id: String,
}

#[derive(diesel::QueryableByName)]
struct AgentKeyPackageAuthorityRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Text)]
    verification_method: String,
}

/// A published Agent endpoint must be claimable under the same accepted key
/// authorization at this transaction's cut. Membership is established by the
/// caller's join; it cannot be a precondition of this first-join check. The
/// subsequent Add/Welcome has its own claim and RFC public-transition gate.
async fn require_agent_membership_keypackage(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    pcr: &arkret_wire::RealmId,
    agent: &arkret_wire::AccountId,
    controller: &arkret_wire::AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let candidate = sql_query(
        "SELECT e.envelope,c.commit_json,kp.endpoint_verification_method AS verification_method \
         FROM mls_key_packages kp JOIN accounts a ON a.principal_id=kp.owner_account_id->>'principal_id' AND a.station_id=kp.owner_account_id->>'station_id' \
         JOIN canonical_events e ON e.id=kp.agent_key_authorize_event_id AND e.state='committed' \
           AND e.kind='ak.agent.key.authorize' \
         JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=$1 \
         JOIN agent_key_current_results k ON k.realm_id=$1 AND k.agent_id=$2 \
           AND k.agent_key_id=e.envelope->'payload'->>'key_id' \
         JOIN realm_commits kc ON kc.commit_id=k.current_commit_id AND kc.realm_id=k.realm_id \
           AND kc.stream_position=k.current_stream_position \
         WHERE kp.actor_id=$2 AND a.principal_id=$6 AND a.station_id=$3 \
           AND kp.device_id IS NULL AND kp.device_authorize_event_id IS NULL \
           AND kp.endpoint_verification_method=e.envelope->'payload'->>'verification_method' \
           AND kp.lifetime_not_before <= $4 AND kp.lifetime_not_after > $4 \
           AND kp.capabilities @> '[\"ak.content.v1\",\"mimi.content.v1\"]'::jsonb \
           AND kp.claimed_by_mls_group_id IS NULL AND kp.claimed_at IS NULL \
           AND kp.claim_expires_at_unix_ms IS NULL AND kp.consumed_at IS NULL \
           AND (NOT kp.last_resort OR kp.last_resort_realm_id IS NULL OR kp.last_resort_realm_id=$5) \
           AND EXISTS(SELECT 1 FROM jsonb_array_elements(k.value->'authorizations') entry \
             WHERE entry->>'tag_id'=(e.envelope->>'event_id')||':1' \
               AND entry->'value'=e.envelope->'payload') \
         ORDER BY kp.created_at,kp.id LIMIT 1 FOR SHARE OF kp,k",
    )
    .bind::<Text, _>(pcr.as_str())
    .bind::<Text, _>(agent.principal_id.as_str())
    .bind::<Text, _>(agent.station_id.as_str())
    .bind::<diesel::sql_types::BigInt, _>(at.timestamp())
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(controller.principal_id.as_str())
    .get_result::<AgentKeyPackageAuthorityRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| failed_precondition("Agent has no claimable membership KeyPackage"))?;
    let event: arkret_wire::Event =
        serde_json::from_value(candidate.envelope).map_err(PersistenceError::database)?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(candidate.commit_json).map_err(PersistenceError::database)?;
    crate::authority_commit::check_agent_endpoint_current_in_connection(
        conn,
        pcr,
        &agent.principal_id,
        &arkret_wire::CommittedEventRef {
            event_id: event.event_id,
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        },
        &arkret_wire::DidUrl::new(candidate.verification_method)
            .map_err(PersistenceError::database)?,
        at,
    )
    .await
}

fn failed_precondition(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::FailedPrecondition))
}

fn invalid_membership_transition(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "{}: {detail}",
        ConflictCode::InvalidMembershipTransition
    ))
}

fn capability_denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::CapabilityDenied))
}

fn gate_check_failed() -> PersistenceError {
    PersistenceError::Conflict(ConflictCode::GateCheckFailed.as_str().to_owned())
}

fn unsupported(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::UnsupportedFeature))
}

fn state_name(state: MembershipPayloadState) -> &'static str {
    match state {
        MembershipPayloadState::Join => "join",
        MembershipPayloadState::Knock => "knock",
        MembershipPayloadState::Leave => "leave",
        MembershipPayloadState::Ban => "ban",
    }
}

/// Who may write one listed edge of the shared membership FSM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EdgeWriter {
    /// Only the target ActorId, subject to the join rule.
    SelfEntry,
    /// The target ActorId or an authorized administrator.
    SelfOrAdmin,
    /// Only an authorized administrator.
    Admin,
}

/// The closed edge table of `common-fields.md` §4.5 for an ordinary
/// transition. `leave -> join` by invite acceptance is a separate Event kind
/// and the bootstrap creator slot is its own atomic unit, so neither is here.
fn edge_writer(from: &str, to: &str) -> Option<EdgeWriter> {
    match (from, to) {
        ("leave", "knock" | "join") => Some(EdgeWriter::SelfEntry),
        ("knock", "join") => Some(EdgeWriter::Admin),
        ("knock", "leave") | ("join", "leave") => Some(EdgeWriter::SelfOrAdmin),
        ("leave" | "knock" | "join", "ban") => Some(EdgeWriter::Admin),
        ("ban", "leave") => Some(EdgeWriter::Admin),
        _ => None,
    }
}

/// Realm membership moves only on the Realm stream. Managed Applet authors
/// additionally close their identity and Service authorization at this cut.
fn require_realm_stream_carrier(
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if !matches!(&event.scope_ref, arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(unsupported(
            "Realm membership is admitted only on the Realm stream",
        ));
    }
    if event.executed_by.is_some() && event.applet_id.is_none() {
        return Err(unsupported(
            "delegated or Applet-authored membership has no same-cut admission",
        ));
    }
    Ok(())
}

/// Only an ordinary collaboration Realm has the membership admission here;
/// other Realm roles are governed by their own profile, and an Agent enters
/// only through its controller binding.
pub(crate) async fn require_ordinary_member(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> PersistenceResult<()> {
    require_ordinary_realm(conn, realm_id).await?;
    if let Some(account) = member.as_account_id()
        && crate::realm_authorization_cut::is_owned_agent_in_connection(conn, realm_id, account)
            .await?
    {
        return Err(unsupported(
            "Agent membership needs its controller binding admission",
        ));
    }
    Ok(())
}

async fn require_ordinary_realm(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<()> {
    let ordinary = sql_query(
        "SELECT EXISTS (SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_position=0 AND e.kind='ak.realm.create' \
           AND e.state='committed' AND e.envelope->'payload'->'object'->>'purpose'='collaboration') AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !ordinary.present {
        return Err(unsupported(
            "membership of this Realm role is governed by its own profile",
        ));
    }
    Ok(())
}

/// Lock the member row the current writer uses and read its membership at
/// this cut. An absent row is the FSM's initial `leave`.
pub(crate) async fn locked_membership(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> PersistenceResult<String> {
    let member_key = member.to_string();
    crate::unit_of_work::advisory_lock(
        conn,
        format!(
            "parent-membership:member:{}:{member_key}",
            realm_id.as_str()
        ),
    )
    .await?;
    membership_at_cut(conn, realm_id, member, true).await
}

/// Membership from the caller's existing repeatable-read snapshot, without
/// admission locks. The same accepted Commit binding remains mandatory.
pub(crate) async fn snapshot_membership(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> PersistenceResult<String> {
    membership_at_cut(conn, realm_id, member, false).await
}

async fn membership_at_cut(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
    lock: bool,
) -> PersistenceResult<String> {
    let base = "SELECT m.membership FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         WHERE m.realm_id=$1 AND m.member_id=$2 \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id";
    let query = if lock {
        format!("{base} FOR UPDATE OF m")
    } else {
        base.to_owned()
    };
    Ok(sql_query(query)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(member.to_string())
        .get_result::<MembershipRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map_or_else(|| "leave".to_owned(), |row| row.membership))
}

#[derive(diesel::QueryableByName)]
struct MembershipRevisionRow {
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    current_stream_position: i64,
}

/// The locked parent Realm `member_state` current of `member` with its exact
/// typed revision on the Realm stream, under the same lock as
/// [`locked_membership`]. `None` when the actor has no Realm member row.
pub(crate) async fn locked_membership_revision(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> PersistenceResult<Option<(arkret_wire::MembershipState, arkret_wire::CurrentRevision)>> {
    let member_key = member.to_string();
    crate::unit_of_work::advisory_lock(
        conn,
        format!(
            "parent-membership:member:{}:{member_key}",
            realm_id.as_str()
        ),
    )
    .await?;
    let Some(row) = sql_query(
        "SELECT m.membership,m.current_commit_id,m.current_stream_position \
         FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         WHERE m.realm_id=$1 AND m.member_id=$2 \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id \
         FOR UPDATE OF m",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&member_key)
    .get_result::<MembershipRevisionRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(None);
    };
    let membership = serde_json::from_value(Value::String(row.membership))
        .map_err(PersistenceError::database)?;
    let revision = arkret_wire::CurrentRevision {
        commit_id: row
            .current_commit_id
            .parse()
            .map_err(PersistenceError::database)?,
        stream_position: u64::try_from(row.current_stream_position)
            .map_err(PersistenceError::database)?,
    };
    Ok(Some((membership, revision)))
}

async fn realm_current_value(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    family: &str,
) -> PersistenceResult<Option<Value>> {
    Ok(sql_query(
        "SELECT b.value FROM realm_bootstrap_current_results b \
         JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE b.realm_id=$1 AND b.result_family=$2 \
           AND c.realm_id=b.realm_id AND c.stream_position=b.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=b.realm_id \
         FOR SHARE OF b",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(family)
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| row.value))
}

/// The Realm's join policy component at this cut, if one is declared.
async fn join_policy(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<Value>> {
    Ok(sql_query(
        "SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1 FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .and_then(|row| row.value.get("join_policy").cloned()))
}

/// Entry by the target itself (`leave -> join` or `leave -> knock`).
///
/// The rule must open that entry. Every declared gate would have to be
/// re-evaluated at this cut; a policy whose only gates are
/// `parent_membership` is already re-proved by the co-governed dependency
/// transaction, and any other gate stays closed until its proof and replay
/// inputs are read here too.
async fn check_self_entry(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    to: &str,
    has_gate_proofs: bool,
) -> PersistenceResult<()> {
    let rule = realm_current_value(conn, realm_id, "realm_join_rule")
        .await?
        .ok_or_else(gate_check_failed)?;
    let rule = rule.as_str().ok_or_else(gate_check_failed)?;
    let gates = supported_join_gates(conn, realm_id, has_gate_proofs).await?;
    if !self_entry_open(rule, to, gates.len()) {
        return Err(gate_check_failed());
    }
    Ok(())
}

fn self_entry_open(rule: &str, to: &str, supported_gate_count: usize) -> bool {
    match (rule, to) {
        ("public", "join") | ("knock", "knock") => true,
        // Only parent-membership gates reach here. Their authoritative
        // dependencies were re-proved in the same accepting transaction.
        // A missing or empty policy must never turn restricted into public.
        ("restricted", "join") => supported_gate_count > 0,
        _ => false,
    }
}

/// Join Policy constrains every admission path, including the controller's
/// explicit Agent join. The ordinary self-entry rule is a separate gate:
/// actor.md section 3.3 admits the owned Agent without an Invite or opt-in.
async fn check_join_policy(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    has_gate_proofs: bool,
) -> PersistenceResult<()> {
    supported_join_gates(conn, realm_id, has_gate_proofs)
        .await
        .map(|_| ())
}

async fn supported_join_gates(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    has_gate_proofs: bool,
) -> PersistenceResult<Vec<Value>> {
    let policy = join_policy(conn, realm_id).await?;
    let gates = policy
        .as_ref()
        .map(|policy| {
            policy
                .get("gates")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(gate_check_failed)
        })
        .transpose()?
        .unwrap_or_default();
    let only_parent_membership = gates
        .iter()
        .all(|gate| gate.get("kind").and_then(Value::as_str) == Some("parent_membership"));
    if !only_parent_membership || (has_gate_proofs && gates.is_empty()) {
        return Err(gate_check_failed());
    }
    Ok(gates)
}

/// The ordinary-Realm controller carve-out is a caller-signed Agent join.
/// Every input that authorizes it is read under this RealmCommit transaction.
async fn check_agent_controller_join(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    payload: &MembershipPayload,
    review: Option<&crate::agent_management_review::ReviewAdmission>,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::agent::AgentProvisioningValue;
    use arkret_models_collaboration::governance::accountability::AccountabilityProjection;

    let binding = payload
        .agent_controller_binding
        .as_ref()
        .ok_or_else(|| failed_precondition("Agent join lacks its controller binding"))?;
    let controller = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| capability_denied("Agent controller must be an Account"))?;
    let agent = payload
        .member_id
        .as_account_id()
        .ok_or_else(|| capability_denied("Agent target must be an Account"))?;
    if controller != &binding.controller_account_id
        || controller == agent
        || controller.station_id != agent.station_id
        || binding.controller_terminal_event_ref.is_some()
        || payload.membership_cause.is_some()
    {
        return Err(capability_denied(
            "Agent controller binding is not the exact writer/target pair",
        ));
    }
    if crate::realm_authorization_cut::is_owned_agent_in_connection(
        conn,
        &event.realm_id,
        controller,
    )
    .await?
    {
        return Err(capability_denied(
            "an Agent cannot supply another Agent's controller authority",
        ));
    }
    let current = sql_query(
        "SELECT m.membership, e.envelope->>'event_id' AS event_id FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE m.realm_id=$1 AND m.member_id=$2 \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id \
         FOR SHARE OF m",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(event.actor_id.to_string())
    .get_result::<ControllerJoinRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if !current.is_some_and(|row| {
        row.membership == "join"
            && row.event_id == binding.controller_membership_generation_ref.as_str()
    }) {
        return Err(failed_precondition(
            "controller is not in its bound joined generation",
        ));
    }

    let provisioning = sql_query(
        "SELECT p.value FROM agent_provisioning_current_results p \
         JOIN pcr_genesis_units g ON g.realm_id=p.realm_id \
         WHERE p.agent_id=$1 AND g.principal_id=$2 AND g.station_id=$3 FOR SHARE OF p",
    )
    .bind::<Text, _>(agent.principal_id.as_str())
    .bind::<Text, _>(controller.principal_id.as_str())
    .bind::<Text, _>(controller.station_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| failed_precondition("Agent has no accepted provision"))?;
    let provisioning: AgentProvisioningValue =
        serde_json::from_value(provisioning.value).map_err(|error| {
            PersistenceError::Internal(format!("Agent provision current invalid: {error}"))
        })?;
    if provisioning.controller_principal_id != controller.principal_id {
        return Err(capability_denied("writer did not provision the Agent"));
    }
    crate::agent_current_results::lock_agent_producer_current(
        conn,
        &provisioning.principal_control_realm_id,
        &agent.principal_id,
    )
    .await?;
    let status = sql_query(
        "SELECT value FROM agent_status_current_results \
         WHERE realm_id=$1 AND agent_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(provisioning.principal_control_realm_id.as_str())
    .bind::<Text, _>(agent.principal_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if !status.is_some_and(|row| row.value.as_str() == Some("active")) {
        return Err(failed_precondition("Agent lifecycle is not active"));
    }
    let accountability = sql_query(
        "SELECT value FROM identity_accountability_current_results \
         WHERE subject_id=$1 AND issuer_id=$2 \
         ORDER BY realm_id,scope_set_digest FOR SHARE",
    )
    .bind::<Text, _>(agent.principal_id.as_str())
    .bind::<Text, _>(controller.principal_id.as_str())
    .get_results::<CurrentValueRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut accountable = false;
    for row in accountability {
        let value: AccountabilityProjection =
            serde_json::from_value(row.value).map_err(|error| {
                PersistenceError::Internal(format!("Agent accountability current invalid: {error}"))
            })?;
        accountable |= value.verifies_at(commit.committed_at);
    }
    if !accountable {
        return Err(failed_precondition(
            "Agent accountability grant is not active",
        ));
    }
    // Genesis installs active once; it does not complete DID binding. The same
    // verified ownership reader is used by first join, review and later current
    // reads, so default-allow policy cannot bypass the independent bootstrap.
    crate::agent_interaction_current_results::owned_provenance_in_connection(
        conn,
        agent,
        controller,
        commit.committed_at,
        true,
    )
    .await?
    .ok_or_else(|| {
        failed_precondition("Agent complete accepted ownership and DID binding are unavailable")
    })?;
    crate::agent_management_admission::require_join_in_connection(
        conn,
        &event.realm_id,
        controller,
        agent,
        commit.committed_at,
        event,
        review,
    )
    .await?;
    // Joining changes the key-access revision. It does not install an MLS
    // leaf; the later Add must cover the new revision with its own claim.
    let mls_active = sql_query(
        "SELECT EXISTS(SELECT 1 FROM mls_group_current_results \
         WHERE realm_id=$1 AND value->'effective_scope'->>'kind'='realm') AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if mls_active.present {
        require_agent_membership_keypackage(
            conn,
            &event.realm_id,
            &provisioning.principal_control_realm_id,
            agent,
            controller,
            commit.committed_at,
        )
        .await?;
    }
    check_join_policy(conn, &event.realm_id, !payload.gate_proofs.is_empty()).await
}

/// Decide one ordinary `ak.member.state` Event at its accepting cut.
async fn admit_member_state(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    review: Option<&crate::agent_management_review::ReviewAdmission>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    let payload: MembershipPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if payload
        .realm_id
        .as_ref()
        .is_some_and(|realm_id| realm_id != &event.realm_id)
    {
        return Err(PersistenceError::SchemaViolation(
            "member_state realm_id differs from its Event Realm".to_owned(),
        ));
    }
    if payload.strand_id.is_some()
        || payload.invite_ref.is_some()
        || payload.membership_cause.is_some()
    {
        return Err(unsupported(
            "scoped, invited or cascade membership has its own admission",
        ));
    }
    // Direct Conversation membership is a closed profile.  The profile
    // evaluator has already checked the immutable pair, binding ref, exact
    // authority source and current membership at this same locked cut.  Do
    // not fall through to the ordinary collaboration Realm join rule: the
    // only admitted edges here are participant self-leave and repair
    // self-rejoin.
    if let Some(authority) =
        crate::direct_conversation_admission::profile_authority_in_connection(conn, event).await?
    {
        if authority != crate::direct_conversation_admission::ProfileAuthority::Profile
            || event.executed_by.is_some()
            || event.applet_id.is_some()
            || event.actor_id != payload.member_id
        {
            return Err(capability_denied(
                "Direct Conversation membership requires its exact self profile",
            ));
        }
        let from = locked_membership(conn, &event.realm_id, &payload.member_id).await?;
        let to = state_name(payload.membership);
        return match (from.as_str(), to) {
            ("join", "leave") | ("leave", "join") => Ok(()),
            _ => Err(invalid_membership_transition(
                "Direct Conversation membership transition is not self-leave or self-rejoin",
            )),
        };
    }
    if payload.agent_controller_binding.is_some() {
        if payload.membership != MembershipPayloadState::Join {
            return Err(unsupported(
                "Agent controller binding currently admits only join",
            ));
        }
        require_ordinary_realm(conn, &event.realm_id).await?;
        let from = locked_membership(conn, &event.realm_id, &payload.member_id).await?;
        if from != "leave" {
            return Err(invalid_membership_transition(
                "Agent controller join requires the leave state",
            ));
        }
        return check_agent_controller_join(conn, event, commit, &payload, review).await;
    }
    // Agent entry still requires its exact controller binding. An
    // administrator's terminal transition uses the ordinary FSM instead:
    // it removes an existing membership and grants no Agent admission.
    // Keep unsupported Agent self-cleanup separate from this admin path.
    if event.actor_id != payload.member_id
        && matches!(
            payload.membership,
            MembershipPayloadState::Leave | MembershipPayloadState::Ban
        )
    {
        require_ordinary_realm(conn, &event.realm_id).await?;
    } else {
        require_ordinary_member(conn, &event.realm_id, &payload.member_id).await?;
    }
    let from = locked_membership(conn, &event.realm_id, &payload.member_id).await?;
    let to = state_name(payload.membership);
    let writer = edge_writer(&from, to).ok_or_else(|| {
        invalid_membership_transition("membership transition is not a listed edge")
    })?;
    let self_authored = event.actor_id == payload.member_id;
    match writer {
        EdgeWriter::SelfEntry => {
            if !self_authored {
                return Err(capability_denied(
                    "only the target itself may enter a Realm by membership state",
                ));
            }
            check_self_entry(conn, &event.realm_id, to, !payload.gate_proofs.is_empty()).await
        }
        EdgeWriter::SelfOrAdmin if self_authored => Ok(()),
        EdgeWriter::SelfOrAdmin | EdgeWriter::Admin => {
            crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
                conn, event, commit, prepared,
            )
            .await
            .map(|_| ())
        }
    }
}

/// Decide one ordinary `ak.member.state` transition at its accepting cut.
///
/// Runs before any write of the Event's transaction, after the co-governed
/// `parent_membership` cut (if any) was locked. It takes the Realm authority
/// lock first and then the member row lock the current writer uses, so the
/// verdict and the member write are one cut.
pub(crate) async fn admit_member_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    review: Option<&crate::agent_management_review::ReviewAdmission>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MemberState {
        return Ok(());
    }
    require_realm_stream_carrier(event, commit)?;
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if event.applet_id.is_some() {
        crate::managed_message_actor::require_managed_actor_in_connection(
            conn,
            event,
            commit.committed_at,
        )
        .await?;
        RealmAuthorizationCut::read(conn, &event.realm_id, &event.actor_id)
            .await?
            .require_managed_self_action_in_connection(conn, event, commit, prepared)
            .await?;
    }
    admit_member_state(conn, event, commit, review, prepared).await
}

#[cfg(test)]
mod tests {
    use super::{EdgeWriter, edge_writer, self_entry_open};

    #[test]
    fn restricted_self_join_requires_a_supported_automatic_gate() {
        assert!(!self_entry_open("restricted", "join", 0));
        assert!(self_entry_open("restricted", "join", 1));
        assert!(self_entry_open("restricted", "join", 2));
        assert!(!self_entry_open("restricted", "knock", 1));
    }

    #[test]
    fn automatic_parent_gate_does_not_open_other_entry_modes() {
        assert!(self_entry_open("public", "join", 0));
        assert!(self_entry_open("public", "join", 1));
        assert!(self_entry_open("knock", "knock", 0));
        for rule in ["invite", "knock", "knock_restricted", "closed", "unknown"] {
            assert!(!self_entry_open(rule, "join", 1));
        }
        assert!(!self_entry_open("knock_restricted", "knock", 1));
        assert!(!self_entry_open("public", "knock", 1));
        assert!(!self_entry_open("public", "leave", 1));
    }

    #[test]
    fn only_the_listed_membership_edges_have_a_writer() {
        let states = ["join", "knock", "leave", "ban"];
        let mut listed = Vec::new();
        for from in states {
            for to in states {
                if let Some(writer) = edge_writer(from, to) {
                    listed.push((from, to, writer));
                }
            }
        }
        assert_eq!(
            listed,
            vec![
                ("join", "leave", EdgeWriter::SelfOrAdmin),
                ("join", "ban", EdgeWriter::Admin),
                ("knock", "join", EdgeWriter::Admin),
                ("knock", "leave", EdgeWriter::SelfOrAdmin),
                ("knock", "ban", EdgeWriter::Admin),
                ("leave", "join", EdgeWriter::SelfEntry),
                ("leave", "knock", EdgeWriter::SelfEntry),
                ("leave", "ban", EdgeWriter::Admin),
                ("ban", "leave", EdgeWriter::Admin),
            ]
        );
    }
}
