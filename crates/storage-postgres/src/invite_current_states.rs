//! The three Invite typed current writers at the accepting RealmCommit cut.
//!
//! `models/governance-objects.md` §5.3 splits one directed Invite into three
//! registered families, all written in the transaction that installs the
//! Event's Commit:
//!
//! - `invite_lifecycle`, keyed by InviteId: the process-state register;
//! - `invite_directed_invitee`, keyed by InviteId: the create-locked directed invitee;
//! - `invite_live_target`, keyed by `canonical_json(invitee_account_id)`: the one live
//!   directed-invite slot of that account in the Realm, whose value is the occupying create Event
//!   id or null.
//!
//! `ak.invite.create` opens all three, `ak.invite.cancel`, every terminal
//! `ak.invite.revoke` and `ak.invite.accept` move the register by exact
//! `previous_state` CAS and release the slot. Acceptance also decides the
//! accepting actor's `leave -> join` edge, whose `member_state` row the
//! membership writer installs in the same transaction. Every refusal leaves zero writes because the
//! caller rolls the whole transaction back. Authorization is decided by the same-cut
//! evaluator in [`crate::realm_authorization_cut`]; the in-process reducer
//! projection and the retired `realm_invites` mirror are never read.

use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InviteCancelPayload, InviteCancelTargetState, InviteCreatePayload,
    InviteDirectedInviteeValue, InviteLiveTargetOccupant, InviteLiveTargetValue,
    InvitePreviousState, InviteRevokePayload, InviteRevokeTargetState,
    validate_invite_create_wire_keys,
};
use arkret_wire::{AccountId, ActorId, EventKind, InviteId, InviteState};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

use crate::realm_authorization_cut::{
    RealmAuthorizationCut, authorize_capability_gated_event_with_approvals,
    lock_realm_authorization_cut,
};

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct ActorRow {
    #[diesel(sql_type = Text)]
    actor_id: String,
}

fn coded(code: ConflictCode, detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("stored Invite typed current is invalid: {detail}"))
}

fn schema_violation(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_string())
}

/// `canonical_json(invitee_account_id)`, the only `invite_live_target` subject.
fn live_target_key(invitee: &AccountId) -> PersistenceResult<String> {
    let bytes = arkret_canonical::canonical_json_bytes(invitee).map_err(schema_violation)?;
    String::from_utf8(bytes).map_err(schema_violation)
}

fn stream_position(commit: &arkret_wire::RealmCommit) -> PersistenceResult<i64> {
    i64::try_from(commit.stream_position)
        .map_err(|_| schema_violation("Invite stream position exceeds BIGINT"))
}

fn typed_payload<T: serde::de::DeserializeOwned>(
    event: &arkret_wire::Event,
) -> PersistenceResult<T> {
    serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(schema_violation)
}

/// Invite Events are Realm-scope and carried on the Realm stream. They are
/// directly authored, with one exception: an Applet-managed Bot or Ghost has
/// no runtime credential of its own, so its exact acceptance of an Invite
/// addressed to it is executed by its Applet Service (`common-fields.md` §4.5,
/// `extensions/applet-integration.md` §8, §9.1, §11). That acceptance carries
/// both `executed_by` and `applet_id`; its managed identity is closed in
/// [`commit_invite_accept`]. No other Invite Event admits an executor.
fn require_realm_stream_carrier(
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    arkret_schema::validate_event_for_submit(event).map_err(schema_violation)?;
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if !matches!(&event.scope_ref, arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
        || commit.stream_ref != realm_stream
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::Conflict(
            "Invite typed current writers require the Realm source stream".to_owned(),
        ));
    }
    let applet_managed_acceptance = event.kind == EventKind::InviteAccept
        && event.executed_by.is_some()
        && event.applet_id.is_some();
    if (event.executed_by.is_some() || event.applet_id.is_some()) && !applet_managed_acceptance {
        return Err(coded(
            ConflictCode::CapabilityDenied,
            "an Invite Event must be directly authored by its actor",
        ));
    }
    Ok(())
}

async fn locked_value(
    conn: &mut AsyncPgConnection,
    sql: &'static str,
    realm_id: &str,
    subject: &str,
) -> PersistenceResult<Option<Value>> {
    diesel::sql_query(sql)
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(subject)
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(|row| row.value))
        .map_err(PersistenceError::database)
}

async fn locked_lifecycle(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    invite_id: &InviteId,
) -> PersistenceResult<Option<InviteState>> {
    locked_value(
        conn,
        "SELECT value FROM invite_lifecycle_current_states \
         WHERE realm_id=$1 AND invite_id=$2 FOR UPDATE",
        realm_id,
        invite_id.as_str(),
    )
    .await?
    .map(|value| {
        value
            .as_str()
            .and_then(InviteState::from_wire)
            .ok_or_else(|| corrupt("invite_lifecycle value is not a registered state"))
    })
    .transpose()
}

async fn directed_invitee(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    invite_id: &InviteId,
) -> PersistenceResult<Option<AccountId>> {
    locked_value(
        conn,
        "SELECT value FROM invite_directed_invitee_current_states \
         WHERE realm_id=$1 AND invite_id=$2 FOR UPDATE",
        realm_id,
        invite_id.as_str(),
    )
    .await?
    .map(|value| {
        serde_json::from_value::<InviteDirectedInviteeValue>(value)
            .map(|value| value.invitee_account_id)
            .map_err(corrupt)
    })
    .transpose()
}

async fn locked_live_target(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    key: &str,
) -> PersistenceResult<InviteLiveTargetValue> {
    Ok(locked_value(
        conn,
        "SELECT value FROM invite_live_target_current_states \
         WHERE realm_id=$1 AND invitee_account_id=$2 FOR UPDATE",
        realm_id,
        key,
    )
    .await?
    .map(serde_json::from_value::<InviteLiveTargetValue>)
    .transpose()
    .map_err(corrupt)?
    .flatten())
}

/// The actor that signed the Invite's `ak.invite.create`, found through the
/// registered retype of its InviteId (`models/common-fields.md` §6.0).
async fn inviter(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    invite_id: &InviteId,
) -> PersistenceResult<ActorId> {
    let create_event_id = invite_id.event_id();
    let token = crate::ids::parse_event_id(create_event_id.as_str())
        .ok_or_else(|| corrupt("InviteId does not retype to a canonical Event token"))?;
    let row = diesel::sql_query(
        "SELECT e.actor_id FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.realm_id=$2 AND e.kind=$3 AND e.state='committed'",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(EventKind::InviteCreate.as_str())
    .get_result::<ActorRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| corrupt("invite_lifecycle has no committed ak.invite.create"))?;
    serde_json::from_str(&row.actor_id).map_err(corrupt)
}

async fn upsert(
    conn: &mut AsyncPgConnection,
    sql: &'static str,
    realm_id: &str,
    subject: &str,
    value: &Value,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<usize> {
    diesel::sql_query(sql)
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(subject)
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<BigInt, _>(stream_position(commit)?)
        .bind::<Jsonb, _>(value)
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
}

async fn set_live_target(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    key: &str,
    value: &InviteLiveTargetValue,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let value = serde_json::to_value(value).map_err(PersistenceError::database)?;
    upsert(
        conn,
        "INSERT INTO invite_live_target_current_states \
         (realm_id,invitee_account_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (realm_id,invitee_account_id) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value, updated_at=EXCLUDED.updated_at",
        realm_id,
        key,
        &value,
        commit,
    )
    .await
    .map(|_| ())
}

async fn set_lifecycle(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    invite_id: &InviteId,
    state: InviteState,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let updated = upsert(
        conn,
        "UPDATE invite_lifecycle_current_states SET current_commit_id=$3, \
         current_stream_position=$4, value=$5, updated_at=$6 \
         WHERE realm_id=$1 AND invite_id=$2",
        realm_id,
        invite_id.as_str(),
        &Value::String(state.as_str().to_owned()),
        commit,
    )
    .await?;
    if updated != 1 {
        return Err(corrupt("invite_lifecycle row vanished inside its lock"));
    }
    Ok(())
}

/// Release the slot of a directed Invite that leaves the live set. The slot
/// must still name this Invite's create Event: a live directed Invite always
/// occupies its own slot, and it can leave the live set only once.
async fn release_live_target(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    invite_id: &InviteId,
    invitee: &AccountId,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let key = live_target_key(invitee)?;
    let occupant = locked_live_target(conn, realm_id, &key).await?;
    if occupant.map(|occupant| occupant.create_event_id) != Some(invite_id.event_id()) {
        return Err(coded(
            ConflictCode::ReducerProjectionFailed,
            "a live directed Invite does not occupy its own live-target slot",
        ));
    }
    set_live_target(conn, realm_id, &key, &None, commit).await
}

/// `terminal_states` refuse every later transition; otherwise the declared
/// `previous_state` must equal the frozen register exactly.
fn require_transition_from(stored: InviteState, declared: InviteState) -> PersistenceResult<()> {
    if stored.is_terminal() {
        return Err(coded(
            ConflictCode::InviteAlreadyTerminal,
            format!("the Invite is already {}", stored.as_str()),
        ));
    }
    if stored != declared {
        return Err(coded(
            ConflictCode::FailedPrecondition,
            format!(
                "previous_state {} does not match the current invite_lifecycle {}",
                declared.as_str(),
                stored.as_str()
            ),
        ));
    }
    Ok(())
}

async fn commit_invite_create(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    authorize_capability_gated_event_with_approvals(conn, event, commit, prepared).await?;
    let wire = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    validate_invite_create_wire_keys(&wire).map_err(schema_violation)?;
    let payload: InviteCreatePayload = serde_json::from_value(wire).map_err(schema_violation)?;
    payload
        .invitee_account_id
        .validate()
        .map_err(schema_violation)?;
    let realm_id = event.realm_id.as_str();
    let invite_id = InviteId::from_event_id(&event.event_id);
    let key = live_target_key(&payload.invitee_account_id)?;
    if let Some(occupant) = locked_live_target(conn, realm_id, &key).await? {
        return Err(coded(
            ConflictCode::InviteLiveTargetOccupied,
            occupant.create_event_id,
        ));
    }
    let inserted = upsert(
        conn,
        "INSERT INTO invite_lifecycle_current_states \
         (realm_id,invite_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
        realm_id,
        invite_id.as_str(),
        &Value::String(InviteState::Pending.as_str().to_owned()),
        commit,
    )
    .await?;
    if inserted != 1 {
        return Err(coded(
            ConflictCode::DuplicateConflict,
            "the Invite already exists",
        ));
    }
    let directed = serde_json::to_value(InviteDirectedInviteeValue {
        invitee_account_id: payload.invitee_account_id.clone(),
    })
    .map_err(PersistenceError::database)?;
    let inserted = upsert(
        conn,
        "INSERT INTO invite_directed_invitee_current_states \
         (realm_id,invite_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
        realm_id,
        invite_id.as_str(),
        &directed,
        commit,
    )
    .await?;
    if inserted != 1 {
        return Err(coded(
            ConflictCode::DuplicateConflict,
            "the Invite already has a directed invitee",
        ));
    }
    set_live_target(
        conn,
        realm_id,
        &key,
        &Some(InviteLiveTargetOccupant {
            create_event_id: event.event_id.clone(),
        }),
        commit,
    )
    .await
}

async fn commit_invite_revoke(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    authorize_capability_gated_event_with_approvals(conn, event, commit, prepared).await?;
    let payload: InviteRevokePayload = typed_payload(event)?;
    payload.validate().map_err(schema_violation)?;
    let realm_id = event.realm_id.as_str();
    let stored = locked_lifecycle(conn, realm_id, &payload.invite_id)
        .await?
        .ok_or_else(|| PersistenceError::NotFound("invite not found".to_owned()))?;
    require_transition_from(
        stored,
        match payload.previous_state {
            InvitePreviousState::Pending => InviteState::Pending,
        },
    )?;
    let target = match payload.target_state {
        InviteRevokeTargetState::Revoked => InviteState::Revoked,
        InviteRevokeTargetState::Expired => InviteState::Expired,
    };
    {
        // Match the stored target in both directions for every terminal edge.
        let stored_invitee = directed_invitee(conn, realm_id, &payload.invite_id).await?;
        if stored_invitee.as_ref() != Some(&payload.invitee_account_id) {
            return Err(coded(
                ConflictCode::InviteDirectedInviteeMismatch,
                "invitee_account_id does not match the stored directed invitee",
            ));
        }
    }
    set_lifecycle(conn, realm_id, &payload.invite_id, target, commit).await?;
    release_live_target(
        conn,
        realm_id,
        &payload.invite_id,
        &payload.invitee_account_id,
        commit,
    )
    .await?;
    Ok(())
}

/// `ak.invite.cancel` is authorized by who the actor is towards this Invite
/// (`models/governance-objects.md` §5.3): the invitee may only decline
/// (`rejected`); cancelling (`revoked`) belongs to the inviter while it is a
/// joined member, or to an actor holding an action authorizing the kind.
async fn authorize_invite_cancel(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    payload: &InviteCancelPayload,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    match payload.target_state {
        InviteCancelTargetState::Rejected => {
            if event.actor_id.as_account_id() == Some(&payload.invitee_account_id) {
                Ok(())
            } else {
                Err(coded(
                    ConflictCode::CapabilityDenied,
                    "only the invitee may decline an Invite",
                ))
            }
        }
        InviteCancelTargetState::Revoked => {
            let cut = RealmAuthorizationCut::read(conn, &event.realm_id, &event.actor_id).await?;
            let inviter = inviter(conn, event.realm_id.as_str(), &payload.invite_id).await?;
            if inviter == event.actor_id && cut.actor_is_joined() {
                return Ok(());
            }
            crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
                conn, event, commit, prepared,
            )
            .await
            .map(|_| ())
        }
    }
}

async fn commit_invite_cancel(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    let payload: InviteCancelPayload = typed_payload(event)?;
    payload
        .invitee_account_id
        .validate()
        .map_err(schema_violation)?;
    let realm_id = event.realm_id.as_str();
    let stored = locked_lifecycle(conn, realm_id, &payload.invite_id)
        .await?
        .ok_or_else(|| PersistenceError::NotFound("invite not found".to_owned()))?;
    authorize_invite_cancel(conn, event, &payload, commit, prepared).await?;
    match directed_invitee(conn, realm_id, &payload.invite_id).await? {
        None => {
            return Err(coded(
                ConflictCode::InviteDirectedInviteeMismatch,
                "the Invite has no stored directed invitee",
            ));
        }
        Some(stored_invitee) if stored_invitee != payload.invitee_account_id => {
            return Err(coded(
                ConflictCode::InviteDirectedInviteeMismatch,
                "invitee_account_id does not match the stored directed invitee",
            ));
        }
        Some(_) => {}
    }
    require_transition_from(
        stored,
        match payload.previous_state {
            InvitePreviousState::Pending => InviteState::Pending,
        },
    )?;
    let target = match payload.target_state {
        InviteCancelTargetState::Rejected => InviteState::Rejected,
        InviteCancelTargetState::Revoked => InviteState::Revoked,
    };
    set_lifecycle(conn, realm_id, &payload.invite_id, target, commit).await?;
    release_live_target(
        conn,
        realm_id,
        &payload.invite_id,
        &payload.invitee_account_id,
        commit,
    )
    .await
}

/// `ak.invite.accept` (`models/governance-objects.md` §5.3): only the exact
/// directed invitee accepts, out of the declared live state, and only while
/// its own membership is `leave`. The Invite moves to `accepted` and releases
/// its slot; the `leave -> join` member write follows in the same
/// transaction. Authorization is the invitee's own signature over the exact
/// target Invite, not a Realm grant: the invitee is not yet a member, and
/// `ak.invite.accept` is `subject_only` (`authz/capabilities.md` §13,
/// decision 0113).
async fn commit_invite_accept(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let payload: InviteAcceptPayload = typed_payload(event)?;
    payload.validate().map_err(schema_violation)?;
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if event.applet_id.is_some() {
        // The Applet producer guard has already bound the Service proof,
        // active exact install, revoke fence and the actor's own
        // install-bound grant. The actor must additionally be a Bot or Ghost
        // this Applet provisioned; the Invite binding below stays the only
        // authority for the acceptance itself (`ak.invite.accept` is
        // `subject_only`).
        crate::managed_message_actor::require_managed_actor_in_connection(
            conn,
            event,
            commit.committed_at,
        )
        .await?;
    }
    let realm_id = event.realm_id.as_str();
    let stored = locked_lifecycle(conn, realm_id, &payload.invite_id)
        .await?
        .ok_or_else(|| PersistenceError::NotFound("invite not found".to_owned()))?;
    // `stored_field_matches_payload`, unconditional for accept: both absent,
    // or both present and byte-equal.
    let stored_invitee = directed_invitee(conn, realm_id, &payload.invite_id).await?;
    if stored_invitee.as_ref() != Some(&payload.invitee_account_id) {
        return Err(coded(
            ConflictCode::InviteDirectedInviteeMismatch,
            "invitee_account_id does not match the stored directed invitee",
        ));
    }
    let invitee = stored_invitee.ok_or_else(|| corrupt("directed Invite has no stored target"))?;
    if event.actor_id.as_account_id() != Some(&invitee) {
        return Err(coded(
            ConflictCode::FailedPrecondition,
            "only the directed invitee may accept the Invite",
        ));
    }
    require_transition_from(
        stored,
        match payload.previous_state {
            InvitePreviousState::Pending => InviteState::Pending,
        },
    )?;
    crate::member_state_admission::require_invitation_entry(conn, event).await?;
    let token = crate::ids::parse_event_id(payload.invite_id.event_id().as_str())
        .ok_or_else(|| corrupt("invalid Invite ID"))?;
    let source = diesel::sql_query(
        "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
        WHERE e.id=$1 AND e.realm_id=$2 AND e.kind='ak.invite.create' AND e.state='committed'",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<EnvelopeRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let source: arkret_wire::Event = serde_json::from_value(source.envelope).map_err(corrupt)?;
    let create: InviteCreatePayload = typed_payload(&source)?;
    if commit.committed_at >= create.expires_at {
        return Err(PersistenceError::NotFound("invitation not found".into()));
    }
    set_lifecycle(
        conn,
        realm_id,
        &payload.invite_id,
        InviteState::Accepted,
        commit,
    )
    .await?;
    release_live_target(conn, realm_id, &payload.invite_id, &invitee, commit).await
}

/// Admit and write the registered Invite typed current results of `event`.
/// Every other kind is left to its own writer.
pub(crate) async fn commit_invite_current_states_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if !matches!(
        event.kind,
        EventKind::InviteCreate
            | EventKind::InviteRevoke
            | EventKind::InviteCancel
            | EventKind::InviteAccept
    ) {
        return Ok(());
    }
    require_realm_stream_carrier(event, commit)?;
    match event.kind {
        EventKind::InviteCreate => commit_invite_create(conn, event, commit, prepared).await,
        EventKind::InviteRevoke => commit_invite_revoke(conn, event, commit, prepared).await,
        EventKind::InviteCancel => commit_invite_cancel(conn, event, commit, prepared).await,
        EventKind::InviteAccept => commit_invite_accept(conn, event, commit).await,
        _ => Ok(()),
    }
}

#[derive(diesel::QueryableByName)]
struct OpenDirectedInviteRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    invite_id: String,
    #[diesel(sql_type = Jsonb)]
    lifecycle: Value,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    invitee: Value,
}

#[derive(diesel::QueryableByName)]
struct InviteCurrentRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    invite_id: String,
    #[diesel(sql_type = Jsonb)]
    lifecycle: Value,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    invitee: Value,
}

#[derive(diesel::QueryableByName)]
struct EnvelopeRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

/// Invite typed current reads outside any accepting transaction.
pub struct PgInviteCurrentStateStore {
    pub pool: crate::PgPool,
}

#[async_trait::async_trait]
impl coland_storage::InviteCurrentStateStore for PgInviteCurrentStateStore {
    async fn check_realm_invite_link_preview(
        &self,
        request: &arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinPreviewRequestBody,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        use diesel_async::AsyncConnection as _;
        let id = request
            .realm_invite_link_id
            .as_ref()
            .ok_or_else(|| PersistenceError::NotFound("Realm invite link not found".into()))?;
        let proof = request
            .link_proof
            .as_ref()
            .ok_or_else(|| PersistenceError::NotFound("Realm invite link not found".into()))?;
        let mut conn = crate::pg_conn(&self.pool).await?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            crate::realm_invite_links::preview_in_connection(
                conn,
                &request.realm_id,
                id,
                &request.requester_account_id,
                &request.request_id,
                proof,
                at,
            )
            .await?;
            Ok(())
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn invites_in_realm(
        &self,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<coland_storage::InviteCurrent>> {
        use diesel_async::AsyncConnection as _;

        let mut conn = crate::pg_conn(&self.pool).await?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *conn)
                .await?;
            let rows = diesel::sql_query(
                "SELECT l.realm_id,l.invite_id,l.value AS lifecycle,l.updated_at, \
                        d.value->'invitee_account_id' AS invitee \
                 FROM invite_lifecycle_current_states l \
                 JOIN invite_directed_invitee_current_states d \
                   ON d.realm_id=l.realm_id AND d.invite_id=l.invite_id \
                 WHERE ($1::text IS NULL OR l.realm_id=$1) \
                 ORDER BY l.realm_id ASC,l.invite_id ASC",
            )
            .bind::<Nullable<Text>, _>(realm_id.map(arkret_wire::RealmId::as_str))
            .load::<InviteCurrentRow>(&mut *conn)
            .await?;
            let mut invites = Vec::with_capacity(rows.len());
            for row in rows {
                invites.push(invite_current(conn, row).await?);
            }
            Ok(invites)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn open_directed_invites_for_invitee(
        &self,
        invitee: &AccountId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<coland_storage::InviteCurrent>> {
        use diesel_async::AsyncConnection as _;

        let invitee_value = serde_json::to_value(invitee).map_err(schema_violation)?;
        let realm_filter = realm_id.map(|realm_id| realm_id.as_str().to_owned());
        let mut conn = crate::pg_conn(&self.pool).await?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *conn)
                .await?;
            let rows = diesel::sql_query(
                "SELECT d.realm_id, d.invite_id, l.value AS lifecycle, l.updated_at, \
                        d.value->'invitee_account_id' AS invitee \
                 FROM invite_directed_invitee_current_states d \
                 JOIN invite_lifecycle_current_states l \
                   ON l.realm_id=d.realm_id AND l.invite_id=d.invite_id \
                 WHERE d.value->'invitee_account_id'=$1 \
                   AND (l.value #>> '{}') = 'pending' \
                   AND ($2::text IS NULL OR d.realm_id=$2) \
                 ORDER BY d.realm_id ASC, d.invite_id ASC",
            )
            .bind::<Jsonb, _>(&invitee_value)
            .bind::<diesel::sql_types::Nullable<Text>, _>(realm_filter.as_deref())
            .load::<OpenDirectedInviteRow>(&mut *conn)
            .await?;
            let mut invites = Vec::with_capacity(rows.len());
            for row in rows {
                invites.push(open_directed_invite(conn, row).await?);
            }
            Ok(invites)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }
}

async fn invite_current(
    conn: &mut AsyncPgConnection,
    row: InviteCurrentRow,
) -> PersistenceResult<coland_storage::InviteCurrent> {
    open_directed_invite(
        conn,
        OpenDirectedInviteRow {
            realm_id: row.realm_id,
            invite_id: row.invite_id,
            lifecycle: row.lifecycle,
            updated_at: row.updated_at,
            invitee: row.invitee,
        },
    )
    .await
}

async fn open_directed_invite(
    conn: &mut AsyncPgConnection,
    row: OpenDirectedInviteRow,
) -> PersistenceResult<coland_storage::InviteCurrent> {
    let realm_id = row
        .realm_id
        .parse::<arkret_wire::RealmId>()
        .map_err(corrupt)?;
    let invite_id = row.invite_id.parse::<InviteId>().map_err(corrupt)?;
    let state = row
        .lifecycle
        .as_str()
        .and_then(InviteState::from_wire)
        .ok_or_else(|| corrupt("invite_lifecycle value is not a registered state"))?;
    let invitee_account_id = serde_json::from_value::<AccountId>(row.invitee).map_err(corrupt)?;
    let create_event_id = invite_id.event_id();
    let token = crate::ids::parse_event_id(create_event_id.as_str())
        .ok_or_else(|| corrupt("InviteId does not retype to a canonical Event token"))?;
    let envelope = diesel::sql_query(
        "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.realm_id=$2 AND e.kind=$3 AND e.state='committed'",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(EventKind::InviteCreate.as_str())
    .get_result::<EnvelopeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| corrupt("invite_lifecycle has no committed ak.invite.create"))?
    .envelope;
    let event = serde_json::from_value::<arkret_wire::Event>(envelope).map_err(corrupt)?;
    let create = typed_payload::<InviteCreatePayload>(&event)?;
    if create.invitee_account_id != invitee_account_id {
        return Err(corrupt(
            "invite_directed_invitee disagrees with its ak.invite.create",
        ));
    }
    Ok(coland_storage::InviteCurrent {
        realm_id,
        invite_id,
        state,
        state_updated_at: row.updated_at,
        inviter: event.actor_id,
        invitee_account_id,
        introduction_evidence_digest: create.introduction_evidence_digest,
        expires_at: create.expires_at,
        created_at: event.created_at,
    })
}
