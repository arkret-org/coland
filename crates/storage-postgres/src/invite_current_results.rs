//! The three Invite typed current writers at the accepting RealmCommit cut.
//!
//! `models/governance-objects.md` §5.3 splits one directed Invite into three
//! registered families, all written in the transaction that installs the
//! Event's Commit:
//!
//! - `invite_lifecycle`, keyed by InviteId: the process-state register;
//! - `invite_directed_invitee`, keyed by InviteId: the create-locked invitee, absent for a
//!   third-party Invite;
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

mod acceptance_attestation;
mod claim_admission;
mod provider_liveness;

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload;
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InviteCancelPayload, InviteCancelTargetState, InviteClaimPayload,
    InviteCreatePayload, InviteDirectedInviteeValue, InviteLiveTargetOccupant,
    InviteLiveTargetValue, InvitePreviousState, InviteRevokePayload, InviteRevokePreviousState,
    InviteRevokeTargetState, InviteThirdPartyCreatePayload, validate_invite_create_wire_keys,
};
use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInviteAcceptanceAttestationOutcome, ThirdPartyInviteAcceptanceAttestationRequestBody,
};
use arkret_wire::{AccountId, ActorId, EventKind, InviteId, InviteState, SecurityClass};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

use crate::realm_authorization_cut::{
    RealmAuthorizationCut, authorize_capability_gated_event_in_connection,
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
        "SELECT value FROM invite_lifecycle_current_results \
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
        "SELECT value FROM invite_directed_invitee_current_results \
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
        "SELECT value FROM invite_live_target_current_results \
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
        "INSERT INTO invite_live_target_current_results \
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
        "UPDATE invite_lifecycle_current_results SET current_commit_id=$3, \
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
) -> PersistenceResult<()> {
    authorize_capability_gated_event_in_connection(conn, event, commit.committed_at).await?;
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
        "INSERT INTO invite_lifecycle_current_results \
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
        "INSERT INTO invite_directed_invitee_current_results \
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

/// Accept the 3PID create with its pure lifecycle and rebuildable commitment
/// index at the same authority cut. A claim remains closed until its two
/// independent signatures can be verified against accepted key history.
async fn commit_invite_third_party_create(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    authorize_capability_gated_event_in_connection(conn, event, commit.committed_at).await?;
    if event.actor_id.as_account_id().is_none() {
        return Err(coded(
            ConflictCode::CapabilityDenied,
            "a third-party Invite must be authored by an Account",
        ));
    }
    let payload: InviteThirdPartyCreatePayload = typed_payload(event)?;
    payload.validate().map_err(schema_violation)?;
    let genesis = diesel::sql_query(
        "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE c.realm_id=$1 AND c.stream_position=0 AND e.kind=$2 AND e.state='committed'",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(EventKind::RealmCreate.as_str())
    .get_result::<EnvelopeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| corrupt("third-party Invite Realm has no accepted genesis"))?;
    let genesis = serde_json::from_value::<arkret_wire::Event>(genesis.envelope)
        .map_err(corrupt)?
        .as_realm_create()
        .map_err(corrupt)?
        .object;
    let max_lifetime = if genesis.security_class == SecurityClass::HighAssurance {
        chrono::TimeDelta::hours(24)
    } else {
        chrono::TimeDelta::days(7)
    };
    if payload.expires_at <= commit.committed_at
        || payload.expires_at <= event.created_at
        || payload.expires_at > event.created_at + max_lifetime
    {
        return Err(coded(
            ConflictCode::FailedPrecondition,
            "third-party Invite is expired or exceeds its Realm security-class lifetime",
        ));
    }
    let policy = diesel::sql_query(
        "SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| serde_json::from_value::<RealmPolicyBundlePayload>(row.value).map_err(corrupt))
    .transpose()?;
    if !policy
        .as_ref()
        .and_then(|policy| policy.allowed_third_party_invite_verification_ids.as_ref())
        .is_some_and(|allowed| allowed.contains(&payload.third_party_invite.verification_id))
    {
        return Err(coded(
            ConflictCode::CapabilityDenied,
            "verification service is absent from the accepted Realm policy allowlist",
        ));
    }
    let commitment = payload
        .third_party_invite
        .token_commitment
        .as_ref()
        .ok_or_else(|| schema_violation("third-party Invite has no token commitment"))?;
    let invite_id = InviteId::from_event_id(&event.event_id);
    let inserted = diesel::sql_query(
        "INSERT INTO invite_third_party_create_index \
         (realm_id,invite_id,token_commitment,create_event_id,create_commit_id) \
         VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(invite_id.as_str())
    .bind::<Text, _>(commitment.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(coded(
            ConflictCode::DuplicateConflict,
            "third-party Invite or token commitment already exists",
        ));
    }
    let inserted = upsert(
        conn,
        "INSERT INTO invite_lifecycle_current_results \
         (realm_id,invite_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
        event.realm_id.as_str(),
        invite_id.as_str(),
        &Value::String(InviteState::Pending.as_str().to_owned()),
        commit,
    )
    .await?;
    if inserted != 1 {
        return Err(coded(
            ConflictCode::DuplicateConflict,
            "the third-party Invite already has a lifecycle result",
        ));
    }
    Ok(())
}

async fn commit_invite_revoke(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    authorize_capability_gated_event_in_connection(conn, event, commit.committed_at).await?;
    let payload: InviteRevokePayload = typed_payload(event)?;
    payload.validate().map_err(schema_violation)?;
    let realm_id = event.realm_id.as_str();
    let stored = locked_lifecycle(conn, realm_id, &payload.invite_id)
        .await?
        .ok_or_else(|| PersistenceError::NotFound("invite not found".to_owned()))?;
    require_transition_from(
        stored,
        match payload.previous_state {
            InviteRevokePreviousState::Pending => InviteState::Pending,
            InviteRevokePreviousState::Claimed => InviteState::Claimed,
            InviteRevokePreviousState::SendFailed => InviteState::SendFailed,
        },
    )?;
    let target = match payload.target_state {
        InviteRevokeTargetState::Revoked => InviteState::Revoked,
        InviteRevokeTargetState::Expired => InviteState::Expired,
        InviteRevokeTargetState::SendFailed => InviteState::SendFailed,
        InviteRevokeTargetState::RevokedByCapabilityLoss => InviteState::RevokedByCapabilityLoss,
        InviteRevokeTargetState::RevokedByInviterLeft => InviteState::RevokedByInviterLeft,
        InviteRevokeTargetState::InvalidatedByRateLimit => InviteState::InvalidatedByRateLimit,
    };
    if payload.target_state.releases_live_target() {
        // `stored_field_matches_payload`, conditioned on target_state: both
        // absent, or both present and byte-equal.
        let stored_invitee = directed_invitee(conn, realm_id, &payload.invite_id).await?;
        if stored_invitee != payload.invitee_account_id {
            return Err(coded(
                ConflictCode::InviteDirectedInviteeMismatch,
                "invitee_account_id does not match the stored directed invitee",
            ));
        }
    }
    set_lifecycle(conn, realm_id, &payload.invite_id, target, commit).await?;
    if let Some(invitee) = payload.invitee_account_id.as_ref() {
        release_live_target(conn, realm_id, &payload.invite_id, invitee, commit).await?;
    }
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
    at: chrono::DateTime<chrono::Utc>,
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
            cut.require_event_in_connection(conn, event, at).await
        }
    }
}

async fn commit_invite_cancel(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
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
    authorize_invite_cancel(conn, event, &payload, commit.committed_at).await?;
    match directed_invitee(conn, realm_id, &payload.invite_id).await? {
        None => {
            return Err(coded(
                ConflictCode::InviteKindRequiresRevoke,
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
            InvitePreviousState::Claimed => InviteState::Claimed,
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
/// decision 0113). A third-party Invite has no stored directed invitee
/// and accepts only through the exact accepted claim and its invited member row.
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
    if stored_invitee != payload.invitee_account_id {
        return Err(coded(
            ConflictCode::InviteDirectedInviteeMismatch,
            "invitee_account_id does not match the stored directed invitee",
        ));
    }
    let third_party = stored_invitee.is_none();
    let invitee = match stored_invitee {
        Some(invitee) => invitee,
        None if stored == InviteState::Claimed
            && payload.previous_state == InvitePreviousState::Claimed =>
        {
            claim_admission::accepted_claimant(conn, event, commit, &payload.invite_id)
                .await?
                .ok_or_else(|| {
                    coded(
                        ConflictCode::FailedPrecondition,
                        "third-party acceptance has no exact accepted claim",
                    )
                })?
        }
        None => {
            return Err(coded(
                ConflictCode::FailedPrecondition,
                "third-party acceptance requires claimed state",
            ));
        }
    };
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
            InvitePreviousState::Claimed => InviteState::Claimed,
        },
    )?;
    crate::member_state_admission::require_ordinary_member(conn, &event.realm_id, &event.actor_id)
        .await?;
    if crate::member_state_admission::locked_membership(conn, &event.realm_id, &event.actor_id)
        .await?
        != "leave"
    {
        return Err(coded(
            ConflictCode::FailedPrecondition,
            "invite acceptance requires its directed or claimed membership predecessor",
        ));
    }
    set_lifecycle(
        conn,
        realm_id,
        &payload.invite_id,
        InviteState::Accepted,
        commit,
    )
    .await?;
    if third_party {
        Ok(())
    } else {
        release_live_target(conn, realm_id, &payload.invite_id, &invitee, commit).await
    }
}

/// Admit and write the registered Invite typed current results of `event`.
/// Every other kind is left to its own writer.
pub(crate) async fn commit_invite_current_results_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    claim_proof: Option<&coland_storage::InviteClaimProofCommit>,
) -> PersistenceResult<()> {
    if !matches!(
        event.kind,
        EventKind::InviteCreate
            | EventKind::InviteThirdParty
            | EventKind::InviteClaim
            | EventKind::InviteRevoke
            | EventKind::InviteCancel
            | EventKind::InviteAccept
    ) {
        return Ok(());
    }
    require_realm_stream_carrier(event, commit)?;
    match event.kind {
        EventKind::InviteCreate => commit_invite_create(conn, event, commit).await,
        EventKind::InviteThirdParty => commit_invite_third_party_create(conn, event, commit).await,
        EventKind::InviteClaim => {
            claim_admission::commit_claim(conn, event, commit, claim_proof).await
        }
        EventKind::InviteRevoke => commit_invite_revoke(conn, event, commit).await,
        EventKind::InviteCancel => commit_invite_cancel(conn, event, commit).await,
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
    #[diesel(sql_type = Nullable<Jsonb>)]
    invitee: Option<Value>,
}

#[derive(diesel::QueryableByName)]
struct EnvelopeRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

/// Invite typed current reads outside any accepting transaction.
pub struct PgInviteCurrentResultStore {
    pub pool: crate::PgPool,
}

#[async_trait::async_trait]
impl coland_storage::InviteCurrentResultStore for PgInviteCurrentResultStore {
    async fn third_party_invite_acceptance_attestation(
        &self,
        request: &ThirdPartyInviteAcceptanceAttestationRequestBody,
        caller: &AccountId,
        station: &arkret_wire::DidCoreId,
        verification_method: &arkret_wire::DidUrl,
        observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
        sign: &coland_storage::InviteAcceptanceAttestationSigner<'_>,
    ) -> PersistenceResult<ThirdPartyInviteAcceptanceAttestationOutcome> {
        use diesel_async::AsyncConnection as _;
        let mut conn = crate::pg_conn(&self.pool).await?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            Ok(acceptance_attestation::issue(
                conn,
                request,
                caller,
                station,
                verification_method,
                observe,
                sign,
            )
            .await?)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn acquire_third_party_invite_provision_device(
        &self,
        request: &arkret_models_collaboration::governance::third_party_invite::ThirdPartyInviteProvisionRequestBody,
        station: &arkret_wire::DidCoreId,
        observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
    ) -> PersistenceResult<Box<dyn coland_storage::ThirdPartyInviteProviderLivenessGuard>> {
        provider_liveness::acquire_provision_device(&self.pool, request, station, observe).await
    }

    async fn acquire_third_party_invite_provider_liveness(
        &self,
        request: &coland_storage::ThirdPartyInviteProviderLivenessRequest,
        station: &arkret_wire::DidCoreId,
        observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
    ) -> PersistenceResult<Box<dyn coland_storage::ThirdPartyInviteProviderLivenessGuard>> {
        provider_liveness::acquire(&self.pool, request, station, observe).await
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
                 FROM invite_lifecycle_current_results l \
                 LEFT JOIN invite_directed_invitee_current_results d \
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
    ) -> PersistenceResult<Vec<coland_storage::DirectedInviteCurrent>> {
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
                 FROM invite_directed_invitee_current_results d \
                 JOIN invite_lifecycle_current_results l \
                   ON l.realm_id=d.realm_id AND l.invite_id=d.invite_id \
                 WHERE d.value->'invitee_account_id'=$1 \
                   AND (l.value #>> '{}') IN ('pending','claimed') \
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
    let invitee_account_id = row
        .invitee
        .map(serde_json::from_value)
        .transpose()
        .map_err(corrupt)?;
    let token = crate::ids::parse_event_id(invite_id.event_id().as_str())
        .ok_or_else(|| corrupt("InviteId does not retype to a canonical Event token"))?;
    let envelope = diesel::sql_query(
        "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.realm_id=$2 AND e.kind IN ($3,$4) AND e.state='committed'",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(EventKind::InviteCreate.as_str())
    .bind::<Text, _>(EventKind::InviteThirdParty.as_str())
    .get_result::<EnvelopeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| corrupt("invite_lifecycle has no committed create Event"))?
    .envelope;
    let event = serde_json::from_value::<arkret_wire::Event>(envelope).map_err(corrupt)?;
    let (introduction_evidence_digest, third_party_invite, expires_at) = match event.kind {
        EventKind::InviteCreate => {
            let create = typed_payload::<InviteCreatePayload>(&event)?;
            if Some(&create.invitee_account_id) != invitee_account_id.as_ref() {
                return Err(corrupt(
                    "directed invitee disagrees with committed create Event",
                ));
            }
            (
                Some(create.introduction_evidence_digest),
                None,
                create.expires_at,
            )
        }
        EventKind::InviteThirdParty => {
            if invitee_account_id.is_some() {
                return Err(corrupt("third-party Invite has a directed invitee"));
            }
            let create = typed_payload::<InviteThirdPartyCreatePayload>(&event)?;
            (None, Some(create.third_party_invite), create.expires_at)
        }
        _ => return Err(corrupt("Invite create Event kind is invalid")),
    };
    let accepted_claim = if third_party_invite.is_some() {
        let claims = diesel::sql_query(
            "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
             WHERE e.realm_id=$1 AND e.kind=$2 AND e.state='committed' \
               AND e.envelope->'payload'->>'invite_id'=$3 LIMIT 2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(EventKind::InviteClaim.as_str())
        .bind::<Text, _>(invite_id.as_str())
        .load::<EnvelopeRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if claims.len() > 1 {
            return Err(corrupt("more than one committed claim names an Invite"));
        }
        claims
            .into_iter()
            .next()
            .map(|row| {
                let event =
                    serde_json::from_value::<arkret_wire::Event>(row.envelope).map_err(corrupt)?;
                let claim = typed_payload::<InviteClaimPayload>(&event)?;
                Ok(coland_storage::AcceptedThirdPartyClaim {
                    event_id: event.event_id,
                    subject_account_id: claim.subject_account_id,
                    claim_nonce: claim.claim_nonce,
                    token_commitment: claim.token_commitment,
                    verification_id: claim.binding_proof.verification_id,
                    claimed_at: event.created_at,
                })
            })
            .transpose()?
    } else {
        None
    };
    if third_party_invite.is_some() && state == InviteState::Claimed && accepted_claim.is_none() {
        return Err(corrupt(
            "claimed third-party Invite has no committed claim Event",
        ));
    }
    Ok(coland_storage::InviteCurrent {
        realm_id,
        invite_id,
        state,
        state_updated_at: row.updated_at,
        inviter: event.actor_id,
        invitee_account_id,
        introduction_evidence_digest,
        third_party_invite,
        expires_at,
        created_at: event.created_at,
        accepted_claim,
    })
}

async fn open_directed_invite(
    conn: &mut AsyncPgConnection,
    row: OpenDirectedInviteRow,
) -> PersistenceResult<coland_storage::DirectedInviteCurrent> {
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
    Ok(coland_storage::DirectedInviteCurrent {
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
