//! The Agent PCR control unit: `ak.agent.key.authorize`,
//! `ak.agent.key.revoke` and `ak.self.agent.{pause,resume,deactivate}`
//! (key-management.md sections 3.6 and 3.6.1).
//!
//! Each Event is authored as the Agent's complete account, executed by its
//! controller under the delegation the accepted provision recorded, and
//! signed by one of the controller's devices. The unit takes the Agent PCR
//! authority lock, orders itself against the controller PCR's writers, and
//! decides at that one cut: the provision binding (controller, delegation and
//! Agent PCR), the controller device's active status and proof, the
//! controller's accountability for the Agent, and the kind's own gate (a
//! non-terminal lifecycle for key changes, the registered lifecycle FSM for
//! status transitions, the exact active set for `supersedes`). The Event, its
//! Commit and the `agent_key` / `agent_status` current results are written
//! together or not at all.

use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyAuthorizePayload, AgentKeyRevokePayload,
};
use arkret_wire::{CommitStreamRef, EventKind, RealmCommit, ScopeRef};
use coland_storage::{
    AgentControlAdmissionOutcome, AgentControlAdmissionWrite, AuthorityCommitWriteOutcome,
    ConflictCode, PersistenceError,
};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::Value;

use crate::actor_profiles::{
    accountability_holds_in_connection, corrupt, rejected, verify_device_signer_in_connection,
};
use crate::{AsyncPgConnection, PgTransactionError, ids};

const WHAT: &str = "Agent control Event";

#[derive(QueryableByName)]
struct KnownEventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    commit_json: Option<Value>,
}

#[derive(QueryableByName)]
struct PcrRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn schema(reason: &str) -> PgTransactionError {
    rejected(ConflictCode::SchemaViolation, reason)
}

fn precondition(reason: &str) -> PgTransactionError {
    rejected(ConflictCode::FailedPrecondition, reason)
}

/// The kinds this unit admits, each authored by the controller for the Agent.
pub(crate) fn is_agent_control_kind(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::AgentKeyAuthorize
            | EventKind::AgentKeyRevoke
            | EventKind::SelfAgentPause
            | EventKind::SelfAgentResume
            | EventKind::SelfAgentDeactivate
    )
}

async fn pcr_of(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
) -> Result<Option<arkret_wire::RealmId>, PgTransactionError> {
    sql_query(
        "SELECT pcr_realm_id FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<PcrRow>(&mut *conn)
    .await
    .optional()?
    .map(|row| arkret_wire::RealmId::new(row.pcr_realm_id).map_err(corrupt))
    .transpose()
}

async fn lock_realm(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    mode: &str,
) -> Result<bool, PgTransactionError> {
    #[derive(QueryableByName)]
    struct LockRow {
        #[diesel(sql_type = Text)]
        #[allow(dead_code)]
        realm_id: String,
    }
    Ok(sql_query(format!(
        "SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR {mode}"
    ))
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<LockRow>(&mut *conn)
    .await
    .optional()?
    .is_some())
}

async fn accepted_lifecycle(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    agent: &arkret_wire::ActorId,
) -> Result<Option<String>, PgTransactionError> {
    let key = arkret_wire::derive_agent_status_current_key(agent)
        .map_err(|error| corrupt(error.to_string()))?;
    let row = sql_query(
        "SELECT value FROM agent_status_current_results \
         WHERE realm_id=$1 AND current_key=$2 FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&key)
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()?;
    row.map(|row| {
        row.value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| corrupt("stored Agent status is not a string"))
    })
    .transpose()
}

pub(crate) async fn admit_agent_control_event_in_connection(
    conn: &mut AsyncPgConnection,
    write: &AgentControlAdmissionWrite,
) -> Result<AgentControlAdmissionOutcome, PgTransactionError> {
    let transaction = &write.commit;
    let event = &transaction.event;
    let commit = &transaction.commit;
    if !is_agent_control_kind(&event.kind)
        || event.applet_id.is_some()
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || event.scope_ref
            != (ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(schema(
            "an Agent control Event is one direct Agent PCR Realm-stream write",
        ));
    }
    let agent = event
        .actor_id
        .as_account_id()
        .cloned()
        .ok_or_else(|| schema("an Agent control Event actor is the Agent's account"))?;
    let controller = event
        .executed_by
        .as_ref()
        .and_then(arkret_wire::ActorId::as_account_id)
        .cloned()
        .ok_or_else(|| schema("an Agent control Event is executed by the controller account"))?;
    let authorization_ref = event
        .authorization_ref
        .as_deref()
        .ok_or_else(|| schema("an Agent control Event carries the controller delegation"))?;
    if agent.station_id != controller.station_id || agent.principal_id == controller.principal_id {
        return Err(precondition(
            "the Agent and its controller are two accounts of one Station",
        ));
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(|error| schema(&error.to_string()))?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|_| {
            rejected(
                ConflictCode::EventIdDigestMismatch,
                "Agent control Event id does not match its content",
            )
        })?;
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            "Agent control Event is unsigned",
        )
    })?;
    let signer = crate::key_backup_current_results::verification_method_device(
        &proof.verification_method,
        &controller,
    )
    .ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            "Agent control Event is not signed by a device of its controller",
        )
    })?;

    // Every writer of the Agent PCR takes this lock first.
    if !lock_realm(conn, &event.realm_id, "UPDATE").await? {
        return Err(precondition("the Agent PCR authority is absent"));
    }
    let token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| schema("Agent control Event id is not canonical"))?;
    let known = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         LEFT JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<KnownEventRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(known) = known {
        let envelope = serde_json::to_value(event).map_err(PersistenceError::database)?;
        let Some(stored) = known.commit_json.filter(|_| known.envelope == envelope) else {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "Agent control Event is already known with different content",
            ));
        };
        let stored: RealmCommit = serde_json::from_value(stored).map_err(corrupt)?;
        return Ok(AgentControlAdmissionOutcome::Duplicate(stored));
    }

    // The Agent PCR is the Agent account's own, and the accepted provision
    // in the controller's PCR binds this controller and delegation to it.
    if pcr_of(conn, &agent).await?.as_ref() != Some(&event.realm_id) {
        return Err(precondition(
            "the Event Realm is not the Agent account's Principal Control Realm",
        ));
    }
    let controller_realm = pcr_of(conn, &controller)
        .await?
        .ok_or_else(|| precondition("the controller account has no Principal Control Realm"))?;
    let provisioning = sql_query(
        "SELECT value FROM agent_provisioning_current_results \
         WHERE realm_id=$1 AND agent_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(controller_realm.as_str())
    .bind::<Text, _>(agent.principal_id.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| precondition("the controller never provisioned this Agent"))?;
    let provisioning: arkret_models_collaboration::events_payloads::agent::AgentProvisioningValue =
        serde_json::from_value(provisioning.value).map_err(corrupt)?;
    if provisioning.controller_principal_id != controller.principal_id
        || provisioning.principal_control_realm_id != event.realm_id
        || provisioning.controller_authorization_ref.as_str() != authorization_ref
    {
        return Err(precondition(
            "the Event differs from the controller delegation its provision recorded",
        ));
    }
    if !lock_realm(conn, &controller_realm, "SHARE").await? {
        return Err(precondition("the controller PCR authority is absent"));
    }
    let (controller_status, _) = verify_device_signer_in_connection(
        conn,
        event,
        &controller,
        &signer,
        &controller_realm,
        commit.committed_at,
        suite,
        WHAT,
    )
    .await?;
    if !accountability_holds_in_connection(
        conn,
        std::slice::from_ref(&controller.principal_id),
        &agent.principal_id,
        commit.committed_at,
    )
    .await?
    {
        return Err(rejected(
            ConflictCode::AccountabilityGrantMissing,
            "the controller holds no active accountability record for the Agent",
        ));
    }

    let lifecycle = accepted_lifecycle(conn, &event.realm_id, &event.actor_id).await?;
    let non_terminal = matches!(lifecycle.as_deref(), Some("active" | "paused"));
    let payload_value = Value::Object(event.payload.clone().into_iter().collect());
    match event.kind {
        EventKind::AgentKeyAuthorize => {
            let payload: AgentKeyAuthorizePayload = serde_json::from_value(payload_value)
                .map_err(|error| schema(&format!("Agent key authorization is invalid: {error}")))?;
            if payload.agent_id != agent.principal_id
                || payload.accountable_principal_id != controller.principal_id
            {
                return Err(precondition(
                    "the key authorization names another Agent or accountable controller",
                ));
            }
            arkret_signatures::agent::validate_agent_runtime_public_key(
                &payload.public_key,
                &payload.verification_method,
            )
            .map_err(|error| schema(&error.to_string()))?;
            let method_did = payload
                .verification_method
                .as_str()
                .split_once('#')
                .and_then(|(did, _)| arkret_wire::Did::new(did.to_owned()).ok())
                .ok_or_else(|| schema("the Agent key method is not a DID URL"))?;
            if arkret_wire::project_did_to_core_id(&method_did)
                .map_err(|error| schema(&error.to_string()))?
                != agent.principal_id
            {
                return Err(schema("the Agent key method is not the Agent's DID"));
            }
            if !non_terminal {
                return Err(precondition(
                    "an Agent key is authorized only while the Agent is active or paused",
                ));
            }
        }
        EventKind::AgentKeyRevoke => {
            let payload: AgentKeyRevokePayload = serde_json::from_value(payload_value)
                .map_err(|error| schema(&format!("Agent key revocation is invalid: {error}")))?;
            if payload.agent_id != agent.principal_id
                || payload.revoked_by != controller.principal_id
            {
                return Err(precondition(
                    "the key revocation names another Agent or revoker",
                ));
            }
            if !non_terminal {
                return Err(precondition(
                    "an Agent key is revoked only while the Agent is active or paused",
                ));
            }
        }
        _ => {}
    }

    let historical =
        crate::agent_producer_signer_keys::prepare_agent_controller_outcome_in_connection(
            conn,
            event,
            commit,
            &controller_status,
            &controller,
            &signer,
        )
        .await?;
    crate::authority_commit::queue_event_in_connection(conn, event, write.queued_at).await?;
    match crate::authority_commit::commit_verified_agent_control_in_connection(conn, transaction)
        .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        AuthorityCommitWriteOutcome::Duplicate => {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "Agent control Event was committed outside this unit",
            ));
        }
        AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            return Err(rejected(
                ConflictCode::TemporarilyUnavailable,
                "Agent PCR authority changed before the commit",
            ));
        }
    }
    // The registered reducer writes; a supersedes set that is not the exact
    // active set, a revoke with nothing active or a status edge outside the
    // lifecycle FSM refuses the whole Event.
    let projected = match event.kind {
        EventKind::AgentKeyAuthorize | EventKind::AgentKeyRevoke => {
            crate::agent_current_results::project_agent_key_in_connection(conn, event, commit).await
        }
        _ => {
            crate::agent_current_results::project_agent_status_in_connection(conn, event, commit)
                .await
        }
    };
    projected.map_err(|error| {
        rejected(
            ConflictCode::ReducerProjectionFailed,
            &format!("Agent control projection refused: {error}"),
        )
    })?;
    crate::sidecar_authority_change_guard::after_current_writes_in_connection(conn, event).await?;
    crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
        conn, event, commit, historical,
    )
    .await?;
    Ok(AgentControlAdmissionOutcome::Committed(commit.clone()))
}
