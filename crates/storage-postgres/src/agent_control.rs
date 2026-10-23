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
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
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

pub(crate) fn is_agent_control_event(event: &arkret_wire::Event) -> bool {
    is_agent_control_kind(&event.kind)
        || (matches!(
            event.kind,
            EventKind::ProfileCreate | EventKind::ProfileUpdate
        ) && event
            .executed_by
            .as_ref()
            .is_some_and(|actor| actor.as_account_id().is_some()))
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

async fn validate_same_key_renewal(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    payload: &AgentKeyAuthorizePayload,
    provision: &arkret_models_collaboration::events_payloads::agent::AgentProvisioningValue,
) -> Result<(), PgTransactionError> {
    use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
    if !payload.audience.iter().any(|audience| {
        audience
            == event
                .actor_id
                .as_account_id()
                .expect("validated Agent account")
                .station_id
                .as_str()
    }) {
        return Err(precondition(
            "Agent key authorization audience excludes its Station",
        ));
    }
    #[derive(QueryableByName)]
    struct KeyRow {
        #[diesel(sql_type = Jsonb)]
        value: Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
    }
    let key_id =
        arkret_wire::AgentKeyId::new(payload.key_id.as_str().to_owned()).map_err(corrupt)?;
    let key =
        arkret_wire::derive_agent_key_current_key(&payload.agent_id, &key_id).map_err(corrupt)?;
    let row = sql_query("SELECT k.value,c.commit_json FROM agent_key_current_results k JOIN realm_commits c ON c.realm_id=k.realm_id AND c.commit_id=k.current_commit_id AND c.stream_position=k.current_stream_position WHERE k.realm_id=$1 AND k.current_key=$2 FOR UPDATE OF k")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&key)
        .get_result::<KeyRow>(&mut *conn).await.optional()?
        .ok_or_else(|| precondition("same-key renewal requires a current accepted key"))?;
    let covering: RealmCommit = serde_json::from_value(row.commit_json).map_err(corrupt)?;
    covering.validate_content_address().map_err(corrupt)?;
    if covering.realm_id != event.realm_id {
        return Err(corrupt(
            "Agent current key covering Commit belongs to another Realm",
        ));
    }
    let entries = row
        .value
        .get("authorizations")
        .and_then(Value::as_array)
        .ok_or_else(|| corrupt("Agent current key entries are malformed"))?;
    let mut active = 0;
    for entry in entries {
        if entry.pointer("/value/verification_method").is_none() {
            continue;
        }
        let prior: AgentKeyAuthorizePayload =
            serde_json::from_value(entry["value"].clone()).map_err(corrupt)?;
        let reference = entry
            .get("tag_id")
            .and_then(Value::as_str)
            .and_then(|tag| tag.rsplit_once(':'))
            .map(|(id, _)| id)
            .ok_or_else(|| corrupt("Agent authorization dot has no original Event id"))?;
        let original = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND e.state='committed'")
            .bind::<Text,_>(reference).get_result::<KnownEventRow>(&mut *conn).await.optional()?
            .ok_or_else(|| corrupt("Agent authorization dot has no accepted original"))?;
        let original_event: arkret_wire::Event =
            serde_json::from_value(original.envelope).map_err(corrupt)?;
        let original_commit: RealmCommit = serde_json::from_value(
            original
                .commit_json
                .ok_or_else(|| corrupt("Agent authorization has no covering Commit"))?,
        )
        .map_err(corrupt)?;
        original_commit
            .validate_content_address()
            .map_err(corrupt)?;
        original_event
            .verify_event_id_matches_content_with_digest_suite(
                event.realm_id.digest_suite_code().digest_suite(),
            )
            .map_err(corrupt)?;
        if original_event.kind != EventKind::AgentKeyAuthorize
            || original_event.realm_id != event.realm_id
            || original_event.event_id.as_str() != reference
            || original_commit.event_ref != original_event.event_id
            || original_commit.realm_id != event.realm_id
            || serde_json::to_value(&original_event.payload).map_err(corrupt)?
                != serde_json::to_value(&prior).map_err(corrupt)?
        {
            return Err(corrupt(
                "Agent active key differs from its accepted original",
            ));
        }
        if prior.key_id != payload.key_id
            || prior.verification_method != payload.verification_method
            || serde_json::to_value(&prior.public_key).map_err(corrupt)?
                != serde_json::to_value(&payload.public_key).map_err(corrupt)?
        {
            return Err(precondition(
                "same-key renewal cannot replace key material; fresh keys require pairing",
            ));
        }
        if !payload.supersedes.iter().any(|basis| {
            basis.key_id == prior.key_id && basis.authorized_event_ref.as_str() == reference
        }) {
            return Err(precondition(
                "same-key renewal has a stale or incomplete signed basis",
            ));
        }
        active += 1;
    }
    if active == 0 {
        return Err(precondition(
            "revoked keys require fresh pairing and cannot be renewed",
        ));
    }
    let row = sql_query("SELECT requested_scope AS value FROM agent_principals WHERE id=$1 AND principal_control_realm_id=$2 AND controller_principal_id=$3 FOR SHARE")
        .bind::<Text,_>(payload.agent_id.as_str()).bind::<Text,_>(event.realm_id.as_str())
        .bind::<Text,_>(payload.accountable_principal_id.as_str()).get_result::<ValueRow>(&mut *conn).await.optional()?
        .ok_or_else(|| precondition("same-key renewal has no private provision selection"))?;
    let ceiling: AgentKeyScope = serde_json::from_value(row.value).map_err(corrupt)?;
    if payload.agent_key_scope.actions.iter().any(|action| {
        arkret_wire::ServiceOperationId::from_wire(action).is_none()
            && arkret_schema::capability_action(action).is_none()
    }) || arkret_schema::agent_runtime_scope::assess_agent_runtime_key_scopes(
        &ceiling.actions,
        &payload.agent_key_scope.actions,
    )
    .map_err(corrupt)?
    .is_some()
    {
        return Err(precondition(
            "Agent key scope omits required or contains unregistered operations",
        ));
    }
    let digest = arkret_models_collaboration::agent_scope::agent_requested_scope_digest(
        &payload.agent_id,
        &payload.accountable_principal_id,
        &ceiling,
    );
    if digest.map_err(corrupt)? != provision.requested_scope_digest
        || !arkret_models_collaboration::agent_scope::agent_key_scope_within_provision(
            &ceiling,
            &payload.agent_key_scope,
        )
    {
        return Err(precondition(
            "same-key authorization exceeds its immutable provision ceiling",
        ));
    }
    Ok(())
}

pub(crate) async fn admit_agent_control_event_in_connection(
    conn: &mut AsyncPgConnection,
    write: &AgentControlAdmissionWrite,
    origin: Option<&coland_storage::AgentControlOriginSource>,
) -> Result<AgentControlAdmissionOutcome, PgTransactionError> {
    admit_agent_control_in_connection(conn, write, origin, false).await
}

pub(crate) async fn admit_agent_same_key_renewal_in_connection(
    conn: &mut AsyncPgConnection,
    write: &AgentControlAdmissionWrite,
    origin: Option<&coland_storage::AgentControlOriginSource>,
) -> Result<AgentControlAdmissionOutcome, PgTransactionError> {
    if write.commit.event.kind != EventKind::AgentKeyAuthorize {
        return Err(schema(
            "same-key renewal requires an Agent key authorization",
        ));
    }
    admit_agent_control_in_connection(conn, write, origin, true).await
}

async fn admit_agent_control_in_connection(
    conn: &mut AsyncPgConnection,
    write: &AgentControlAdmissionWrite,
    origin: Option<&coland_storage::AgentControlOriginSource>,
    same_key_renewal: bool,
) -> Result<AgentControlAdmissionOutcome, PgTransactionError> {
    let transaction = &write.commit;
    let event = &transaction.event;
    let commit = &transaction.commit;
    if !is_agent_control_event(event)
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

    if transaction.expected_authority.service_id != agent.station_id
        || transaction.expected_authority.generation != 0
    {
        return Err(precondition(
            "Agent PCR remains at its account Station and initial tenure",
        ));
    }
    crate::pcr_private_authority::validate_installed_governance(conn, &event.realm_id).await?;

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
            if same_key_renewal {
                validate_same_key_renewal(conn, event, &payload, &provisioning).await?;
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

    let profile = if matches!(
        event.kind,
        EventKind::ProfileCreate | EventKind::ProfileUpdate
    ) {
        if !non_terminal {
            return Err(precondition(
                "a deactivated Agent cannot author a new profile Event",
            ));
        }
        let profile =
            crate::actor_profiles::materialize_profile_in_connection(conn, event, commit, &agent)
                .await?;
        if profile.actor_kind != arkret_wire::ActorKind::Agent
            || !profile
                .accountable_principal_ids
                .as_ref()
                .is_some_and(|principals| principals.contains(&controller.principal_id))
        {
            return Err(precondition(
                "the Agent profile retains its kind and accountable controller",
            ));
        }
        if let Some(slug) = &profile.agent_slug {
            let selected = sql_query(
                "SELECT value FROM agent_selector_claim_current_results \
                 WHERE realm_id=$1 AND controller_principal_id=$2 AND agent_slug=$3 FOR SHARE",
            )
            .bind::<Text, _>(controller_realm.as_str())
            .bind::<Text, _>(controller.principal_id.as_str())
            .bind::<Text, _>(slug)
            .get_result::<ValueRow>(&mut *conn)
            .await
            .optional()?
            .ok_or_else(|| {
                precondition("Agent profile slug has no accepted controller selector claim")
            })?;
            let selected: arkret_models_identity::AgentSelectorClaimValue =
                serde_json::from_value(selected.value).map_err(corrupt)?;
            if selected.subject_account_id != agent {
                return Err(precondition(
                    "Agent profile slug is claimed for another Account",
                ));
            }
        }
        Some(profile)
    } else {
        None
    };
    if let Some((dependency, history)) = origin {
        crate::agent_origin::stage_control_source_in_connection(
            conn,
            &arkret_wire::CommittedEventFullView {
                event: event.clone(),
                commit: commit.clone(),
            },
            dependency,
            history,
        )
        .await?;
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
        EventKind::ProfileCreate | EventKind::ProfileUpdate => {
            crate::actor_profiles::write_profile_current_in_connection(
                conn,
                event,
                commit,
                profile
                    .as_ref()
                    .expect("profile materialized at the Agent cut"),
            )
            .await
            .map_err(PgTransactionError::into_persistence)
        }
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
    if same_key_renewal {
        let payload: AgentKeyAuthorizePayload =
            serde_json::from_value(Value::Object(event.payload.clone().into_iter().collect()))
                .map_err(corrupt)?;
        let jwk = arkret_signatures::jwk::JsonWebKey::ed25519(payload.public_key.key.clone());
        let evidence = arkret_models_identity::authenticated_signer_resolution_evidence::build_agent_signer_evidence(
            payload.agent_id.clone(), payload.verification_method.clone(),
            serde_json::from_value(serde_json::to_value(jwk).map_err(corrupt)?).map_err(corrupt)?,
            commit.commit_id.clone(), commit.committed_at,
        ).map_err(corrupt)?;
        let reference = evidence.signer_evidence_ref().map_err(corrupt)?;
        let material = crate::agent_principal_row::pack_authorized_key_material(
            Some(event.clone()),
            Some(reference),
            Some(evidence),
        )?
        .ok_or_else(|| corrupt("same-key renewal produced no authorized material"))?;
        // The original qualified receipt and sequence allocator stay attached
        // to this same key. Only its current authorization witness advances.
        let count = sql_query("UPDATE agent_principals SET authorized_event_ref=$1,authorized_key_event=$2,updated_at=$3 WHERE id=$4 AND principal_control_realm_id=$5 AND authorized_verification_method=$6 AND paired_pairing_request_id IS NOT NULL AND authorized_event_ref IS NOT NULL")
            .bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(material)
            .bind::<diesel::sql_types::Timestamptz,_>(commit.committed_at)
            .bind::<Text,_>(payload.agent_id.as_str()).bind::<Text,_>(event.realm_id.as_str())
            .bind::<Text,_>(payload.verification_method.as_str()).execute(&mut *conn).await?;
        if count != 1 {
            return Err(precondition(
                "same-key renewal lost its qualified runtime binding",
            ));
        }
    }
    crate::sidecar_authority_change_guard::after_current_writes_in_connection(conn, event).await?;
    crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
        conn, event, commit, historical,
    )
    .await?;
    Ok(AgentControlAdmissionOutcome::Committed(commit.clone()))
}
