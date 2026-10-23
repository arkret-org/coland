//! The Agent PCR genesis unit (key-management.md section 3.6.3,
//! realm-and-space.md section 2.5).
//!
//! An Agent PCR `ak.realm.create` is authored as the Agent's complete account
//! and executed by its controller. It carries no reference back to its
//! provision, so admission reverse-looks-up the `agent_pcr_genesis_declaration`
//! row an accepted `ak.agent.provision` wrote for `retype(event_id)`; without
//! that row nothing is written. The controller's signing device must be
//! active in the controller PCR at the Commit, read under that PCR's lock, and
//! the controller must still hold an active accountability record for the
//! Agent. The unit then installs the new Realm authority and writes the
//! genesis Event, its position-zero Commit and the registered create results
//! (`realm_genesis`, `realm_authority_root`, `identity_resolution`,
//! `realm_history_access` and the `uninitialized -> active` `agent_status`
//! transition) together.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
use arkret_wire::{CommitStreamRef, EventKind, RealmCommit, RealmId, ScopeRef};
use coland_storage::{
    AgentPcrGenesisAdmissionOutcome, AgentPcrGenesisAdmissionWrite, AuthorityCommitWriteOutcome,
    ConflictCode, PersistenceError,
};
use diesel::sql_types::{Binary, Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::Value;

use crate::actor_profiles::{
    accountability_holds_in_connection, corrupt, rejected, verify_device_signer_in_connection,
};
use crate::{AsyncPgConnection, PgTransactionError, ids};

const WHAT: &str = "Agent PCR genesis";

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
struct RealmLockRow {
    #[diesel(sql_type = Text)]
    #[allow(dead_code)]
    realm_id: String,
}

fn schema(reason: &str) -> PgTransactionError {
    rejected(ConflictCode::SchemaViolation, reason)
}

pub(crate) async fn admit_agent_pcr_genesis_in_connection(
    conn: &mut AsyncPgConnection,
    write: &AgentPcrGenesisAdmissionWrite,
) -> Result<AgentPcrGenesisAdmissionOutcome, PgTransactionError> {
    let transaction = &write.commit;
    let event = &transaction.event;
    let commit = &transaction.commit;
    let authority = &transaction.expected_authority;

    // The event-derived Realm at position zero of its own stream, installed
    // by this Station as generation-0 governance.
    let realm_id = RealmId::from_event_id(&event.event_id);
    if event.kind != EventKind::RealmCreate
        || event.scope_ref != ScopeRef::RealmGenesis
        || event.realm_id != realm_id
        || event.applet_id.is_some()
        || !event.semantic_refs.is_empty()
        || commit.event_ref != event.event_id
        || commit.realm_id != realm_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            })
        || commit.stream_position != 0
        || commit.previous_commit_ref.is_some()
        || authority.realm_id != realm_id
        || authority.generation != 0
        || authority.last_handoff_ref.is_some()
        || authority.authority_ref
            != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone())
    {
        return Err(schema(
            "Agent PCR genesis is not the event-derived create at position zero",
        ));
    }
    let genesis = event
        .as_realm_create()
        .map_err(|error| schema(&format!("Agent PCR genesis payload is invalid: {error}")))?
        .object;
    genesis
        .validate()
        .map_err(|error| schema(&format!("Agent PCR genesis is invalid: {error}")))?;
    let agent = event
        .actor_id
        .as_account_id()
        .cloned()
        .ok_or_else(|| schema("Agent PCR genesis actor must be the Agent's account"))?;
    let controller = event
        .executed_by
        .as_ref()
        .and_then(arkret_wire::ActorId::as_account_id)
        .cloned()
        .ok_or_else(|| schema("Agent PCR genesis must be executed by the controller account"))?;
    let authorization_ref = event
        .authorization_ref
        .as_deref()
        .ok_or_else(|| schema("Agent PCR genesis must carry the controller delegation"))?;
    let initial_resolution = genesis
        .initial_resolution
        .as_ref()
        .ok_or_else(|| schema("Agent PCR genesis must carry the accepted inception"))?;
    if genesis.purpose != RealmPurpose::AgentControl
        || genesis.founding_device_descriptor.is_some()
        || genesis.security_class != arkret_wire::SecurityClass::HighAssurance
        || genesis.initial_history_access != arkret_wire::HistoryAccess::SinceJoin
    {
        return Err(schema(
            "Agent PCR genesis does not match the registered Agent control Realm profile",
        ));
    }
    if agent.station_id != controller.station_id
        || genesis.governance_station_id != agent.station_id
        || authority.service_id != agent.station_id
        || arkret_wire::project_did_to_core_id(&initial_resolution.did)
            .map_err(|error| schema(&error.to_string()))?
            != agent.principal_id
    {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "Agent PCR genesis Agent, controller and governance Station are not one Station",
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
                "Agent PCR genesis Event id does not match its content",
            )
        })?;
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            "Agent PCR genesis is unsigned",
        )
    })?;
    let signer = crate::key_backup_current_results::verification_method_device(
        &proof.verification_method,
        &controller,
    )
    .ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            "Agent PCR genesis is not signed by a device of its controller",
        )
    })?;

    let token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| schema("Agent PCR genesis Event id is not canonical"))?;
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
                "Agent PCR genesis Event is already known with different content",
            ));
        };
        let stored: RealmCommit = serde_json::from_value(stored).map_err(corrupt)?;
        return Ok(AgentPcrGenesisAdmissionOutcome::Duplicate(stored));
    }

    // The genesis names no provision: the accepted forward declaration of
    // this exact realm id is the only binding (section 3.6.3).
    let (controller_realm, provision, provision_ref) =
        crate::agent_provisioning::declared_agent_provision_in_connection(conn, &realm_id)
            .await?
            .ok_or_else(|| {
                rejected(
                    ConflictCode::AgentPcrGenesisDeclarationMissing,
                    "no accepted ak.agent.provision declares this Agent PCR id",
                )
            })?;
    if provision.agent_id != agent.principal_id
        || provision.controller_principal_id != controller.principal_id
        || provision.controller_authorization_ref.as_str() != authorization_ref
    {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "Agent PCR genesis differs from the provision that declared its realm id",
        ));
    }
    let controller_pcr = sql_query(
        "SELECT pcr_realm_id FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(controller.principal_id.as_str())
    .bind::<Text, _>(controller.station_id.as_str())
    .get_result::<PcrRow>(&mut *conn)
    .await
    .optional()?;
    if controller_pcr.as_ref().map(|row| row.pcr_realm_id.as_str())
        != Some(controller_realm.as_str())
    {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "the declaring provision is not in the controller's own PCR",
        ));
    }

    // Order this admission against every writer of the controller PCR, so
    // the controller device cut and accountability read below hold at the
    // Commit.
    sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR SHARE")
        .bind::<Text, _>(controller_realm.as_str())
        .get_result::<RealmLockRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| {
            rejected(
                ConflictCode::FailedPrecondition,
                "the controller PCR authority is absent",
            )
        })?;
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

    let historical =
        crate::agent_producer_signer_keys::prepare_agent_genesis_outcome_in_connection(
            conn,
            event,
            commit,
            &controller_status,
            &controller,
            &signer,
            &provision_ref,
            &provision.controller_authorization_ref,
        )
        .await?;
    let authority_inserted = sql_query(
        "INSERT INTO realm_authorities \
         (realm_id,generation,service_id,authority_ref,last_handoff_ref) \
         VALUES ($1,0,$2,$3,NULL) ON CONFLICT (realm_id) DO NOTHING",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(authority.service_id.as_str())
    .bind::<Jsonb, _>(
        serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?,
    )
    .execute(&mut *conn)
    .await?;
    if authority_inserted != 1 {
        return Err(rejected(
            ConflictCode::RealmAlreadyExists,
            "the Agent PCR already exists",
        ));
    }
    crate::authority_commit::queue_event_in_connection(conn, event, write.queued_at).await?;
    match crate::authority_commit::commit_verified_agent_pcr_genesis_in_connection(
        conn,
        transaction,
    )
    .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        AuthorityCommitWriteOutcome::Duplicate => {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "Agent PCR genesis was committed outside this unit",
            ));
        }
        AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            return Err(rejected(
                ConflictCode::TemporarilyUnavailable,
                "Agent PCR authority changed before the genesis commit",
            ));
        }
    }
    crate::capability_grant_current_results::commit_realm_authority_root_current_result_in_connection(
        conn, event, commit,
    )
    .await?;
    crate::realm_bootstrap_current_results::commit_ordinary_bootstrap_singleton_current_result_in_connection(
        conn, event, commit,
    )
    .await?;
    crate::agent_current_results::project_agent_status_in_connection(conn, event, commit).await?;
    crate::sidecar_authority_change_guard::after_current_writes_in_connection(conn, event).await?;

    let resolution = arkret_models_identity::PrincipalResolutionProjection {
        did: initial_resolution.did.clone(),
        method_history_head: initial_resolution.method_history_head.clone(),
        version_id: initial_resolution.version_id.clone(),
        resolution_event_ref: event.event_id.to_string(),
        updated_at: event.created_at,
    };
    let inserted = sql_query(
        "WITH inserted AS ( \
           INSERT INTO principal_resolutions \
             (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) \
           VALUES ($1,$2,$3,$4,$4,$5,$6) ON CONFLICT DO NOTHING \
           RETURNING principal_id,station_id \
         ), inserted_event AS ( \
           INSERT INTO principal_resolution_events \
             (principal_id,station_id,event_id,previous_event_id,method_history_head,event_json,created_at) \
           SELECT principal_id,station_id,$4,NULL,$7,$8,$6 FROM inserted \
         ) SELECT realm_id AS pcr_realm_id FROM (SELECT $3::text AS realm_id) r \
           WHERE EXISTS(SELECT 1 FROM inserted)",
    )
    .bind::<Text, _>(agent.principal_id.as_str())
    .bind::<Text, _>(agent.station_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&resolution).map_err(PersistenceError::database)?)
    .bind::<Timestamptz, _>(resolution.updated_at)
    .bind::<Text, _>(&resolution.method_history_head)
    .bind::<Jsonb, _>(serde_json::to_value(event).map_err(PersistenceError::database)?)
    .get_result::<PcrRow>(&mut *conn)
    .await
    .optional()?;
    if inserted.is_none() {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "the Agent account already has a Principal Control Realm",
        ));
    }
    crate::principal_resolution_unit::initialize_in_connection(
        conn,
        &agent,
        event,
        commit,
        &resolution,
    )
    .await?;
    crate::accounts::create_agent_holder_account_in_connection(conn, &agent, commit.committed_at)
        .await?;
    crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
        conn, event, commit, historical,
    )
    .await?;
    Ok(AgentPcrGenesisAdmissionOutcome::Committed(commit.clone()))
}
