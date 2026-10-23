//! Service recovery at one private Realm cut, independent of business grants.
use arkret_models_integration::*;
use arkret_wire::{ActorId, CommittedEventRef, CurrentRevision, Event, EventKind, RealmCommit};
use coland_storage::{AppletEventProducerGuard, AuthorityCommitTransaction, PersistenceError};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

use crate::PgTransactionError;
use crate::realm_actor_control::{current_source, write_current};

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
fn invalid(error: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::Conflict(format!("failed_precondition: {error}")).into()
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, PgTransactionError> {
    serde_json::from_value(value).map_err(invalid)
}
fn revision(source: &CommittedEventRef) -> CurrentRevision {
    CurrentRevision {
        commit_id: source.commit_id.clone(),
        stream_position: source.stream_position,
    }
}
fn reference(commit: &RealmCommit) -> CommittedEventRef {
    CommittedEventRef {
        event_id: commit.event_ref.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    }
}
fn target(event: &Event) -> Result<ActorId, PgTransactionError> {
    let actor = match event.kind {
        EventKind::RealmActorRecoveryBegin => {
            decode::<RealmActorRecoveryBeginPayload>(json!(event.payload))?.target_actor_id
        }
        EventKind::RealmActorControlReset => {
            decode::<RealmActorControlResetPayload>(json!(event.payload))?.target_actor_id
        }
        _ => return Err(invalid("recovery unit requires begin or reset")),
    };
    if actor
        .as_realm_actor_id()
        .is_none_or(|actor| actor.realm_id != event.realm_id)
        || event.scope_ref
            != (arkret_wire::ScopeRef::RealmControl {
                realm_id: event.realm_id.clone(),
            })
        || event.authorization_ref.is_some()
        || event.executed_by.is_some()
    {
        return Err(invalid(
            "recovery target, scope or producer authority differs",
        ));
    }
    Ok(actor)
}

/// Authentication is checked by the caller even for a historical exact replay.
pub(crate) async fn replay(
    conn: &mut AsyncPgConnection,
    event: &Event,
    digest: &arkret_wire::Hash,
    governor: &arkret_wire::DidCoreId,
) -> Result<Option<RealmCommit>, PgTransactionError> {
    event.validate_for_submit_structural().map_err(invalid)?;
    let actor = target(event)?;
    crate::realm_actor_control::require_current_governor(conn, &event.realm_id, governor).await?;
    let Some(original) =
        crate::committed_disclosure::accepted_full_event_in_connection(conn, &event.event_id)
            .await?
    else {
        return Ok(None);
    };
    if original.event != *event {
        return Err(invalid("duplicate_conflict: recovery original differs"));
    }
    if !matches!(crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(conn, event, &original.commit).await?, Some(arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::RealmRecoveryService(_))) {
        return Err(invalid("recovery signer original is unavailable"));
    }
    let outcome = arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit: original.commit.clone(),
    };
    crate::realm_actor_material::retain_outcome(
        conn,
        event,
        &actor,
        digest,
        &outcome,
        original.commit.committed_at,
    )
    .await?;
    Ok(Some(original.commit))
}

pub(crate) async fn admit(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    producer: &AppletEventProducerGuard,
    publication: Option<&arkret_models_identity::ResolutionCommitment>,
    digest: &arkret_wire::Hash,
) -> Result<arkret_wire::AuthoritySubmitOutcome, PgTransactionError> {
    let event = &transaction.event;
    let commit = &transaction.commit;
    let actor = target(event)?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if let Some(commit) = replay(
        conn,
        event,
        digest,
        &transaction.expected_authority.service_id,
    )
    .await?
    {
        return Ok(arkret_wire::AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate,
            commit,
        });
    }
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &event.realm_id,
        &event.actor_id,
    )
    .await?;
    cut.require_open_lifecycle(event)?;
    let fact = crate::realm_actor_control::recovery_service_fact(
        conn,
        event,
        producer,
        commit.committed_at,
    )
    .await?;
    crate::agent_producer_signer_keys::validate_producer_fact_binding(event, commit, Some(&fact))?;
    let control = crate::realm_actor_control_source::current(conn, &actor).await?;
    let (_, manager_ref) = current_source(
        conn,
        &actor,
        json!({"kind":"realm_actor_manager","actor_id":actor}),
    )
    .await?;
    let recovery_selector = json!({"kind":"realm_actor_recovery","actor_id":actor});
    let (recovery, recovery_ref) = current_source(conn, &actor, recovery_selector.clone()).await?;
    let mut recovery: RealmActorRecoveryValue = decode(recovery)?;
    let generation_selector = json!({"kind":"realm_actor_device_generation","actor_id":actor});
    let (generation, generation_ref) =
        current_source(conn, &actor, generation_selector.clone()).await?;
    let generation: RealmActorDeviceGenerationValue = decode(generation)?;
    let owner_selector = json!({"kind":"realm_actor_status","actor_id":actor,"gate":"owner"});
    let (owner, owner_ref) = current_source(conn, &actor, owner_selector.clone()).await?;
    let (governance, governance_ref) = current_source(
        conn,
        &actor,
        json!({"kind":"realm_actor_status","actor_id":actor,"gate":"governance"}),
    )
    .await?;
    if owner == "retired" || governance == "retired" || !recovery.enabled {
        return Err(invalid("retired identity or disabled recovery"));
    }
    let mut writes = Vec::new();
    let accepted = reference(commit);
    match event.kind {
        EventKind::RealmActorRecoveryBegin => {
            let payload: RealmActorRecoveryBeginPayload = decode(json!(event.payload))?;
            if payload.manager_ref != manager_ref
                || payload.recovery_ref != recovery_ref
                || payload.expected_control_revision != revision(&control.source)
                || payload.expected_owner_status_revision != revision(&owner_ref)
                || payload.expected_governance_status_revision != revision(&governance_ref)
                || payload.expected_device_generation_revision != revision(&generation_ref)
                || payload.expected_generation != generation.current_device_generation_ref
                || payload.replaces_recovery_ref.as_ref()
                    != recovery.pending.as_ref().map(|pending| &pending.begin_ref)
            {
                return Err(invalid("recovery begin current CAS differs"));
            }
            let applet = event
                .applet_id
                .as_ref()
                .ok_or_else(|| invalid("recovery Applet absent"))?;
            let previous_request = sql_query("SELECT outcome AS value FROM realm_actor_recovery_intents WHERE realm_id=$1 AND actor_id=$2 AND manager_ref=$3 AND request_id=$4")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(json!(manager_ref))
                .bind::<Text,_>(&payload.request_id).get_result::<Row>(&mut *conn).await.optional()?;
            if previous_request.is_some() {
                return Err(PersistenceError::Conflict("duplicate_conflict: recovery request_id already names another accepted original".into()).into());
            }
            let service = match &event.actor_id {
                ActorId::Service { service_id } => service_id,
                _ => return Err(invalid("recovery Service absent")),
            };
            arkret_identity::verify_realm_actor_recovery_plan(
                applet,
                service,
                &control.value.resolution,
                &control.value.control_method_kid,
                &payload,
                event.created_at,
                commit.committed_at,
            )
            .map_err(invalid)?;
            if let Some(previous) = &recovery.pending {
                terminal(
                    conn,
                    &actor,
                    &previous.begin_ref,
                    RealmActorRecoveryState::Superseded,
                    &accepted,
                )
                .await?;
            }
            let candidate_digest = arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(&payload).map_err(invalid)?,
            )
            .map_err(invalid)?;
            let outcome = RealmActorOperationOutcome::Recovery {
                status: RealmActorRecoveryOutcomeStatus::Recovery,
                begin_ref: accepted.clone(),
                state: RealmActorRecoveryState::Pending,
                terminal_ref: None,
            };
            sql_query("INSERT INTO realm_actor_recovery_intents(realm_id,actor_id,manager_ref,request_id,begin_event_id,outcome) VALUES($1,$2,$3,$4,$5,$6)")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(json!(manager_ref))
                .bind::<Text,_>(&payload.request_id).bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(json!(outcome)).execute(&mut *conn).await?;
            inventory(
                conn,
                &actor,
                generation.current_device_generation_ref,
                &accepted,
            )
            .await?;
            recovery.pending = Some(RealmActorRecoveryIntent {
                begin_ref: accepted.clone(),
                candidate_digest,
                manager_revision: revision(&manager_ref),
                control_revision: revision(&control.source),
                device_generation_ref: payload.new_generation,
            });
            writes.push((owner_selector, json!("paused")));
            writes.push((
                generation_selector,
                json!(RealmActorDeviceGenerationValue {
                    current_device_generation_ref: payload.new_generation
                }),
            ));
        }
        EventKind::RealmActorControlReset => {
            let payload: RealmActorControlResetPayload = decode(json!(event.payload))?;
            let pending = recovery
                .pending
                .as_ref()
                .ok_or_else(|| invalid("recovery has no pending intent"))?;
            if owner != "paused"
                || payload.recovery_begin_ref != pending.begin_ref
                || recovery_ref != pending.begin_ref
                || payload.expected_recovery_revision != revision(&recovery_ref)
                || payload.expected_manager_revision != revision(&manager_ref)
                || pending.manager_revision != revision(&manager_ref)
                || payload.expected_control_revision != revision(&control.source)
                || pending.control_revision != revision(&control.source)
                || payload.expected_device_generation_revision != revision(&generation_ref)
                || generation.current_device_generation_ref != pending.device_generation_ref
            {
                return Err(invalid("recovery reset current CAS differs"));
            }
            let (begin, _) =
                crate::realm_actor_control_source::original(conn, &pending.begin_ref).await?;
            let plan: RealmActorRecoveryBeginPayload = decode(json!(begin.payload))?;
            if begin.kind != EventKind::RealmActorRecoveryBegin
                || begin.actor_id != event.actor_id
                || begin.applet_id != event.applet_id
                || plan.target_actor_id != actor
                || plan.manager_ref != manager_ref
                || pending.candidate_digest.as_str()
                    != arkret_canonical::canonical_sha256(&plan).map_err(invalid)?
                || publication != Some(&plan.next_resolution)
            {
                return Err(invalid(
                    "recovery publication is not the accepted plan's current native head",
                ));
            }
            arkret_identity::verify_realm_actor_recovery_publication(
                &plan,
                &payload.published_method_history_evidence,
                commit.committed_at,
            )
            .map_err(invalid)?;
            writes.push((
                json!({"kind":"realm_actor_control","actor_id":actor}),
                json!(RealmActorControlValue {
                    resolution: arkret_models_identity::PrincipalResolutionProjection {
                        did: plan.next_resolution.did,
                        method_history_head: plan.next_resolution.method_history_head,
                        version_id: plan.next_resolution.version_id,
                        resolution_event_ref: event.event_id.to_string(),
                        updated_at: event.created_at
                    },
                    control_method_kid: plan.next_control_method_kid,
                }),
            ));
            terminal(
                conn,
                &actor,
                &pending.begin_ref,
                RealmActorRecoveryState::Completed,
                &accepted,
            )
            .await?;
            recovery.pending = None;
        }
        _ => unreachable!("closed recovery target"),
    }
    crate::authority_commit::queue_event_in_connection(conn, event, commit.committed_at).await?;
    if !matches!(
        crate::authority_commit::commit_verified_realm_recovery_in_connection(conn, transaction)
            .await?,
        coland_storage::AuthorityCommitWriteOutcome::Committed
    ) {
        return Err(invalid("recovery control head or governance changed"));
    }
    crate::agent_producer_signer_keys::retain_prepared_applet_in_connection(
        conn, event, commit, &fact,
    )
    .await?;
    writes.push((recovery_selector, json!(recovery)));
    for (selector, value) in writes {
        write_current(conn, &actor, selector, value, commit).await?;
    }
    let outcome = arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    crate::realm_actor_material::retain_outcome(
        conn,
        event,
        &actor,
        digest,
        &outcome,
        commit.committed_at,
    )
    .await?;
    Ok(outcome)
}

pub(crate) async fn terminal(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    begin: &CommittedEventRef,
    state: RealmActorRecoveryState,
    terminal: &CommittedEventRef,
) -> Result<(), PgTransactionError> {
    let outcome = RealmActorOperationOutcome::Recovery {
        status: RealmActorRecoveryOutcomeStatus::Recovery,
        begin_ref: begin.clone(),
        state,
        terminal_ref: Some(terminal.clone()),
    };
    let changed = sql_query("UPDATE realm_actor_recovery_intents SET outcome=$1 WHERE actor_id=$2 AND begin_event_id=$3 AND outcome->>'state'='pending'")
        .bind::<Jsonb,_>(json!(outcome)).bind::<Jsonb,_>(json!(actor)).bind::<Text,_>(begin.event_id.as_str()).execute(conn).await?;
    if changed != 1 {
        return Err(invalid("recovery terminal has no exact pending ledger"));
    }
    Ok(())
}

/// Snapshot actual occupied leaves and their accepted Device originals before
/// fencing. Replaced intents preserve all earlier incomplete cleanup rows.
pub(crate) async fn inventory(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    fenced: u64,
    begin: &CommittedEventRef,
) -> Result<(), PgTransactionError> {
    inventory_selected(conn, actor, fenced, begin, None).await
}

/// Revoke inventories stay inert until the corresponding command is accepted.
pub(crate) async fn inventory_selected(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    fenced: u64,
    begin: &CommittedEventRef,
    revoke_device: Option<&arkret_wire::DeviceId>,
) -> Result<(), PgTransactionError> {
    #[derive(QueryableByName)]
    struct Group {
        #[diesel(sql_type=Text)]
        mls_group_id: String,
        #[diesel(sql_type=Jsonb)]
        value: Value,
        #[diesel(sql_type=Binary)]
        public_state: Vec<u8>,
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
    }
    let realm = &actor
        .as_realm_actor_id()
        .ok_or_else(|| invalid("Realm actor required"))?
        .realm_id;
    let groups = sql_query("SELECT g.mls_group_id,g.value,g.public_state,c.commit_json FROM mls_group_current_results g JOIN realm_commits c ON c.commit_id=g.current_commit_id AND c.realm_id=g.realm_id WHERE g.realm_id=$1 FOR SHARE OF g")
        .bind::<Text,_>(realm.as_str()).load::<Group>(&mut *conn).await?;
    let devices = sql_query("SELECT jsonb_build_object('selector',selector,'value',value) AS value FROM realm_actor_current_results WHERE realm_id=$1 AND actor_id=$2 AND selector->>'kind'='realm_actor_device_authorization'")
        .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!(actor)).load::<Row>(&mut *conn).await?;
    for group in groups {
        let current: arkret_wire::MlsGroupCurrent = decode(group.value)?;
        let group_commit: RealmCommit = decode(group.commit_json)?;
        let leaves = arkret_mls::MlsPublicGroupTracker::restore(
            &group.public_state,
            &group.mls_group_id,
            current.epoch,
        )
        .and_then(|tracker| tracker.leaves())
        .map_err(invalid)?;
        for leaf in leaves.into_iter().filter(|leaf| leaf.actor_id == *actor) {
            let mut matched = None;
            for device in &devices {
                let value: RealmActorDeviceAuthorizationValue =
                    decode(device.value["value"].clone())?;
                let multibase = value
                    .device_public_key_did
                    .strip_prefix("did:key:")
                    .ok_or_else(|| invalid("Device key fingerprint absent"))?;
                let key = arkret_canonical::decode_ed25519_multibase(multibase).map_err(invalid)?;
                if arkret_canonical::base64url_encode(key) == leaf.signature_key.as_str() {
                    if matched.is_some() {
                        return Err(invalid("MLS leaf has ambiguous Device ownership"));
                    }
                    let (_, authorization_source) =
                        current_source(conn, actor, device.value["selector"].clone()).await?;
                    let (authorization_event, _) =
                        crate::realm_actor_control_source::original(conn, &authorization_source)
                            .await?;
                    if RealmActorDeviceAuthorizationValue::from_event(&authorization_event)
                        .map_err(invalid)?
                        != value
                    {
                        return Err(invalid(
                            "cleanup Device differs from its accepted authorization original",
                        ));
                    }
                    matched = Some((
                        device.value["selector"]["device_id"]
                            .as_str()
                            .ok_or_else(|| invalid("Device identity absent"))?
                            .to_owned(),
                        value.authorized_generation_ref,
                        authorization_source,
                    ));
                }
            }
            let (device, generation, authorization_source) = matched.ok_or_else(|| {
                invalid("occupied Realm leaf lacks its accepted Device authorization")
            })?;
            if revoke_device.is_some_and(|target| target.as_str() != device) {
                continue;
            }
            if generation > fenced {
                return Err(invalid("MLS leaf is ahead of the fenced generation"));
            }
            if revoke_device.is_some() {
                sql_query("INSERT INTO realm_actor_device_revoke_cleanup(proposal_commit_id,realm_id,actor_id,fenced_generation,device_id,mls_group_id,leaf_index,signature_key,authorization_ref,begin_ref,group_state_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
                    .bind::<Text,_>(begin.commit_id.as_str()).bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!(actor))
                    .bind::<BigInt,_>(i64::try_from(generation).map_err(invalid)?).bind::<Text,_>(&device)
                    .bind::<Text,_>(&group.mls_group_id).bind::<BigInt,_>(i64::from(leaf.leaf_index))
                    .bind::<Text,_>(leaf.signature_key.as_str()).bind::<Jsonb,_>(json!(authorization_source))
                    .bind::<Jsonb,_>(json!(begin)).bind::<Jsonb,_>(json!(reference(&group_commit))).execute(&mut *conn).await?;
                continue;
            }
            sql_query("INSERT INTO realm_actor_mls_cleanup(realm_id,actor_id,fenced_generation,device_id,mls_group_id,leaf_index,signature_key,authorization_ref,begin_ref,group_state_ref,queue_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending') ON CONFLICT DO NOTHING")
                .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<BigInt,_>(i64::try_from(generation).map_err(invalid)?)
                .bind::<Text,_>(device).bind::<Text,_>(&group.mls_group_id).bind::<BigInt,_>(i64::from(leaf.leaf_index))
                .bind::<Text,_>(leaf.signature_key.as_str()).bind::<Jsonb,_>(json!(authorization_source)).bind::<Jsonb,_>(json!(begin)).bind::<Jsonb,_>(json!(reference(&group_commit))).execute(&mut *conn).await?;
        }
    }
    Ok(())
}

/// Only an accepted RFC transition can complete a frozen cleanup intent. A
/// different member's Update, a new control key or a timer cannot complete it.
pub(crate) async fn complete_mls_cleanup(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    installation: &coland_storage::MlsStateInstallation,
) -> Result<(), PgTransactionError> {
    let group = installation
        .effective_scope
        .canonical_mls_group_id()
        .map_err(invalid)?;
    let mut pending = sql_query("SELECT to_jsonb(c)||jsonb_build_object('revoke_intent',false) AS value FROM realm_actor_mls_cleanup c WHERE realm_id=$1 AND mls_group_id=$2 AND queue_state='pending' FOR UPDATE")
        .bind::<Text,_>(transaction.event.realm_id.as_str()).bind::<Text,_>(group.as_str()).load::<Row>(&mut *conn).await?;
    let inert = sql_query("SELECT to_jsonb(c)||jsonb_build_object('revoke_intent',true) AS value FROM realm_actor_device_revoke_cleanup c JOIN realm_actor_device_revoke_results r ON r.proposal_commit_id=c.proposal_commit_id WHERE c.realm_id=$1 AND c.mls_group_id=$2 AND c.completion_ref IS NULL AND r.command_result='pending' FOR UPDATE OF c")
        .bind::<Text,_>(transaction.event.realm_id.as_str()).bind::<Text,_>(group.as_str()).load::<Row>(&mut *conn).await?;
    pending.extend(inert);
    if pending.is_empty() {
        return Ok(());
    }
    let leaves = arkret_mls::MlsPublicGroupTracker::restore(
        &installation.public_state,
        group.as_str(),
        installation.epoch,
    )
    .and_then(|tracker| tracker.leaves())
    .map_err(invalid)?;
    for row in pending {
        let actor: ActorId = decode(row.value["actor_id"].clone())?;
        let index = row.value["leaf_index"]
            .as_u64()
            .ok_or_else(|| invalid("cleanup leaf index absent"))?;
        let old_key = row.value["signature_key"]
            .as_str()
            .ok_or_else(|| invalid("cleanup key absent"))?;
        let generation = row.value["fenced_generation"]
            .as_u64()
            .ok_or_else(|| invalid("cleanup generation absent"))?;
        if leaves
            .iter()
            .any(|leaf| leaf.actor_id == actor && leaf.signature_key.as_str() == old_key)
        {
            continue;
        }
        let mut completed = false;
        for proposal in &installation.consumed_proposals {
            if !proposal.target_before.as_ref().is_some_and(|leaf| {
                leaf.actor_id == actor
                    && u64::from(leaf.leaf_index) == index
                    && leaf.signature_key.as_str() == old_key
            }) {
                continue;
            }
            if proposal.proposal_type == 3 && proposal.target_after.is_none() {
                completed = true;
            } else if proposal.proposal_type == 2 {
                let Some(after) = &proposal.target_after else {
                    continue;
                };
                if after.actor_id != actor
                    || u64::from(after.leaf_index) != index
                    || after.signature_key.as_str() == old_key
                {
                    continue;
                }
                let begin: CommittedEventRef = decode(row.value["begin_ref"].clone())?;
                let (source, _) = crate::realm_actor_control_source::original(conn, &begin).await?;
                let device_revoke = source.kind == EventKind::DeviceRevoke;
                let devices = sql_query("SELECT jsonb_build_object('selector',selector,'value',value) AS value FROM realm_actor_current_results WHERE realm_id=$1 AND actor_id=$2 AND selector->>'kind'='realm_actor_device_authorization'")
                    .bind::<Text,_>(transaction.event.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).load::<Row>(&mut *conn).await?;
                for device in devices {
                    let authorization: RealmActorDeviceAuthorizationValue =
                        decode(device.value["value"].clone())?;
                    let multibase = authorization
                        .device_public_key_did
                        .strip_prefix("did:key:")
                        .ok_or_else(|| invalid("Device fingerprint absent"))?;
                    if authorization.authorized_generation_ref < generation
                        || (authorization.authorized_generation_ref == generation && !device_revoke)
                        || arkret_canonical::base64url_encode(
                            arkret_canonical::decode_ed25519_multibase(multibase)
                                .map_err(invalid)?,
                        ) != after.signature_key.as_str()
                    {
                        continue;
                    }
                    let id: arkret_wire::DeviceId =
                        decode(device.value["selector"]["device_id"].clone())?;
                    if crate::realm_actor_device_authority::current_in_connection(
                        conn,
                        &actor,
                        &id,
                        transaction.commit.committed_at,
                    )
                    .await?
                    .is_some()
                    {
                        completed = true;
                    }
                }
            }
        }
        if completed {
            if row.value["revoke_intent"] == true {
                sql_query("UPDATE realm_actor_device_revoke_cleanup SET completion_ref=$1 WHERE proposal_commit_id=$2 AND mls_group_id=$3 AND leaf_index=$4 AND completion_ref IS NULL")
                    .bind::<Jsonb,_>(json!(reference(&transaction.commit)))
                    .bind::<Text,_>(row.value["proposal_commit_id"].as_str().ok_or_else(|| invalid("revoke proposal absent"))?)
                    .bind::<Text,_>(group.as_str()).bind::<BigInt,_>(i64::try_from(index).map_err(invalid)?)
                    .execute(&mut *conn).await?;
                continue;
            }
            sql_query("UPDATE realm_actor_mls_cleanup SET queue_state='completed',completion_ref=$1 WHERE actor_id=$2 AND fenced_generation=$3 AND device_id=$4 AND mls_group_id=$5 AND leaf_index=$6 AND queue_state='pending'")
                .bind::<Jsonb,_>(json!(reference(&transaction.commit))).bind::<Jsonb,_>(json!(actor)).bind::<BigInt,_>(i64::try_from(generation).map_err(invalid)?)
                .bind::<Text,_>(row.value["device_id"].as_str().ok_or_else(|| invalid("cleanup Device absent"))?)
                .bind::<Text,_>(group.as_str()).bind::<BigInt,_>(i64::try_from(index).map_err(invalid)?).execute(&mut *conn).await?;
        }
    }
    Ok(())
}
