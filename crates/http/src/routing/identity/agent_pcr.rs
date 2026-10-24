use arkret_identifiers::{Did, Hash, RealmId};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::agent_scope::agent_requested_scope_digest;
use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
use arkret_wire::{AccountId, ActorId, DidCoreId, DidUrl};
use chrono::{DateTime, Utc};
use coland_http::error::AppError;
use coland_services::identity::{
    AgentPairingState as AgentPrincipalRecord, PinnedDidVersionStatus,
};
use serde_json::Value;

use crate::state::AppState;

fn managed_controller_core_id(controller_principal_id: &str) -> Result<DidCoreId, AppError> {
    DidCoreId::new(controller_principal_id.to_owned())
        .or_else(|_| {
            Did::new(controller_principal_id.to_owned())
                .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        })
        .map_err(|error| schema_error(format!("Agent controller DID is invalid: {error}")))
}

const CONTROLLER_DELEGATION_FRAGMENT: &str = "managed-controller";

pub(crate) fn controller_authorization_ref(agent_did: &Did) -> Result<DidUrl, AppError> {
    DidUrl::new(format!(
        "{}#{CONTROLLER_DELEGATION_FRAGMENT}",
        agent_did.as_str()
    ))
    .map_err(|error| {
        AppError::internal(format!(
            "generated Agent controller authorization ref is invalid: {error}"
        ))
    })
}

pub(crate) async fn accepted_agent_initial_resolution(
    state: &AppState,
    agent_did: &Did,
    controller_principal_id: &arkret_identifiers::DidCoreId,
) -> Result<arkret_models_identity::ResolutionCommitment, AppError> {
    let pinned = state
        .dids()
        .resolve_current_webvh_state(agent_did)
        .await
        .map_err(|error| {
            failed_precondition(
                format!("Agent accepted inception is unavailable: {error}"),
                "agent_inception_unavailable",
            )
        })?;
    if pinned.status != PinnedDidVersionStatus::Current || !pinned.version_id.starts_with("1-") {
        return Err(failed_precondition(
            "Agent prepare requires an unrotated accepted inception",
            "agent_inception_not_current",
        ));
    }
    validate_agent_inception_document(
        &pinned.document,
        agent_did,
        controller_principal_id.as_str(),
        false,
    )?;
    Ok(arkret_models_identity::ResolutionCommitment {
        did: agent_did.clone(),
        method_history_head: pinned.log_head_digest.to_string(),
        version_id: pinned.version_id,
    })
}

fn validate_agent_inception_document(
    document: &Value,
    agent_did: &Did,
    controller_principal_id: &str,
    allow_pcr_binding: bool,
) -> Result<(), AppError> {
    arkret_signatures::webvh::validate_agent_did_document_profile(
        agent_did.as_str(),
        document,
        &[],
    )
    .map_err(|error| schema_error(format!("Agent DID profile is invalid: {error}")))?;
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .ok_or_else(|| schema_error("Agent inception service set is missing"))?;
    let expected_service_count = if allow_pcr_binding { 3 } else { 2 };
    if services.len() != expected_service_count {
        return Err(schema_error(
            "Agent DID service set does not match its lifecycle phase",
        ));
    }
    let expected_id = format!("{}#{CONTROLLER_DELEGATION_FRAGMENT}", agent_did.as_str());
    let controller = &services[1];
    if controller.get("id").and_then(Value::as_str) != Some(expected_id.as_str())
        || controller
            .pointer("/serviceEndpoint/controller_did")
            .and_then(Value::as_str)
            != Some(controller_principal_id)
    {
        return Err(schema_error(
            "Agent inception must contain one matching controller delegation",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn agent_binding_is_accepted(
    state: &AppState,
    initial_resolution: &arkret_models_identity::ResolutionCommitment,
    controller_principal_id: &str,
    principal_control_realm_id: &RealmId,
    authorization_ref: &DidUrl,
    requested_scope_digest: &Hash,
) -> Result<bool, AppError> {
    let controller_core_id = managed_controller_core_id(controller_principal_id)?;
    let initial_head =
        arkret_identifiers::Hash::new(initial_resolution.method_history_head.clone())
            .map_err(|error| schema_error(format!("Agent inception head is invalid: {error}")))?;
    state
        .dids()
        .resolve_pinned_webvh_state(
            &initial_resolution.did,
            &initial_resolution.version_id,
            &initial_head,
        )
        .await
        .map_err(|error| {
            failed_precondition(
                format!("Agent committed inception is unavailable: {error}"),
                "agent_inception_unavailable",
            )
        })?;
    let current = state
        .dids()
        .resolve_current_webvh_state(&initial_resolution.did)
        .await
        .map_err(|error| {
            failed_precondition(
                format!("Agent current DID history is unavailable: {error}"),
                "agent_did_binding_unavailable",
            )
        })?;
    if current.version_id == initial_resolution.version_id {
        return Ok(false);
    }
    if !current.version_id.starts_with("2-") {
        return Err(failed_precondition(
            "Agent PCR binding must be the first continuous update after inception",
            "agent_did_binding_not_entry_one",
        ));
    }
    validate_agent_inception_document(
        &current.document,
        &initial_resolution.did,
        controller_core_id.as_str(),
        true,
    )?;
    validate_agent_binding_document(
        &current.document,
        &initial_resolution.did,
        &controller_core_id,
        principal_control_realm_id,
        authorization_ref,
        requested_scope_digest,
    )?;
    Ok(true)
}

fn validate_agent_binding_document(
    document: &Value,
    agent_did: &Did,
    controller_core_id: &DidCoreId,
    principal_control_realm_id: &RealmId,
    authorization_ref: &DidUrl,
    requested_scope_digest: &Hash,
) -> Result<(), AppError> {
    validate_agent_inception_document(document, agent_did, controller_core_id.as_str(), true)?;
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .ok_or_else(|| schema_error("Agent DID service set is missing"))?;
    let expected_id = format!("{}#arkret-principal-control-realm", agent_did.as_str());
    let mut bindings = services.iter().filter(|service| {
        service.get("type").and_then(Value::as_str) == Some("ArkretPrincipalControlRealm")
    });
    let Some(binding) = bindings.next() else {
        return Err(schema_error("Agent DID PCR binding is missing"));
    };
    if bindings.next().is_some()
        || binding.get("id").and_then(Value::as_str) != Some(expected_id.as_str())
        || binding
            .pointer("/serviceEndpoint/realm_id")
            .and_then(Value::as_str)
            != Some(principal_control_realm_id.as_str())
        || binding
            .pointer("/serviceEndpoint/controller_did")
            .and_then(Value::as_str)
            != Some(controller_core_id.as_str())
        || binding
            .pointer("/serviceEndpoint/authorization_ref")
            .and_then(Value::as_str)
            != Some(authorization_ref.as_str())
        || binding
            .pointer("/serviceEndpoint/requested_scope_digest")
            .and_then(Value::as_str)
            != Some(requested_scope_digest.as_str())
        || binding
            .pointer("/serviceEndpoint/requested_scope")
            .is_some()
    {
        return Err(schema_error(
            "Agent DID PCR service binding does not match the accepted create-locked tuple",
        ));
    }
    Ok(())
}

/// All state comparisons use one already verified native snapshot. Inception
/// is the exact commitment in accepted PCR genesis, and every effective
/// successor must retain entry one's create-locked binding, even if a later
/// successor restores a previously changed value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_agent_binding_history_at(
    history: &arkret_identity::VerifiedDidWebvhLog,
    initial_resolution: &arkret_models_identity::ResolutionCommitment,
    controller_principal_id: &str,
    principal_control_realm_id: &RealmId,
    authorization_ref: &DidUrl,
    requested_scope_digest: &Hash,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    use coland_services::identity::{select_did_webvh_state_at, select_pinned_did_webvh_state};
    let controller = managed_controller_core_id(controller_principal_id)?;
    let initial_head = Hash::new(initial_resolution.method_history_head.clone())
        .map_err(|error| schema_error(error.to_string()))?;
    let inception = select_pinned_did_webvh_state(
        &initial_resolution.did,
        history,
        &initial_resolution.version_id,
        &initial_head,
    )
    .map_err(|error| schema_error(format!("Agent accepted inception pin is invalid: {error}")))?;
    if !inception.version_id.starts_with("1-") {
        return Err(schema_error("Agent accepted inception must be entry zero"));
    }
    validate_agent_inception_document(
        &inception.document,
        &initial_resolution.did,
        controller.as_str(),
        false,
    )?;
    let selected = select_did_webvh_state_at(&initial_resolution.did, history, accepted_at)
        .map_err(|error| {
            schema_error(format!("Agent accepted-at DID history is invalid: {error}"))
        })?;
    if selected.version_id == initial_resolution.version_id {
        return Err(schema_error(
            "Agent PCR binding was not published at the evaluation time",
        ));
    }
    let binding = history
        .entries
        .get(1)
        .filter(|entry| {
            entry.version_id.starts_with("2-") && entry.version_created_at <= accepted_at
        })
        .ok_or_else(|| schema_error("Agent PCR binding must be the first continuous update"))?;
    validate_agent_binding_document(
        &binding.state,
        &initial_resolution.did,
        &controller,
        principal_control_realm_id,
        authorization_ref,
        requested_scope_digest,
    )?;
    for entry in history
        .entries
        .iter()
        .skip(2)
        .filter(|entry| entry.version_created_at <= accepted_at)
    {
        validate_agent_binding_document(
            &entry.state,
            &initial_resolution.did,
            &controller,
            principal_control_realm_id,
            authorization_ref,
            requested_scope_digest,
        )?;
    }
    Ok(())
}

pub(crate) async fn agent_controller_account(
    state: &AppState,
    record: &AgentPrincipalRecord,
) -> Result<AccountId, AppError> {
    // The initial provision reservation precedes pairing's account-PK field.
    // Its accepted controller Account is retained in provision_event_refs.
    let declared = record
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs.get("controller_authority"))
        .map(|value| serde_json::from_value::<AccountId>(value.clone()))
        .transpose()
        .map_err(|_| schema_error("stored Agent controller Account is invalid"))?;
    let account = if let Some(pk) = record.controller_account_pk {
        state.identities().account_by_id(pk).await
    } else if let Some(authority) = declared.as_ref() {
        state.identities().account(authority).await
    } else {
        return Err(failed_precondition(
            "Agent controller Account binding is missing",
            "agent_controller_binding_missing",
        ));
    }
    .map_err(|error| {
        AppError::internal(format!("Agent controller Account lookup failed: {error}"))
    })?
    .ok_or_else(|| {
        failed_precondition(
            "Agent controller Account no longer exists",
            "agent_controller_binding_missing",
        )
    })?;
    if account.account_id.principal_id
        != managed_controller_core_id(&record.controller_principal_id)?
        || record
            .controller_account_pk
            .is_some_and(|pk| pk != account.pk)
        || account.principal_id != account.account_id.principal_id
        || account.account_id.station_id != state.service_core_id()
        || declared
            .as_ref()
            .is_some_and(|authority| authority != &account.account_id)
    {
        return Err(failed_precondition(
            "Agent controller Account binding does not match",
            "agent_controller_binding_mismatch",
        ));
    }
    Ok(account.account_id)
}

fn agent_actor_for_account(
    record: &AgentPrincipalRecord,
    account: &AccountId,
) -> Result<ActorId, AppError> {
    Ok(ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new(record.id.clone())
            .map_err(|_| schema_error("stored Agent principal is invalid"))?,
        account.station_id.clone(),
    )))
}

pub(crate) async fn agent_record_for_actor(
    state: &AppState,
    actor: &ActorId,
) -> Result<Option<AgentPrincipalRecord>, AppError> {
    let Some(record) = state
        .agent_pairings()
        .agent(actor.signing_principal_id().as_str())
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    let account = agent_controller_account(state, &record).await?;
    if actor != &agent_actor_for_account(&record, &account)? {
        return Err(failed_precondition(
            "Agent Actor does not match its stored hosting Station",
            "agent_principal_binding_mismatch",
        ));
    }
    Ok(Some(record))
}

pub(crate) async fn agent_record_for_controller_pcr(
    state: &AppState,
    controller_principal_id: &str,
    pcr_id: &str,
) -> Result<Option<AgentPrincipalRecord>, AppError> {
    let agents = state
        .agent_pairings()
        .agents_for_controller(controller_principal_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR lookup failed: {error}")))?;
    Ok(agents.into_iter().find(|record| {
        record.principal_control_realm_id == pcr_id
            && record.state != AgentLifecycleState::Deactivated
    }))
}

/// Resolve delegated PCR authority for one exact controller AccountId.
///
/// The principal-only index is an implementation lookup aid; authorization
/// must still compare the immutable controller Account binding, including its
/// Station component.
pub(crate) async fn agent_record_for_controller_account_pcr(
    state: &AppState,
    controller_account_id: &AccountId,
    pcr_id: &str,
) -> Result<Option<AgentPrincipalRecord>, AppError> {
    let Some(record) =
        agent_record_for_controller_pcr(state, controller_account_id.principal_id.as_str(), pcr_id)
            .await?
    else {
        return Ok(None);
    };
    if agent_controller_account(state, &record).await? != *controller_account_id {
        return Ok(None);
    }
    Ok(Some(record))
}

/// When the Agent PCR genesis was accepted: the covering Commit of the
/// genesis the Agent account's durable principal resolution records.
pub(crate) async fn agent_pcr_genesis_accepted_at(
    state: &AppState,
    agent_id: &str,
    pcr_id: &str,
) -> Result<Option<DateTime<Utc>>, AppError> {
    let record = agent_record(state, agent_id).await?;
    let account = agent_controller_account(state, &record).await?;
    let actor = agent_actor_for_account(&record, &account)?;
    if record.principal_control_realm_id != pcr_id {
        return Ok(None);
    }
    let agent_account = actor
        .as_account_id()
        .ok_or_else(|| schema_error("Agent actor is not an account"))?;
    let Some(resolution) = state
        .persistence()
        .principal_resolution_by_account_id(agent_account)
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    if resolution.pcr_realm_id.as_str() != pcr_id {
        return Err(failed_precondition(
            "Agent account resolves to another Principal Control Realm",
            "agent_pcr_genesis_identity_mismatch",
        ));
    }
    let committed = state
        .authority_commits()
        .committed_event(&resolution.genesis_event.event_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR genesis lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("Agent PCR genesis has no covering Commit"))?;
    Ok(Some(committed.commit.committed_at))
}

pub(crate) async fn validate_agent_controller_binding(
    state: &AppState,
    agent_record: &AgentPrincipalRecord,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    validate_agent_requested_scope_binding_at(
        state,
        agent_record,
        &requested_scope_digest_for_record(agent_record)?,
        accepted_at,
    )
    .await?;
    validate_agent_runtime_authority(agent_record)?;
    validate_active_agent_accountability(state, agent_record, accepted_at).await
}

/// Bind privately disclosed scope to accepted provisioning and PCR genesis,
/// then to the create-locked public commitment in verified native history.
/// Service-local rows only locate the accepted sources; they grant no authority.
pub(crate) async fn validate_agent_requested_scope_binding_at(
    state: &AppState,
    record: &AgentPrincipalRecord,
    requested_scope_digest: &Hash,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    qualified_agent_scope_binding_at(state, record, requested_scope_digest, accepted_at)
        .await
        .map(|_| ())
}

pub(crate) async fn qualified_agent_scope_binding_at(
    state: &AppState,
    record: &AgentPrincipalRecord,
    requested_scope_digest: &Hash,
    accepted_at: DateTime<Utc>,
) -> Result<coland_storage::AgentScopeAcceptedBinding, AppError> {
    let controller = agent_controller_account(state, record).await?;
    let actor = agent_actor_for_account(record, &controller)?;
    let account = actor
        .as_account_id()
        .ok_or_else(|| schema_error("Agent Account is missing"))?;
    let resolution = state
        .persistence()
        .principal_resolution_by_account_id(account)
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR source lookup failed: {error}")))?
        .ok_or_else(|| schema_error("Agent accepted PCR genesis is missing"))?;
    coland_storage::validate_principal_resolution_record(&resolution)
        .map_err(|error| schema_error(error.to_string()))?;
    let genesis = state
        .authority_commits()
        .committed_event(&resolution.genesis_event.event_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent accepted genesis lookup failed: {error}"))
        })?
        .ok_or_else(|| schema_error("Agent PCR genesis covering Commit is missing"))?;
    let realm = RealmId::new(record.principal_control_realm_id.clone())
        .map_err(|error| schema_error(error.to_string()))?;
    if genesis.event != resolution.genesis_event
        || genesis.commit.event_ref != genesis.event.event_id
        || genesis.commit.realm_id != realm
        || genesis.event.realm_id != realm
        || genesis.commit.stream_position != 0
        || genesis.commit.committed_at > accepted_at
        || genesis.event.actor_id != actor
        || genesis.event.executed_by.as_ref() != Some(&ActorId::account(controller.clone()))
        || genesis
            .event
            .authorization_ref
            .as_ref()
            .map(|reference| reference.as_str())
            != Some(record.controller_authorization_ref.as_str())
        || genesis.event.scope_ref != arkret_wire::ScopeRef::RealmGenesis
        || RealmId::from_event_id(&genesis.event.event_id) != realm
    {
        return Err(schema_error(
            "Agent PCR genesis does not bind its exact accepted Account, controller and Realm",
        ));
    }
    genesis
        .event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| schema_error(error.to_string()))?;
    let genesis_payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&genesis.event.payload)
                .map_err(|error| schema_error(error.to_string()))?,
        )
        .map_err(|error| schema_error(error.to_string()))?;
    let initial = agent_initial_resolution_for_record(record)?;
    let trust_domain = state
        .did_binding_trust_domain()
        .map_err(AppError::internal)?;
    validate_agent_pcr_genesis_object(
        &serde_json::to_value(&genesis_payload.object)
            .map_err(|error| schema_error(error.to_string()))?,
        &record.id,
        &record.controller_principal_id,
        realm.as_str(),
        trust_domain.as_str(),
        &initial,
    )?;
    if genesis_payload.object.governance_station_id != account.station_id
        || initial.did != agent_did(record)?
    {
        return Err(schema_error(
            "Agent accepted genesis inception or hosting Station differs from its binding",
        ));
    }
    let provision_id = record
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs.get("provision_event_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| schema_error("Agent accepted provisioning reference is missing"))?;
    let provision_id = arkret_wire::EventId::new(provision_id.to_owned())
        .map_err(|error| schema_error(error.to_string()))?;
    let provision = state
        .authority_commits()
        .committed_event(&provision_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent provisioning source lookup failed: {error}"))
        })?
        .ok_or_else(|| schema_error("Agent provisioning covering Commit is missing"))?;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
            &provision.event,
        )
        .map_err(|error| schema_error(error.to_string()))?;
    provision
        .event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| schema_error(error.to_string()))?;
    if provision.event.event_id != provision_id
        || provision.commit.event_ref != provision_id
        || provision.commit.realm_id != provision.event.realm_id
        || provision.commit.committed_at > genesis.commit.committed_at
        || provision.event.actor_id != ActorId::account(controller.clone())
        || payload.agent_id != account.principal_id
        || payload.controller_principal_id != controller.principal_id
        || payload.principal_control_realm_id != realm
        || payload.controller_authorization_ref != record.controller_authorization_ref
        || &payload.requested_scope_digest != requested_scope_digest
    {
        return Err(schema_error(
            "Agent disclosed scope differs from its exact accepted provisioning source",
        ));
    }
    let history = state
        .dids()
        .verified_webvh_history(&initial.did)
        .await
        .map_err(|error| {
            schema_error(format!(
                "Agent verified DID history is unavailable: {error}"
            ))
        })?;
    validate_agent_binding_history_at(
        &history,
        &initial,
        &record.controller_principal_id,
        &realm,
        &record.controller_authorization_ref,
        requested_scope_digest,
        accepted_at,
    )?;
    let entry_one = history
        .entries
        .get(1)
        .ok_or_else(|| schema_error("Agent entry one is missing"))?;
    let raw = history
        .raw_entries
        .get(1)
        .ok_or_else(|| schema_error("Agent entry one bytes are missing"))?;
    let binding_digest = arkret_canonical::sha256_digest(
        &arkret_canonical::canonical_json_bytes(raw)
            .map_err(|error| schema_error(error.to_string()))?,
    );
    Ok(coland_storage::AgentScopeAcceptedBinding {
        controller_account: controller,
        binding_resolution: arkret_models_identity::ResolutionCommitment {
            did: initial.did.clone(),
            method_history_head: binding_digest,
            version_id: entry_one.version_id.clone(),
        },
        initial_resolution: initial,
        provision_ref: arkret_wire::CommittedEventRef {
            event_id: provision.event.event_id.clone(),
            commit_id: provision.commit.commit_id.clone(),
            stream_ref: provision.commit.stream_ref.clone(),
            stream_position: provision.commit.stream_position,
        },
        pcr_genesis_ref: arkret_wire::CommittedEventRef {
            event_id: genesis.event.event_id.clone(),
            commit_id: genesis.commit.commit_id.clone(),
            stream_ref: genesis.commit.stream_ref.clone(),
            stream_position: genesis.commit.stream_position,
        },
        requested_scope_digest: requested_scope_digest.clone(),
        verified_at: accepted_at,
    })
}

pub(crate) async fn validate_effective_agent_realm_membership(
    state: &AppState,
    agent_record: &AgentPrincipalRecord,
    realm_id: &str,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    if agent_record.state != AgentLifecycleState::Active {
        return Err(failed_precondition(
            "Agent lifecycle is not active",
            "agent_membership_inactive",
        ));
    }
    let controller_account = agent_controller_account(state, agent_record).await?;
    let agent_actor = agent_actor_for_account(agent_record, &controller_account)?;
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())
        .map_err(|_| schema_error("Agent membership Realm id is invalid"))?;
    // MemberState is decided at the durable commit cut and deliberately does
    // not advance the process-local projection. Read the accepted Agent row
    // and controller's exact join generation together from durable current.
    let joined = state
        .authority_commits()
        .accepted_effective_agent_member_joined(&realm_id, &agent_actor, &controller_account)
        .await
        .map_err(|error| AppError::internal(format!("Agent membership current lookup: {error}")))?;
    if !joined {
        return Err(failed_precondition(
            "Agent membership controller authority or generation is no longer current",
            "agent_membership_inactive",
        ));
    }
    validate_agent_controller_binding(state, agent_record, accepted_at).await
}

pub(crate) fn agent_initial_resolution_for_record(
    agent_record: &AgentPrincipalRecord,
) -> Result<arkret_models_identity::ResolutionCommitment, AppError> {
    let value = agent_record
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs.get("initial_resolution"))
        .cloned()
        .ok_or_else(|| {
            failed_precondition(
                "Agent provisioning initial resolution is missing",
                "agent_initial_resolution_missing",
            )
        })?;
    serde_json::from_value(value).map_err(|error| {
        AppError::internal(format!(
            "stored Agent initial resolution is invalid: {error}"
        ))
    })
}

/// The controller must hold an `identity_accountability` record for this
/// Agent that is active at `accepted_at`: the provision projection or a later
/// independent grant in the controller PCR (`zh/models/actor.md` 3.3.1).
async fn validate_active_agent_accountability(
    state: &AppState,
    agent_record: &AgentPrincipalRecord,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let controller_account_id = agent_controller_account(state, agent_record).await?;
    let agent_id = DidCoreId::new(agent_record.id.clone())
        .map_err(|_| schema_error("stored Agent principal is invalid"))?;
    let active = state
        .persistence()
        .accountability_verified_at(&controller_account_id.principal_id, &agent_id, accepted_at)
        .await
        .map_err(|error| AppError::internal(format!("accountability lookup failed: {error}")))?;
    if !active {
        return Err(failed_precondition(
            "Agent accountability grant is missing or inactive",
            arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        ));
    }
    Ok(())
}

#[cfg(test)]
fn agent_envelope_uses_root_anchor(envelope: &serde_json::Map<String, Value>) -> bool {
    envelope
        .get("semantic_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| reference.get("role").and_then(Value::as_str))
        .any(|role| {
            matches!(
                role,
                "did_inception" | "did_recovery_anchor" | "bootstrap_binding"
            )
        })
}

#[cfg(test)]
fn validate_agent_pcr_genesis_effect(
    envelope: &serde_json::Map<String, Value>,
    realm_id: &RealmId,
) -> Result<(), AppError> {
    let event = serde_json::from_value::<arkret_wire::Event>(Value::Object(envelope.clone()))
        .map_err(|error| schema_error(format!("Agent PCR genesis Event is invalid: {error}")))?;
    if &event.realm_id != realm_id {
        return Err(schema_error(
            "Agent PCR genesis Realm differs from its account binding",
        ));
    }
    // The accepted provision is resolved by the whole-value reverse lookup
    // performed before this validator: its declared PCR id must equal
    // retype(this EventId).  A provision ref here would make EventId
    // derivation cyclic.
    if !event.semantic_refs.is_empty() {
        return Err(failed_precondition(
            "Agent PCR genesis must not carry semantic references",
            "agent_pcr_genesis_ref_forbidden",
        ));
    }
    if event.kind != arkret_wire::EventKind::RealmCreate
        || event.scope_ref != arkret_wire::ScopeRef::RealmGenesis
        || RealmId::from_event_id(&event.event_id) != *realm_id
    {
        return Err(failed_precondition(
            "Agent PCR genesis must be the event-derived Realm create",
            "agent_pcr_genesis_identity_mismatch",
        ));
    }
    let genesis: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
            schema_error(format!("Agent PCR payload encoding failed: {error}"))
        })?)
        .map_err(|error| schema_error(format!("Agent PCR payload is invalid: {error}")))?;
    let Some(agent_actor) = event.actor_id.as_account_id() else {
        return Err(schema_error("Agent PCR genesis actor must be an Account"));
    };
    let Some(controller_actor) = event
        .executed_by
        .as_ref()
        .and_then(|actor| actor.as_account_id())
    else {
        return Err(schema_error(
            "Agent PCR genesis controller executor is missing",
        ));
    };
    if event.authorization_ref.is_none()
        || agent_actor.station_id != controller_actor.station_id
        || genesis.object.governance_station_id != agent_actor.station_id
    {
        return Err(failed_precondition(
            "Agent PCR genesis controller and governance Station binding is invalid",
            "agent_pcr_genesis_authority_mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn validate_agent_pcr_genesis_object(
    object: &Value,
    agent_id: &str,
    _controller_principal_id: &str,
    expected_realm_id: &str,
    trust_domain: &str,
    expected_initial_resolution: &arkret_models_identity::ResolutionCommitment,
) -> Result<(), AppError> {
    RealmId::new(expected_realm_id.to_owned())
        .map_err(|error| schema_error(format!("Agent PCR Realm id is invalid: {error}")))?;
    let genesis: arkret_models_collaboration::events_payloads::RealmGenesis =
        serde_json::from_value(object.clone())
            .map_err(|error| schema_error(format!("Agent PCR genesis is invalid: {error}")))?;
    genesis
        .validate()
        .map_err(|error| schema_error(format!("Agent PCR genesis is invalid: {error}")))?;
    if genesis.initial_resolution.as_ref() != Some(expected_initial_resolution) {
        return Err(failed_precondition(
            "Agent PCR initial_resolution differs from the accepted inception locked by provisioning",
            "agent_initial_resolution_mismatch",
        ));
    }
    if arkret_wire::project_did_to_core_id(&expected_initial_resolution.did)
        .map_err(|error| schema_error(format!("Agent DID is invalid: {error}")))?
        .as_str()
        != agent_id
        || genesis.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::AgentControl
        || genesis.trust_domain.as_str() != trust_domain
        || genesis.security_class != arkret_wire::SecurityClass::HighAssurance
        || genesis.initial_history_access != arkret_wire::HistoryAccess::SinceJoin
        || genesis.founding_device_descriptor.is_some()
    {
        return Err(failed_precondition(
            "Agent PCR genesis does not match the registered control Realm profile",
            "principal_control_realm_profile_mismatch",
        ));
    }
    Ok(())
}

async fn agent_record(state: &AppState, agent_id: &str) -> Result<AgentPrincipalRecord, AppError> {
    state
        .agent_pairings()
        .agent(agent_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
        .ok_or_else(|| schema_error("managed_principal_id does not identify a local Agent"))
}

fn agent_did(record: &AgentPrincipalRecord) -> Result<Did, AppError> {
    let (controller, _) = record
        .controller_authorization_ref
        .as_str()
        .split_once('#')
        .ok_or_else(|| schema_error("Agent controller authorization ref has no fragment"))?;
    let did = Did::new(controller.to_owned())
        .map_err(|error| schema_error(format!("Agent DID is invalid: {error}")))?;
    let projected = arkret_wire::project_did_to_core_id(&did)
        .map_err(|error| schema_error(format!("Agent DID projection failed: {error}")))?;
    if projected.as_str() != record.id.as_str() {
        return Err(schema_error(
            "Agent DID does not project to the stored core id",
        ));
    }
    let expected_authorization_ref = controller_authorization_ref(&did)?;
    if expected_authorization_ref != record.controller_authorization_ref {
        return Err(schema_error(
            "Agent controller authorization ref does not match its DID",
        ));
    }
    Ok(did)
}

#[cfg(test)]
fn validate_agent_did_identity_anchor(document: &Value, agent_did: &Did) -> Result<(), AppError> {
    arkret_signatures::webvh::validate_agent_did_document_profile(agent_did.as_str(), document, &[])
        .map_err(|error| schema_error(format!("Agent DID identity profile is invalid: {error}")))
}

fn validate_agent_runtime_authority(record: &AgentPrincipalRecord) -> Result<(), AppError> {
    record.runtime_bindings().map(|_| ()).map_err(|error| {
        failed_precondition(
            format!("Agent accepted key authority is invalid: {error}"),
            "agent_key_authority_invalid",
        )
    })
}

pub(crate) fn requested_scope_digest_for_record(
    record: &AgentPrincipalRecord,
) -> Result<Hash, AppError> {
    let requested_scope: AgentKeyScope = serde_json::from_value(
        record
            .requested_scope
            .clone()
            .ok_or_else(|| schema_error("Agent requested_scope is missing"))?,
    )
    .map_err(|error| schema_error(format!("Agent requested_scope is invalid: {error}")))?;
    let agent_id = arkret_identifiers::DidCoreId::new(record.id.clone())
        .map_err(|error| schema_error(format!("Agent DID is invalid: {error}")))?;
    let controller_principal_id = managed_controller_core_id(&record.controller_principal_id)?;
    agent_requested_scope_digest(&agent_id, &controller_principal_id, &requested_scope)
        .map_err(|error| schema_error(format!("Agent ceiling digest failed: {error}")))
}

fn schema_error(message: impl Into<String>) -> AppError {
    crate::app_error!(SchemaViolation, message)
}

fn failed_precondition(message: impl Into<String>, reason: &str) -> AppError {
    crate::app_error!(FailedPrecondition, message).with_internal_reason(reason)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn agent_account_binding_rejects_same_principal_at_another_station() {
        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let local = super::AccountId::new(
            super::DidCoreId::new(CONTROLLER).unwrap(),
            state.service_core_id(),
        );
        let foreign = super::AccountId::new(
            local.principal_id.clone(),
            super::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        );
        for (label, account_id) in [("local", local.clone()), ("foreign", foreign.clone())] {
            state
                .identities()
                .save_account(coland_services::identity::AccountProfileState {
                    // The store assigns the primary key.
                    pk: coland_storage::AccountPk(0),
                    principal_id: account_id.principal_id.clone(),
                    account_id,
                    localpart: format!("controller-{label}"),
                    display_name: None,
                    biography: None,
                    avatar_blob_ref: None,
                    created_at: chrono::Utc::now(),
                })
                .await
                .unwrap();
        }
        let local_pk = state
            .identities()
            .account(&local)
            .await
            .expect("local account lookup")
            .expect("local account was just saved")
            .pk;
        let foreign_pk = state
            .identities()
            .account(&foreign)
            .await
            .expect("foreign account lookup")
            .expect("foreign account was just saved")
            .pk;
        let mut record = super::AgentPrincipalRecord::new(
            AGENT.into(),
            CONTROLLER.into(),
            PCR.into(),
            super::controller_authorization_ref(&super::Did::new(AGENT_DID).unwrap()).unwrap(),
            super::AgentLifecycleState::Active,
            chrono::Utc::now(),
        );
        // Pre-genesis reservation has no PK yet, but has its exact accepted Account.
        record.provision_event_refs = Some(serde_json::json!({"controller_authority":local}));
        assert_eq!(
            super::agent_controller_account(&state, &record)
                .await
                .unwrap(),
            local
        );
        record.controller_account_pk = Some(local_pk);
        state
            .agent_pairings()
            .save_agent(record.clone())
            .await
            .unwrap();
        let actor = super::agent_actor_for_account(&record, &local).unwrap();
        assert!(
            super::agent_record_for_actor(&state, &actor)
                .await
                .unwrap()
                .is_some()
        );
        let foreign_actor = super::ActorId::account(arkret_wire::AccountId::new(
            actor.signing_principal_id().clone(),
            super::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert!(
            super::agent_record_for_actor(&state, &foreign_actor)
                .await
                .is_err()
        );
        assert!(
            super::agent_record_for_controller_account_pcr(&state, &local, PCR)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            super::agent_record_for_controller_account_pcr(&state, &foreign, PCR)
                .await
                .unwrap()
                .is_none()
        );
        record.controller_account_pk = Some(foreign_pk);
        assert!(
            super::agent_controller_account(&state, &record)
                .await
                .is_err()
        );
    }

    use serde_json::json;

    use super::*;

    const AGENT: &str = "ak:did_core:webvh:z6mkfixtureagent";
    const AGENT_DID: &str = "did:webvh:z6mkfixtureagent:agent.example";
    const CONTROLLER: &str = "ak:did_core:web:controller.example";
    const CONTROLLER_DID: &str = "did:web:controller.example";
    const PCR: &str = "ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M";
    const TRUST_DOMAIN: &str = "ak:trust_domain:agent-pcr";

    fn requested_scope() -> Value {
        json!({
            "actions": ["ak.event.read"],
            "resources": [{
                "kind": "operation",
                "operation": "ak.self.committed_event.read.scan.v1"
            }]
        })
    }

    fn did_document() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": AGENT_DID,
            "alsoKnownAs": [],
            "service": [
                {
                    "id": format!("{AGENT_DID}#coland"),
                    "type": "ArkretService",
                    "serviceKind": "station",
                    "serviceEndpoint": "https://agent.example/"
                },
                {
                    "id": format!("{AGENT_DID}#managed-controller"),
                    "type": "ArkretManagedPrincipalController",
                    "serviceEndpoint": {
                        "controller_did": CONTROLLER,
                        "purposes": [
                            "agent_control_authoring",
                            "principal_control_realm_bootstrap",
                            "principal_control_realm_recovery"
                        ]
                    }
                }
            ]
        })
    }

    fn pcr_genesis() -> Value {
        let payload = arkret_bootstrap::build_agent_pcr_create_payload(
            arkret_bootstrap::AgentPcrCreatePayloadInput {
                agent_id: arkret_identifiers::DidCoreId::new(AGENT).unwrap(),
                governance_station_id: arkret_identifiers::DidCoreId::new(
                    "ak:did_core:web:station.example",
                )
                .unwrap(),
                initial_resolution: arkret_models_identity::ResolutionCommitment {
                    did: arkret_identifiers::Did::new(AGENT_DID).unwrap(),
                    method_history_head: format!("sha256:{}", "8".repeat(64)),
                    version_id: "1-Qmfixture".to_owned(),
                },
                genesis_salt: arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new(TRUST_DOMAIN).unwrap(),
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
            },
        )
        .unwrap();
        serde_json::to_value(payload.object).unwrap()
    }

    fn pcr_initial_resolution() -> arkret_models_identity::ResolutionCommitment {
        serde_json::from_value(pcr_genesis()["initial_resolution"].clone()).unwrap()
    }

    #[test]
    fn did_identity_anchor_rejects_business_authority_fields() {
        let agent_did = Did::new(AGENT_DID).unwrap();
        validate_agent_did_identity_anchor(&did_document(), &agent_did)
            .expect("identity-only Agent DID document must pass");

        let mut wrong_id = did_document();
        wrong_id["id"] = json!(CONTROLLER_DID);
        assert!(validate_agent_did_identity_anchor(&wrong_id, &agent_did).is_err());

        let mut authority_bearing = did_document();
        authority_bearing["service"] = json!([{
            "id": format!("{AGENT}#business-authority"),
            "type": "ArkretBusinessAuthority",
        }]);
        assert!(validate_agent_did_identity_anchor(&authority_bearing, &agent_did).is_err());

        let mut embedded_scope = did_document();
        embedded_scope["requested_scope"] = requested_scope();
        assert!(validate_agent_did_identity_anchor(&embedded_scope, &agent_did).is_err());
    }

    #[test]
    fn agent_pcr_genesis_requires_restricted_mls_e2ee_profile() {
        validate_agent_pcr_genesis_object(
            &pcr_genesis(),
            AGENT,
            CONTROLLER,
            PCR,
            TRUST_DOMAIN,
            &pcr_initial_resolution(),
        )
        .expect("strict Agent PCR genesis must pass");

        let mut ordinary_realm = pcr_genesis();
        ordinary_realm["initial_history_access"] = json!("all_history_for_current_members");
        assert!(
            validate_agent_pcr_genesis_object(
                &ordinary_realm,
                AGENT,
                CONTROLLER,
                PCR,
                TRUST_DOMAIN,
                &pcr_initial_resolution(),
            )
            .is_err()
        );
    }

    #[test]
    fn agent_pcr_genesis_rejects_resolution_not_locked_by_provisioning() {
        let mut different = pcr_initial_resolution();
        different.method_history_head = format!("sha256:{}", "9".repeat(64));
        assert!(
            validate_agent_pcr_genesis_object(
                &pcr_genesis(),
                AGENT,
                CONTROLLER,
                PCR,
                TRUST_DOMAIN,
                &different,
            )
            .is_err()
        );
    }

    /// Agent PCR identity is the accepted Realm-create Event ID, and cannot
    /// be selected from a payload field or from a retired cell projection.
    #[test]
    fn agent_pcr_genesis_requires_event_derived_realm_id() {
        let mut event = crate::test_event::raw_event(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::RealmGenesis,
            crate::test_actor_id_str(AGENT_DID),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1".to_owned()).unwrap(),
            json!({"object": pcr_genesis()}),
        )
        .unwrap();
        // The Agent Account, its controller and the generation-0 governance
        // Station share one Station (key-management.md section 4).
        event.actor_id = super::ActorId::account(super::AccountId::new(
            super::DidCoreId::new(AGENT).unwrap(),
            super::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        event.executed_by = Some(super::ActorId::account(super::AccountId::new(
            super::DidCoreId::new(CONTROLLER).unwrap(),
            super::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )));
        event.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new(format!("{AGENT_DID}#managed-controller")).unwrap(),
        );
        event.semantic_refs.clear();
        event
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let realm_id = event.realm_id.clone();
        let envelope = serde_json::to_value(&event).unwrap();
        validate_agent_pcr_genesis_effect(envelope.as_object().unwrap(), &realm_id)
            .expect("canonical Agent PCR create has its event-derived Realm ID");

        let mut unprojectable = envelope;
        unprojectable["payload"] = json!({});
        assert!(
            validate_agent_pcr_genesis_effect(unprojectable.as_object().unwrap(), &realm_id)
                .is_err()
        );
    }

    #[test]
    fn agent_envelope_rejects_self_principal_root_anchor_roles() {
        for role in ["did_inception", "did_recovery_anchor", "bootstrap_binding"] {
            let envelope = serde_json::json!({
                "semantic_refs": [{
                    "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "role": role,
                    "critical": true
                }]
            });
            assert!(agent_envelope_uses_root_anchor(
                envelope.as_object().unwrap()
            ));
        }
        assert!(!agent_envelope_uses_root_anchor(
            serde_json::json!({}).as_object().unwrap()
        ));
    }

    // did-usage-and-verification.md §2.2 — a proof `verification_method` MUST
    // be a DID URL with a `#fragment`. A bare `did:key:<mb>` names no concrete
    // verification method and must not satisfy the active-series binding.
}
