use arkret_event_draft::{EventPayloadExt as _, TypedEventDraft};
use arkret_identifiers::SidecarId;
use arkret_models_collaboration::agent_operations::{
    AgentLifecycleState, AgentSidecarList, AgentSidecarView,
};
#[cfg(test)]
use arkret_models_collaboration::agent_sidecar::SidecarAccessProvisioningPhase;
use arkret_models_collaboration::agent_sidecar::{
    AgentSidecar, AgentSidecarAccessReadiness, AgentSidecarMlsContext, AgentSidecarState,
    PendingSidecarAccessReconciliation,
};
use arkret_models_collaboration::events_payloads::sidecar::{
    SidecarContextAttachPayload, SidecarCreatePayload,
};
use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
use arkret_models_collaboration::sidecar_operations::{
    SidecarContextRef, SidecarEnsureAcceptedOutcome, SidecarEnsureAcceptedPhase,
    SidecarEnsureAcceptedStatus, SidecarEnsureExistingBranch, SidecarEnsureNewBranch,
    SidecarEnsureOutcome, SidecarEnsurePreparedExistingOutcome, SidecarEnsurePreparedNewOutcome,
    SidecarEnsurePreparedStatus, SidecarEnsureRequestBody,
};
#[cfg(test)]
use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_models_crypto::SidecarMlsBinding;
use arkret_wire::NonEmptyString;
use coland_services::identity::{
    AgentSidecarContextState as AgentSidecarContextRecord, AgentSidecarState as AgentSidecarRecord,
};
use salvo::oapi::extract::QueryParam;

use super::*;

const SIDECAR_ENSURE_LOCK_SHARDS: usize = 256;
const SIDECAR_LIST_PAGE_SIZE: usize = 100;

async fn lock_sidecar_ensure(
    realm_id: &str,
    controller_account_id: &arkret_wire::AccountId,
) -> tokio::sync::OwnedMutexGuard<()> {
    use std::hash::{Hash as _, Hasher as _};
    use std::sync::{Arc, OnceLock};

    static LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| {
        (0..SIDECAR_ENSURE_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    realm_id.hash(&mut hasher);
    controller_account_id
        .principal_id
        .as_str()
        .hash(&mut hasher);
    controller_account_id.station_id.as_str().hash(&mut hasher);
    let shard = (hasher.finish() as usize) % SIDECAR_ENSURE_LOCK_SHARDS;
    locks[shard].clone().lock_owned().await
}

pub(super) fn sidecar_create_denied(message: impl Into<String>) -> AppError {
    AppError::capability_denied(message)
        .with_reason_code(arkret_wire::ReasonCode::SIDECAR_CREATE_DENIED)
}

pub(super) fn sidecar_failed_precondition(
    reason: &'static str,
    message: impl Into<String>,
) -> AppError {
    crate::app_error!(FailedPrecondition, message.into()).with_rejection_code(reason)
}

async fn authorize_sidecar_ensure(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &str,
) -> Result<(), AppError> {
    let controller_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    if controller_actor.as_account_id().is_none() {
        return Err(sidecar_create_denied(
            "Sidecar controller must be an Account",
        ));
    }
    match crate::authz::authorize(
        state,
        realm_id,
        &controller_actor,
        &[arkret_wire::CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1],
        realm_id,
        chrono::Utc::now(),
    )
    .await?
    {
        verdict if verdict.allowed() => return Ok(()),
        crate::authz::CapabilityVerdict::ConstraintsNotSatisfied
        | crate::authz::CapabilityVerdict::Quarantined
        | crate::authz::CapabilityVerdict::RequiresReview => {
            return Err(sidecar_create_denied(
                "ak.self.agent.sidecar.command.ensure.v1 denied by policy",
            ));
        }
        _ => {}
    }
    if realm_member_joined(state, realm_id, &controller_actor.to_string()) {
        return Ok(());
    }
    Err(sidecar_create_denied(
        "ak.self.agent.sidecar.command.ensure.v1 requires a Realm member controller",
    ))
}

pub(super) fn realm_member_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    if serde_json::from_str::<arkret_wire::ActorId>(actor).is_err() {
        return false;
    }
    let projection = state.projections().snapshot();
    projection
        .member(realm_id, actor)
        .is_some_and(|membership| membership.state == "join")
        && (projection
            .agent_membership_binding(realm_id, actor)
            .is_none()
            || projection.effective_agent_membership_base(realm_id, actor))
}

async fn validate_sidecar_context(
    state: &AppState,
    realm_id: &RealmId,
    context_ref: &SidecarContextRef,
    controller: &arkret_wire::ActorId,
) -> Result<(), AppError> {
    match context_ref {
        SidecarContextRef::Strand { strand_id } => {
            // Canonical Strand writes do not depend on the reducer mirror.
            // Prepare reads the accepted current, while the atomic attach
            // transaction rechecks the source at its own locked cut.
            let scope = state
                .authority_commits()
                .visible_strand_scope_for_actor(realm_id, strand_id, controller)
                .await
                .map_err(|error| AppError::internal(format!("Sidecar source current: {error}")))?
                .ok_or_else(|| AppError::not_found("context_ref.strand_id not found"))?;
            if scope
                != (arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                })
            {
                return Err(AppError::not_found("context_ref.strand_id not found"));
            }
        }
        SidecarContextRef::Relation { relation_id } => {
            let projection = state.projections().snapshot();
            let relation = projection
                .relations
                .get(relation_id.as_str())
                .ok_or_else(|| AppError::not_found("context_ref.relation_id not found"))?;
            if relation.realm_id != realm_id.as_str() {
                return Err(sidecar_failed_precondition(
                    "context_ref_realm_mismatch",
                    "context_ref.relation_id belongs to another Realm",
                ));
            }
            if relation.state != "active" {
                return Err(sidecar_failed_precondition(
                    "relation_not_active",
                    "context_ref.relation_id is not active",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) async fn derive_sidecar_desired_agent_ids(
    state: &AppState,
    realm_id: &str,
    controller: &arkret_wire::AccountId,
) -> Result<Vec<String>, AppError> {
    let records = state
        .agent_pairings()
        .agents_for_controller(controller.principal_id.as_str())
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?;
    let mut desired = BTreeSet::new();
    for record in &records {
        if agent_record_is_desired_sidecar_member(state, realm_id, controller, record).await? {
            desired.insert(record.id.clone());
        }
    }
    Ok(desired.into_iter().collect())
}

async fn agent_record_is_desired_sidecar_member(
    state: &AppState,
    realm_id: &str,
    controller: &arkret_wire::AccountId,
    record: &AgentPrincipalRecord,
) -> Result<bool, AppError> {
    let agent_id = record.id.as_str();
    if record.controller_principal_id != controller.principal_id.as_str()
        || record.state != AgentLifecycleState::Active
    {
        return Ok(false);
    }
    let account =
        crate::routing::identity::agent_pcr::agent_controller_account(state, record).await?;
    if &account != controller {
        return Ok(false);
    }
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(agent_id)
            .map_err(|error| AppError::internal(format!("invalid Agent principal: {error}")))?,
        account.station_id,
    ));
    let has_authorization = !accepted_agent_key_authorizations(state, record)
        .await?
        .is_empty();
    Ok(
        realm_member_joined(state, realm_id, &agent_actor.to_string()) && {
            let projection = state.projections().snapshot();
            !matches!(
                projection.agent_lifecycles.get(&agent_actor.to_string()),
                Some(AgentLifecycleState::Paused | AgentLifecycleState::Deactivated)
            ) && has_authorization
        },
    )
}

fn sidecar_from_record(record: &AgentSidecarRecord) -> Result<AgentSidecar, AppError> {
    Ok(AgentSidecar {
        id: SidecarId::new(record.sidecar_id.clone())
            .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?,
        schema: arkret_wire::SchemaId::AGENT_SIDECAR_V1.to_owned(),
        realm_id: RealmId::new(record.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored Realm id: {error}")))?,
        controller_account_id: record.controller_account_id.clone(),
        state: match record.state {
            coland_storage::SidecarLifecycleState::Active => AgentSidecarState::Active,
            coland_storage::SidecarLifecycleState::Suspended => AgentSidecarState::Suspended,
            coland_storage::SidecarLifecycleState::Tombstoned => AgentSidecarState::Tombstoned,
        },
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

fn sidecar_access_readiness(
    pending: &[PendingSidecarAccessReconciliation],
    has_group: bool,
    controller_device_ready: bool,
    epoch_binding_stale: bool,
) -> AgentSidecarAccessReadiness {
    if epoch_binding_stale
        || pending.iter().any(|item| {
            matches!(
                item.provisioning_phase,
                arkret_models_collaboration::agent_sidecar::SidecarAccessProvisioningPhase::MlsRemove
                    | arkret_models_collaboration::agent_sidecar::SidecarAccessProvisioningPhase::EpochRotation
            )
        })
    {
        AgentSidecarAccessReadiness::EpochUpdateRequired
    } else if !has_group || !controller_device_ready || !pending.is_empty() {
        AgentSidecarAccessReadiness::KeyMaterialPending
    } else {
        AgentSidecarAccessReadiness::Ready
    }
}

#[cfg(test)]
/// Decode one signed MLS governance binding and apply its closed member rules:
/// the five shared members, plus `participant_authority_digest` and
/// `authority_stream_head` exactly for Sidecar scope, where the head holds
/// 1..=64 UTF-8 sorted unique refs (`encryption-and-audit.md` §2.5.1,
/// `sidecar.md` §6). Realm and Circle bindings carrying either Sidecar member
/// are rejected before any state comparison.
fn decode_mls_governance_binding(
    value: &Value,
) -> Result<MlsGovernanceBindingPayload, &'static str> {
    let binding = serde_json::from_value::<MlsGovernanceBindingPayload>(value.clone())
        .map_err(|_| "mls_governance_binding_invalid")?;
    binding
        .validate()
        .map_err(|_| "mls_governance_binding_invalid")?;
    Ok(binding)
}

#[cfg(test)]
fn device_coordinates_match(projected: Option<&str>, authenticated: &str) -> bool {
    !authenticated.is_empty()
        && projected.is_some_and(|projected| !projected.is_empty() && projected == authenticated)
}

async fn sidecar_view(
    state: &AppState,
    record: &AgentSidecarRecord,
    session: &SessionRecord,
) -> Result<AgentSidecarView, AppError> {
    let controller_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let controller_account = record.controller_account_id.clone();
    if controller_actor.as_account_id() != Some(&controller_account) {
        return Err(AppError::not_found("Sidecar not found"));
    }
    let sidecar_scope = arkret_wire::ScopeRef::Sidecar {
        realm_id: arkret_wire::RealmId::new(record.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored Sidecar Realm id: {error}")))?,
        sidecar_id: arkret_wire::SidecarId::new(record.sidecar_id.clone())
            .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?,
    };
    let controller_device =
        arkret_wire::DeviceId::new(session.require_human_device_id().clone())
            .map_err(|_| AppError::param_invalid("invalid authenticated controller device id"))?;
    let (cut, effective, epoch_row, controller_device_ready) = state
        .authority_commits()
        .sidecar_access_cut(
            sidecar_scope.realm_id(),
            sidecar_scope.sidecar_id().expect("native Sidecar id"),
            &controller_account,
            &controller_device,
        )
        .await
        .map_err(|error| AppError::internal(format!("Sidecar accepted access cut: {error}")))?
        .ok_or_else(|| AppError::not_found("Sidecar not found"))?;
    let desired_typed = cut.desired_agent_ids;
    let expected_binding = SidecarMlsBinding {
        sidecar_id: cut.sidecar_id,
        participant_authority_digest: cut.participant_authority_digest,
        authority_stream_head: cut.authority_stream_head,
    };
    let epoch_binding_current = match &epoch_row {
        Some(row) => {
            crate::routing::mls::current_mls_group_binding(state, row)
                .await?
                .sidecar_binding()
                .as_ref()
                == Some(&expected_binding)
        }
        None => false,
    };
    let pending = desired_typed
            .iter().filter(|agent| !effective.contains(agent))
            .cloned().map(|agent_id| {
                PendingSidecarAccessReconciliation {
                    agent_id,
                    provisioning_phase: if epoch_row.is_some() {
                        arkret_models_collaboration::agent_sidecar::SidecarAccessProvisioningPhase::EpochRotation
                    } else {
                        arkret_models_collaboration::agent_sidecar::SidecarAccessProvisioningPhase::MlsWelcome
                    },
                }
            })
            .collect::<Vec<_>>();
    let access_readiness = sidecar_access_readiness(
        &pending,
        epoch_row.is_some(),
        controller_device_ready,
        epoch_row.is_some() && !epoch_binding_current,
    );
    let mls_context = AgentSidecarMlsContext {
        participant_authority_digest: expected_binding.participant_authority_digest.clone(),
        authority_stream_head: expected_binding.authority_stream_head.clone(),
        mls_group_id: epoch_row
            .as_ref()
            .map(|row| row.effective_scope.canonical_mls_group_id())
            .transpose()
            .map_err(|error| AppError::internal(format!("stored MLS group id: {error}")))?
            .map(|id| id.to_string()),
        epoch: epoch_row.as_ref().map(|row| row.epoch),
        genesis_event_ref: epoch_row
            .as_ref()
            .map(|row| row.genesis_event_ref.to_string()),
        current_controller_device_ready: controller_device_ready,
    };
    let view = AgentSidecarView {
        sidecar: sidecar_from_record(record)?,
        desired_agent_ids: desired_typed,
        effective_agent_ids: effective,
        mls_context,
        access_readiness,
        pending_access_reconciliations: pending,
    };
    view.validate()
        .map_err(|error| AppError::internal(format!("Sidecar view invariant: {error}")))?;
    Ok(view)
}

fn sidecar_event_draft(
    event: &arkret_wire::Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<PreparedEventDraft, AppError> {
    let unsigned_bytes = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|error| AppError::internal(format!("Sidecar draft payload: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Sidecar draft canonicalize: {error}")))?;
    let event_digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::internal(format!("Sidecar draft digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Sidecar draft digest invalid: {error}")))?;
    Ok(PreparedEventDraft {
        unsigned_event_bytes: arkret_wire::Base64UrlString::new(
            URL_SAFE_NO_PAD.encode(unsigned_bytes),
        )
        .map_err(|error| AppError::internal(format!("Sidecar draft bytes invalid: {error}")))?,
        event_digest,
    })
}

fn author_typed_sidecar_event<K: arkret_event_draft::EventSpec>(
    scope_ref: arkret_wire::ScopeRef,
    actor_id: arkret_wire::ActorId,
    semantic_refs: Vec<arkret_wire::SemanticRef>,
    created_at: chrono::DateTime<chrono::Utc>,
    payload: K::Payload,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<arkret_wire::AuthoredEvent, AppError> {
    TypedEventDraft::<K>::new(scope_ref, actor_id, payload)
        .map(|draft| draft.with_semantic_refs(semantic_refs))
        .and_then(|draft| draft.author_with_digest_suite(created_at, digest_suite))
        .map_err(|error| AppError::internal(format!("Sidecar typed Event draft: {error}")))
}

fn sidecar_reservation_key(handle: &arkret_wire::ReservationHandle) -> String {
    format!("sidecar-reservation:{}", handle.as_str())
}

async fn store_sidecar_prepare(
    state: &AppState,
    principal_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    reservation_handle: &arkret_wire::ReservationHandle,
    expires_at: chrono::DateTime<chrono::Utc>,
    outcome: &SidecarEnsureOutcome,
) -> Result<(), AppError> {
    let principal_id = arkret_wire::DidCoreId::new(principal_id.to_owned())
        .map_err(|error| AppError::internal(format!("Sidecar principal id invalid: {error}")))?;
    let response_body = serde_json::to_value(outcome)
        .map_err(|error| AppError::internal(format!("Sidecar outcome encode: {error}")))?;
    let created_at = chrono::Utc::now();
    for key in [
        idempotency_key.to_owned(),
        sidecar_reservation_key(reservation_handle),
    ] {
        state
            .jobs()
            .store_idempotency_record(coland_services::jobs::IdempotencyState {
                authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    principal_id.clone(),
                    state.service_core_id(),
                )),
                operation_id: "ak.self.agent.sidecar.command.ensure".to_owned(),
                idempotency_key: key,
                request_hash: request_hash.to_owned(),
                response_status: StatusCode::OK.as_u16().into(),
                response_body: response_body.clone(),
                created_at,
                expires_at,
            })
            .await
            .map_err(|error| AppError::internal(format!("Sidecar reservation store: {error}")))?;
    }
    Ok(())
}

async fn store_sidecar_final_outcome(
    state: &AppState,
    principal_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    outcome: &SidecarEnsureOutcome,
) -> Result<(), AppError> {
    let created_at = chrono::Utc::now();
    let principal_id = arkret_wire::DidCoreId::new(principal_id.to_owned())
        .map_err(|error| AppError::internal(format!("Sidecar principal id invalid: {error}")))?;
    state
        .jobs()
        .store_idempotency_record(coland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                state.service_core_id(),
            )),
            operation_id: "ak.self.agent.sidecar.command.ensure".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            request_hash: request_hash.to_owned(),
            response_status: StatusCode::OK.as_u16().into(),
            response_body: serde_json::to_value(outcome)
                .map_err(|error| AppError::internal(format!("Sidecar outcome encode: {error}")))?,
            created_at,
            expires_at: created_at + chrono::Duration::hours(24),
        })
        .await
        .map_err(|error| AppError::internal(format!("Sidecar outcome store: {error}")))
}

fn next_sidecar_context_version(
    current: Option<&coland_storage::AgentSidecarContextRecord>,
) -> Result<(u64, Option<arkret_wire::EventId>), AppError> {
    match current {
        None => Ok((1, None)),
        Some(current) => {
            let version = u64::try_from(current.version)
                .ok()
                .filter(|version| *version > 0)
                .and_then(|version| version.checked_add(1))
                .filter(|version| i64::try_from(*version).is_ok())
                .ok_or_else(|| AppError::internal("Sidecar context version cannot advance"))?;
            let predecessor =
                arkret_wire::EventId::new(current.attach_event_ref.clone()).map_err(|error| {
                    AppError::internal(format!("Sidecar current attach ref: {error}"))
                })?;
            Ok((version, Some(predecessor)))
        }
    }
}

async fn prepare_sidecar(
    state: &AppState,
    session: &SessionRecord,
    body: arkret_models_collaboration::sidecar_operations::SidecarEnsurePrepareRequestBody,
) -> JsonResult<SidecarEnsureOutcome> {
    let principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?;
    let authenticated_controller_account_id =
        arkret_wire::AccountId::new(principal_id.clone(), state.service_core_id().clone());
    if body.controller_account_id != authenticated_controller_account_id {
        return Err(sidecar_create_denied(
            "Sidecar controller_account_id must match the authenticated session",
        ));
    }
    authorize_sidecar_ensure(state, session, body.source_realm_id.as_str()).await?;
    validate_sidecar_context(
        state,
        &body.source_realm_id,
        &body.context_ref,
        &arkret_wire::ActorId::account(authenticated_controller_account_id),
    )
    .await?;
    let request_hash = arkret_canonical::canonical_sha256(&body)
        .map_err(|error| AppError::internal(format!("Sidecar prepare digest: {error}")))?;
    if let Some(cached) = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id.clone(),
                state.service_core_id(),
            )),
            "ak.self.agent.sidecar.command.ensure",
            body.idempotency_key.as_str(),
        )
        .await
        .map_err(|error| AppError::internal(format!("Sidecar idempotency lookup: {error}")))?
    {
        if cached.request_hash != request_hash {
            return Err(AppError::conflict(
                "idempotency key was used for another Sidecar prepare",
            ));
        }
        let outcome = serde_json::from_value::<SidecarEnsureOutcome>(cached.response_body)
            .map_err(|error| AppError::internal(format!("stored Sidecar outcome: {error}")))?;
        return json_ok(outcome);
    }

    let _guard =
        lock_sidecar_ensure(body.source_realm_id.as_str(), &body.controller_account_id).await;
    let existing_current = state
        .authority_commits()
        .sidecar_context_prepare_current(
            &body.source_realm_id,
            &body.controller_account_id,
            &body.context_ref,
        )
        .await
        .map_err(|error| {
            crate::app_error!(
                TemporarilyUnavailable,
                "Sidecar prepare current cannot be confirmed: {error}"
            )
        })?;
    let controller_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let digest_suite = state
        .projections()
        .realm_digest_suite(body.source_realm_id.as_str());
    let created_at = chrono::Utc::now();
    let create_event = if existing_current.is_none() {
        Some(author_typed_sidecar_event::<
            arkret_wire::event_spec::SidecarCreate,
        >(
            arkret_wire::ScopeRef::Realm {
                realm_id: body.source_realm_id.clone(),
            },
            controller_actor.clone(),
            Vec::new(),
            created_at,
            SidecarCreatePayload::default(),
            digest_suite,
        )?)
    } else {
        None
    };
    let (genesis_ref, current_context) = match existing_current {
        Some(current) => current,
        None => (
            create_event
                .as_ref()
                .expect("new Sidecar Genesis")
                .event_id
                .clone(),
            None,
        ),
    };
    let sidecar_id = SidecarId::from_event_id(&genesis_ref);
    let (version, predecessor_event_ref) = next_sidecar_context_version(current_context.as_ref())?;
    let attach_event = author_typed_sidecar_event::<arkret_wire::event_spec::SidecarContextAttach>(
        arkret_wire::ScopeRef::Sidecar {
            realm_id: body.source_realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        },
        controller_actor,
        vec![arkret_wire::SemanticRef::new(
            genesis_ref.to_string(),
            "after",
        )],
        created_at,
        SidecarContextAttachPayload {
            sidecar_id: sidecar_id.clone(),
            source_context_ref: body.context_ref.clone(),
            version,
            predecessor_event_ref,
        },
        digest_suite,
    )?;
    let context_attach_event_draft = sidecar_event_draft(&attach_event, digest_suite)?;
    let reservation_handle = arkret_wire::ReservationHandle::new(ids::generate("reservation"))
        .map_err(AppError::internal)?;
    let expires_at = created_at + chrono::Duration::minutes(10);
    let prepared = if let Some(create_event) = create_event {
        SidecarEnsureOutcome::PreparedNew(SidecarEnsurePreparedNewOutcome {
            status: SidecarEnsurePreparedStatus::Prepared,
            branch: SidecarEnsureNewBranch::New,
            operation_id: body.operation_id.clone(),
            reservation_handle: reservation_handle.clone(),
            expires_at,
            create_event_draft: sidecar_event_draft(&create_event, digest_suite)?,
            context_attach_event_draft,
        })
    } else {
        SidecarEnsureOutcome::PreparedExisting(SidecarEnsurePreparedExistingOutcome {
            status: SidecarEnsurePreparedStatus::Prepared,
            branch: SidecarEnsureExistingBranch::Existing,
            operation_id: body.operation_id.clone(),
            reservation_handle: reservation_handle.clone(),
            expires_at,
            sidecar_id,
            context_attach_event_draft,
        })
    };
    let outcome = prepared;
    store_sidecar_prepare(
        state,
        session.actor.as_str(),
        body.idempotency_key.as_str(),
        &request_hash,
        &reservation_handle,
        expires_at,
        &outcome,
    )
    .await?;
    json_ok(outcome)
}

fn validate_signed_sidecar_draft(
    signed_event: &arkret_wire::Event,
    draft: &PreparedEventDraft,
) -> Result<(), AppError> {
    let actual_unsigned = arkret_canonical::canonical_json_bytes(
        &signed_event
            .digest_payload()
            .map_err(|error| AppError::param_invalid(format!("signed Sidecar Event: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("signed Sidecar Event: {error}")))?;
    let expected_unsigned = URL_SAFE_NO_PAD
        .decode(draft.unsigned_event_bytes.as_str())
        .map_err(|_| AppError::internal("stored Sidecar draft bytes are invalid"))?;
    let digest_suite = draft
        .event_digest
        .digest_suite()
        .map_err(|error| AppError::internal(format!("stored Sidecar digest suite: {error}")))?;
    let digest = Hash::new(
        signed_event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::param_invalid(format!("signed Sidecar Event: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("signed Sidecar Event digest: {error}")))?;
    if actual_unsigned != expected_unsigned
        || digest != draft.event_digest
        || signed_event.producer_proof.is_none()
        || signed_event
            .producer_proof
            .as_ref()
            .is_some_and(|proof| proof.event_digest != draft.event_digest)
    {
        return Err(AppError::param_invalid(
            "signed Sidecar Event does not exactly match its reservation draft",
        ));
    }
    Ok(())
}

async fn validate_sidecar_commit_reservation(
    state: &AppState,
    session: &SessionRecord,
    operation_id: &arkret_wire::ProtocolOperationId,
    reservation_handle: &arkret_wire::ReservationHandle,
    create_event: Option<&arkret_wire::Event>,
    context_attach_event: &arkret_wire::Event,
) -> Result<SidecarEnsureOutcome, AppError> {
    let principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?;
    let record = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id.clone(),
                state.service_core_id(),
            )),
            "ak.self.agent.sidecar.command.ensure",
            &sidecar_reservation_key(reservation_handle),
        )
        .await
        .map_err(|error| AppError::internal(format!("Sidecar reservation lookup: {error}")))?
        .ok_or_else(|| AppError::conflict("Sidecar reservation is missing or expired"))?;
    if record.expires_at <= chrono::Utc::now() {
        return Err(AppError::conflict("Sidecar reservation has expired"));
    }
    let outcome = serde_json::from_value::<SidecarEnsureOutcome>(record.response_body)
        .map_err(|error| AppError::internal(format!("stored Sidecar reservation: {error}")))?;
    if matches!(outcome, SidecarEnsureOutcome::Accepted(_)) {
        return Err(AppError::conflict(
            "Sidecar reservation is already finalized",
        ));
    }
    match &outcome {
        SidecarEnsureOutcome::PreparedNew(SidecarEnsurePreparedNewOutcome {
            operation_id: reserved_operation_id,
            reservation_handle: reserved_handle,
            create_event_draft,
            context_attach_event_draft,
            ..
        }) => {
            if reserved_operation_id != operation_id || reserved_handle != reservation_handle {
                return Err(AppError::param_invalid(
                    "Sidecar reservation binding mismatch",
                ));
            }
            let create_event = create_event.ok_or_else(|| {
                AppError::param_invalid("new Sidecar commit requires create_event")
            })?;
            validate_signed_sidecar_draft(create_event, create_event_draft)?;
            validate_signed_sidecar_draft(context_attach_event, context_attach_event_draft)?;
        }
        SidecarEnsureOutcome::PreparedExisting(SidecarEnsurePreparedExistingOutcome {
            operation_id: reserved_operation_id,
            reservation_handle: reserved_handle,
            context_attach_event_draft,
            ..
        }) => {
            if reserved_operation_id != operation_id || reserved_handle != reservation_handle {
                return Err(AppError::param_invalid(
                    "Sidecar reservation binding mismatch",
                ));
            }
            if create_event.is_some() {
                return Err(AppError::param_invalid(
                    "existing Sidecar attach must not carry create_event",
                ));
            }
            validate_signed_sidecar_draft(context_attach_event, context_attach_event_draft)?;
        }
        SidecarEnsureOutcome::Accepted(_) => unreachable!("accepted reservation rejected above"),
    }
    Ok(outcome)
}

fn sidecar_prepared_sidecar_id(prepared: &SidecarEnsureOutcome) -> Result<SidecarId, AppError> {
    match prepared {
        SidecarEnsureOutcome::PreparedNew(SidecarEnsurePreparedNewOutcome {
            create_event_draft,
            ..
        }) => create_event_draft
            .event_id()
            .map(|event_id| SidecarId::from_event_id(&event_id))
            .map_err(|error| AppError::internal(format!("stored Sidecar draft: {error}"))),
        SidecarEnsureOutcome::PreparedExisting(outcome) => Ok(outcome.sidecar_id.clone()),
        SidecarEnsureOutcome::Accepted(_) => {
            Err(AppError::internal("accepted Sidecar is not a preparation"))
        }
    }
}

async fn finalize_sidecar_projection_records(
    state: &AppState,
    session: &SessionRecord,
    prepared: &SidecarEnsureOutcome,
    context_attach_event: &arkret_wire::Event,
) -> Result<(), AppError> {
    let sidecar_id = sidecar_prepared_sidecar_id(prepared)?;
    let created_at = context_attach_event.created_at;
    state
        .agent_pairings()
        .ensure_sidecar(AgentSidecarRecord {
            sidecar_id: sidecar_id.to_string(),
            realm_id: context_attach_event.realm_id.to_string(),
            controller_account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
                    AppError::internal(format!("session actor invalid: {error}"))
                })?,
                state.service_core_id().clone(),
            ),
            state: coland_storage::SidecarLifecycleState::Active,
            state_changed_at: None,
            created_at,
            updated_at: None,
        })
        .await
        .map_err(|error| AppError::internal(format!("Sidecar projection persistence: {error}")))?;
    let payload = serde_json::from_value::<SidecarContextAttachPayload>(
        serde_json::to_value(&context_attach_event.payload)
            .map_err(|error| AppError::internal(format!("accepted Sidecar payload: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("accepted Sidecar context payload: {error}")))?;
    let normalized_context_ref = serde_json::to_value(&payload.source_context_ref)
        .map_err(|error| AppError::internal(format!("accepted Sidecar context ref: {error}")))?;
    let normalized_context_ref_digest = arkret_canonical::canonical_sha256(&normalized_context_ref)
        .map_err(|error| AppError::internal(format!("accepted Sidecar context digest: {error}")))?;
    state
        .agent_pairings()
        .ensure_sidecar_context(AgentSidecarContextRecord {
            sidecar_id: sidecar_id.to_string(),
            normalized_context_ref_digest,
            normalized_context_ref,
            version: i64::try_from(payload.version)
                .map_err(|_| AppError::internal("Sidecar context version exceeds i64"))?,
            predecessor_event_ref: payload.predecessor_event_ref.map(|id| id.to_string()),
            attach_event_ref: context_attach_event.event_id.to_string(),
            created_at,
        })
        .await
        .map(|_| ())
        .map_err(|error| AppError::internal(format!("Sidecar context persistence: {error}")))
}

async fn ensure_sidecar_impl(
    aa: AuthArgs,
    body: SidecarEnsureRequestBody,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SidecarEnsureOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?;
    match body {
        SidecarEnsureRequestBody::Prepare(body) => prepare_sidecar(state, &session, body).await,
        SidecarEnsureRequestBody::Commit(body) => {
            let request_hash = arkret_canonical::canonical_sha256(&body)
                .map_err(|error| AppError::internal(format!("Sidecar commit digest: {error}")))?;
            if let Some(cached) = state
                .jobs()
                .scoped_idempotency_record(
                    &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        principal_id.clone(),
                        state.service_core_id(),
                    )),
                    "ak.self.agent.sidecar.command.ensure",
                    body.idempotency_key.as_str(),
                )
                .await
                .map_err(|error| AppError::internal(format!("Sidecar commit replay: {error}")))?
            {
                if cached.request_hash != request_hash {
                    return Err(AppError::conflict(
                        "idempotency key was used for another Sidecar commit",
                    ));
                }
                return json_ok(
                    serde_json::from_value(cached.response_body).map_err(|error| {
                        AppError::internal(format!("stored Sidecar commit outcome: {error}"))
                    })?,
                );
            }
            let prepared = validate_sidecar_commit_reservation(
                state,
                &session,
                &body.operation_id,
                &body.reservation_handle,
                Some(&body.create_event),
                &body.context_attach_event,
            )
            .await?;
            authorize_sidecar_ensure(state, &session, body.create_event.realm_id.as_str()).await?;
            crate::routing::events::event_log::submit_sidecar_ensure_batch(
                state,
                &session,
                Some(body.create_event),
                body.context_attach_event.clone(),
            )
            .await
            .map_err(|error| {
                crate::routing::events::event_log::submit_one_error_to_app_error(
                    "Sidecar ensure",
                    error.status(),
                    error.code(),
                    &error.message(),
                )
            })?;
            finalize_sidecar_projection_records(
                state,
                &session,
                &prepared,
                &body.context_attach_event,
            )
            .await?;
            let sidecar_id = sidecar_prepared_sidecar_id(&prepared)?;
            let source_context_ref = body
                .context_attach_event
                .typed_payload::<arkret_wire::event_spec::SidecarContextAttach>()
                .map_err(|error| AppError::internal(format!("accepted Sidecar context: {error}")))?
                .source_context_ref;
            let outcome = SidecarEnsureOutcome::Accepted(SidecarEnsureAcceptedOutcome {
                status: SidecarEnsureAcceptedStatus::Accepted,
                operation_id: body.operation_id,
                accepted_phase: SidecarEnsureAcceptedPhase::Commit,
                sidecar_id: sidecar_id.clone(),
                source_context_ref,
                access_readiness: AgentSidecarAccessReadiness::KeyMaterialPending,
                pending_access_reconciliations: Vec::new(),
            });
            store_sidecar_final_outcome(
                state,
                session.actor.as_str(),
                body.idempotency_key.as_str(),
                &request_hash,
                &outcome,
            )
            .await?;
            json_ok(outcome)
        }
        SidecarEnsureRequestBody::Attach(body) => {
            let request_hash = arkret_canonical::canonical_sha256(&body)
                .map_err(|error| AppError::internal(format!("Sidecar attach digest: {error}")))?;
            if let Some(cached) = state
                .jobs()
                .scoped_idempotency_record(
                    &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        principal_id.clone(),
                        state.service_core_id(),
                    )),
                    "ak.self.agent.sidecar.command.ensure",
                    body.idempotency_key.as_str(),
                )
                .await
                .map_err(|error| AppError::internal(format!("Sidecar attach replay: {error}")))?
            {
                if cached.request_hash != request_hash {
                    return Err(AppError::conflict(
                        "idempotency key was used for another Sidecar attach",
                    ));
                }
                return json_ok(
                    serde_json::from_value(cached.response_body).map_err(|error| {
                        AppError::internal(format!("stored Sidecar attach outcome: {error}"))
                    })?,
                );
            }
            let prepared = validate_sidecar_commit_reservation(
                state,
                &session,
                &body.operation_id,
                &body.reservation_handle,
                None,
                &body.context_attach_event,
            )
            .await?;
            authorize_sidecar_ensure(state, &session, body.context_attach_event.realm_id.as_str())
                .await?;
            crate::routing::events::event_log::submit_sidecar_ensure_batch(
                state,
                &session,
                None,
                body.context_attach_event.clone(),
            )
            .await
            .map_err(|error| {
                crate::routing::events::event_log::submit_one_error_to_app_error(
                    "Sidecar ensure",
                    error.status(),
                    error.code(),
                    &error.message(),
                )
            })?;
            finalize_sidecar_projection_records(
                state,
                &session,
                &prepared,
                &body.context_attach_event,
            )
            .await?;
            let sidecar_id = sidecar_prepared_sidecar_id(&prepared)?;
            let source_context_ref = body
                .context_attach_event
                .typed_payload::<arkret_wire::event_spec::SidecarContextAttach>()
                .map_err(|error| AppError::internal(format!("accepted Sidecar context: {error}")))?
                .source_context_ref;
            let outcome = SidecarEnsureOutcome::Accepted(SidecarEnsureAcceptedOutcome {
                status: SidecarEnsureAcceptedStatus::Accepted,
                operation_id: body.operation_id,
                accepted_phase: SidecarEnsureAcceptedPhase::Attach,
                sidecar_id: sidecar_id.clone(),
                source_context_ref,
                access_readiness: AgentSidecarAccessReadiness::KeyMaterialPending,
                pending_access_reconciliations: Vec::new(),
            });
            store_sidecar_final_outcome(
                state,
                session.actor.as_str(),
                body.idempotency_key.as_str(),
                &request_hash,
                &outcome,
            )
            .await?;
            json_ok(outcome)
        }
    }
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.agent.sidecar.command.ensure",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.sidecar.command.ensure.v1"))]
pub(super) async fn ensure_sidecar(
    aa: AuthArgs,
    body: JsonBody<SidecarEnsureRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SidecarEnsureOutcome> {
    ensure_sidecar_impl(aa, body.into_inner(), depot, req).await
}

#[salvo::oapi::endpoint(tags("identity"))]
pub(super) async fn get_sidecar(
    aa: AuthArgs,
    sidecar_id: PathParam<SidecarId>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let controller_account_id = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(session.actor.clone())
            .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?,
        state.service_core_id().clone(),
    );
    let record = state
        .agent_pairings()
        .sidecar(sidecar_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Sidecar lookup failed: {error}")))?
        .filter(|record| record.controller_account_id == controller_account_id)
        .ok_or_else(|| AppError::not_found("Sidecar not found"))?;
    json_ok(sidecar_view(state, &record, &session).await?)
}

#[salvo::oapi::endpoint(tags("identity"))]
pub(super) async fn list_sidecars(
    aa: AuthArgs,
    realm_id: QueryParam<RealmId, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let controller_account_id = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(session.actor.clone())
            .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?,
        state.service_core_id().clone(),
    );
    let mut records = state
        .agent_pairings()
        .sidecars_for_controller(
            &controller_account_id,
            realm_id.as_ref().map(RealmId::as_str),
        )
        .await
        .map_err(|error| AppError::internal(format!("Sidecar list failed: {error}")))?;
    records.sort_by(|left, right| left.sidecar_id.cmp(&right.sidecar_id));
    if let Some(cursor) = cursor.as_ref() {
        records.retain(|record| record.sidecar_id.as_str() > cursor.as_str());
    }
    let has_more = records.len() > SIDECAR_LIST_PAGE_SIZE;
    records.truncate(SIDECAR_LIST_PAGE_SIZE);
    let next_cursor = has_more
        .then(|| records.last().map(|record| record.sidecar_id.clone()))
        .flatten()
        .map(NonEmptyString::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("Sidecar cursor: {error}")))?;
    let mut items = Vec::with_capacity(records.len());
    for record in records {
        items.push(sidecar_view(state, &record, &session).await?);
    }
    json_ok(AgentSidecarList {
        sidecars: items,
        next_cursor,
    })
}

#[cfg(test)]
#[path = "../../../../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod source_context_test_realm;

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Timelike as _};

    use super::*;

    #[tokio::test]
    async fn sidecar_source_strand_reads_durable_current_without_a_reducer_mirror() {
        let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let discussion = source_context_test_realm::open_human_discussion(
            &pool,
            "sidecar-source-durable-current",
        )
        .await;
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: Some(pool) },
        );
        state.test_projection().lock().strands.clear();
        let realm = discussion.head.authority_commit.event.realm_id;
        let controller = discussion.head.authority_commit.event.actor_id;
        let context = SidecarContextRef::Strand {
            strand_id: discussion.strand_id,
        };
        validate_sidecar_context(&state, &realm, &context, &controller)
            .await
            .unwrap();
        let foreign_station = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            controller.as_account_id().unwrap().principal_id.clone(),
            DidCoreId::new("ak:did_core:web:foreign-source-station.example").unwrap(),
        ));
        assert!(
            validate_sidecar_context(&state, &realm, &context, &foreign_station)
                .await
                .is_err()
        );
        let wrong_realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x9f; 32],
        ));
        assert!(
            validate_sidecar_context(&state, &wrong_realm, &context, &controller)
                .await
                .is_err()
        );
        assert!(state.projections().snapshot().strands.is_empty());
    }

    #[tokio::test]
    async fn existing_sidecar_prepare_uses_accepted_context_and_signed_successor_cas() {
        use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
        use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};
        use diesel_async::RunQueryDsl;
        let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let discussion = Box::pin(source_context_test_realm::open_human_discussion(
            &pool,
            "sidecar-repeat-context-cas",
        ))
        .await;
        let realm = discussion.realm_id();
        let actor = discussion.head.authority_commit.event.actor_id.clone();
        let controller = actor.as_account_id().unwrap().clone();
        let at =
            discussion.head.authority_commit.commit.committed_at + chrono::Duration::seconds(1);
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let context = SidecarContextRef::Strand {
            strand_id: discussion.strand_id.clone(),
        };
        assert!(
            store
                .sidecar_context_prepare_current(&realm, &controller, &context)
                .await
                .unwrap()
                .is_none()
        );
        let create = source_context_test_realm::next_request_for_actor(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::SidecarCreate,
            actor.clone(),
            json!({}),
            at,
        );
        Box::pin(uow.commit_event(create.clone())).await.unwrap();
        let genesis = create.authority_commit.event.event_id.clone();
        let sidecar = SidecarId::from_event_id(&genesis);
        let scope = arkret_wire::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        };
        let mut opening = source_context_test_realm::event_for_actor(
            arkret_wire::EventKind::SidecarContextAttach,
            scope.clone(),
            actor.clone(),
            serde_json::to_value(SidecarContextAttachPayload {
                sidecar_id: sidecar.clone(),
                source_context_ref: context.clone(),
                version: 1,
                predecessor_event_ref: None,
            })
            .unwrap(),
            at + chrono::Duration::seconds(1),
        );
        opening.semantic_refs = vec![arkret_wire::SemanticRef::new(genesis.to_string(), "after")];
        source_context_test_realm::reseal(&mut opening);
        let mut first = source_context_test_realm::request_for_event(
            &create.authority_commit,
            opening,
            at + chrono::Duration::seconds(1),
        );
        first.authority_commit.commit.stream_ref = arkret_wire::CommitStreamRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        };
        first.authority_commit.commit.stream_position = 0;
        first.authority_commit.commit.previous_commit_ref = None;
        let first = Box::pin(source_context_test_realm::source_request(&pool, first)).await;
        Box::pin(uow.commit_event(first.clone())).await.unwrap();
        let (accepted_genesis, current) = store
            .sidecar_context_prepare_current(&realm, &controller, &context)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted_genesis, genesis);
        let (version, predecessor) = next_sidecar_context_version(current.as_ref()).unwrap();
        assert_eq!(version, 2);
        assert_eq!(
            predecessor.as_ref(),
            Some(&first.authority_commit.event.event_id)
        );
        let draft_event =
            author_typed_sidecar_event::<arkret_wire::event_spec::SidecarContextAttach>(
                scope.clone(),
                actor.clone(),
                vec![arkret_wire::SemanticRef::new(genesis.to_string(), "after")],
                at + chrono::Duration::seconds(2),
                SidecarContextAttachPayload {
                    sidecar_id: sidecar.clone(),
                    source_context_ref: context.clone(),
                    version,
                    predecessor_event_ref: predecessor.clone(),
                },
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
        let draft =
            sidecar_event_draft(&draft_event, arkret_canonical::DigestSuite::Sha256).unwrap();
        assert!(validate_signed_sidecar_draft(&draft_event, &draft).is_err());
        // A new reservation freezes an attach-only successor, never Accepted.
        let prepared =
            SidecarEnsureOutcome::PreparedExisting(SidecarEnsurePreparedExistingOutcome {
                status: SidecarEnsurePreparedStatus::Prepared,
                branch: SidecarEnsureExistingBranch::Existing,
                operation_id: arkret_wire::ProtocolOperationId::new(
                    "ak:operation:sidecar.ensure.context-fixture",
                )
                .unwrap(),
                reservation_handle: arkret_wire::ReservationHandle::new(ids::generate(
                    "reservation",
                ))
                .unwrap(),
                expires_at: at + chrono::Duration::minutes(10),
                sidecar_id: sidecar.clone(),
                context_attach_event_draft: draft.clone(),
            });
        assert!(matches!(
            prepared,
            SidecarEnsureOutcome::PreparedExisting(_)
        ));
        let mut signed = draft_event.clone().into_event();
        signed.producer_proof = first.authority_commit.event.producer_proof.clone();
        source_context_test_realm::reseal(&mut signed);
        validate_signed_sidecar_draft(&signed, &draft).unwrap();
        for (version, predecessor) in [(3, predecessor.clone()), (2, Some(genesis.clone()))] {
            let mut changed = signed.clone();
            changed.payload = serde_json::from_value(json!({"sidecar_id": sidecar, "source_context_ref": context, "version": version, "predecessor_event_ref": predecessor})).unwrap();
            changed
                .refresh_content_bound_identity_with_digest_suite(
                    arkret_canonical::DigestSuite::Sha256,
                )
                .unwrap();
            assert!(validate_signed_sidecar_draft(&changed, &draft).is_err());
        }
        let mut second = source_context_test_realm::request_for_event(
            &first.authority_commit,
            signed,
            at + chrono::Duration::seconds(2),
        );
        second.authority_commit.commit.stream_ref =
            first.authority_commit.commit.stream_ref.clone();
        second.authority_commit.commit.stream_position = 1;
        second.authority_commit.commit.previous_commit_ref =
            Some(first.authority_commit.commit.commit_id.clone());
        let second = Box::pin(source_context_test_realm::source_request(&pool, second)).await;
        let mut stale = second.clone();
        stale.authority_commit.event.created_at += chrono::Duration::seconds(1);
        source_context_test_realm::reseal(&mut stale.authority_commit.event);
        stale = source_context_test_realm::request_for_event(
            &first.authority_commit,
            stale.authority_commit.event,
            at + chrono::Duration::seconds(3),
        );
        stale.authority_commit.commit.stream_ref = first.authority_commit.commit.stream_ref.clone();
        stale.authority_commit.commit.stream_position = 2;
        stale.authority_commit.commit.previous_commit_ref =
            Some(second.authority_commit.commit.commit_id.clone());
        let stale = Box::pin(source_context_test_realm::source_request(&pool, stale)).await;
        Box::pin(uow.commit_event(second.clone())).await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type=diesel::sql_types::BigInt)]
            count: i64,
        }
        let counts = "SELECT (SELECT count(*) FROM canonical_events)+(SELECT count(*) FROM realm_commits)+(SELECT count(*) FROM sidecar_context_current_results)+(SELECT count(*) FROM member_state_current_results)+(SELECT count(*) FROM strand_current_results)+(SELECT count(*) FROM circle_current_results)+(SELECT count(*) FROM mls_group_current_results)+(SELECT count(*) FROM mls_welcome_provenance) AS count";
        let mut conn = pool.get().await.unwrap();
        assert_eq!(diesel::sql_query("SELECT (SELECT count(*) FROM agent_sidecars)+(SELECT count(*) FROM agent_sidecar_contexts) AS count").get_result::<Count>(&mut conn).await.unwrap().count, 0);
        let before = diesel::sql_query(counts)
            .get_result::<Count>(&mut conn)
            .await
            .unwrap()
            .count;
        let stale_error = Box::pin(uow.commit_event(stale)).await.unwrap_err();
        assert!(
            stale_error.to_string().contains("cas_conflict"),
            "{stale_error}"
        );
        assert_eq!(
            diesel::sql_query(counts)
                .get_result::<Count>(&mut conn)
                .await
                .unwrap()
                .count,
            before
        );
        let mut wrong_previous = second.authority_commit.event.clone();
        wrong_previous.payload = serde_json::from_value(json!({"sidecar_id": sidecar, "source_context_ref": context, "version": 3, "predecessor_event_ref": genesis})).unwrap();
        wrong_previous.created_at += chrono::Duration::seconds(2);
        source_context_test_realm::reseal(&mut wrong_previous);
        let mut wrong_previous = source_context_test_realm::request_for_event(
            &second.authority_commit,
            wrong_previous,
            at + chrono::Duration::seconds(4),
        );
        wrong_previous.authority_commit.commit.stream_ref =
            first.authority_commit.commit.stream_ref.clone();
        wrong_previous.authority_commit.commit.stream_position = 2;
        wrong_previous.authority_commit.commit.previous_commit_ref =
            Some(second.authority_commit.commit.commit_id.clone());
        let wrong_previous = Box::pin(source_context_test_realm::source_request(
            &pool,
            wrong_previous,
        ))
        .await;
        let predecessor_error = Box::pin(uow.commit_event(wrong_previous))
            .await
            .unwrap_err();
        assert!(
            predecessor_error.to_string().contains("cas_conflict"),
            "{predecessor_error}"
        );
        assert_eq!(
            diesel::sql_query(counts)
                .get_result::<Count>(&mut conn)
                .await
                .unwrap()
                .count,
            before
        );
        assert_eq!(next_sidecar_context_version(None).unwrap(), (1, None));
        let mut different_commit = second.clone();
        different_commit.authority_commit.commit.committed_at += chrono::Duration::seconds(1);
        let replay_conflict = Box::pin(uow.commit_event(different_commit))
            .await
            .unwrap_err();
        assert!(
            replay_conflict.to_string().contains("duplicate_conflict"),
            "{replay_conflict}"
        );
        let mut different_envelope = second.clone();
        // Preserve the accepted ID while changing its content: this must never
        // become an exact retry merely because its version matches current.
        different_envelope.authority_commit.event.created_at += chrono::Duration::seconds(1);
        assert!(
            Box::pin(uow.commit_event(different_envelope))
                .await
                .is_err()
        );
        assert_eq!(
            diesel::sql_query(counts)
                .get_result::<Count>(&mut conn)
                .await
                .unwrap()
                .count,
            before
        );
        Box::pin(uow.commit_event(second)).await.unwrap();
        assert_eq!(
            diesel::sql_query(counts)
                .get_result::<Count>(&mut conn)
                .await
                .unwrap()
                .count,
            before
        );
        diesel::sql_query(
            "UPDATE sidecar_current_results SET value=jsonb_set(value,'{state}','\"tombstoned\"')",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        assert!(
            store
                .sidecar_context_prepare_current(&realm, &controller, &context)
                .await
                .is_err()
        );
        diesel::sql_query(
            "UPDATE sidecar_current_results SET value=jsonb_set(value,'{state}','\"active\"')",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        diesel::sql_query("UPDATE realm_commits SET event_pk=NULL WHERE commit_id IN (SELECT current_commit_id FROM sidecar_context_current_results)")
            .execute(&mut conn).await.unwrap();
        assert!(
            store
                .sidecar_context_prepare_current(&realm, &controller, &context)
                .await
                .is_err()
        );
        diesel::sql_query("UPDATE realm_commits c SET event_pk=e.pk FROM canonical_events e WHERE c.event_pk IS NULL AND e.envelope->>'event_id'=c.commit_json->>'event_ref'")
            .execute(&mut conn).await.unwrap();
        let (_, current) = store
            .sidecar_context_prepare_current(&realm, &controller, &context)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.unwrap().version, 2);
        let alias = arkret_wire::AccountId::new(
            controller.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:foreign-controller.example").unwrap(),
        );
        assert!(
            store
                .sidecar_context_prepare_current(&realm, &alias, &context)
                .await
                .is_err()
        );
        let mut overflow = coland_storage::AgentSidecarContextRecord {
            sidecar_id: sidecar.to_string(),
            normalized_context_ref_digest: String::new(),
            normalized_context_ref: json!({}),
            version: i64::MAX,
            predecessor_event_ref: None,
            attach_event_ref: genesis.to_string(),
            created_at: at,
        };
        assert!(next_sidecar_context_version(Some(&overflow)).is_err());
        overflow.version = 0;
        assert!(next_sidecar_context_version(Some(&overflow)).is_err());
    }

    #[test]
    fn prepared_create_event_is_content_bound_and_derives_sidecar_id() {
        let created_at = chrono::Utc
            .with_ymd_and_hms(2026, 7, 20, 12, 34, 56)
            .unwrap()
            .with_nanosecond(987_654_321)
            .unwrap();
        let realm_id =
            RealmId::new("ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b".to_owned())
                .unwrap();
        let event = author_typed_sidecar_event::<arkret_wire::event_spec::SidecarCreate>(
            arkret_wire::ScopeRef::Realm { realm_id },
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                crate::test_actor_id_str("did:web:example.com:users:alice"),
                crate::test_event::station_id(),
            )),
            Vec::new(),
            created_at,
            SidecarCreatePayload::default(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        event
            .verify_event_id_matches_content_with_digest_suite(
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
        let sidecar_id = SidecarId::from_event_id(&event.event_id);
        assert_eq!(
            sidecar_id.as_str().strip_prefix("ak:sidecar:"),
            event.event_id.as_str().strip_prefix("ak:event:")
        );
        // sidecar_create_payload is closed and empty; encryption is activated
        // by the Sidecar's own ak.mls.genesis (sidecar.md section 2).
        assert!(event.payload.is_empty());
    }

    #[test]
    fn context_attach_contains_only_the_native_source_mapping() {
        let payload = serde_json::to_value(SidecarContextAttachPayload {
            sidecar_id: SidecarId::new("ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo")
                .unwrap(),
            source_context_ref: SidecarContextRef::Strand {
                strand_id: arkret_identifiers::StrandId::new(
                    "ak:strand:ATxk9k3t-DqTNiiB9n8GoSjjar3vZJvO3Dtpd1SzdHZF",
                )
                .unwrap(),
            },
            version: 1,
            predecessor_event_ref: None,
        });
        let payload = payload.unwrap();
        assert_eq!(
            payload.pointer("/source_context_ref/kind"),
            Some(&json!("strand"))
        );
        assert!(payload.get("private_strand").is_none());
        assert!(payload.get("relation").is_none());
    }

    #[test]
    fn empty_agent_reconciliation_does_not_prove_controller_device_readiness() {
        assert_eq!(
            sidecar_access_readiness(&[], false, false, false),
            AgentSidecarAccessReadiness::KeyMaterialPending
        );
    }

    #[test]
    fn sidecar_membership_uses_exact_projected_actor_not_directory_principal() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let realm_id = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let local_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let foreign_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        let mut directory = coland_services::events::RealmDirectoryEntry::new(
            RealmId::new(realm_id).unwrap(),
            "discovery only",
            coland_services::events::DirectoryProvenance::LocalOnly,
        );
        directory.members.insert(principal.clone());
        state.realm_directory().upsert(directory);
        assert!(!realm_member_joined(
            &state,
            realm_id,
            &local_actor.to_string()
        ));
        let now = chrono::Utc::now();
        state.test_projection().lock().members.insert(
            (realm_id.to_owned(), local_actor.to_string()),
            coland_domain::reducer::ColandMembershipState {
                member: local_actor.to_string(),
                realm_id: realm_id.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
        assert!(realm_member_joined(
            &state,
            realm_id,
            &local_actor.to_string()
        ));
        assert!(!realm_member_joined(
            &state,
            realm_id,
            &foreign_actor.to_string()
        ));
        assert!(!realm_member_joined(&state, realm_id, principal.as_str()));
    }

    #[test]
    fn absent_device_coordinates_never_match() {
        assert!(!device_coordinates_match(None, ""));
        assert!(!device_coordinates_match(Some(""), ""));
        assert!(!device_coordinates_match(
            None,
            "ak:device:01904100-0000-7000-8000-a11ce0000001"
        ));
        assert!(device_coordinates_match(
            Some("ak:device:01904100-0000-7000-8000-a11ce0000001"),
            "ak:device:01904100-0000-7000-8000-a11ce0000001"
        ));
    }

    #[test]
    fn welcome_pending_takes_precedence_over_key_material() {
        let pending = PendingSidecarAccessReconciliation {
            agent_id: DidCoreId::new("ak:did_core:web:example.com:agents:assistant".to_owned())
                .unwrap(),
            provisioning_phase: SidecarAccessProvisioningPhase::MlsWelcome,
        };

        assert_eq!(
            sidecar_access_readiness(&[pending], true, true, false),
            AgentSidecarAccessReadiness::KeyMaterialPending
        );
    }

    #[test]
    fn stale_epoch_requires_update_before_ready() {
        assert_eq!(
            sidecar_access_readiness(&[], true, true, true),
            AgentSidecarAccessReadiness::EpochUpdateRequired
        );
    }

    #[test]
    fn pending_sidecar_removal_requires_epoch_update() {
        let pending = PendingSidecarAccessReconciliation {
            agent_id: DidCoreId::new("ak:did_core:web:example.com:agents:assistant".to_owned())
                .unwrap(),
            provisioning_phase: SidecarAccessProvisioningPhase::MlsRemove,
        };

        assert_eq!(
            sidecar_access_readiness(&[pending], true, true, false),
            AgentSidecarAccessReadiness::EpochUpdateRequired
        );
    }

    const BINDING_REALM_ID: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
    const BINDING_SIDECAR_ID: &str = "ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo";

    fn binding_event_ref(seed: u8) -> String {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32]).to_string()
    }

    fn sorted_event_refs(count: u8) -> Vec<String> {
        let mut refs = (1..=count).map(binding_event_ref).collect::<Vec<_>>();
        refs.sort();
        refs
    }

    fn sidecar_binding_value(authority_stream_head: Vec<String>) -> Value {
        json!({
            "effective_scope": {
                "kind": "sidecar",
                "realm_id": BINDING_REALM_ID,
                "sidecar_id": BINDING_SIDECAR_ID,
            },
            "base_group_state_ref": null,
            "previous_epoch": 0,
            "next_epoch": 0,
            "key_access_revision": 0,
            "participant_authority_digest": format!("sha256:{}", "4".repeat(64)),
            "authority_stream_head": authority_stream_head,
        })
    }

    #[test]
    fn sidecar_governance_binding_carries_the_seven_members() {
        let head = sorted_event_refs(2);
        let binding = decode_mls_governance_binding(&sidecar_binding_value(head.clone()))
            .expect("the seven-member Sidecar binding decodes");
        assert!(matches!(
            binding.effective_scope(),
            arkret_wire::ScopeRef::Sidecar { .. }
        ));
        let sidecar = binding.sidecar_binding().expect("Sidecar members");
        assert_eq!(sidecar.sidecar_id.as_str(), BINDING_SIDECAR_ID);
        assert_eq!(
            sidecar
                .authority_stream_head
                .iter()
                .map(|event_id| event_id.to_string())
                .collect::<Vec<_>>(),
            head
        );
    }

    #[test]
    fn governance_binding_rejects_sidecar_member_violations() {
        for member in ["participant_authority_digest", "authority_stream_head"] {
            let mut missing = sidecar_binding_value(sorted_event_refs(1));
            missing.as_object_mut().unwrap().remove(member);
            assert_eq!(
                decode_mls_governance_binding(&missing).unwrap_err(),
                "mls_governance_binding_invalid",
                "Sidecar binding without {member}"
            );
        }

        let mut realm = sidecar_binding_value(sorted_event_refs(1));
        realm["effective_scope"] = json!({"kind": "realm", "realm_id": BINDING_REALM_ID});
        assert_eq!(
            decode_mls_governance_binding(&realm).unwrap_err(),
            "mls_governance_binding_invalid",
            "a Realm binding must not carry Sidecar members"
        );

        let mut unsorted = sorted_event_refs(2);
        unsorted.reverse();
        let duplicate = vec![binding_event_ref(1), binding_event_ref(1)];
        for head in [unsorted, duplicate, Vec::new(), sorted_event_refs(65)] {
            assert_eq!(
                decode_mls_governance_binding(&sidecar_binding_value(head)).unwrap_err(),
                "mls_governance_binding_invalid"
            );
        }
        assert_eq!(
            arkret_models_collaboration::agent_sidecar::SIDECAR_AUTHORITY_STREAM_HEAD_MAX_ITEMS,
            64
        );
        decode_mls_governance_binding(&sidecar_binding_value(sorted_event_refs(64)))
            .expect("64 authority refs fit the decoder bound");
    }
}
