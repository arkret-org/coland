//! Account lifecycle state transitions, deactivation fanout and
//! erasure-execution / erasure-receipt helpers. Split out of `account.rs`
//! (SOL-07-002) as a cohesive unit; external paths preserved via
//! `pub(crate) use` re-export in the parent module. There is deliberately no
//! self-service deactivate route: operation-registry has no
//! `ak.self.account.*deactivate*` operation, and account-lifecycle.md §10
//! assigns deactivation initiation to the admin/support surface
//! (`/_coland/admin/accounts/{principal_id}/deactivate`).

use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
use arkret_models_collaboration::governance::erasure::{
    ErasedClass, ErasureOutcome, ErasureReceipt, ErasureReceiptPackage, ErasureReceiptProof,
    ErasureReceiptSubmitRequestBody, ErasureScope, ErasureStorageBoundary, ErasureSubject,
    ErasureSubjectKind,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer as _;

use super::*;

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub(crate) struct AccountLifecycleChange {
    pub principal_id: arkret_wire::DidCoreId,
    pub previous_state: String,
    pub state: String,
    pub changed_by: arkret_wire::DidCoreId,
    pub reason: Option<String>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub changed_at: chrono::DateTime<chrono::Utc>,
    pub sessions_revoked: usize,
    pub devices_revoked: usize,
    pub keypackages_retired: usize,
    pub push_routes_revoked: usize,
    pub to_device_messages_dropped: usize,
    pub identity_link_cache_invalidated: usize,
}

pub(crate) async fn set_account_lifecycle_state(
    state: &AppState,
    principal_id: &str,
    next_state: &str,
    changed_by: &str,
    reason: Option<String>,
) -> Result<AccountLifecycleChange, AppError> {
    let principal_id = arkret_wire::DidCoreId::new(principal_id.to_owned())
        .map_err(|_| AppError::param_invalid("invalid account identity core"))?;
    let changed_by = arkret_wire::DidCoreId::new(changed_by.to_owned())
        .map_err(|_| AppError::param_invalid("invalid state-change actor identity core"))?;
    let station_id = arkret_wire::DidCoreId::new(state.service_id().to_owned())
        .map_err(|_| AppError::internal("configured service identity is invalid"))?;
    let principal_id_value = principal_id.as_str();
    let changed_by_id_value = changed_by.as_str();
    let next_status = parse_account_lifecycle_target_state(next_state)?;
    let next_state = next_status.as_str();
    let account = state
        .identities()
        .account(&arkret_wire::AccountId::new(
            principal_id.clone(),
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(account) = account else {
        return Err(AppError::not_found("account not found"));
    };

    let previous_state = state.account_lifecycle_state(principal_id_value);
    if previous_state == "erasure_pending" {
        return Err(
            AppError::conflict("accounts pending erasure cannot transition state")
                .with_internal_reason(arkret_wire::ErrorCode::ACCOUNT_ERASED),
        );
    }
    if previous_state == "deactivated" && next_state == "active" {
        // This product-private admin surface has no Account Authority
        // recovery-completion record or replacement-device generation proof.
        // Protocol reactivation is admitted only by the signed account-status
        // replica path after those issuer-side gates have succeeded.
        return Err(AppError::conflict(
            "deactivated accounts cannot be reactivated through the local admin surface",
        )
        .with_internal_reason(arkret_wire::ErrorCode::ACCOUNT_DEACTIVATED));
    }

    let changed_at = now();
    let mut sessions_revoked = 0;
    let mut devices_revoked = 0;
    let mut keypackages_retired = 0;
    let mut push_routes_revoked = 0;
    let mut to_device_messages_dropped = 0;
    let mut identity_link_cache_invalidated = 0;
    if previous_state != next_state {
        let record = AccountLifecycleState {
            state: next_state.to_owned(),
            reason: reason.clone(),
            changed_by: Some(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                changed_by.clone(),
                station_id,
            ))),
            changed_at,
        };
        persist_account_lifecycle_record(state, account.pk, principal_id_value, &record).await?;
        if next_state == "deactivated" {
            let fanout = run_account_deactivation_fanout(state, principal_id_value).await?;
            sessions_revoked = fanout.sessions_revoked;
            devices_revoked = fanout.devices_revoked;
            keypackages_retired = fanout.keypackages_retired;
            push_routes_revoked = fanout.push_routes_revoked;
            to_device_messages_dropped = fanout.to_device_messages_dropped;
            identity_link_cache_invalidated = fanout.identity_link_cache_invalidated;
        } else if next_state == "locked" {
            sessions_revoked = revoke_sessions_for_actor(state, principal_id_value)
                .await
                .map_err(AppError::internal)?;
            devices_revoked = revoke_devices_for_actor(state, principal_id_value)
                .await
                .map_err(AppError::internal)?;
        }
        append_account_state_change_audit(
            state,
            principal_id_value,
            changed_by_id_value,
            &previous_state,
            next_state,
            reason.clone(),
            changed_at,
            sessions_revoked,
            devices_revoked,
            keypackages_retired,
            push_routes_revoked,
            to_device_messages_dropped,
            identity_link_cache_invalidated,
        )
        .await;
    }

    Ok(AccountLifecycleChange {
        principal_id,
        previous_state,
        state: next_state.to_owned(),
        changed_by,
        reason,
        changed_at,
        sessions_revoked,
        devices_revoked,
        keypackages_retired,
        push_routes_revoked,
        to_device_messages_dropped,
        identity_link_cache_invalidated,
    })
}

fn parse_account_lifecycle_target_state(next_state: &str) -> Result<AccountStatus, AppError> {
    let Some(status) = AccountStatus::from_wire(next_state) else {
        return Err(AppError::param_invalid(
            "state must be active, soft_logged_out, locked, suspended, or deactivated",
        ));
    };
    if matches!(status, AccountStatus::ErasurePending) {
        return Err(AppError::param_invalid(
            "erasure_pending must use the account erasure flow",
        ));
    }
    Ok(status)
}

#[derive(Default)]
struct AccountDeactivationFanout {
    sessions_revoked: usize,
    devices_revoked: usize,
    keypackages_retired: usize,
    push_routes_revoked: usize,
    to_device_messages_dropped: usize,
    identity_link_cache_invalidated: usize,
}

async fn run_account_deactivation_fanout(
    state: &AppState,
    principal_id: &str,
) -> Result<AccountDeactivationFanout, AppError> {
    let sessions_revoked = revoke_sessions_for_actor(state, principal_id)
        .await
        .map_err(AppError::internal)?;
    let devices_revoked = revoke_devices_for_actor(state, principal_id)
        .await
        .map_err(AppError::internal)?;
    let account_id = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal_id.to_owned())
            .map_err(|error| AppError::internal(error.to_string()))?,
        state.service_core_id().clone(),
    );
    state
        .persistence()
        .begin_public_push_account_deactivation(&account_id, now())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let (to_device_messages_dropped, push_routes_revoked) =
        purge_delivery_state_for_actor(state, principal_id).await?;
    let keypackages_retired = retire_owner_account_keypackages(state, account_id).await?;
    let identity_link_cache_invalidated = state
        .invalidate_cached_handle_claims_for_subject(principal_id)
        .await;
    // §7.1 Push-route completion criterion: when a push gateway independently
    // holds registration/delivery state, the local purge above does NOT
    // complete the Push-route row — the gateway must be notified over the
    // registered internal channel and report a processing result. A gateway
    // failure raises `deactivation_partial` (retried by the reconciliation
    // worker) instead of failing the deactivation.
    crate::deactivation_push_fanout::ensure_fanout(state, principal_id).await;
    Ok(AccountDeactivationFanout {
        sessions_revoked,
        devices_revoked,
        keypackages_retired,
        push_routes_revoked,
        to_device_messages_dropped,
        identity_link_cache_invalidated,
    })
}

async fn purge_delivery_state_for_actor(
    state: &AppState,
    principal_id: &str,
) -> Result<(usize, usize), AppError> {
    let devices = state
        .identities()
        .devices_for_actor(principal_id)
        .await
        .map_err(|error| AppError::internal(format!("device inventory lookup failed: {error}")))?;
    let mut to_device_messages_dropped = 0usize;
    let mut push_routes_revoked = 0usize;
    for device in devices {
        let purge = purge_device_delivery_state(state, principal_id, &device.device_id).await;
        to_device_messages_dropped += purge.to_device_messages_dropped;
        push_routes_revoked += purge.push_registrations_removed;
    }
    Ok((to_device_messages_dropped, push_routes_revoked))
}

async fn retire_owner_account_keypackages(
    state: &AppState,
    owner_account_id: arkret_wire::AccountId,
) -> Result<usize, AppError> {
    state
        .mls_key_packages()
        .retire_owner_account_keypackages(owner_account_id, now().timestamp())
        .await
        .map_err(|error| AppError::internal(format!("mls keypackage retirement failed: {error}")))
}

#[allow(clippy::too_many_arguments)]
async fn append_account_state_change_audit(
    state: &AppState,
    principal_id: &str,
    changed_by: &str,
    previous_state: &str,
    next_state: &str,
    reason: Option<String>,
    changed_at: chrono::DateTime<chrono::Utc>,
    sessions_revoked: usize,
    devices_revoked: usize,
    keypackages_retired: usize,
    push_routes_revoked: usize,
    to_device_messages_dropped: usize,
    identity_link_cache_invalidated: usize,
) {
    // Product-private audit actions must not occupy the protocol `ak.` prefix.
    let payload = json!({
        "schema": "org.arkret.coland.account.state_change.v1",
        "actor": changed_by,
        "subject": principal_id,
        "from": previous_state,
        "to": next_state,
        "changed_by": changed_by,
        "reason": reason,
        "timestamp": arkret_canonical::format_timestamp_canonical(changed_at),
        "sessions_revoked": sessions_revoked,
        "devices_revoked": devices_revoked,
        "keypackages_retired": keypackages_retired,
        "push_routes_revoked": push_routes_revoked,
        "to_device_messages_dropped": to_device_messages_dropped,
        "identity_link_cache_invalidated": identity_link_cache_invalidated,
        "fanout_domains": [
            "bearer_sessions",
            "device_records",
            "keypackages",
            "push_routes",
            "to_device_queue",
            "identity_link_cache"
        ],
    });
    append_audit_log(
        state,
        Some(principal_id),
        "org.arkret.coland.account.state_change",
        payload.clone(),
        "accepted",
    )
    .await;
    if changed_by != principal_id {
        append_audit_log(
            state,
            Some(changed_by),
            "org.arkret.coland.account.state_change",
            payload,
            "accepted",
        )
        .await;
    }
}

/// Persist operator evidence only when the durable propagation state machine
/// actually crosses the timeout or completion boundary. Target discovery by
/// itself is not an incomplete propagation and must never produce this audit.
pub(crate) async fn audit_account_status_propagation_transition(
    state: &AppState,
    transition: &coland_storage::AccountStatusPropagationProjectionTransition,
    deactivation: bool,
) {
    if !deactivation || (!transition.became_incomplete && !transition.became_complete) {
        return;
    }
    let projection = &transition.projection;
    for (transition_name, incomplete, outcome) in [
        (
            "incomplete",
            transition.became_incomplete,
            "pending_peer_ack",
        ),
        ("complete", transition.became_complete, "accepted"),
    ] {
        if !incomplete {
            continue;
        }
        append_audit_log(
            state,
            Some(projection.account_id.principal_id.as_str()),
            "org.arkret.coland.account.deactivation_propagation",
            json!({
                "schema": "org.arkret.coland.account.deactivation_propagation.v1",
                "account_authority_id": projection.account_authority_id,
                "account_id": projection.account_id,
                "account_status_record_id": projection.account_status_record_id,
                "status_seq": projection.status_seq,
                "propagation_state": transition_name,
                "pending_destination_count": projection.pending_destination_count,
                "deadline_at": projection.deadline_at,
                "updated_at": projection.updated_at,
                "deactivation_federation_incomplete": transition_name == "incomplete",
            }),
            outcome,
        )
        .await;
    }
}

pub(crate) fn deactivation_peer_service_targets_for_account(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
) -> Vec<Value> {
    let projection = state.projections().snapshot();
    let account_actor = arkret_wire::ActorId::account(account_id.clone()).to_string();
    let actor_realms = projection
        .members
        .values()
        .filter(|member| member.member == account_actor && member.state == "join")
        .map(|member| member.realm_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut targets: std::collections::BTreeMap<
        String,
        (
            std::collections::BTreeSet<String>,
            std::collections::BTreeSet<String>,
        ),
    > = std::collections::BTreeMap::new();
    for realm_id in actor_realms {
        for member in projection.members_of_realm(&realm_id) {
            if member.state != "join" {
                continue;
            }
            let Ok(member_id) = serde_json::from_str::<arkret_wire::ActorId>(&member.member) else {
                continue;
            };
            let service_id = member_id.route_service_id().as_str();
            if service_id == state.service_id() {
                continue;
            }
            let entry = targets.entry(service_id.to_owned()).or_default();
            entry.0.insert(realm_id.clone());
            if let Some(frontier) = member.membership_event_ref.as_deref() {
                entry.1.insert(frontier.to_owned());
            }
        }
    }
    targets
        .into_iter()
        .map(|(service_id, (realm_ids, membership_frontier))| {
            json!({
                "service_id": service_id,
                "realm_ids": realm_ids.into_iter().collect::<Vec<_>>(),
                "membership_frontier": membership_frontier.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// Merge the rebuildable Realm-membership view into the durable affected
/// service index and return the complete known target set. Later source-family
/// observers use the same store; an index row never expires merely because a
/// current Realm projection no longer exposes the historical relationship.
pub(crate) async fn durable_deactivation_peer_service_targets_for_account(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
) -> Result<Vec<Value>, AppError> {
    let projected = deactivation_peer_service_targets_for_account(state, account_id);
    let observed_at = now();
    let local_service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("local service id is invalid: {error}")))?;
    let mut observations = state
        .persistence()
        .discover_account_status_affected_services(account_id, &local_service_id, observed_at)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "affected-service source discovery unavailable: {error}"
            ))
        })?;
    observations.extend(
        projected
            .iter()
            .filter_map(|target| target.get("service_id").and_then(Value::as_str))
            .map(|service_id| {
                Ok(coland_storage::AccountStatusAffectedServiceObservation {
                    service_id: arkret_wire::DidCoreId::new(service_id.to_owned()).map_err(
                        |error| {
                            AppError::internal(format!("affected service id is invalid: {error}"))
                        },
                    )?,
                    source: coland_storage::AccountStatusAffectedServiceSource::RealmMembership,
                    observed_at,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?,
    );
    let durable = state
        .persistence()
        .merge_account_status_affected_services(account_id, &observations, 256)
        .await
        .map_err(|error| {
            AppError::internal(format!("affected-service index unavailable: {error}"))
        })?;
    let mut targets = projected
        .into_iter()
        .filter_map(|target| {
            let service_id = target
                .get("service_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)?;
            Some((service_id, target))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for service_id in durable {
        if service_id.as_str() == state.service_id() {
            continue;
        }
        targets.entry(service_id.to_string()).or_insert_with(|| {
            json!({
                "service_id": service_id,
                "realm_ids": [],
                "membership_frontier": [],
            })
        });
    }
    Ok(targets.into_values().collect())
}

fn deterministic_erasure_receipt_id(
    triggering_status_record_id: &arkret_wire::AccountStatusRecordId,
    storage_boundary: ErasureStorageBoundary,
) -> String {
    arkret_models_collaboration::governance::erasure::account_erasure_receipt_id(
        triggering_status_record_id,
        storage_boundary,
    )
}

/// Execute the physical side effects authorized by one already accepted
/// `erasure_pending` account-status record. The caller owns durable leasing and
/// exact replay; this function is intentionally transport-free and returns the
/// exact package to persist before receipt fanout.
pub(crate) async fn execute_account_status_erasure(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    triggering_status_record_id: &arkret_wire::AccountStatusRecordId,
) -> Result<ErasureReceiptPackage, AppError> {
    let actor = account_id.principal_id.as_str();
    let mut account = state
        .identities()
        .account(account_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("erasure account not found"))?;
    if account.account_id != *account_id {
        return Err(AppError::conflict("erasure account identity mismatch"));
    }
    let account_pk = account.pk;
    let previous_localpart = account.localpart.clone();
    account.display_name = Some("[user erased]".to_owned());
    account.bio = None;
    account.avatar_blob_ref = None;
    account.localpart = String::new();
    state
        .identities()
        .save_account(account)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    state
        .identities()
        .clear_localparts(account_pk)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if !previous_localpart.is_empty() {
        record_handle_release(state, &previous_localpart)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    // Fence new active handoffs before the fanout. The fanout is retryable
    // after a crash, but a registration admitted during it could otherwise
    // escape its terminal tombstone scan.
    let changed_at = now();
    persist_account_lifecycle_record(
        state,
        account_pk,
        actor,
        &AccountLifecycleState {
            state: "erasure_pending".to_owned(),
            reason: Some("account_status_erasure".to_owned()),
            changed_by: None,
            changed_at,
        },
    )
    .await?;
    let fanout = run_account_deactivation_fanout(state, actor).await?;
    // `consent-model.md` section 6.1.1.4 -- erasure MUST drop the holder's
    // whole seen-source ledger. Consent revoke and source list edits must not,
    // which is why this lives here and not in those paths.
    state
        .persistence()
        .invite_new_source_ledger_store()
        .delete_for_holder(account_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let memberships_removed = remove_realm_memberships_for_actor(state, actor);
    append_audit_log(
        state,
        Some(actor),
        "org.arkret.coland.audit.erasure_executed",
        json!({
            "account_id": account_id,
            "actor": actor,
            "triggering_status_record_id": triggering_status_record_id,
            "memberships_removed": memberships_removed,
            "sessions_revoked": fanout.sessions_revoked,
            "devices_revoked": fanout.devices_revoked,
        }),
        "accepted",
    )
    .await;
    append_audit_redaction_marker(state, actor).await;
    let completed_at = now();
    let package = build_erasure_receipt_package(
        state,
        deterministic_erasure_receipt_id(
            triggering_status_record_id,
            ErasureStorageBoundary::AccountPrivateStore,
        ),
        triggering_status_record_id,
        ErasureSubject {
            kind: ErasureSubjectKind::Principal,
            subject_ref: actor.to_owned(),
        },
        ErasureScope {
            storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
            realm_id: None,
            target_refs: vec![actor.to_owned()],
            retention_policy_id: None,
            service_scope: Some("account_status.erasure_execution".to_owned()),
        },
        vec![
            ErasedClass::AccountPrivateState,
            ErasedClass::PushRoutes,
            ErasedClass::DeviceSecrets,
            ErasedClass::ProjectionRows,
        ],
        completed_at,
    )?;
    package
        .validate_bindings()
        .map_err(|error| AppError::internal(format!("erasure package self-check: {error}")))?;
    Ok(package)
}

/// The deployment's independent receipt rail. Realm scope uses its durable
/// destinations; Account erasure without a Realm keeps the exact Actor tuple.
pub(crate) async fn fanout_erasure_receipt(
    state: &AppState,
    package: &ErasureReceiptPackage,
    account_id: Option<&arkret_wire::AccountId>,
) -> Result<(), AppError> {
    let peers = if let Some(realm) = &package.receipt.scope.realm_id {
        state
            .persistence()
            .historical_content_holders(std::slice::from_ref(realm))
            .await
    } else {
        let account = account_id.ok_or_else(|| {
            AppError::param_invalid("erasure scope lacks an exact Account or Realm")
        })?;
        state
            .persistence()
            .historical_content_holders_for_actor(&arkret_wire::ActorId::account(account.clone()))
            .await
    }
    .map_err(|error| AppError::internal(format!("historical erasure holders: {error}")))?;
    enqueue_erasure_receipt_to_targets(state, &peers, package).await
}

async fn enqueue_erasure_receipt_to_targets(
    state: &AppState,
    peers: &[arkret_wire::DidCoreId],
    package: &ErasureReceiptPackage,
) -> Result<(), AppError> {
    if package.receipt.issuer_id != state.service_core_id() {
        return Err(AppError::capability_denied(
            "erasure fanout belongs to another issuer",
        ));
    }
    package
        .validate_bindings()
        .map_err(|error| AppError::internal(format!("outbound erasure package: {error}")))?;
    let body = ErasureReceiptSubmitRequestBody {
        package: package.clone(),
    };
    let payload = arkret_canonical::canonical_json_string(&body)
        .map_err(|error| AppError::internal(error.to_string()))?;
    for peer in peers
        .iter()
        .filter(|peer| peer.as_str() != state.service_id())
    {
        crate::routing::federation::outbox::enqueue_outbound_with_lane(
            state,
            None,
            peer.as_str(),
            "/_arkret/peer/erasure-receipts",
            &format!(
                "ak:outbox:erasure-receipt:{}",
                body.package.receipt.receipt_id
            ),
            &payload,
            None,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    }
    Ok(())
}

/// Remove the erased actor from every in-memory Realm membership set.
/// Returns the count of realms touched so the audit row + response body
/// can report it. Durable Realm membership lives in the projection
/// rewrite worker; this is the v1 "memory ledger" cascade. Spec: A.3
/// + identity/account-lifecycle.md.
fn remove_realm_memberships_for_actor(state: &AppState, actor: &str) -> usize {
    let actor_id = match arkret_identifiers::DidCoreId::new(actor.to_owned()) {
        Ok(actor_id) => actor_id,
        Err(_) => return 0,
    };
    state.realm_directory().remove_member_from_all(&actor_id)
}

/// Append a single audit row that marks every prior entry for `actor` as
/// `redacted` while preserving timestamps + audit_ids. Spec: A.3.
async fn append_audit_redaction_marker(state: &AppState, actor: &str) {
    let prior = state
        .governance()
        .audit_entries_for_actor(actor)
        .await
        .unwrap_or_default();
    let entries: Vec<Value> = prior
        .iter()
        .map(|entry| {
            json!({
                "audit_id": entry.get("audit_id").cloned().unwrap_or(Value::Null),
                "created_at": entry.get("created_at").cloned().unwrap_or(Value::Null),
                "action": entry.get("action").cloned().unwrap_or(Value::Null),
                "redacted": true,
            })
        })
        .collect();
    append_audit_log(
        state,
        Some(actor),
        "org.arkret.coland.audit.actor_audit_redacted",
        json!({
            "actor": actor,
            "redacted_entry_count": entries.len(),
            "entries": entries,
        }),
        "accepted",
    )
    .await;
}

fn build_erasure_receipt_package(
    state: &AppState,
    receipt_id: String,
    triggering_status_record_id: &arkret_wire::AccountStatusRecordId,
    subject: ErasureSubject,
    scope: ErasureScope,
    erased_classes: Vec<ErasedClass>,
    completed_at: chrono::DateTime<chrono::Utc>,
) -> Result<ErasureReceiptPackage, AppError> {
    let issuer = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID is invalid: {error}")))?;
    let retained_stub = erasure_retained_stub(
        &receipt_id,
        triggering_status_record_id,
        &subject,
        &scope,
        completed_at,
    )?;
    // Canonical timestamp decoding normalizes the stub to millisecond precision.
    // Bind the receipt to that exact decoded timestamp so the inline-stub
    // self-check compares the same wire value instead of the pre-serialization
    // nanoseconds carried by `Utc::now()`.
    let completed_at = retained_stub.completed_at;
    let retained_stub_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&retained_stub)
            .map_err(|error| AppError::internal(format!("erasure retained stub: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("erasure retained stub digest: {error}")))?;
    let mut receipt = ErasureReceipt {
        receipt_id,
        trigger: ErasureTrigger::AccountStatusRecord {
            account_status_record_id: triggering_status_record_id.clone(),
        },
        schema: ErasureReceipt::SCHEMA.to_owned(),
        issuer_id: issuer,
        subject,
        scope,
        outcome: ErasureOutcome::Completed,
        erased_classes,
        retained_stub_digest,
        retained_stub: None,
        legal_hold_ref: None,
        completed_at,
        issued_at: Some(completed_at),
        proofs: Vec::new(),
        fanout_status: None,
        peer_receipts: Vec::new(),
    };
    let payload_digest = receipt
        .canonical_payload_digest()
        .map_err(|error| AppError::internal(format!("erasure receipt digest: {error}")))?;
    let proof_payload = receipt
        .canonical_proof_input()
        .map_err(|error| AppError::internal(format!("erasure receipt proof input: {error}")))?;
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_did())).map_err(
            |error| {
                AppError::internal(format!(
                    "erasure receipt verification method is invalid: {error}"
                ))
            },
        )?;
    let signature = erasure_receipt_proof_signature(state, &proof_payload, &verification_method)?;
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "scheme".to_owned(),
        Value::String("ed25519-detached-jws".to_owned()),
    );
    extra.insert(
        "signature_input".to_owned(),
        Value::String("rfc7515-detached-jws".to_owned()),
    );
    receipt.proofs.push(ErasureReceiptProof {
        verification_method,
        payload_digest,
        signature,
        extra,
    });
    receipt
        .validate_with_retained_stub(&retained_stub)
        .map_err(|error| AppError::internal(format!("erasure receipt self-check: {error}")))?;
    Ok(ErasureReceiptPackage {
        receipt,
        retained_stub,
    })
}

fn erasure_retained_stub(
    receipt_id: &str,
    triggering_status_record_id: &arkret_wire::AccountStatusRecordId,
    subject: &ErasureSubject,
    scope: &ErasureScope,
    completed_at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_models_collaboration::events_payloads::event_wire::VerificationStub, AppError> {
    serde_json::from_value(json!({
        "stub_schema": arkret_wire::SchemaId::ERASURE_VERIFICATION_STUB_V1,
        "receipt_id": receipt_id,
        "trigger": {
            "kind": "account_status_record",
            "account_status_record_id": triggering_status_record_id,
        },
        "subject": serde_json::to_value(subject)
            .map_err(|error| AppError::internal(format!("erasure stub subject: {error}")))?,
        "scope": serde_json::to_value(scope)
            .map_err(|error| AppError::internal(format!("erasure stub scope: {error}")))?,
        "completed_at": arkret_canonical::format_timestamp_canonical(completed_at),
    }))
    .map_err(|error| AppError::internal(format!("erasure retained stub encode: {error}")))
}

async fn persist_account_lifecycle_record(
    state: &AppState,
    account_pk: coland_storage::AccountPk,
    principal_id: &str,
    record: &AccountLifecycleState,
) -> Result<(), AppError> {
    if record.state == "active" {
        state
            .identities()
            .delete_account_lifecycle(account_pk, principal_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))
    } else {
        state
            .identities()
            .save_account_lifecycle(account_pk, principal_id, record.clone())
            .await
            .map_err(|error| AppError::internal(error.to_string()))
    }
}

fn erasure_receipt_proof_signature(
    state: &AppState,
    payload: &[u8],
    verification_method: &str,
) -> Result<String, AppError> {
    let protected = json!({
        "alg": "Ed25519",
        "kid": verification_method,
    });
    let protected = arkret_canonical::canonical_json_bytes(&protected)
        .map_err(|error| AppError::internal(format!("erasure proof header: {error}")))?;
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = state.notary_signing_key().sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{protected_b64}..{signature_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_target_accepts_soft_logged_out() {
        assert_eq!(
            parse_account_lifecycle_target_state("soft_logged_out").unwrap(),
            AccountStatus::SoftLoggedOut
        );
    }

    #[test]
    fn lifecycle_target_rejects_erasure_pending() {
        assert!(parse_account_lifecycle_target_state("erasure_pending").is_err());
    }

    #[test]
    fn lifecycle_target_rejects_unknown_state() {
        assert!(parse_account_lifecycle_target_state("pending_deletion").is_err());
    }
}
