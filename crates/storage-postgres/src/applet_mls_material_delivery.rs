//! Public MLS material selected from actual accepted history under native locks.

use arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody;
use arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody;
use coland_storage::{MlsMemberGroupStateMaterialRead, MlsMemberRosterSelectorRead};

use super::*;

fn require_subject(
    endpoint: &AppletManagedDeviceScopeGuard,
    caller: &ActorId,
    scope: &ScopeRef,
) -> PersistenceResult<()> {
    if caller != &endpoint.authority.actor_id.clone() || scope != &endpoint.effective_scope {
        return Err(refused("native MLS material has another caller or scope"));
    }
    Ok(())
}

pub(super) async fn group_state(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    expiry: chrono::DateTime<chrono::Utc>,
    request: &MlsMemberGroupStateMaterialReadRequestBody,
) -> PersistenceResult<ReadProof> {
    request.validate().map_err(PersistenceError::database)?;
    require_subject(endpoint, &request.caller_actor_id, &request.effective_scope)?;
    let selector = crate::mls_group_state_material_read::MemberMlsTargetSelector {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        group_state_event_id: Some(request.group_state_event_id.clone()),
        group_state_epoch: Some(request.epoch),
        caller_actor_id: request.caller_actor_id.clone(),
        target_commit_event_ref: request.target_commit_event_ref.clone(),
        target_epoch: request.target_epoch,
    };
    let MlsMemberGroupStateMaterialRead::Authorized {
        group_state_event: Some(published),
    } = crate::mls_group_state_material_read::read_in_connection(conn, &selector, station, None)
        .await?
    else {
        return Err(refused(
            "native MLS material has no actual member history cut",
        ));
    };
    let value =
        serde_json::to_value(&published.event.payload).map_err(PersistenceError::database)?;
    let (info_ref, tree_ref) = match published.event.kind {
        arkret_wire::EventKind::MlsGenesis => {
            let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                serde_json::from_value(value).map_err(PersistenceError::database)?;
            (payload.group_info_ref, payload.ratchet_tree_ref)
        }
        arkret_wire::EventKind::MlsCommit => {
            let payload: arkret_models_crypto::MlsCommitPayload =
                serde_json::from_value(value).map_err(PersistenceError::database)?;
            (
                payload.group_info_ref().clone(),
                payload.ratchet_tree_ref().clone(),
            )
        }
        _ => {
            return Err(refused(
                "native MLS material is not an accepted group state",
            ));
        }
    };
    if info_ref != request.group_info_ref
        || tree_ref != request.ratchet_tree_ref
        || published.event.scope_ref != endpoint.effective_scope
    {
        return Err(refused(
            "native MLS material differs from the accepted group state",
        ));
    }
    super::mls_scope_read_proof(conn, endpoint, expiry, None).await
}

pub(super) async fn roster(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    expiry: chrono::DateTime<chrono::Utc>,
    request: &MlsMemberRosterAuthorityReadRequestBody,
) -> PersistenceResult<ReadProof> {
    request.validate().map_err(PersistenceError::database)?;
    require_subject(endpoint, &request.caller_actor_id, &request.effective_scope)?;
    let selected =
        crate::mls_roster_authority_read::member_selector_in_connection(conn, request, station)
            .await?;
    if !matches!(selected, MlsMemberRosterSelectorRead::Authorized { governance_station_id, .. }
        if &governance_station_id == station)
    {
        return Err(refused(
            "native MLS roster has no actual local member history cut",
        ));
    }
    super::mls_scope_read_proof(conn, endpoint, expiry, None).await
}
