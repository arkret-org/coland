//! Own-Human PCR archive reads on the existing committed-Event surfaces.

use arkret_wire::{CommittedEventView, EventId, StreamScanRequestBody, StreamScanResponseBody};
use coland_http::error::AppError;
use coland_http::result::GuardedJsonResult;
use coland_services::identity::SessionIdentityState;
use coland_storage::{HumanPcrHistoryRead, HumanPcrHistoryReader};

use crate::state::AppState;

fn unavailable() -> AppError {
    AppError::not_found("committed PCR history is unavailable")
}

async fn reader(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<Option<HumanPcrHistoryReader>, AppError> {
    let Some(device) = session.human_device_id() else {
        return Ok(None);
    };
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let account_id = actor.as_account_id().cloned().ok_or_else(unavailable)?;
    Ok(Some(HumanPcrHistoryReader {
        account_id,
        device_id: arkret_wire::DeviceId::new(device.clone()).map_err(|_| unavailable())?,
        credential_device_binding: session
            .session_grant
            .as_ref()
            .and_then(|grant| grant.device_binding.clone()),
        credential_expires_at: session.expires_at,
        account_status_observation: None,
    }))
}

async fn resolve_current_status(
    state: &AppState,
    session: &SessionIdentityState,
    reader: &mut HumanPcrHistoryReader,
) -> Result<(), AppError> {
    if !session.session_grant.as_ref().is_some_and(|grant| {
        grant.credential_class == arkret_models_identity::SessionGrantCredentialClass::Standard
            && matches!(&grant.holder_binding,
                arkret_models_identity::session_credential::SessionGrantHolderBinding::HumanDevice { device_binding }
                if device_binding.as_str() == reader.device_id.as_str())
            && grant.account_id == reader.account_id
            && grant.device_binding.is_some()
    }) {
        return Err(unavailable());
    }
    reader.account_status_observation =
        Some(super::peer::refresh_current_account_status(state, &reader.account_id).await?);
    Ok(())
}

pub(crate) async fn current_reader(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<HumanPcrHistoryReader, AppError> {
    let mut reader = reader(state, session).await?.ok_or_else(unavailable)?;
    resolve_current_status(state, session, &mut reader).await?;
    Ok(reader)
}

pub(crate) async fn mls_material(
    state: &AppState,
    session: &SessionIdentityState,
    request: &arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody,
) -> Option<
    GuardedJsonResult<
        arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialResponseBody,
    >,
> {
    use coland_storage::MlsMemberGroupStateMaterialRead as Material;
    let mut reader = match reader(state, session).await {
        Ok(Some(reader)) => reader,
        Ok(None) => return None,
        Err(error) => return Some(Err(error)),
    };
    let peer = request.as_peer_request();
    let mut result = state
        .authority_commits()
        .read_human_pcr_group_state_material(&reader, &peer, &state.service_core_id())
        .await;
    let matched = matches!(result, Ok(HumanPcrHistoryRead::CurrentStatusRequired));
    if matched {
        if let Err(error) = resolve_current_status(state, session, &mut reader).await {
            return Some(Err(error));
        }
        result = state
            .authority_commits()
            .read_human_pcr_group_state_material(&reader, &peer, &state.service_core_id())
            .await;
    }
    match result {
        Ok(HumanPcrHistoryRead::NotApplicable) if !matched => None,
        Ok(HumanPcrHistoryRead::Ready {
            value:
                Material::Authorized {
                    group_state_event: Some(original),
                },
            guard,
        }) => {
            let response =
                crate::routing::mls::serve_group_state_material(state, &peer, &original.event)
                    .await;
            Some(match response {
                Ok(response) => coland_http::result::guarded_json_ok(response, Some(guard)),
                Err(error) => {
                    let _ = guard.finish().await;
                    Err(error)
                }
            })
        }
        Ok(HumanPcrHistoryRead::Ready { value, guard }) => {
            let _ = guard.finish().await;
            Some(Err(match value {
                Material::RevisionUnavailable | Material::Authorized { .. } => {
                    crate::routing::mls::mls_group_state_material_revision_unavailable()
                }
                Material::NotFound => crate::routing::mls::mls_group_state_material_not_found(),
            }))
        }
        Ok(HumanPcrHistoryRead::NotApplicable | HumanPcrHistoryRead::CurrentStatusRequired)
        | Err(_) => Some(Err(unavailable())),
    }
}

pub(crate) async fn page(
    state: &AppState,
    session: &SessionIdentityState,
    request: &StreamScanRequestBody,
) -> Option<GuardedJsonResult<StreamScanResponseBody>> {
    let mut reader = match reader(state, session).await {
        Ok(Some(reader)) => reader,
        Ok(None) => return None,
        Err(error) => return Some(Err(error)),
    };
    let mut result = state
        .authority_commits()
        .read_human_pcr_history_page(&reader, request, &state.service_core_id())
        .await;
    let pcr_matched = matches!(result, Ok(HumanPcrHistoryRead::CurrentStatusRequired));
    if pcr_matched {
        if let Err(error) = resolve_current_status(state, session, &mut reader).await {
            return Some(Err(error));
        }
        result = state
            .authority_commits()
            .read_human_pcr_history_page(&reader, request, &state.service_core_id())
            .await;
    }
    match result {
        Ok(HumanPcrHistoryRead::NotApplicable) if !pcr_matched => None,
        Ok(HumanPcrHistoryRead::Ready { value, guard }) => {
            Some(coland_http::result::guarded_json_ok(value, Some(guard)))
        }
        Ok(HumanPcrHistoryRead::NotApplicable | HumanPcrHistoryRead::CurrentStatusRequired)
        | Err(_) => Some(Err(unavailable())),
    }
}

pub(crate) async fn event(
    state: &AppState,
    session: &SessionIdentityState,
    event_id: &EventId,
) -> Option<GuardedJsonResult<CommittedEventView>> {
    let mut reader = match reader(state, session).await {
        Ok(Some(reader)) => reader,
        Ok(None) => return None,
        Err(error) => return Some(Err(error)),
    };
    let mut result = state
        .authority_commits()
        .read_human_pcr_history_event(&reader, event_id, &state.service_core_id())
        .await;
    let pcr_matched = matches!(result, Ok(HumanPcrHistoryRead::CurrentStatusRequired));
    if pcr_matched {
        if let Err(error) = resolve_current_status(state, session, &mut reader).await {
            return Some(Err(error));
        }
        result = state
            .authority_commits()
            .read_human_pcr_history_event(&reader, event_id, &state.service_core_id())
            .await;
    }
    match result {
        Ok(HumanPcrHistoryRead::NotApplicable) if !pcr_matched => None,
        Ok(HumanPcrHistoryRead::Ready { value, guard }) => {
            Some(coland_http::result::guarded_json_ok(value, Some(guard)))
        }
        Ok(HumanPcrHistoryRead::NotApplicable | HumanPcrHistoryRead::CurrentStatusRequired)
        | Err(_) => Some(Err(unavailable())),
    }
}
