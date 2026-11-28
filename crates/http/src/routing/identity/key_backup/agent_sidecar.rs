//! Bind the private root operation to the actual issuer-qualified Agent endpoint.
use arkret_wire::ServiceOperationId;

use super::*;

pub(super) async fn writer(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
) -> Result<coland_storage::AccountContentDeliveryInput, AppError> {
    let agent = session
        .agent_session()
        .ok_or_else(|| AppError::capability_denied("Sidecar root requires a runtime session"))?;
    for scope in [
        "ak.message.create",
        ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
        ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1,
    ] {
        crate::routing::events::require_agent_session_scope(session, scope)?;
    }
    let account = &agent.metadata.account_id;
    if account.station_id != state.service_core_id()
        || account.principal_id.as_str() != session.actor
    {
        return Err(AppError::capability_denied(
            "Sidecar root requires the Agent's home Station",
        ));
    }
    let mut input = coland_storage::AccountContentDeliveryInput::default();
    crate::routing::events::sync::bind_agent_delivery_endpoint(
        state,
        session,
        &arkret_wire::ActorId::account(account.clone()),
        account,
        &mut input,
    )
    .await?;
    Ok(input)
}
