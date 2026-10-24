//! Complete Actor identities derived from authenticated Station credentials.

use arkret_models_identity::session_credential::{
    SessionGrantCredentialClass, SessionGrantHolderBinding,
};
use arkret_wire::{AccountId, ActorId, DidCoreId};
use coland_http::error::AppError;
use coland_services::identity::SessionIdentityState;

use crate::state::AppState;

/// Pure projection for read models receiving an already authenticated session.
/// The HTTP boundary verifies its local account row separately below.
pub(crate) fn session_actor_from_credential(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<ActorId, AppError> {
    let principal = DidCoreId::new(session.actor.clone())
        .map_err(|_| AppError::unauthenticated("session principal is invalid"))?;
    let station = DidCoreId::new(session.audience.clone())
        .map_err(|_| AppError::unauthenticated("session Station is invalid"))?;
    if station != state.service_core_id() {
        return Err(AppError::unauthenticated(
            "session audience does not match this Station",
        ));
    }
    if let Some(grant) = session.session_grant.as_ref()
        && (grant.account_id.principal_id != principal || grant.account_id.station_id != station)
    {
        return Err(AppError::unauthenticated(
            "session must retain the signed grant's exact AccountId",
        ));
    }
    match session
        .session_grant
        .as_ref()
        .map(|grant| &grant.holder_binding)
    {
        Some(SessionGrantHolderBinding::AgentRuntime { agent_id, .. }) => {
            if agent_id != &principal || session.agent_session().is_none() {
                return Err(AppError::unauthenticated(
                    "AgentRuntime holder does not match the session",
                ));
            }
        }
        Some(_) if session.agent_session().is_some() => {
            return Err(AppError::unauthenticated(
                "human credential cannot carry an Agent session",
            ));
        }
        Some(_) | None => {}
    };
    Ok(ActorId::account(AccountId::new(principal, station)))
}

/// Credential classification is independent of the shared AccountId shape.
/// Callers have already authenticated the grant or stored Agent session.
fn has_agent_credential(session: &SessionIdentityState) -> bool {
    session.agent_session().is_some()
        || session.session_grant.as_ref().is_some_and(|grant| {
            matches!(
                grant.holder_binding,
                SessionGrantHolderBinding::AgentRuntime { .. }
            )
        })
}

/// Verify the exact stored Account binding without a principal-only lookup.
pub(crate) async fn validated_session_actor(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<ActorId, AppError> {
    let actor = session_actor_from_credential(state, session)?;
    // Agent provisioning and runtime grants are validated by the authentication
    // boundary; they do not imply a human account-directory row.
    if has_agent_credential(session) {
        return Ok(actor);
    }
    let Some(account_id) = actor.as_account_id() else {
        return Ok(actor);
    };
    let Some(account_pk) = session.account_pk else {
        // Recovery pre-proof credentials identify an Account but grant no
        // account-data access. The recovery operation allowlist remains in force.
        if session.session_grant.as_ref().is_some_and(|grant| {
            grant.credential_class == SessionGrantCredentialClass::RecoverySession
        }) {
            return Ok(actor);
        }
        return Err(AppError::unauthenticated(
            "session account binding is missing",
        ));
    };
    let account = state
        .identities()
        .account_by_id(account_pk)
        .await
        .map_err(|error| AppError::internal(format!("session account lookup failed: {error}")))?
        .ok_or_else(|| AppError::unauthenticated("session account no longer exists"))?;
    if account.pk != account_pk
        || &account.account_id != account_id
        || account.principal_id != account_id.principal_id
    {
        return Err(AppError::unauthenticated(
            "session does not bind the exact stored Account",
        ));
    }
    Ok(actor)
}

/// Resolve an introspected credential's already verified AccountId to its local
/// row, then apply the same binding check as a persisted bearer session.
pub(crate) async fn bind_authenticated_session_account(
    state: &AppState,
    session: &mut SessionIdentityState,
) -> Result<(), AppError> {
    let actor = session_actor_from_credential(state, session)?;
    if session.account_pk.is_none()
        && session.session_grant.is_some()
        && !has_agent_credential(session)
        && let Some(account_id) = actor.as_account_id()
    {
        session.account_pk = state
            .identities()
            .account(account_id)
            .await
            .map_err(|error| AppError::internal(format!("session account lookup failed: {error}")))?
            .map(|account| account.pk);
    }
    validated_session_actor(state, session).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        )
    }

    fn session(state: &AppState) -> SessionIdentityState {
        SessionIdentityState {
            token_hash: "test".into(),
            account_pk: None,
            actor: "ak:did_core:web:alice.example".into(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "device".into(),
            },
            audience: state.service_id().clone(),
            session_public_key: None,
            session_grant: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn same_principal_credential_at_another_station_is_rejected() {
        let state = state();
        let mut session = session(&state);
        session.audience = "ak:did_core:web:other-station.example".into();
        assert!(session_actor_from_credential(&state, &session).is_err());
    }

    #[tokio::test]
    async fn human_bearer_without_an_account_binding_is_rejected() {
        let state = state();
        assert!(
            validated_session_actor(&state, &session(&state))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn verified_agent_session_uses_account_identity_without_a_human_account_row() {
        let state = state();
        let mut session = session(&state);
        session.endpoint = coland_services::identity::SessionEndpointState::AgentRuntime {
            state: coland_services::identity::AgentSessionState {
                granted_scope: vec![],
                scope_details: serde_json::json!({}),
                freshness_state: arkret_wire::FreshnessState::Fresh,
            },
        };
        let actor = session_actor_from_credential(&state, &session).unwrap();
        assert_eq!(
            actor,
            ActorId::account(AccountId::new(
                DidCoreId::new(session.actor.clone()).unwrap(),
                state.service_core_id(),
            ))
        );
        assert_eq!(
            validated_session_actor(&state, &session).await.unwrap(),
            actor
        );
    }

    #[tokio::test]
    async fn account_pk_cannot_substitute_the_same_principal_at_another_station() {
        let state = state();
        let mut session = session(&state);
        let local_account = session_actor_from_credential(&state, &session)
            .unwrap()
            .as_account_id()
            .unwrap()
            .clone();
        let other_station_account = AccountId::new(
            local_account.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        );
        for (label, account_id) in [
            ("local", local_account.clone()),
            ("other-station", other_station_account.clone()),
        ] {
            state
                .identities()
                .save_account(coland_services::identity::AccountProfileState {
                    // The store assigns the primary key.
                    pk: coland_storage::AccountPk(0),
                    principal_id: account_id.principal_id.clone(),
                    account_id,
                    localpart: format!("account-{label}"),
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
            .account(&local_account)
            .await
            .expect("local account lookup")
            .expect("local account was just saved")
            .pk;
        let other_station_pk = state
            .identities()
            .account(&other_station_account)
            .await
            .expect("other-station account lookup")
            .expect("other-station account was just saved")
            .pk;
        session.account_pk = Some(local_pk);
        assert_eq!(
            validated_session_actor(&state, &session).await.unwrap(),
            ActorId::account(local_account)
        );
        session.account_pk = Some(other_station_pk);
        assert!(validated_session_actor(&state, &session).await.is_err());
    }
}
