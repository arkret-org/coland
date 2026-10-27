//! Typed local issuer calls; this adapter performs no network request.
use arkret_models_collaboration::session_grants::{
    AuthenticationSessionTerminationInput, AuthenticationSessionTerminationReason,
    AuthenticationSessionTerminationResponseBody, SessionGrantValidationByJwt,
    SessionGrantValidationInput, SessionGrantValidationResponseBody,
};
use chrono::{DateTime, Utc};
use coland_contracts::account_authority::LocalAccountAuthority;
use coland_http::error::AppError;

use crate::state::AppState;

pub(crate) struct AccountAuthorityClient<'a> {
    state: &'a AppState,
    authority: &'a dyn LocalAccountAuthority,
}
impl<'a> AccountAuthorityClient<'a> {
    pub(crate) fn from_state(state: &'a AppState) -> Result<Self, AppError> {
        let authority = state.local_account_authority().ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "local Account Authority is unavailable".to_owned()
            )
        })?;
        Ok(Self { state, authority })
    }
    pub(crate) async fn introspect_logout_grant(
        &self,
        grant_jwt: &str,
    ) -> Result<SessionGrantValidationResponseBody, AppError> {
        self.authority
            .validate_session_grant(SessionGrantValidationInput::ByJwt(
                SessionGrantValidationByJwt {
                    grant_jwt: grant_jwt.to_owned(),
                    audience_id: Some(self.state.service_core_id()),
                    proof: None,
                },
            ))
            .await
            .map_err(|_| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    "issuer logout metadata unavailable".to_owned()
                )
            })
    }
    pub(crate) async fn logout_auth_session(
        &self,
        grant_jwt: &str,
        validated_at: DateTime<Utc>,
    ) -> Result<AuthenticationSessionTerminationResponseBody, AppError> {
        self.authority
            .terminate_authentication_session(AuthenticationSessionTerminationInput {
                grant_jwt: grant_jwt.to_owned(),
                logout_request_digest: None,
                validated_at: Some(validated_at),
                reason_code: Some(AuthenticationSessionTerminationReason::AccountLogout),
            })
            .await
            .map_err(|_| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    "issuer session termination unavailable".to_owned()
                )
            })
    }
}
