use arkret_models_collaboration::session_grants::{
    AuthSessionTerminationInput, AuthSessionTerminationOutcome, AuthSessionTerminationReason,
    SessionGrantValidationByJwt,
};
use chrono::{DateTime, Utc};
use coland_http::error::AppError;

use crate::state::AppState;
use crate::wire::{SessionGrantValidationInput, SessionGrantValidationOutcome};

/// Typed deployment-internal boundary from the Station to its Account Authority process.
///
/// Endpoint selection, S2S authentication, timeouts and
/// transport error mapping live here so product handlers cannot couple sibling
/// operations through URL string conventions.
pub(crate) struct AccountAuthorityClient<'a> {
    state: &'a AppState,
    introspection_url: &'a str,
    logout_url: &'a str,
    bearer: &'a str,
}

impl<'a> AccountAuthorityClient<'a> {
    pub(crate) fn from_state(state: &'a AppState) -> Result<Self, AppError> {
        let config = state.config();
        let introspection_url = config
            .session_grant_introspection_url
            .as_deref()
            .ok_or_else(|| {
                AppError::unsupported_feature(
                    "session grant introspection requires COLAND_SESSION_GRANT_INTROSPECTION_URL outside development mode",
                )
            })?;
        let logout_url = config.auth_session_logout_url.as_deref().ok_or_else(|| {
            AppError::unsupported_feature(
                "Auth-side session logout requires COLAND_AUTH_SESSION_LOGOUT_URL",
            )
        })?;
        let channel = config.internal_authority_channel.as_ref().ok_or_else(|| {
            AppError::unsupported_feature(
                "Account Authority S2S calls require a registered internal authority peer",
            )
        })?;
        Ok(Self {
            state,
            introspection_url,
            logout_url,
            bearer: channel.credential(),
        })
    }

    pub(crate) async fn introspect_logout_grant(
        &self,
        grant_jwt: &str,
    ) -> Result<SessionGrantValidationOutcome, AppError> {
        let audience = arkret_identifiers::DidCoreId::new(self.state.service_id().clone())
            .map_err(|error| {
                AppError::internal(format!(
                    "runtime principal service_id is not a core_id: {error}"
                ))
            })?;
        let request = SessionGrantValidationInput::ByJwt(SessionGrantValidationByJwt {
            grant_jwt: grant_jwt.to_owned(),
            audience_id: Some(audience),
            proof: None,
        });
        self.post_json(
            self.introspection_url,
            "session grant logout introspection",
            &request,
        )
        .await
    }

    pub(crate) async fn logout_auth_session(
        &self,
        grant_jwt: &str,
        validated_at: DateTime<Utc>,
    ) -> Result<AuthSessionTerminationOutcome, AppError> {
        let request = AuthSessionTerminationInput {
            grant_jwt: grant_jwt.to_owned(),
            logout_request_digest: None,
            validated_at: Some(validated_at),
            reason_code: Some(AuthSessionTerminationReason::AccountLogout),
        };
        self.post_json(self.logout_url, "Auth-side session logout", &request)
            .await
    }

    async fn post_json<Request, Response>(
        &self,
        endpoint: &str,
        operation: &str,
        request: &Request,
    ) -> Result<Response, AppError>
    where
        Request: serde::Serialize + ?Sized,
        Response: serde::de::DeserializeOwned,
    {
        let (endpoint, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
            endpoint,
            operation,
            self.state.config().development_mode,
            std::time::Duration::from_secs(10),
        )
        .map_err(AppError::capability_denied)?;
        let response = client
            .post(endpoint)
            .bearer_auth(self.bearer)
            .json(request)
            .send()
            .await
            .map_err(|error| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    format!("{operation} request failed: {error}"),
                )
            })?;
        if !response.status().is_success() {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                format!(
                    "{operation} was rejected by the Account Authority process: {}",
                    response.status()
                ),
            ));
        }
        response.json::<Response>().await.map_err(|error| {
            crate::app_error!(
                TemporarilyUnavailable,
                format!("invalid {operation} response: {error}"),
            )
        })
    }
}
