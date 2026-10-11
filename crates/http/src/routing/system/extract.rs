//! Authentication extraction shared by protected HTTP handlers.

use coland_http::error::AppError;
use coland_services::identity::SessionIdentityState as SessionRecord;
use salvo::extract::{Extractible, Metadata};
use salvo::http::ParseError;
use salvo::prelude::{Depot, Request};

use super::auth::authenticated_session as authenticated_session_inner;
use crate::state::AppState;

/// Authentication marker that exposes the shared session validation path.
#[derive(Clone, Debug, Default)]
pub struct AuthArgs;

impl<'ex> Extractible<'ex> for AuthArgs {
    fn metadata() -> &'static Metadata {
        static METADATA: Metadata = Metadata::new("");
        &METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(_req: &'ex mut Request, _depot: &'ex mut Depot) -> Result<Self, ParseError> {
        Ok(Self)
    }
}

/// Document the shared bearer-session requirement on every `#[endpoint]` that
/// takes an [`AuthArgs`]. The extractor pulls the credential from the
/// `Authorization` header (validated in [`AuthArgs::authenticated_session`]),
/// so it contributes a security requirement rather than a request parameter or
/// body.
impl salvo::oapi::EndpointArgRegister for AuthArgs {
    fn register(
        components: &mut salvo::oapi::Components,
        operation: &mut salvo::oapi::Operation,
        _arg: &str,
    ) {
        use salvo::oapi::security::{Http, HttpAuthScheme, SecurityRequirement, SecurityScheme};
        components.security_schemes.insert(
            "bearer_session".to_owned(),
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer).bearer_format("JWT")),
        );
        operation.securities.push(SecurityRequirement::new(
            "bearer_session",
            Vec::<String>::new(),
        ));
    }
}

impl AuthArgs {
    /// Validate the bearer session against `state` and return the matched
    /// session record.
    pub async fn authenticated_session(
        &self,
        state: &AppState,
        req: &Request,
    ) -> Result<SessionRecord, AppError> {
        match authenticated_session_inner(state, req).await {
            Ok(session) => Ok(session),
            Err((_status, code, message)) => {
                let typed = coland_http::error::ErrorCode::from_wire(code);
                let mut error = AppError::from_rejection(
                    typed.unwrap_or(coland_http::error::ErrorCode::Unauthenticated),
                    message,
                );
                if typed.is_none() {
                    error = error.with_rejection_code(code);
                }
                Err(error)
            }
        }
    }
}
