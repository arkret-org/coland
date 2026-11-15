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

/// Document the shared DPoP SessionGrant requirement on every `#[endpoint]` that
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
        use salvo::oapi::security::{ApiKey, ApiKeyValue, SecurityRequirement, SecurityScheme};
        components.security_schemes.insert(
            "DpopProof".to_owned(),
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("DPoP"))).into(),
        );
        operation.securities.get_or_insert_with(Vec::new).push(
            SecurityRequirement::new("SessionGrantAuth", Vec::<String>::new())
                .add("DpopProof", Vec::<String>::new()),
        );
    }
}

/// Salvo's closed HTTP scheme enum cannot represent DPoP. Complete the
/// registered scheme in the serialized document without a Bearer placeholder.
pub(crate) fn install_session_grant_security_scheme(document: &mut serde_json::Value) {
    let Some(schemes) = document
        .pointer_mut("/components/securitySchemes")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    if schemes.contains_key("DpopProof") {
        schemes.insert(
            "SessionGrantAuth".to_owned(),
            serde_json::json!({ "type": "http", "scheme": "DPoP" }),
        );
    }
}

impl AuthArgs {
    /// Validate the DPoP SessionGrant against `state` and return the matched
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

#[cfg(test)]
mod tests {
    use salvo::oapi::{Components, EndpointArgRegister, Operation};
    use serde_json::json;

    use super::{AuthArgs, install_session_grant_security_scheme};

    #[test]
    fn session_grant_registration_requires_dpop_credential_and_proof_together() {
        let mut components = Components::new();
        let mut operation = Operation::new();
        AuthArgs::register(&mut components, &mut operation, "aa");
        let mut document = json!({ "components": components, "operation": operation });
        install_session_grant_security_scheme(&mut document);

        assert_eq!(
            document["components"]["securitySchemes"],
            json!({
                "SessionGrantAuth": { "type": "http", "scheme": "DPoP" },
                "DpopProof": { "type": "apiKey", "in": "header", "name": "DPoP" }
            })
        );
        assert_eq!(
            document["operation"]["security"],
            json!([{ "SessionGrantAuth": [], "DpopProof": [] }])
        );
        let serialized = document.to_string();
        for retired in ["bearer_session", "bearer", "JWT"] {
            assert!(!serialized.contains(retired));
        }
    }

    #[test]
    fn product_document_resolves_registered_session_grant_security() {
        let document = crate::openapi::product_openapi_surface_doc();
        assert_eq!(
            document["components"]["securitySchemes"]["SessionGrantAuth"],
            json!({ "type": "http", "scheme": "DPoP" })
        );
        assert_eq!(
            document["components"]["securitySchemes"]["DpopProof"],
            json!({ "type": "apiKey", "in": "header", "name": "DPoP" })
        );
        assert!(
            document["components"]["securitySchemes"]
                .get("bearer_session")
                .is_none()
        );
        let mut session_operation_count = 0;
        for path in document["paths"].as_object().expect("paths").values() {
            for operation in path.as_object().expect("path item").values() {
                for requirement in operation["security"].as_array().into_iter().flatten() {
                    if requirement.get("SessionGrantAuth").is_some() {
                        assert_eq!(requirement["DpopProof"], json!([]));
                        session_operation_count += 1;
                    }
                    assert!(requirement.get("bearer_session").is_none());
                }
            }
        }
        assert!(session_operation_count > 0);
    }
}
