use salvo::prelude::*;

mod actors;
pub(crate) mod audit;
mod collection;
mod handles;
mod introspect;
mod media;
mod queries;
mod retention;
mod server_ops;
mod service_routes;
mod settings;

use audit::append_audit_log;
use coland_http::error::AppError;
use coland_http::util;
use coland_services::identity::SessionIdentityState as SessionRecord;
pub(super) use introspect::{introspect_admin_scopes, require_admin_scope};

use super::{
    AuthArgs, discussion_track_for_projection_event, now, policy_document_to_response,
    projection_event_from_operation, realm_has_member, strand_id_for_projection_event,
    strand_id_from_realm_id, strand_projection_for_realm,
};
use crate::state::AppState;

/// Salvo middleware that gates an admin route on an OAuth-style admin
/// scope. The middleware is the only place an admin request is
/// authenticated: it performs the session lookup (for a DPoP session this
/// verifies and consumes the request's single DPoP proof), introspects the
/// session grant through `require_admin_scope`, and stores the resulting
/// [`AdminPrincipal`] in the request [`Depot`] before the endpoint handler
/// runs. Handlers read that principal through [`AdminAuth`] and never
/// authenticate the request a second time, so a request-scoped proof is
/// consumed exactly once.
#[derive(Clone, Debug)]
pub(super) struct RequireAdmin {
    scope: &'static str,
}

impl RequireAdmin {
    pub(super) fn scope(scope: &'static str) -> Self {
        Self { scope }
    }
}

/// The admin principal authenticated by [`RequireAdmin`] for this request.
///
/// Only [`RequireAdmin`] constructs it, and only after authentication and
/// the admin-scope check both succeeded; it lives in the per-request
/// [`Depot`], never in client-controlled request data.
#[derive(Clone, Debug)]
pub(crate) struct AdminPrincipal {
    session: SessionRecord,
}

#[async_trait]
impl Handler for RequireAdmin {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let result = match depot.get_typed::<AppState>() {
            Ok(state) => {
                // A nested gate reuses the principal an outer gate already
                // authenticated for this request instead of verifying (and
                // replaying) the request's credential again.
                let authenticated = match depot.get_typed::<AdminPrincipal>() {
                    Ok(principal) => Ok(principal.session.clone()),
                    Err(_) => AuthArgs.authenticated_session(state, req).await,
                };
                match authenticated {
                    Ok(session) => require_admin_scope(state, req, &session, self.scope)
                        .await
                        .map(|_| session),
                    Err(error) => Err(error),
                }
            }
            Err(_) => Err(AppError::internal("state not injected")),
        };

        match result {
            Ok(session) => {
                depot.insert_typed(AdminPrincipal { session });
                ctrl.call_next(req, depot, res).await;
            }
            Err(error) => {
                error.write(req, depot, res).await;
                ctrl.skip_rest();
            }
        }
    }
}

/// Endpoint argument that yields the admin principal [`RequireAdmin`]
/// authenticated for this request.
///
/// It never reads credentials from the request itself. A handler reached
/// without passing through [`RequireAdmin`] (for example one mounted
/// outside the gated admin routers) finds no principal and fails closed.
#[derive(Clone, Debug)]
pub(crate) struct AdminAuth(Option<SessionRecord>);

impl<'ex> salvo::extract::Extractible<'ex> for AdminAuth {
    fn metadata() -> &'static salvo::extract::Metadata {
        static METADATA: salvo::extract::Metadata = salvo::extract::Metadata::new("");
        &METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(
        _req: &'ex mut Request,
        depot: &'ex mut Depot,
    ) -> Result<Self, salvo::http::ParseError> {
        Ok(Self::from_depot(depot))
    }
}

/// Same bearer-session security requirement as [`AuthArgs`]: the credential
/// is the request's `Authorization` header, validated once by
/// [`RequireAdmin`].
impl salvo::oapi::EndpointArgRegister for AdminAuth {
    fn register(
        components: &mut salvo::oapi::Components,
        operation: &mut salvo::oapi::Operation,
        arg: &str,
    ) {
        <AuthArgs as salvo::oapi::EndpointArgRegister>::register(components, operation, arg);
    }
}

impl AdminAuth {
    /// Read the principal [`RequireAdmin`] stored in this request's depot.
    pub(crate) fn from_depot(depot: &Depot) -> Self {
        Self(
            depot
                .get_typed::<AdminPrincipal>()
                .ok()
                .map(|principal| principal.session.clone()),
        )
    }

    /// The session authenticated by [`RequireAdmin`] for this request.
    pub(crate) fn session(self) -> Result<SessionRecord, AppError> {
        self.0.ok_or_else(|| {
            tracing::error!("admin handler reached without the RequireAdmin gate");
            AppError::internal("admin handler reached without the RequireAdmin gate")
        })
    }
}

/// Gate a write-side admin handler on the caller's authorization.
///
/// In an explicitly compiled development harness, any harness session is allowed. Otherwise
/// the session actor MUST appear in `AppConfig::admin_principal_ids`
/// (env `COLAND_ADMIN_PRINCIPAL_IDS`). Returns the original session on
/// success or an `AppError` with `capability_denied` on failure.
pub(super) fn require_admin_principal(
    state: &AppState,
    session: SessionRecord,
) -> Result<SessionRecord, AppError> {
    if state.config().development_harness_enabled() || state.is_admin_principal(&session.actor) {
        Ok(session)
    } else {
        Err(crate::app_error!(
            CapabilityDenied,
            "admin API requires the caller principal ID to be listed in COLAND_ADMIN_PRINCIPAL_IDS"
                .to_owned(),
        ))
    }
}

/// Deployment-local admin branch served at the bare `/admin/*`
/// namespace (collection snapshot and retention), per arkret-spec `service-http-binding.md`
/// §2.1: `/admin/*` is deployment-local and MUST NOT carry the
/// `/_arkret/...` protocol prefix. Gated by the shared `RequireAdmin` hoop.
///
/// Salvo selects the first child whose path and method filters match, so the
/// single-segment `admin/{resource}` collection wildcard is pushed last: a
/// concrete sibling such as `GET admin/settings` must win over the wildcard,
/// which otherwise answers it as an unknown collection (404).
pub fn router() -> Router {
    Router::new()
        .hoop(RequireAdmin::scope(
            arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ,
        ))
        .push(retention::router())
        .push(settings::router())
        .push(Router::with_path("admin/{resource}").get(collection::admin_collection))
}

pub fn server_ops_router() -> Router {
    server_ops::router().hoop(RequireAdmin::scope(
        arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ,
    ))
}

pub fn admin_router() -> Router {
    // Deployment-local operator surface served at the bare `/admin/*`
    // namespace (Realm and account administration, moderation). Realm-scoped
    // operations use `/admin/realms/{realm_id}`; Space containers are
    // reserved for `/admin/spaces/*`. Per arkret-spec
    // `service-http-binding.md` §2.1 the `/admin/*` namespace is
    // deployment-local and MUST NOT carry the `/_arkret/...` protocol prefix.
    // Registered ahead of `router()` (the `{resource}` collection
    // wildcard) at the root so concrete admin resources take precedence.
    Router::with_path("admin")
        .hoop(RequireAdmin::scope(
            arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ,
        ))
        .push(Router::with_path("realms").post(collection::admin_create_realm))
        .push(Router::with_path("realms/{realm_id}").get(collection::admin_get_realm))
        .push(
            Router::with_path("realms/{realm_id}/links")
                .get(crate::routing::realms::admin_list_realm_links),
        )
        .push(
            Router::with_path("realms/{realm_id}/organizations")
                .get(crate::routing::realm_organization::admin_list_realm_organizations),
        )
        .push(
            Router::with_path("viewer")
                .get(crate::routing::identity::account::admin_account_viewer),
        )
        .push(crate::routing::identity::key_backup::admin_router())
        // B2 — operator handle cluster (list / get / audit / revoke / reassign).
        .push(handles::router())
        .push(actors::router())
        // D14 — production typed queries replacing the dev snapshot
        // collection for capabilities / devices (actors and audit hang off
        // their own routers above/below).
        .push(Router::with_path("capabilities").get(queries::admin_list_capabilities))
        .push(Router::with_path("devices").get(queries::admin_list_devices))
        .push(media::router())
        .push(service_routes::router())
        // Operator audit queries (`/_coland/admin/audit/events`,
        // `/_coland/admin/audit/erasure-receipts`) under the shared
        // `RequireAdmin` gate (SOL-NAME-02 — client ingest lives at
        // `/_coland/self/audit/*` instead of a second mount of this tree).
        .push(audit::ops_router())
}

#[cfg(test)]
mod gate_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use salvo::affix_state;
    use salvo::test::{ResponseExt, TestClient};

    use super::*;

    fn state() -> AppState {
        AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        )
    }

    /// Admin handler stand-in: records whether its body ran with a principal.
    struct Probe(Arc<AtomicBool>);

    #[async_trait]
    impl Handler for Probe {
        async fn handle(
            &self,
            req: &mut Request,
            depot: &mut Depot,
            res: &mut Response,
            _ctrl: &mut FlowCtrl,
        ) {
            match AdminAuth::from_depot(depot).session() {
                Ok(_) => {
                    self.0.store(true, Ordering::SeqCst);
                    res.render("reached");
                }
                Err(error) => error.write(req, depot, res).await,
            }
        }
    }

    async fn status(router: Router, authorization: Option<&str>) -> StatusCode {
        let mut request = TestClient::get("http://server/admin/probe");
        if let Some(value) = authorization {
            request = request.add_header("authorization", value, true);
        }
        request
            .send(&Service::new(router))
            .await
            .status_code
            .expect("status")
    }

    /// A handler reached without `RequireAdmin` finds no principal in the
    /// depot and fails closed; it never falls back to reading credentials.
    #[tokio::test]
    async fn admin_handler_without_the_gate_fails_closed() {
        let reached = Arc::new(AtomicBool::new(false));
        let router = Router::new()
            .hoop(affix_state::inject(state()))
            .push(Router::with_path("admin/probe").get(Probe(reached.clone())));
        assert_eq!(
            status(router, Some("Bearer anything")).await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(!reached.load(Ordering::SeqCst));
    }

    /// The gate rejects a request without credentials before the handler
    /// runs and stores no principal for it.
    #[tokio::test]
    async fn gate_rejects_missing_authentication_before_the_handler() {
        let reached = Arc::new(AtomicBool::new(false));
        let router = Router::new().hoop(affix_state::inject(state())).push(
            Router::with_path("admin/probe")
                .hoop(RequireAdmin::scope(
                    arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ,
                ))
                .get(Probe(reached.clone())),
        );
        assert_eq!(status(router, None).await, StatusCode::UNAUTHORIZED);
        assert!(!reached.load(Ordering::SeqCst));
    }

    /// `AdminAuth` yields exactly the principal the gate stored for this
    /// request, and nothing when the gate stored none.
    #[test]
    fn admin_auth_reads_only_the_gate_principal() {
        let mut depot = Depot::new();
        assert!(AdminAuth::from_depot(&depot).session().is_err());
        depot.insert_typed(AdminPrincipal {
            session: SessionRecord {
                token_hash: "gate".into(),
                account_pk: None,
                actor: "ak:did_core:web:op.example".into(),
                endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                    device_id: "ak:device:0196419b-0000-7000-8000-000000000001".into(),
                },
                audience: "ak:did_core:web:server.example".into(),
                session_public_key: None,
                session_grant: None,
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                created_at: chrono::Utc::now(),
                revoked_at: None,
            },
        });
        assert_eq!(
            AdminAuth::from_depot(&depot).session().unwrap().actor,
            "ak:did_core:web:op.example"
        );
    }

    /// Stand-in for an outer `RequireAdmin` that already authenticated this
    /// request, so the gate under test reuses its principal instead of
    /// reading a credential.
    struct AuthenticatedPrincipal;

    #[async_trait]
    impl Handler for AuthenticatedPrincipal {
        async fn handle(
            &self,
            _req: &mut Request,
            depot: &mut Depot,
            _res: &mut Response,
            _ctrl: &mut FlowCtrl,
        ) {
            depot.insert_typed(AdminPrincipal {
                session: SessionRecord {
                    token_hash: "outer-gate".into(),
                    account_pk: None,
                    actor: "ak:did_core:web:op.example".into(),
                    endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                        device_id: "ak:device:0196419b-0000-7000-8000-000000000001".into(),
                    },
                    audience: "ak:did_core:web:server.example".into(),
                    session_public_key: None,
                    session_grant: None,
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                    created_at: chrono::Utc::now(),
                    revoked_at: None,
                },
            });
        }
    }

    /// The `admin/{resource}` collection wildcard must not shadow a concrete
    /// sibling route: `GET admin/settings` reaches the settings handler, and
    /// an unknown collection still reaches the wildcard's own 404.
    #[tokio::test]
    async fn concrete_admin_routes_take_precedence_over_the_collection_wildcard() {
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let expected = serde_json::to_value(&*state.settings()).expect("settings JSON");
        let service = Service::new(
            Router::new()
                .hoop(affix_state::inject(state))
                .hoop(AuthenticatedPrincipal)
                .push(router()),
        );

        let mut response = TestClient::get("http://server/admin/settings")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body: serde_json::Value = response.take_json().await.expect("settings body");
        assert_eq!(body, expected);

        let mut response = TestClient::get("http://server/admin/no-such-collection")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        let body = response.take_string().await.expect("collection body");
        assert!(body.contains("admin resource not found"), "{body}");
    }
}
