//! Admin scopes from the request's already authenticated issuer grant.
//! Authentication takes one authoritative result at the operation's strictest
//! freshness. Scope gates reuse that exact result without another ledger read.

use arkret_models_identity::admin_grant::{
    SessionGrantAdminIntrospectionStatus, SessionGrantIntrospection,
};
use coland_http::error::AppError;
use coland_services::identity::SessionIdentityState as SessionRecord;
use salvo::prelude::Request;

use crate::state::AppState;

/// Synthetic introspection in an explicitly compiled harness when no upstream IdP
/// is configured. Grants every well-known admin scope to any DID listed
/// in `admin_principal_ids` (or any principal in development_mode).
#[cfg(any(test, feature = "conformance-harness"))]
fn synthetic_dev_admin_scopes() -> Vec<String> {
    use arkret_models_identity::admin_grant::admin_scopes::*;
    vec![
        AUTHORITY_HANDOFF.to_owned(),
        COMMIT_LOG_COMPACT.to_owned(),
        STREAM_REPAIR.to_owned(),
        ADMIN_READ.to_owned(),
    ]
}

#[cfg(any(test, feature = "conformance-harness"))]
fn synthetic_dev_grant(state: &AppState, session: &SessionRecord) -> SessionGrantIntrospection {
    let principal_id =
        arkret_identifiers::DidCoreId::new(session.actor.clone()).unwrap_or_else(|_| {
            // Dev-login actors may be handles rather than DIDs. Reuse the
            // configured, verified service did; never reconstruct one from
            // the service core_id.
            arkret_identifiers::DidCoreId::new(state.service_id().clone())
                .expect("configured service id is a validated core id")
        });
    SessionGrantIntrospection {
        active: true,
        status: SessionGrantAdminIntrospectionStatus::Active,
        principal_id,
        admin_scopes: synthetic_dev_admin_scopes(),
        expires_at: Some(arkret_canonical::normalize_timestamp_canonical(
            session.expires_at,
        )),
        device_id: Some(session.require_human_device_id().clone()),
        audit_context: serde_json::json!({ "synthetic": "development_mode" }),
    }
}

/// Project the exact grant that authenticated this request; never re-introspect.
pub(crate) async fn introspect_admin_scopes(
    state: &AppState,
    _req: &Request,
    session: &SessionRecord,
) -> Result<SessionGrantIntrospection, AppError> {
    #[cfg(any(test, feature = "conformance-harness"))]
    if state.config().development_harness_enabled() && session.session_grant.is_none() {
        return Ok(synthetic_dev_grant(state, session));
    }
    let grant = session.session_grant.as_ref().ok_or_else(|| {
        crate::app_error!(
            CapabilityDenied,
            "admin scope check requires an authenticated issuer grant".to_owned()
        )
    })?;
    if grant.account_id.principal_id.as_str() != session.actor
        || grant.account_id.station_id.as_str() != state.service_id()
        || session.audience != *state.service_id()
        || session.revoked_at.is_some()
        || session.expires_at <= chrono::Utc::now()
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "admin grant binding is not current at this Station".to_owned()
        ));
    }
    Ok(SessionGrantIntrospection {
        active: true,
        status: SessionGrantAdminIntrospectionStatus::Active,
        principal_id: grant.account_id.principal_id.clone(),
        admin_scopes: grant.scopes.clone(),
        expires_at: Some(arkret_canonical::normalize_timestamp_canonical(
            session.expires_at,
        )),
        device_id: session.human_device_id().cloned(),
        audit_context: serde_json::json!({"source":"request_authoritative_session_grant", "grant_id":grant.grant_id, "audience":session.audience}),
    })
}

/// Gate the calling admin operation on a specific scope. Production
/// strand: introspect the bearer, ensure the grant carries `scope`. Dev
/// strand: synthetic grant accepts every well-known scope.
pub(crate) async fn require_admin_scope(
    state: &AppState,
    req: &Request,
    session: &SessionRecord,
    scope: &str,
) -> Result<SessionGrantIntrospection, AppError> {
    let grant = introspect_admin_scopes(state, req, session).await?;
    if !grant.has_admin_scope(scope) {
        return Err(crate::app_error!(
            CapabilityDenied,
            format!(
                "admin scope `{scope}` not granted to {}",
                grant.principal_id
            ),
        ));
    }
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_adapter_uses_current_status_and_scope_vocabulary() {
        use arkret_models_identity::admin_grant::admin_scopes;

        assert_eq!(
            synthetic_dev_admin_scopes(),
            vec![
                admin_scopes::AUTHORITY_HANDOFF.to_owned(),
                admin_scopes::COMMIT_LOG_COMPACT.to_owned(),
                admin_scopes::STREAM_REPAIR.to_owned(),
                admin_scopes::ADMIN_READ.to_owned(),
            ]
        );
    }
}
