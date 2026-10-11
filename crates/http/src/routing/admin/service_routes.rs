//! Read-only deployment-local service-route operations projection.
//!
//! Every field comes from Coland's verified method state, route cache, or fork quarantine. This
//! surface never resolves a route and never publishes protocol authority.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coland_contracts::admin::{
    AdminServiceMethodState, AdminServiceRouteCache, AdminServiceRouteCurrent,
    AdminServiceRouteDetail, AdminServiceRouteList, AdminServiceRouteQuarantine,
    AdminServiceRouteSummary,
};
use coland_http::error::AppError;
use coland_storage::ServiceRouteStoredKey;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{AdminAuth, append_audit_log, require_admin_principal};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

const DETAIL_LIMIT: usize = 100;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteCursor {
    service_id: String,
    service_kind: String,
}

pub(super) fn router() -> Router {
    Router::with_path("service-routes")
        .get(admin_list_service_routes)
        .push(Router::with_path("{service_id}/{service_kind}").get(admin_get_service_route))
}

fn decode_cursor(value: Option<String>) -> Result<Option<ServiceRouteStoredKey>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::param_invalid("invalid service-route cursor"))?;
    let cursor: RouteCursor = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::param_invalid("invalid service-route cursor"))?;
    Ok(Some(ServiceRouteStoredKey {
        service_id: arkret_wire::DidCoreId::new(cursor.service_id)
            .map_err(|_| AppError::param_invalid("invalid service-route cursor"))?,
        service_kind: validate_service_kind(cursor.service_kind)?,
    }))
}

fn encode_cursor(key: &ServiceRouteStoredKey) -> Result<String, AppError> {
    let bytes = arkret_canonical::canonical_json_bytes(&RouteCursor {
        service_id: key.service_id.to_string(),
        service_kind: key.service_kind.clone(),
    })
    .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn validate_service_kind(value: String) -> Result<String, AppError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AppError::param_invalid("invalid service_kind"));
    }
    Ok(value)
}

fn sanitize_private_diagnostic(value: serde_json::Value) -> serde_json::Value {
    fn sanitize(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(values) => serde_json::Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| {
                        let lower = key.to_ascii_lowercase();
                        let value = if lower.contains("url") || lower.contains("endpoint") {
                            serde_json::Value::String("[redacted_locator]".to_owned())
                        } else {
                            sanitize(value)
                        };
                        (key, value)
                    })
                    .collect(),
            ),
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().take(64).map(sanitize).collect())
            }
            serde_json::Value::String(value)
                if value.starts_with("https://") || value.starts_with("http://") =>
            {
                serde_json::Value::String("[redacted_locator]".to_owned())
            }
            serde_json::Value::String(value) if value.len() > 512 => serde_json::Value::String(
                format!("{}…", value.chars().take(512).collect::<String>()),
            ),
            value => value,
        }
    }
    let sanitized = sanitize(value);
    let size = serde_json::to_vec(&sanitized)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if size > 4_096 {
        json!({"redacted": "diagnostic_too_large", "bytes": size})
    } else {
        sanitized
    }
}

async fn load_detail(
    state: &AppState,
    service_id: arkret_wire::DidCoreId,
    service_kind: String,
) -> Result<AdminServiceRouteDetail, AppError> {
    let observed_at = chrono::Utc::now();
    let floor = state
        .persistence()
        .service_route_method_state(&service_id, &service_kind)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let route_cache = state
        .persistence()
        .service_route_cache(&service_id, &service_kind)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut quarantines = state
        .persistence()
        .stored_service_route_quarantine(&service_id, &service_kind, DETAIL_LIMIT + 1)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let quarantine_truncated = quarantines.len() > DETAIL_LIMIT;
    quarantines.truncate(DETAIL_LIMIT);

    let method_state = floor.map(|f| AdminServiceMethodState {
        did: f.did.to_string(),
        method_history_head: f.method_history_head,
        version_id: f.version_id,
        verified_at: f.verified_at,
    });
    let current_route = route_cache.as_ref().map(|e| AdminServiceRouteCurrent {
        did: e.did().to_string(),
        method_history_head: e.method_history_head().to_owned(),
        version_id: e.version_id().to_owned(),
        base_url: e.base_url().to_owned(),
        verified_at: e.verified_at,
    });
    let cache = route_cache.as_ref().map(|e| AdminServiceRouteCache {
        verified_at: e.verified_at,
        cache_expires_at: e.cache_expires_at,
        routable_at_observed_at: e.is_routable_at(observed_at),
    });
    let quarantine = quarantines
        .into_iter()
        .map(|entry| AdminServiceRouteQuarantine {
            version_id: entry.version_id,
            accepted_digest: entry.accepted_digest.to_string(),
            conflicting_digest: entry.conflicting_digest.to_string(),
            quarantined_at: entry.quarantined_at,
            diagnostic: sanitize_private_diagnostic(entry.evidence),
        })
        .collect::<Vec<_>>();
    let known = method_state.is_some() || current_route.is_some() || !quarantine.is_empty();
    Ok(AdminServiceRouteDetail {
        service_id,
        service_kind,
        known,
        method_state,
        current_route,
        cache,
        quarantine,
        quarantine_truncated,
        observed_at,
        authority: "local_verified_persistence".to_owned(),
    })
}

fn summary(detail: &AdminServiceRouteDetail) -> AdminServiceRouteSummary {
    AdminServiceRouteSummary {
        service_id: detail.service_id.clone(),
        service_kind: detail.service_kind.clone(),
        known: detail.known,
        method_history_head: detail
            .method_state
            .as_ref()
            .map(|s| s.method_history_head.clone()),
        version_id: detail.method_state.as_ref().map(|s| s.version_id.clone()),
        cache_expires_at: detail.cache.as_ref().map(|c| c.cache_expires_at),
        quarantined: !detail.quarantine.is_empty(),
    }
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.service_routes.list",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.service_routes.list"))]
async fn admin_list_service_routes(
    admin: AdminAuth,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<AdminServiceRouteList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = require_admin_principal(state, admin.session()?)?;
    let limit = limit
        .into_inner()
        .unwrap_or(state.config().admin_default_page_limit)
        .clamp(1, state.config().admin_max_page_limit.min(100));
    let after = decode_cursor(cursor.into_inner())?;
    let mut keys = state
        .persistence()
        .stored_service_route_keys(after.as_ref(), limit + 1)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let has_more = keys.len() > limit;
    if has_more {
        keys.truncate(limit);
    }
    let next_cursor = if has_more {
        keys.last().map(encode_cursor).transpose()?
    } else {
        None
    };
    let mut routes = Vec::with_capacity(keys.len());
    for key in keys {
        routes.push(summary(
            &load_detail(state, key.service_id, key.service_kind).await?,
        ));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.service_routes.list",
        json!({"returned": routes.len(), "has_more": has_more}),
        "accepted",
    )
    .await;
    json_ok(AdminServiceRouteList {
        routes,
        next_cursor,
        has_more,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.service_routes.get",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.service_routes.get"))]
async fn admin_get_service_route(
    admin: AdminAuth,
    service_id: PathParam<String>,
    service_kind: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<AdminServiceRouteDetail> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = require_admin_principal(state, admin.session()?)?;
    let service_id = arkret_wire::DidCoreId::new(service_id.into_inner())
        .map_err(|_| AppError::param_invalid("invalid service_id core"))?;
    let service_kind = validate_service_kind(service_kind.into_inner())?;
    let detail = load_detail(state, service_id, service_kind).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.service_routes.get",
        json!({
            "service_id": detail.service_id,
            "service_kind": detail.service_kind,
            "known": detail.known,
        }),
        "accepted",
    )
    .await;
    json_ok(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_diagnostics_never_expose_unverified_locators() {
        let value = sanitize_private_diagnostic(json!({
            "candidate_url": "https://attacker.example/route",
            "nested": ["http://unverified.example", "safe"],
        }));
        assert_eq!(value["candidate_url"], "[redacted_locator]");
        assert_eq!(value["nested"][0], "[redacted_locator]");
        assert_eq!(value["nested"][1], "safe");
    }
}
