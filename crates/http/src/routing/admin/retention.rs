//! Local retention-policy sweeper.
//!
//! The sweeper records tombstones for expired timeline events and deliberately
//! leaves canonical/projection records in place. Read paths render those
//! tombstones as `[expired]`, preserving event_id / causal history for sealed
//! chains without leaking retained content.

use arkret_wire::ActorId;
use chrono::{DateTime, Duration, Utc};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::governance::{RetentionPolicyRecord, RetentionTombstoneRecord};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::AdminAuth;
use super::audit::append_audit_log;
use crate::routing::events::projection::retention_ttl_seconds_from_value;
use crate::state::{AppState, EventNotification, EventNotificationKind};

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ConfigureRetentionPolicyRequestBody {
    #[serde(default)]
    realm_id: Option<String>,
    #[serde(default)]
    ttl_seconds: Option<i64>,
    #[serde(default)]
    ttl_days: Option<i64>,
    #[serde(default)]
    ttl: Option<String>,
    #[serde(default)]
    retention_policy: Option<Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct SweepRetentionPolicyRequestBody {
    #[serde(default)]
    realm_id: Option<String>,
    #[serde(default)]
    now: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct RetentionPolicyOutcome {
    realm_id: String,
    ttl_seconds: i64,
    updated_by: ActorId,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct RetentionTombstoneItem {
    event_id: String,
    realm_id: String,
    retention_state: String,
    reason: String,
    policy_ttl_seconds: i64,
    expired_at: String,
    tombstoned_at: String,
    sealed: bool,
    physical_delete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct RetentionSweepOutcome {
    realm_id: String,
    policy: RetentionPolicyOutcome,
    examined: usize,
    tombstoned_count: usize,
    physical_delete_count: u64,
    tombstoned: Vec<RetentionTombstoneItem>,
}

pub(super) fn router() -> Router {
    Router::with_path("admin/retention")
        .push(Router::with_path("policy").post(configure_retention_policy))
        .push(Router::with_path("sweep").post(sweep_retention_policy))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.retention.policy.configure",
    tags("coland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.admin.retention.policy.configure")
)]
async fn configure_retention_policy(
    admin: AdminAuth,
    depot: &mut Depot,
    body: JsonBody<ConfigureRetentionPolicyRequestBody>,
) -> JsonResult<RetentionPolicyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let body = body.into_inner();
    let realm_id = required_string(body.realm_id.as_deref(), "realm_id")?;
    let ttl_seconds = ttl_seconds_from_configure_body(&body)?;
    let now = Utc::now();
    let record = RetentionPolicyRecord {
        realm_id: realm_id.clone(),
        ttl_seconds,
        updated_by: crate::routing::identity::session_actor::session_actor_from_credential(
            state, &session,
        )?,
        updated_at: now,
    };
    state
        .governance()
        .store_retention_policy(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "org.arkret.coland.audit.retention_policy.updated",
        json!({
            "realm_id": realm_id,
            "ttl_seconds": ttl_seconds,
        }),
        "accepted",
    )
    .await;
    json_ok(policy_outcome(&record))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.retention.sweep",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.retention.sweep"))]
async fn sweep_retention_policy(
    admin: AdminAuth,
    depot: &mut Depot,
    body: JsonBody<SweepRetentionPolicyRequestBody>,
) -> JsonResult<RetentionSweepOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let body = body.into_inner();
    let realm_id = required_string(body.realm_id.as_deref(), "realm_id")?;
    let now = optional_now(body.now.as_deref())?.unwrap_or_else(Utc::now);
    let policy = state
        .governance()
        .retention_policy(&realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("retention policy not found"))?;
    let cutoff = now - Duration::seconds(policy.ttl_seconds);
    let events = state
        .event_queries()
        .projected_events_for_realm(&realm_id)
        .await
        .map_err(|error| AppError::internal(format!("retention scan failed: {error}")))?
        .into_iter()
        .filter(|event| event.event_kind == arkret_wire::EventKind::MessageCreate)
        .collect::<Vec<_>>();
    let examined = events.len();
    let mut created = Vec::new();
    // Filter out already-tombstoned and not-yet-expired events before durable
    // existence checks.
    let pending: Vec<_> = events
        .into_iter()
        .filter(|event| {
            event.created_at <= cutoff
                && state
                    .governance()
                    .cached_retention_tombstone(&event.event_id)
                    .is_none()
        })
        .collect();
    for event in pending {
        if state
            .governance()
            .retention_tombstone(&event.event_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .is_some()
        {
            continue;
        }
        let sealed = state
            .event_queries()
            .has_canonical_event(&event.event_id)
            .await
            .unwrap_or(false);
        let tombstone = RetentionTombstoneRecord {
            event_id: event.event_id.clone(),
            realm_id: event.realm_id.clone(),
            reason: "retention_policy.ttl".to_owned(),
            policy_ttl_seconds: policy.ttl_seconds,
            expired_at: event.created_at + Duration::seconds(policy.ttl_seconds),
            tombstoned_at: now,
            sealed,
        };
        state
            .governance()
            .store_retention_tombstone(&tombstone)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        created.push(tombstone);
    }
    if !created.is_empty() {
        let _ = state.publish_event_notification(EventNotification {
            realm_id: realm_id.clone(),
            kind: EventNotificationKind::ResyncRequired {
                reason: "retention_policy_ttl".to_owned(),
                reconnect_after_ms: None,
            },
        });
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "org.arkret.coland.audit.retention_sweep",
        json!({
            "realm_id": realm_id,
            "examined": examined,
            "tombstoned_count": created.len(),
            "physical_delete_count": 0,
        }),
        "accepted",
    )
    .await;
    json_ok(RetentionSweepOutcome {
        realm_id,
        policy: policy_outcome(&policy),
        examined,
        tombstoned_count: created.len(),
        physical_delete_count: 0,
        tombstoned: created.iter().map(tombstone_item).collect(),
    })
}

fn required_string(value: Option<&str>, field: &str) -> Result<String, AppError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::param_missing(format!("{field} is required")))
}

fn ttl_seconds_from_configure_body(
    body: &ConfigureRetentionPolicyRequestBody,
) -> Result<i64, AppError> {
    if let Some(policy) = body.retention_policy.as_ref()
        && let Some(seconds) = retention_ttl_seconds_from_value(policy)
    {
        return Ok(seconds);
    }
    let body_value = json!({
        "ttl_seconds": body.ttl_seconds,
        "ttl_days": body.ttl_days,
        "ttl": body.ttl.as_deref(),
    });
    retention_ttl_seconds_from_value(&body_value)
        .ok_or_else(|| AppError::param_missing("retention ttl is required"))
}

fn optional_now(value: Option<&str>) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed = arkret_canonical::parse_timestamp_canonical(value)
        .map_err(|_| AppError::param_invalid("now must be a canonical Arkret timestamp"))?;
    Ok(Some(parsed))
}

fn policy_outcome(record: &RetentionPolicyRecord) -> RetentionPolicyOutcome {
    RetentionPolicyOutcome {
        realm_id: record.realm_id.clone(),
        ttl_seconds: record.ttl_seconds,
        updated_by: record.updated_by.clone(),
        updated_at: arkret_canonical::format_timestamp_canonical(record.updated_at),
    }
}

fn tombstone_item(record: &RetentionTombstoneRecord) -> RetentionTombstoneItem {
    RetentionTombstoneItem {
        event_id: record.event_id.clone(),
        realm_id: record.realm_id.clone(),
        retention_state: "tombstoned".to_owned(),
        reason: record.reason.clone(),
        policy_ttl_seconds: record.policy_ttl_seconds,
        expired_at: arkret_canonical::format_timestamp_canonical(record.expired_at),
        tombstoned_at: arkret_canonical::format_timestamp_canonical(record.tombstoned_at),
        sealed: record.sealed,
        physical_delete: false,
    }
}
