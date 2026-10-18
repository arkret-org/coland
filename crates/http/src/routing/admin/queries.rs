//! Production admin query endpoints (D14).
//!
//! Typed, cursor-paginated, server-side-filtered reads for the four resources
//! codmin manages:
//!
//! - `GET /_coland/admin/actors`        → [`AdminActorList`]
//! - `GET /_coland/admin/audit`         → [`AdminAuditList`]
//! - `GET /_coland/admin/capabilities`  → [`AdminCapabilityList`]
//! - `GET /_coland/admin/devices`       → [`AdminDeviceList`]
//!
//! These replace the dev-only `admin/{resource}` snapshot collection for
//! those resources (the collection keeps serving the surfaces that have not
//! been productionised yet). Wire contract lives in
//! `coland_contracts::admin` — see that module for the frozen rules.
//!
//! Pagination: rows are sorted by a stable key (actors: this Station's principal; capabilities:
//! grant id; devices: device id; audit: newest first, audit id as tiebreak).
//! `next_cursor` is the last row id of the page; resume looks the id up
//! again, so the cursor stays valid across inserts. A cursor that no longer
//! resolves is rejected with `cursor-expired` (410) so clients reset to the
//! first page instead of silently skipping rows.
//!
//! Authorization mirrors the rest of the operator surface: the admin tree's
//! `RequireAdmin` hoop enforces the `admin.read` session-grant scope, and
//! each handler additionally requires the caller DID to be an admin
//! principal (`require_admin_principal`). Every query appends an audit
//! record carrying the applied filters and returned row count.

use std::collections::BTreeMap;

use arkret_models_collaboration::objects::account_status::AccountStatus;
use coland_contracts::admin::{
    AdminActor, AdminActorList, AdminAuditEntry, AdminAuditList, AdminCapabilityList, AdminDevice,
    AdminDeviceList, CapabilityGrantState, CapabilitySummary,
};
use coland_http::error::AppError;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde_json::{Value, json};
use util::query_param;

use super::{AdminAuth, append_audit_log, require_admin_principal, util};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// Clamp the caller-supplied page size to the configured admin window.
fn clamp_limit(state: &AppState, limit: Option<usize>) -> usize {
    limit
        .unwrap_or(state.config().admin_default_page_limit)
        .clamp(1, state.config().admin_max_page_limit)
}

/// Resume-by-id keyset pagination over an already-filtered, already-sorted
/// row set. Returns `(page, next_cursor, has_more)`. An unresolvable cursor
/// is a hard `cursor-expired` (410): the row the client saw last is gone, so
/// continuing would silently skip an unknown range.
fn paginate_by_id<T>(
    mut rows: Vec<T>,
    cursor: Option<&str>,
    limit: usize,
    id_of: impl Fn(&T) -> &str,
) -> Result<(Vec<T>, Option<String>, bool), AppError> {
    if let Some(cursor) = cursor {
        let position = rows
            .iter()
            .position(|row| id_of(row) == cursor)
            .ok_or_else(|| {
                crate::app_error!(
                    CursorExpired,
                    "pagination cursor no longer resolves; restart from the first page".to_owned(),
                )
            })?;
        rows.drain(..=position);
    }
    let has_more = rows.len() > limit;
    if has_more {
        rows.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| rows.last().map(|row| id_of(row).to_owned()))
        .flatten();
    Ok((rows, next_cursor, has_more))
}

/// Case-insensitive substring match helper for `filter[search]`-style
/// filters.
fn contains_ci(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_lowercase().contains(needle_lower)
}

async fn query_audit_trail(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    action: &str,
    filters: &BTreeMap<String, String>,
    count: usize,
) {
    append_audit_log(
        state,
        Some(&session.actor),
        action,
        json!({
            "device_id": session.require_human_device_id(),
            "filters": filters,
            "count": count,
        }),
        "accepted",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Actors
// ---------------------------------------------------------------------------

/// Build the production [`AdminActor`] projection for one account record.
/// Only this Station's accounts belong to its deployment-local admin surface.
/// `device_counts` uses the Station-local inventory principal key;
/// `realm_counts` uses full Actor keys from the federated Realm directory.
pub(super) fn admin_actor_row(
    state: &AppState,
    account: &coland_services::identity::AccountProfileState,
    device_counts: &BTreeMap<String, u64>,
    realm_counts: &BTreeMap<String, u64>,
    propagation_state: Option<coland_storage::AccountStatusPropagationProjectionState>,
) -> Option<AdminActor> {
    if account.account_id.station_id != state.service_core_id() {
        return None;
    }
    let principal_id = account.principal_id.clone();
    let actor_key = arkret_wire::ActorId::account(account.account_id.clone()).to_string();
    let status = state.account_lifecycle_status(principal_id.as_str());
    let deactivation_federation_incomplete = (status == AccountStatus::Deactivated)
        .then(|| {
            propagation_state.map(|state| {
                state == coland_storage::AccountStatusPropagationProjectionState::Incomplete
            })
        })
        .flatten();
    // `deactivation_partial` also applies to erasure_pending: erasure
    // execution runs the same deactivation fanout (including the
    // push-gateway leg) before erasing.
    let deactivation_partial = matches!(
        status,
        AccountStatus::Deactivated | AccountStatus::ErasurePending
    )
    .then(|| state.deactivation_push_partial(principal_id.as_str()));
    let handle = account.handle();
    Some(AdminActor {
        id: principal_id.to_string(),
        principal_id: principal_id.clone(),
        account_id: Some(account.account_id.to_string()),
        handle: (!handle.is_empty()).then_some(handle),
        display_name: account.display_name.clone(),
        status: Some(status),
        is_admin: Some(state.is_admin_principal(principal_id.as_str())),
        deactivation_federation_incomplete,
        deactivation_partial,
        created_at: Some(account.created_at),
        // Not tracked by this deployment — reported as unknown, never a
        // fabricated timestamp.
        last_active_at: None,
        device_count: device_counts
            .get(principal_id.as_str())
            .copied()
            .or(Some(0)),
        realm_count: realm_counts.get(&actor_key).copied().or(Some(0)),
    })
}

pub(super) async fn account_status_propagation_state_for_admin(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    deactivated: bool,
) -> Result<Option<coland_storage::AccountStatusPropagationProjectionState>, AppError> {
    if !deactivated {
        return Ok(None);
    }
    let transition = state
        .persistence()
        .current_account_status_propagation_projection(account_id, chrono::Utc::now())
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "account-status propagation projection unavailable: {error}"
            ))
        })?;
    let Some(transition) = transition else {
        return Ok(None);
    };
    crate::routing::identity::account::lifecycle::audit_account_status_propagation_transition(
        state,
        &transition,
        true,
    )
    .await;
    Ok(Some(transition.projection.state))
}

pub(super) async fn actor_count_maps(
    state: &AppState,
) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    let mut device_counts: BTreeMap<String, u64> = BTreeMap::new();
    for actor in state
        .identities()
        .list_active_device_actors(coland_services::identity::ListActiveDeviceActorsQuery)
        .await
        .unwrap_or_default()
    {
        *device_counts.entry(actor).or_default() += 1;
    }
    let realm_counts = realm_membership_counts(&state.projections().snapshot());
    (device_counts, realm_counts)
}

fn realm_membership_counts(
    projection: &coland_domain::reducer::ProjectionState,
) -> BTreeMap<String, u64> {
    let realm_ids: std::collections::BTreeSet<_> = projection
        .members
        .keys()
        .map(|(realm_id, _)| realm_id)
        .collect();
    let mut counts = BTreeMap::new();
    for realm_id in realm_ids {
        for member in projection.members_of_realm(realm_id) {
            *counts.entry(member.member.clone()).or_default() += 1;
        }
    }
    counts
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.actors.query",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.actors.query"))]
pub(super) async fn admin_list_actors(
    admin: AdminAuth,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminActorList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let limit = clamp_limit(state, limit.into_inner());
    let cursor = cursor.into_inner();

    let mut filters = BTreeMap::new();
    let search = query_param(req, "filter[search]").filter(|value| !value.trim().is_empty());
    if let Some(search) = &search {
        filters.insert("search".to_owned(), search.clone());
    }
    let status_filter = match query_param(req, "filter[status]") {
        Some(raw) => {
            let status = AccountStatus::from_wire(&raw).ok_or_else(|| {
                AppError::param_invalid(format!("unknown account status filter: {raw}"))
            })?;
            filters.insert("status".to_owned(), raw);
            Some(status)
        }
        None => None,
    };

    let (device_counts, realm_counts) = actor_count_maps(state).await;
    let accounts = state.identities().accounts().await.map_err(|error| {
        tracing::error!(%error, "failed to list accounts");
        AppError::internal("account store unavailable")
    })?;
    let mut rows: Vec<AdminActor> = Vec::with_capacity(accounts.len());
    for account in &accounts {
        let status = state.account_lifecycle_status(account.principal_id.as_str());
        let propagation_state = account_status_propagation_state_for_admin(
            state,
            &account.account_id,
            status == AccountStatus::Deactivated,
        )
        .await?;
        if let Some(row) = admin_actor_row(
            state,
            account,
            &device_counts,
            &realm_counts,
            propagation_state,
        ) {
            rows.push(row);
        }
    }
    if let Some(search) = &search {
        let needle = search.to_lowercase();
        rows.retain(|actor| {
            contains_ci(&actor.id, &needle)
                || actor
                    .handle
                    .as_deref()
                    .is_some_and(|handle| contains_ci(handle, &needle))
                || actor
                    .display_name
                    .as_deref()
                    .is_some_and(|name| contains_ci(name, &needle))
        });
    }
    if let Some(status) = status_filter {
        rows.retain(|actor| actor.status == Some(status));
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let total = rows.len() as u64;
    let (actors, next_cursor, has_more) =
        paginate_by_id(rows, cursor.as_deref(), limit, |actor| actor.id.as_str())?;

    query_audit_trail(
        state,
        &session,
        "admin.actors.query",
        &filters,
        actors.len(),
    )
    .await;
    json_ok(AdminActorList {
        actors,
        total: Some(total),
        next_cursor,
        has_more,
        filters,
    })
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Parse one durable audit record into the typed wire row. Records without
/// an `audit_id` are dropped (they cannot participate in cursor pagination).
fn audit_entry_from_record(record: &Value) -> Option<AdminAuditEntry> {
    let field = |key: &str| {
        record
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    Some(AdminAuditEntry {
        id: field("audit_id")?,
        request_id: field("request_id"),
        action: field("action").unwrap_or_default(),
        actor_id: field("actor"),
        device_id: field("device_id"),
        realm_id: field("realm_id"),
        operation_id: field("operation_id"),
        outcome: field("outcome"),
        payload: record.get("payload").filter(|p| !p.is_null()).cloned(),
        created_at: field("created_at")
            .and_then(|raw| chrono::DateTime::parse_from_rfc3339(&raw).ok())
            .map(|ts| ts.with_timezone(&chrono::Utc)),
    })
}

fn audit_matches_kind(entry: &AdminAuditEntry, kind: &str) -> bool {
    entry.action == kind
        || entry
            .payload
            .as_ref()
            .and_then(|payload| payload.get("kind"))
            .and_then(Value::as_str)
            == Some(kind)
}

fn parse_time_bound(raw: &str, name: &str) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .map_err(|_| AppError::param_invalid(format!("{name} must be an RFC3339 timestamp")))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.audit.query",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.audit.query"))]
pub(super) async fn admin_query_audit(
    admin: AdminAuth,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminAuditList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let limit = clamp_limit(state, limit.into_inner());
    let cursor = cursor.into_inner();

    let mut filters = BTreeMap::new();
    let mut simple_filter = |key: &str| {
        let value =
            query_param(req, &format!("filter[{key}]")).filter(|value| !value.trim().is_empty());
        if let Some(value) = &value {
            filters.insert(key.to_owned(), value.clone());
        }
        value
    };
    let action_filter = simple_filter("action");
    let actor_filter = simple_filter("actor_id");
    let realm_filter = simple_filter("realm_id");
    let kind_filter = simple_filter("kind");
    let since = match query_param(req, "since").filter(|value| !value.trim().is_empty()) {
        Some(raw) => {
            let bound = parse_time_bound(&raw, "since")?;
            filters.insert("since".to_owned(), raw);
            Some(bound)
        }
        None => None,
    };
    let until = match query_param(req, "until").filter(|value| !value.trim().is_empty()) {
        Some(raw) => {
            let bound = parse_time_bound(&raw, "until")?;
            filters.insert("until".to_owned(), raw);
            Some(bound)
        }
        None => None,
    };

    let mut entries: Vec<AdminAuditEntry> = state
        .governance()
        .audit_entries()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to read audit log");
            AppError::internal("audit store unavailable")
        })?
        .iter()
        .filter_map(audit_entry_from_record)
        .collect();
    if let Some(action) = &action_filter {
        entries.retain(|entry| &entry.action == action);
    }
    if let Some(actor) = &actor_filter {
        entries.retain(|entry| entry.actor_id.as_deref() == Some(actor.as_str()));
    }
    if let Some(realm) = &realm_filter {
        entries.retain(|entry| {
            entry.realm_id.as_deref() == Some(realm.as_str())
                || entry
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.get("realm_id"))
                    .and_then(Value::as_str)
                    == Some(realm.as_str())
        });
    }
    if let Some(kind) = &kind_filter {
        entries.retain(|entry| audit_matches_kind(entry, kind));
    }
    if let Some(since) = since {
        entries.retain(|entry| entry.created_at.is_some_and(|ts| ts >= since));
    }
    if let Some(until) = until {
        entries.retain(|entry| entry.created_at.is_some_and(|ts| ts <= until));
    }
    // Newest first; audit id keeps the order total when timestamps collide.
    entries.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    let total = entries.len() as u64;
    let (entries, next_cursor, has_more) =
        paginate_by_id(entries, cursor.as_deref(), limit, |entry| entry.id.as_str())?;

    query_audit_trail(
        state,
        &session,
        "admin.audit.query",
        &filters,
        entries.len(),
    )
    .await;
    json_ok(AdminAuditList {
        entries,
        total: Some(total),
        next_cursor,
        has_more,
        filters,
    })
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// Preserve every accepted subject branch and its exact durable revision.
fn capability_summary(
    record: &coland_storage::CapabilityGrantCurrentResultRecord,
) -> CapabilitySummary {
    use arkret_models_collaboration::exact_current_results::{
        CapabilityGrantExactCurrentSelector, CapabilityGrantExactCurrentSelectorKind,
    };
    CapabilitySummary {
        selector: CapabilityGrantExactCurrentSelector {
            kind: CapabilityGrantExactCurrentSelectorKind::CapabilityGrant,
            grant_id: record.grant_id.clone(),
        },
        source_stream_ref: record.source.stream_ref.clone(),
        revision: record.revision.clone(),
        value: record.value.clone(),
    }
}

fn capability_subject_matches(row: &CapabilitySummary, actor: &arkret_wire::ActorId) -> bool {
    matches!(&row.value.subject,
        arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject)
        if subject == actor)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.capabilities.query",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.capabilities.query"))]
pub(super) async fn admin_list_capabilities(
    admin: AdminAuth,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminCapabilityList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let operator_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let limit = clamp_limit(state, limit.into_inner());
    let cursor = cursor.into_inner();

    let mut filters = BTreeMap::new();
    let realm_filter = query_param(req, "filter[realm_id]")
        .map(|raw| {
            arkret_wire::RealmId::new(raw)
                .map_err(|_| AppError::param_invalid("realm filter requires a complete RealmId"))
        })
        .transpose()?;
    if let Some(realm) = &realm_filter {
        filters.insert("realm_id".to_owned(), realm.to_string());
    }
    if query_param(req, "filter[subject]").is_some() {
        return Err(AppError::param_invalid(
            "use filter[subject_actor_id] with a complete ActorId; principal-only subject filters are invalid",
        ));
    }
    let subject_filter = query_param(req, "filter[subject_actor_id]")
        .map(|raw| {
            let actor: arkret_wire::ActorId = serde_json::from_str(&raw).map_err(|_| {
                AppError::param_invalid("subject filter requires a complete ActorId")
            })?;
            actor
                .validate()
                .map_err(|_| AppError::param_invalid("subject ActorId is invalid"))?;
            Ok::<_, AppError>(actor)
        })
        .transpose()?;
    if let Some(subject) = &subject_filter {
        filters.insert(
            "subject_actor_id".to_owned(),
            arkret_canonical::canonical_json_string(subject)
                .map_err(|error| AppError::internal(format!("ActorId encoding failed: {error}")))?,
        );
    }
    let state_filter = match query_param(req, "filter[state]") {
        Some(raw) => {
            let parsed = CapabilityGrantState::from_wire(&raw).ok_or_else(|| {
                AppError::param_invalid(format!(
                    "unknown capability state filter: {raw} (expected active|revoked|relinquished|all)"
                ))
            })?;
            filters.insert("state".to_owned(), raw);
            parsed
        }
        // Operators inspect grants for audit purposes, so revoked tombstones
        // are visible by default.
        None => CapabilityGrantState::All,
    };

    let mut rows: Vec<CapabilitySummary> = state
        .persistence()
        .all_capability_grant_current_results()
        .await
        .map_err(|error| AppError::internal(format!("capability grant read failed: {error}")))?
        .iter()
        .map(capability_summary)
        .collect();
    if let Some(realm) = &realm_filter {
        rows.retain(|summary| summary.source_stream_ref.realm_id() == realm);
    }
    if let Some(subject) = &subject_filter {
        rows.retain(|summary| capability_subject_matches(summary, subject));
    }
    match state_filter {
        CapabilityGrantState::Active => rows.retain(|summary| summary.value.status == arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Active),
        CapabilityGrantState::Revoked => rows.retain(|summary| summary.value.status == arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Revoked),
        CapabilityGrantState::Relinquished => rows.retain(|summary| summary.value.status == arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Relinquished),
        CapabilityGrantState::All => {}
        // `CapabilityGrantState` is #[non_exhaustive]; fail closed on any
        // future variant instead of silently widening visibility.
        _ => {
            return Err(AppError::param_invalid(
                "unsupported capability state filter",
            ));
        }
    }
    rows.sort_by(|left, right| left.selector.grant_id.cmp(&right.selector.grant_id));
    let total = rows.len() as u64;
    let (capabilities, next_cursor, has_more) =
        paginate_by_id(rows, cursor.as_deref(), limit, |summary| {
            summary.selector.grant_id.as_str()
        })?;

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.capabilities.query",
        json!({"operator_actor_id": operator_actor,
            "device_id": session.require_human_device_id(),
            "filters": filters, "count": capabilities.len()}),
        "accepted",
    )
    .await;
    json_ok(AdminCapabilityList {
        capabilities,
        total: Some(total),
        next_cursor,
        has_more,
        filters,
    })
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

fn admin_device_row(device: &coland_services::identity::DeviceIdentity) -> AdminDevice {
    AdminDevice {
        id: device.device_id.clone(),
        actor_id: Some(device.actor_id.clone()),
        display_name: device.display_name.clone(),
        verification_state: Some(device.verification_state.clone()),
        payload: (!device.payload.is_null()).then(|| device.payload.clone()),
        created_at: Some(device.created_at),
        updated_at: Some(device.updated_at),
        revoked_at: device.revoked_at,
    }
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.devices.query",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.devices.query"))]
pub(super) async fn admin_list_devices(
    admin: AdminAuth,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminDeviceList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let limit = clamp_limit(state, limit.into_inner());
    let cursor = cursor.into_inner();

    let mut filters = BTreeMap::new();
    let name_or_id =
        query_param(req, "filter[name_or_id]").filter(|value| !value.trim().is_empty());
    if let Some(needle) = &name_or_id {
        filters.insert("name_or_id".to_owned(), needle.clone());
    }

    let mut rows: Vec<AdminDevice> = state
        .identities()
        .devices()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to list devices");
            AppError::internal("device store unavailable")
        })?
        .iter()
        .map(admin_device_row)
        .collect();
    if let Some(needle) = &name_or_id {
        let needle = needle.to_lowercase();
        rows.retain(|device| {
            contains_ci(&device.id, &needle)
                || device
                    .actor_id
                    .as_deref()
                    .is_some_and(|actor| contains_ci(actor, &needle))
                || device
                    .display_name
                    .as_deref()
                    .is_some_and(|name| contains_ci(name, &needle))
        });
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let total = rows.len() as u64;
    let (devices, next_cursor, has_more) =
        paginate_by_id(rows, cursor.as_deref(), limit, |device| device.id.as_str())?;

    query_audit_trail(
        state,
        &session,
        "admin.devices.query",
        &filters,
        devices.len(),
    )
    .await;
    json_ok(AdminDeviceList {
        devices,
        total: Some(total),
        next_cursor,
        has_more,
        filters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_actor_projection_is_station_local_and_counts_exact_actor_membership() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let principal_id = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let local_account =
            arkret_wire::AccountId::new(principal_id.clone(), state.service_core_id());
        let foreign_account = arkret_wire::AccountId::new(
            principal_id.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign-station.example").unwrap(),
        );
        let mut account = coland_services::identity::AccountProfileState {
            pk: coland_storage::AccountPk(1),
            account_id: local_account.clone(),
            principal_id: principal_id.clone(),
            localpart: "alice".to_owned(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        };
        let device_counts = BTreeMap::from([(principal_id.to_string(), 1)]);
        let mut projection = coland_domain::reducer::ProjectionState::default();
        for (realm_id, member_account, membership) in [
            ("realm-a", local_account.clone(), "join"),
            ("realm-b", local_account.clone(), "join"),
            ("realm-c", local_account.clone(), "leave"),
            ("realm-d", foreign_account.clone(), "join"),
        ] {
            let member = arkret_wire::ActorId::account(member_account).to_string();
            projection.members.insert(
                (realm_id.to_owned(), member.clone()),
                coland_domain::reducer::ColandMembershipState {
                    member,
                    realm_id: realm_id.to_owned(),
                    state: membership.to_owned(),
                    role: "member".to_owned(),
                    membership_event_ref: None,
                    invited_at: None,
                    joined_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    reason: None,
                },
            );
        }
        let realm_counts = realm_membership_counts(&projection);
        let row = admin_actor_row(&state, &account, &device_counts, &realm_counts, None).unwrap();
        assert_eq!(row.id, principal_id.to_string());
        assert_eq!(row.account_id, Some(local_account.to_string()));
        assert_eq!(row.device_count, Some(1));
        assert_eq!(row.realm_count, Some(2));

        account.account_id = foreign_account;
        assert!(admin_actor_row(&state, &account, &device_counts, &realm_counts, None).is_none());
    }

    #[test]
    fn paginate_by_id_walks_pages_and_flags_has_more() {
        let rows = vec!["a", "b", "c", "d", "e"];
        let (page, next, has_more) =
            paginate_by_id(rows.clone(), None, 2, |row| row).expect("first page");
        assert_eq!(page, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));
        assert!(has_more);

        let (page, next, has_more) =
            paginate_by_id(rows.clone(), Some("b"), 2, |row| row).expect("second page");
        assert_eq!(page, vec!["c", "d"]);
        assert_eq!(next.as_deref(), Some("d"));
        assert!(has_more);

        let (page, next, has_more) =
            paginate_by_id(rows, Some("d"), 2, |row| row).expect("last page");
        assert_eq!(page, vec!["e"]);
        assert_eq!(next, None);
        assert!(!has_more);
    }

    #[test]
    fn paginate_by_id_expired_cursor_is_gone() {
        let error = paginate_by_id(vec!["a", "b"], Some("zz"), 2, |row| row)
            .expect_err("unresolvable cursor must fail");
        assert_eq!(
            error.http_status(),
            coland_http::error::error_http_status(error.code)
        );
    }

    #[test]
    fn audit_kind_filter_uses_only_the_canonical_kind_member() {
        let canonical = audit_entry_from_record(&json!({
            "audit_id": "audit-1",
            "action": "other",
            "payload": {"kind": "target"}
        }))
        .unwrap();
        assert!(audit_matches_kind(&canonical, "target"));

        let retired = audit_entry_from_record(&json!({
            "audit_id": "audit-2",
            "action": "other",
            "payload": {"type": "target"}
        }))
        .unwrap();
        assert!(!audit_matches_kind(&retired, "target"));
    }

    /// Production-mode admin-principal gate: a session whose actor is not
    /// listed in `COLAND_ADMIN_PRINCIPAL_IDS` is a hard 403; listing the
    /// stable principal ID admits it. (The HTTP-level 401 path is covered by the
    /// `admin_production_queries` contract tests; this locks the
    /// authorization decision itself, which dev-mode fixtures cannot reach.)
    #[test]
    fn require_admin_principal_is_fail_closed_in_production() {
        let session = |actor: &str| coland_services::identity::SessionIdentityState {
            account_pk: None,
            token_hash: "hash".to_owned(),
            actor: actor.to_owned(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "ak:device:test".to_owned(),
            },
            audience: "coland".to_owned(),
            session_public_key: None,
            session_grant: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        let state = AppState::new(
            crate::config::AppConfig {
                development_mode: false,
                admin_principal_ids: vec![
                    arkret_identifiers::DidCoreId::new("ak:did_core:web:op.example").unwrap(),
                ],
                ..crate::config::AppConfig::test_default()
            },
            coland_storage_postgres::Db { pool: None },
        );

        let denied =
            super::require_admin_principal(&state, session("ak:did_core:web:nobody.example"))
                .expect_err("non-admin principal must be rejected in production");
        assert_eq!(
            denied.http_status(),
            coland_http::error::error_http_status(denied.code)
        );

        super::require_admin_principal(&state, session("ak:did_core:web:op.example"))
            .expect("listed admin principal must be admitted");
    }

    #[test]
    fn capability_operator_identity_keeps_station_and_denies_foreign_audience() {
        use crate::routing::identity::session_actor::session_actor_from_credential;
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let mut session = coland_services::identity::SessionIdentityState {
            account_pk: None,
            token_hash: "verified-fixture".to_owned(),
            actor: "ak:did_core:web:operator.example".to_owned(),
            audience: state.service_core_id().to_string(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "operator-device".to_owned(),
            },
            session_public_key: None,
            session_grant: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        let actor = session_actor_from_credential(&state, &session).unwrap();
        assert_eq!(
            actor.as_account_id().unwrap().station_id,
            state.service_core_id()
        );
        session.audience = "ak:did_core:web:foreign-station.example".to_owned();
        assert!(session_actor_from_credential(&state, &session).is_err());
    }
}
