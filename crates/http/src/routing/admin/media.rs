//! Media admin aggregation endpoints.

use std::collections::BTreeMap;

use arkret_identifiers::RealmId;
use arkret_models_collaboration::events_payloads::RealmMediaServicePayload;
use coland_contracts::admin::{
    AdminMediaBucket, AdminMediaByActorList, AdminMediaByActorRow, AdminMediaStatistics,
    AdminRealmMediaService,
};
use coland_http::error::AppError;
use coland_services::delivery::BlobState as BlobRecord;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AdminAuth, append_audit_log, require_admin_principal};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("media/statistics").get(get_media_statistics))
        .push(Router::with_path("media/by-actor").get(get_media_by_actor))
        .push(
            Router::with_path("realms/{realm_id}/media-service").get(admin_get_realm_media_service),
        )
}

/// Project the stored `ak.component.realm.media_service.v1` cell onto the
/// shared admin contract (`bindings/livekit.md` §2 /
/// `media-service-binding.md` §2).
///
/// A focus that does not satisfy the binding shape is a reducer bug, not an
/// operator condition: it is surfaced as an internal error instead of being
/// dropped, so a misconfigured Realm cannot look healthy in the console.
fn response_from_media_cell(
    realm_id: &str,
    value: Option<&Value>,
) -> Result<AdminRealmMediaService, AppError> {
    let Some(value) = value else {
        return Ok(AdminRealmMediaService {
            realm_id: realm_id.to_owned(),
            service_id: None,
            foci: Vec::new(),
        });
    };
    let payload =
        serde_json::from_value::<RealmMediaServicePayload>(value.clone()).map_err(|error| {
            AppError::internal(format!("invalid media_service projection: {error}"))
        })?;
    let descriptor = payload.value;
    descriptor.validate().map_err(|error| {
        AppError::internal(format!("invalid media_service projection: {error}"))
    })?;
    Ok(AdminRealmMediaService {
        realm_id: realm_id.to_owned(),
        service_id: Some(descriptor.service_id.to_string()),
        foci: descriptor.foci,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.realms.media_service.get",
    tags("coland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.admin.realms.media_service.get")
)]
async fn admin_get_realm_media_service(
    admin: AdminAuth,
    depot: &mut Depot,
    realm_id: PathParam<String>,
) -> JsonResult<AdminRealmMediaService> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let realm_id = realm_id.into_inner();
    if RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::param_invalid(format!(
            "invalid realm_id `{realm_id}`: must be a typed ak:realm: id"
        )));
    }
    let value = {
        let proj = state.projections().snapshot();
        proj.realm_facet_value(
            &realm_id,
            coland_domain::reducer::facet::REALM_MEDIA_SERVICE,
        )
        .cloned()
    };

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.media.realm_media_service",
        json!({
            "realm_id": realm_id,
            "present": value.is_some(),
            "device_id": session.require_human_device_id(),
        }),
        "accepted",
    )
    .await;

    json_ok(response_from_media_cell(&realm_id, value.as_ref())?)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.media.statistics",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.media.statistics"))]
async fn get_media_statistics(
    admin: AdminAuth,
    depot: &mut Depot,
) -> JsonResult<AdminMediaStatistics> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let blobs = media_snapshot(state).await;
    let by_actor = media_by_actor_rows(state, &blobs).await;
    let mut by_media_type: BTreeMap<String, AdminMediaBucket> = BTreeMap::new();
    let mut by_realm: BTreeMap<String, AdminMediaBucket> = BTreeMap::new();
    let mut total_size = 0_u64;
    let mut encrypted_count = 0_u64;

    for blob in &blobs {
        let size = blob.size_bytes.max(0) as u64;
        total_size = total_size.saturating_add(size);
        if blob.encryption.is_some() {
            encrypted_count += 1;
        }
        add_bucket(&mut by_media_type, &blob.media_type, size);
        if let Some(realm_id) = blob.realm_id.as_deref() {
            add_bucket(&mut by_realm, realm_id, size);
        }
    }

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.media.statistics",
        json!({
            "count": blobs.len(),
            "device_id": session.require_human_device_id(),
        }),
        "accepted",
    )
    .await;

    json_ok(AdminMediaStatistics {
        total_blobs: blobs.len() as u64,
        total_size,
        encrypted_count,
        quarantined_count: 0,
        by_media_type,
        by_realm,
        by_actor,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.media.by_actor",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.media.by_actor"))]
async fn get_media_by_actor(
    admin: AdminAuth,
    depot: &mut Depot,
) -> JsonResult<AdminMediaByActorList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let session = require_admin_principal(state, session)?;
    let blobs = media_snapshot(state).await;
    let rows = media_by_actor_rows(state, &blobs).await;

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.media.by_actor",
        json!({
            "actor_count": rows.len(),
            "device_id": session.require_human_device_id(),
        }),
        "accepted",
    )
    .await;

    let total = rows.len();
    json_ok(AdminMediaByActorList {
        data: rows,
        total,
        next_cursor: None,
    })
}

async fn media_snapshot(state: &AppState) -> Vec<BlobRecord> {
    state.deliveries().blobs().await.unwrap_or_default()
}

async fn media_by_actor_rows(state: &AppState, blobs: &[BlobRecord]) -> Vec<AdminMediaByActorRow> {
    let accounts: BTreeMap<String, _> = state
        .identities()
        .accounts()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|account| (account.principal_id.to_string(), account))
        .collect();
    let mut rows: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for blob in blobs {
        let size = blob.size_bytes.max(0) as u64;
        let entry = rows.entry(blob.uploaded_by.clone()).or_default();
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(size);
    }
    rows.into_iter()
        .map(|(actor_id, (blob_count, total_size))| {
            let display_name = accounts
                .get(&actor_id)
                .and_then(|account| account.display_name.clone());
            AdminMediaByActorRow {
                actor_id,
                display_name,
                blob_count,
                total_size,
            }
        })
        .collect()
}

fn add_bucket(buckets: &mut BTreeMap<String, AdminMediaBucket>, key: &str, size: u64) {
    let entry = buckets.entry(key.to_owned()).or_default();
    entry.count += 1;
    entry.total_size = entry.total_size.saturating_add(size);
}
