//! Dev-only admin collection surfaces.
//!
//! Surfaces:
//! - `GET /_coland/admin/{resource}` — paginated dev snapshot of one of the builtin admin
//!   collections (`realms`, `spaces`, `federation`, `applets`, `agents`, `reports`,
//!   `invite-tokens`, `policy`, `media`, `handles`). `realms` are security boundaries; `spaces` are
//!   authorization-transparent navigation containers.
//!
//! `actors`, `audit`, `capabilities` and `devices` have moved to the typed
//! production query endpoints (D14, see [`super::queries`]) and are no
//! longer served here.
//!
//! Authorization is enforced by the shared `RequireAdmin` middleware with
//! the SDK `admin.read` scope before this handler runs. Further hardening
//! (durable cursor pagination, redaction policy, high-risk audit signing)
//! is tracked under `_todos.md` Q9.

use std::collections::BTreeMap;

use arkret_identifiers::{DidCoreId, RealmId};
use arkret_wire::JoinRule;
use coland_contracts::admin::{
    AdminFederationOperation, AdminMediaRow, AdminRealmItem, AdminSpaceRow, RealmClass, SpaceHealth,
};
use coland_domain::reducer::SpaceContainerLifecycleState;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::events::RealmMetadata as RealmMetaRecord;
use coland_services::operation_semantics as kinds;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    AdminAuth, append_audit_log, discussion_track_for_projection_event,
    policy_document_to_response, projection_event_from_operation, strand_id_for_projection_event,
    strand_id_from_realm_id, strand_projection_for_realm,
};
use crate::state::{AppState, RealmDirectoryEntry};

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminCollectionOutcome {
    resource: String,
    data: Vec<Value>,
    items: Vec<Value>,
    #[serde(flatten)]
    #[salvo(schema(value_type = serde_json::Value))]
    resource_items: BTreeMap<String, Value>,
    total: usize,
    next_cursor: Option<String>,
    production_gap: String,
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.collection",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.collection"))]
pub(super) async fn admin_collection(
    admin: AdminAuth,
    resource: PathParam<String>,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminCollectionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    if !state.config().development_harness_enabled() && !state.is_admin_principal(&session.actor) {
        return Err(AppError::capability_denied(
            "admin collection API requires the caller principal ID to be listed in COLAND_ADMIN_PRINCIPAL_IDS",
        ));
    }
    let grant = super::introspect_admin_scopes(state, req, &session)
        .await
        .map_err(|error| {
            let _http = error.http_status();
            AppError::capability_denied(format!("admin scope check failed: {error}"))
        })?;
    if !grant.has_admin_scope(arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ) {
        return Err(AppError::capability_denied(
            "admin collection API requires admin.read scope",
        ));
    }
    let resource = resource.into_inner();
    let default_limit = state.config().admin_default_page_limit;
    let max_limit = state.config().admin_max_page_limit;
    let limit = limit
        .into_inner()
        .unwrap_or(default_limit)
        .clamp(1, max_limit);
    let cursor = cursor.into_inner();

    let (field, mut items) = match resource.as_str() {
        "realms" => ("realms", admin_realm_items(state).await),
        "spaces" => ("spaces", admin_space_container_items(state)),
        "federation" => ("federation", admin_federation_items(state).await),
        "applets" => ("applets", admin_applet_items(state)),
        "reports" => (
            "reports",
            crate::routing::interop::moderation::moderation_queue_for_session(
                state,
                &session.actor,
                None,
            )
            .await?
            .into_iter()
            .map(|item| json!(item))
            .collect(),
        ),
        "invite-tokens" => (
            "invite_tokens",
            admin_invite_items(state)
                .await
                .into_iter()
                .map(|item| json!(item))
                .collect(),
        ),
        "policy" => ("policy", admin_policy_items(state).await),
        "media" => ("media", admin_media_items(state).await),
        "handles" => (
            "handles",
            super::handles::admin_handle_items(state)
                .await
                .into_iter()
                .map(|item| json!(item))
                .collect(),
        ),
        _ => {
            return Err(AppError::not_found("admin resource not found"));
        }
    };
    items.sort_by_key(|left| left.to_string());
    let start = match cursor.as_deref() {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| AppError::param_invalid("invalid cursor"))?,
        None => 0,
    };
    let total = items.len();
    let mut page = items.into_iter().skip(start).collect::<Vec<_>>();
    let has_more = page.len() > limit;
    if has_more {
        page.truncate(limit);
    }
    let next_cursor = has_more.then(|| (start + limit).to_string());

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.collection",
        json!({
            "resource": resource.clone(),
            "device_id": session.require_human_device_id(),
            "count": page.len(),
        }),
        "accepted",
    )
    .await;

    let mut resource_items = BTreeMap::new();
    resource_items.insert(field.to_owned(), json!(page.clone()));
    json_ok(AdminCollectionOutcome {
        resource,
        data: page.clone(),
        items: page,
        resource_items,
        total,
        next_cursor,
        production_gap: "admin_authorization_and_durable_pagination".to_owned(),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminCreateRealmRequestBody {
    #[serde(default)]
    title: String,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    discoverability: Option<String>,
    #[serde(default, rename = "default_join_rule")]
    #[salvo(schema(value_type = serde_json::Value))]
    default_join_rule: Option<JoinRule>,
    #[serde(default)]
    is_encrypted: bool,
    realm_class: String,
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.realm.create",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.realm.create"))]
pub(super) async fn admin_create_realm(
    admin: AdminAuth,
    body: JsonBody<AdminCreateRealmRequestBody>,
) -> JsonResult<AdminRealmItem> {
    let session = admin.session()?;
    let body = body.into_inner();
    let title = body.title.trim();
    if title.is_empty() {
        return Err(AppError::param_invalid("title is required"));
    }
    if !matches!(
        body.realm_class.as_str(),
        "principal_control" | "collaboration"
    ) {
        return Err(AppError::param_invalid(
            "realm_class must be principal_control or collaboration",
        ));
    }
    let discoverability = body
        .discoverability
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("invite_only");
    if !matches!(discoverability, "public" | "invite_only" | "private") {
        return Err(AppError::param_invalid(
            "discoverability must be public, invite_only, or private",
        ));
    }
    let _ = (discoverability, session);
    Err(AppError::unsupported_feature(
        "Realm creation requires a caller-signed canonical ak.realm.create Event",
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.realm.get",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.realm.get"))]
pub(super) async fn admin_get_realm(
    realm_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<AdminRealmItem> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let realm_id = realm_id.into_inner();
    json_ok(admin_get_realm_item(state, &realm_id).await?)
}

async fn admin_realm_items(state: &AppState) -> Vec<Value> {
    let meta: BTreeMap<String, _> = state
        .realms()
        .realm_metadata_list()
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    // Snapshot the Realm registry under lock, then drop it: downstream
    // helpers (`strand_projection_for_realm` → plaintext-service policy)
    // reach back into `state.realms`, and `Mutex` is non-reentrant — holding
    // the guard across the map closure deadlocks on the second resource pass.
    let realm_snapshot: Vec<RealmDirectoryEntry> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut items = Vec::new();
    for realm in realm_snapshot {
        let realm_id = realm.realm_id.as_str().to_owned();
        items.push(json!(
            admin_realm_item_value(state, realm, meta.get(&realm_id).cloned()).await
        ));
    }
    items
}

pub(super) async fn admin_get_realm_item(
    state: &AppState,
    realm_id: &str,
) -> Result<AdminRealmItem, AppError> {
    let realm_id_value = RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::param_invalid(format!("invalid realm_id: {error}")))?;
    let realm = {
        let realms = state.realm_directory().snapshot();
        realms.get(&realm_id_value).cloned()
    }
    .ok_or_else(|| AppError::not_found("realm not found"))?;
    let realm_meta = state
        .realms()
        .realm_metadata(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(admin_realm_item_value(state, realm, realm_meta).await)
}

async fn admin_realm_item_value(
    state: &AppState,
    realm: RealmDirectoryEntry,
    realm_meta: Option<RealmMetaRecord>,
) -> AdminRealmItem {
    let realm_id = realm.realm_id.as_str().to_owned();
    let strand =
        strand_projection_for_realm(state, &realm_id, &realm.title, realm.description.as_deref())
            .await
            .expect("RealmDirectoryEntry contains a validated canonical RealmId");
    AdminRealmItem {
        kind: "realm".to_owned(),
        id: realm_id.clone(),
        strand,
        strand_id: strand_id_from_realm_id(&realm_id)
            .expect("RealmDirectoryEntry contains a validated canonical RealmId"),
        realm_id,
        title: realm.title,
        topic: realm.description,
        category: realm.category,
        // Both classifiers are closed registry values held as free-form
        // strings by the directory entry / metadata record. An unrecognised
        // stored value projects as `None` — emitting it raw would make the
        // whole admin page unparsable for every consumer of this contract.
        realm_class: realm.realm_class.as_deref().and_then(RealmClass::from_wire),
        discoverability: realm_meta.as_ref().and_then(|meta| {
            serde_json::from_value(Value::String(meta.discoverability.clone())).ok()
        }),
        default_join_rule: realm
            .default_join_rule
            .and_then(|value| serde_json::from_value(Value::String(value)).ok()),
        tags: realm.tags.into_iter().collect(),
        public: realm.public,
        member_count: realm.members.len(),
        members: realm.members.iter().map(ToString::to_string).collect(),
        created_by: realm_meta.as_ref().map(|meta| {
            serde_json::from_str::<arkret_wire::ActorId>(&meta.owner)
                .expect("RealmMetaRecord owner must be a validated complete ActorId")
                .signing_principal_id()
                .clone()
        }),
        history_access: realm_meta.as_ref().map(|meta| meta.history_access.clone()),
        is_encrypted: realm_meta
            .as_ref()
            .and_then(|meta| meta.encryption_profile.as_deref())
            .is_some_and(|profile| profile != "plaintext"),
        is_blocked: realm_meta.as_ref().is_some_and(|meta| meta.deleted),
        plaintext_visible_services: realm_meta
            .as_ref()
            .map(|meta| {
                meta.plaintext_visible_services
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        deleted: realm_meta.as_ref().is_some_and(|meta| meta.deleted),
        created_at: realm_meta.as_ref().map(|meta| meta.created_at),
        updated_at: realm_meta.as_ref().map(|meta| meta.updated_at),
    }
}

fn admin_space_container_items(state: &AppState) -> Vec<Value> {
    let member_counts: BTreeMap<String, usize> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .map(|realm| (realm.realm_id.as_str().to_owned(), realm.members.len()))
            .collect()
    };
    let projection = state.projections().snapshot();
    projection
        .space_containers
        .values()
        .map(|container| {
            json!(AdminSpaceRow {
                id: container.container_space_id.clone(),
                name: container.title.clone(),
                realm_id: container.realm_id.clone(),
                kind: container.kind.clone(),
                member_count: member_counts
                    .get(&container.realm_id)
                    .copied()
                    .unwrap_or_default(),
                health: space_health(container.state),
                created_at: container.created_at,
                parent_space_id: container.parent_ref.clone(),
            })
        })
        .collect()
}

/// Project the reducer lifecycle onto the admin contract's closed set. The
/// match is exhaustive on purpose: a new reducer state must be classified
/// here rather than degrade to a default badge in the console.
fn space_health(state: SpaceContainerLifecycleState) -> SpaceHealth {
    match state {
        SpaceContainerLifecycleState::Active => SpaceHealth::Active,
        SpaceContainerLifecycleState::Archived => SpaceHealth::Archived,
        SpaceContainerLifecycleState::Tombstoned => SpaceHealth::Tombstoned,
    }
}

async fn admin_federation_items(state: &AppState) -> Vec<Value> {
    state
        .federation()
        .operations()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|operation| {
            let projected = projection_event_from_operation(&operation, None);
            let strand_id = strand_id_for_projection_event(&projected);
            let track = discussion_track_for_projection_event(&projected, strand_id.as_deref())
                .and_then(|value| value.as_str().map(ToOwned::to_owned));
            let canonical_kind = kinds::canonical_kind(&operation);
            let digest = operation.operation_digest().ok();
            json!(AdminFederationOperation {
                kind: "federation_operation".to_owned(),
                operation_id: operation.operation_id,
                realm_id: operation.realm_id,
                operation_kind: operation.operation_kind,
                canonical_kind,
                strand_id,
                track,
                digest,
                created_at: operation.created_at,
            })
        })
        .collect()
}

/// Snapshot of the in-memory applet registry maintained
/// by `reducer::ProjectionState::applets`. Each row is one applet
/// identified by canonical `applet_id`, with the latest registration metadata.
/// Empty until a `ak.applet.registration` or
/// `ak.applet.discovery` event has been accepted.
fn admin_applet_items(state: &AppState) -> Vec<Value> {
    let proj = state.projections().snapshot();
    proj.applets
        .values()
        .map(|applet| {
            json!({
                "applet_id": applet.applet_id,
                "service_id": applet.service_id,
                "capabilities": applet.capabilities,
                "claimed_profiles": applet.claimed_profiles,
                "registration_epoch": applet.registration_epoch,
                "registered_at": arkret_canonical::format_timestamp_canonical(
                    applet.registered_at
                ),
                "updated_at": arkret_canonical::format_timestamp_canonical(
                    applet.updated_at
                ),
            })
        })
        .collect()
}

pub(super) async fn admin_invite_items(
    state: &AppState,
) -> Vec<coland_contracts::admin::invite_tokens::AdminInviteTokenItem> {
    state
        .persistence()
        .invites_in_realm(None)
        .await
        .unwrap_or_default()
        .iter()
        .map(admin_invite_item)
        .collect()
}

pub(super) fn admin_invite_item(
    invite: &coland_storage::InviteCurrent,
) -> coland_contracts::admin::invite_tokens::AdminInviteTokenItem {
    let inviter = invite.inviter.signing_principal_id().clone();
    let invitee = invite
        .invitee_account_id
        .as_ref()
        .or_else(|| {
            invite
                .accepted_claim
                .as_ref()
                .map(|claim| &claim.subject_account_id)
        })
        .map(|account| account.principal_id.clone());
    coland_contracts::admin::invite_tokens::AdminInviteTokenItem {
        kind: "invite_token".to_owned(),
        id: invite.invite_id.to_string(),
        invite_id: invite.invite_id.to_string(),
        realm_id: invite.realm_id.to_string(),
        inviter_id: inviter.clone(),
        created_by: inviter,
        invitee_id: invitee,
        introduction_evidence_digest: invite
            .introduction_evidence_digest
            .as_ref()
            .map(ToString::to_string),
        status: invite.state.as_str().to_owned(),
        uses_allowed: 1,
        uses_completed: u64::from(invite.state == arkret_wire::InviteState::Accepted),
        uses_pending: u64::from(invite.state == arkret_wire::InviteState::Pending),
        expires_at: Some(invite.expires_at),
        created_at: invite.created_at,
    }
}

async fn admin_policy_items(state: &AppState) -> Vec<Value> {
    state
        .governance()
        .policy_documents()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|policy| policy_document_to_response(policy).ok())
        .map(|policy| json!(policy))
        .collect()
}

pub(super) async fn admin_media_items(state: &AppState) -> Vec<Value> {
    state
        .deliveries()
        .blobs()
        .await
        .unwrap_or_default()
        .iter()
        .map(|blob| {
            json!(AdminMediaRow {
                kind: "media".to_owned(),
                sha256: blob.sha256.clone(),
                media_type: blob.media_type.clone(),
                filename: blob.filename.clone(),
                realm_id: blob.realm_id.clone(),
                encrypted: blob.encryption.is_some(),
                uploaded_by: DidCoreId::new(blob.uploaded_by.clone())
                    .expect("BlobRecord uploaded_by must be a validated DID core id"),
                // The blob store keeps the byte count signed; the wire
                // contract does not, so a corrupt negative row reports 0
                // rather than wrapping to 18 exabytes.
                size_bytes: blob.size_bytes.max(0) as u64,
                created_at: blob.created_at,
            })
        })
        .collect()
}
