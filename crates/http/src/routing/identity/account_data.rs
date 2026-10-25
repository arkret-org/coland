//! Actor-private account data protocol handlers.
//!
//! Protocol writes use `ak.account_data.set` actor-private events and
//! `ak.self.account.stream.subscribe.v1` for sync/read. This module is mounted under
//! `/_arkret/self/account_data*`.
//!
//! Spec: `discovery/client-preferences.md` §2 (storage model) plus the per-key
//! sections (§3.1 Space tags, §3.5 blocklist, §3.6 contact remarks, §3.7 Space
//! remarks, §3.8 read-receipt preferences). The server treats `payload` as an
//! opaque encrypted blob; clients own canonical encoding, schema validation,
//! and (where applicable) encryption.

use arkret_models_identity::account::{
    AccountDataDeleteRequestBody, AccountDataDeleteResponseBody, AccountDataEntry, AccountDataList,
    AccountDataReplaceRequestBody, AccountDataRevisionProblemExtensions,
};
use coland_http::error::AppError;
use coland_services::identity::{AccountDataState, FindAgentControllerQuery, IdentityService};
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::Value;

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

const MAX_ACCOUNT_DATA_KEY_BYTES: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// AKP-0008 / AKP-0009 (spec head 37ce729) — controller-private account-data
/// types. Writers MUST be the controller principal (not their own agent
/// runtime, not an applet-bound ghost).
struct AccountDataKeySpec {
    account_data_key: &'static str,
    /// When `true`, only the controller principal may write the entry.
    /// Agents / applets / service principals are rejected with
    /// `capability_denied` even if they hold a controller-scoped session.
    controller_private: bool,
}

const REGISTERED_ACCOUNT_DATA_KEY_PATTERNS: &[AccountDataKeySpec] = &[
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::AGENT_DRAFT_V1,
        controller_private: true,
    },
    // `ak.agent.sidecar_projection.v1` was removed from the account-data
    // registry on 2026-07-23: the exchange projection is a controller-device
    // local Event-fold cache and never an account-data surface
    // (zh/models/sidecar.md §7.2.4).
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::AGENT_SIDECAR_VIEW_STATE_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::REMINDERS_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::SCHEDULED_SEND_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::SNOOZE_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::SAVED_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::DRAFT_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::FILE_TRANSFER_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::SEARCH_INDEX_MANIFEST_V1,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::DND_SCHEDULE,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::PRESENCE_PREFERENCE,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::PRESENCE_VISIBILITY,
        controller_private: true,
    },
    AccountDataKeySpec {
        account_data_key: arkret_wire::AccountDataKey::PUSH_RULES,
        controller_private: true,
    },
];

fn registered_account_data_key_spec(account_data_key: &str) -> Option<&'static AccountDataKeySpec> {
    let canonical_type =
        crate::routing::account_data_encryption::encrypted_account_data_prefix(account_data_key)
            .unwrap_or(account_data_key);
    REGISTERED_ACCOUNT_DATA_KEY_PATTERNS
        .iter()
        .find(|spec| spec.account_data_key == canonical_type)
}

/// Controller-private account data never crosses to Agent runtime sessions:
/// neither over resource reads nor over the account stream, even when an
/// agent-granted session presents the controller as its actor
/// (zh/models/sidecar.md §7 / private-objects.md §4.2).
pub(crate) fn is_controller_private_account_data_key(account_data_key: &str) -> bool {
    registered_account_data_key_spec(account_data_key).is_some_and(|spec| spec.controller_private)
}

fn validate_registered_account_data_key(account_data_key: &str) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_key(account_data_key)
        .map_err(|error| AppError::param_invalid(error.message()))?;
    let is_holder_writable_encrypted = arkret_schema::account_data_pattern(account_data_key)
        .is_some_and(|descriptor| {
            descriptor.storage == "encrypted_account_data"
                && descriptor.writer_authorities.contains(&"holder_event")
                && !descriptor.holder_self_operations.is_empty()
        });
    if !is_holder_writable_encrypted {
        return Err(AppError::param_invalid(
            crate::routing::account_data_encryption::AccountDataEncryptionError::InvalidKeyPattern
                .message(),
        ));
    }
    Ok(())
}

/// Resource reads cover both holder-authored encrypted cells and the two
/// registry-declared plaintext inboxes written by the Station.  The
/// write validator above deliberately remains narrower: a holder must never
/// gain PUT/DELETE authority over a `station_cas` cell merely because
/// it is readable through the actor-private account-data resource.
fn validate_readable_account_data_key(account_data_key: &str) -> Result<(), AppError> {
    let is_plaintext_service_cas = is_station_cas_account_data_key(account_data_key);
    if is_plaintext_service_cas {
        return Ok(());
    }
    validate_registered_account_data_key(account_data_key)
}

pub(crate) fn is_station_cas_account_data_key(account_data_key: &str) -> bool {
    arkret_schema::account_data_pattern(account_data_key).is_some_and(|descriptor| {
        descriptor.storage == "plaintext_account_data"
            && descriptor.writer_authorities.contains(&"station_cas")
            && descriptor.holder_self_operations.is_empty()
            && descriptor.write_event_kinds.is_empty()
    })
}

fn validate_private_account_data_content_for_actor(
    actor_id: &arkret_wire::ActorId,
    account_data_key: &str,
    content: &Value,
) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_value_for_actor(
        account_data_key,
        content,
        Some(actor_id),
    )
    .map_err(|error| AppError::param_invalid(error.message()))
}

#[cfg(test)]
fn validate_private_account_data_content(
    account_data_key: &str,
    content: &Value,
) -> Result<(), AppError> {
    crate::routing::account_data_encryption::validate_encrypted_account_data_value(
        account_data_key,
        content,
    )
    .map_err(|error| AppError::param_invalid(error.message()))
}

pub(super) fn router() -> Router {
    Router::with_path("account_data")
        .get(list_account_data)
        .push(
            Router::with_path("{account_data_key}")
                .get(get_account_data)
                .put(put_account_data)
                .delete(delete_account_data),
        )
}

fn validate_account_data_key(account_data_key: &str) -> Result<(), AppError> {
    if account_data_key.is_empty() {
        return Err(AppError::param_invalid(
            "account_data_key must not be empty",
        ));
    }
    if account_data_key.len() > MAX_ACCOUNT_DATA_KEY_BYTES {
        return Err(AppError::param_invalid("account_data_key too long"));
    }
    // Keys are dot-delimited namespaces (`ak.contacts.realm.<realm_id>` etc.).
    // Reject control chars / whitespace / path separators to keep them URL- and
    // log-safe; everything else (including the `:` in `ak:space:<uuid>`) is
    // permitted so the canonical wire keys round-trip.
    if account_data_key.chars().any(|c| {
        c.is_control() || c.is_whitespace() || c == '/' || c == '\\' || c == '?' || c == '#'
    }) {
        return Err(AppError::param_invalid(
            "account_data_key contains forbidden character",
        ));
    }
    Ok(())
}

fn entry_from(record: AccountDataState) -> AccountDataEntry {
    AccountDataEntry {
        account_data_key: record.account_data_key,
        revision: record.revision,
        content: record.payload,
        updated_at: record.updated_at,
    }
}

fn account_data_revision_extensions(
    account_data_key: &str,
    current: Option<&AccountDataState>,
) -> AccountDataRevisionProblemExtensions {
    AccountDataRevisionProblemExtensions {
        account_data_key: account_data_key.to_owned(),
        current_revision: current.map_or(0, |record| record.revision),
        current_entry: current
            .filter(|record| !record.tombstone)
            .cloned()
            .map(entry_from),
    }
}

fn with_account_data_revision_extensions(
    mut error: AppError,
    account_data_key: &str,
    current: Option<&AccountDataState>,
) -> AppError {
    let fields = serde_json::to_value(account_data_revision_extensions(account_data_key, current))
        .expect("account data revision extensions serialize");
    for (key, value) in fields.as_object().expect("extension fragment is an object") {
        error = error.with_wire_detail(key, value);
    }
    error
}

fn account_data_cas_conflict(
    account_data_key: &str,
    current: Option<&AccountDataState>,
) -> AppError {
    let error = crate::app_error!(
        CasConflict,
        "expected_server_revision does not match current account data revision",
    );
    with_account_data_revision_extensions(error, account_data_key, current)
}

fn account_data_not_found(account_data_key: &str, current: Option<&AccountDataState>) -> AppError {
    with_account_data_revision_extensions(
        AppError::not_found("not found"),
        account_data_key,
        current,
    )
}

async fn session_actor_is_agent_runtime(
    identity: &IdentityService,
    actor: &str,
) -> Result<bool, AppError> {
    identity
        .find_agent_controller(FindAgentControllerQuery {
            agent_id: actor.to_owned(),
        })
        .await
        .map(|controller| controller.is_some())
        .map_err(|error| AppError::internal(format!("agent principal lookup failed: {error}")))
}

/// Unified agent-context predicate for the controller-private gate. A session
/// is an agent context when it carries an agent grant marker OR when its actor
/// is itself a registered agent runtime principal — put/delete and get/list
/// MUST agree on this so a Agent principal cannot read what it is
/// forbidden to write (non-disclosure: get stays `not_found`, list filters).
async fn session_is_agent_context(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
) -> Result<bool, AppError> {
    if session.agent_session().is_some() {
        return Ok(true);
    }
    session_actor_is_agent_runtime(state.identities(), &session.actor).await
}

/// Admit the holder-signed `ak.account_data.set` the caller submitted.
///
/// The holder signs; the service never authors this Event. This function
/// checks the Event says what the endpoint promised and then admits the
/// caller's exact bytes as an actor-private Event whose only effect is the
/// holder's account-data register.
///
/// Returns the accepted revision.
async fn admit_caller_signed_account_data_set(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    account_data_key: &str,
    submission: arkret_wire::EventAdmissionSubmission,
    expect_tombstone: bool,
) -> Result<u64, AppError> {
    submission.validate().map_err(|error| {
        AppError::schema_violation(format!("invalid account data submission: {error}"))
    })?;
    let set_event = submission.event;
    let event = &set_event;
    let session_actor = super::session_actor::session_actor_from_credential(state, session)?;
    validate_account_data_holder(event, &session_actor)?;
    let account_key = session_actor.to_string();
    if event.kind != arkret_wire::EventKind::AccountDataSet {
        return Err(crate::app_error!(
            SchemaViolation,
            format!(
                "set_event.kind must be {}",
                arkret_wire::EventKind::AccountDataSet
            ),
        ));
    }
    let payload_str = |field: &str| -> Option<String> {
        event
            .payload
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    if payload_str("key").as_deref() != Some(account_data_key) {
        return Err(crate::app_error!(
            SchemaViolation,
            "set_event payload.key must equal the path account_data_key",
        ));
    }
    let has_tombstone = event
        .payload
        .get("tombstone")
        .is_some_and(|value| value != &Value::Bool(false));
    if expect_tombstone != has_tombstone {
        return Err(crate::app_error!(
            SchemaViolation,
            if expect_tombstone {
                "set_event payload must carry tombstone on this endpoint"
            } else {
                "set_event payload must not carry tombstone; use the delete endpoint"
            },
        ));
    }
    let expected_revision = event
        .payload
        .get("expected_server_revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            crate::app_error!(
                SchemaViolation,
                "set_event payload.expected_server_revision is required",
            )
        })?;

    // The store judges the CAS after exact retry, so a byte-identical retry of
    // an accepted write returns its revision instead of a conflict.
    let revision = expected_revision.checked_add(1).ok_or_else(|| {
        crate::app_error!(
            CasConflict,
            "account data revision high-water mark is exhausted",
        )
    })?;

    // The caller's exact signed bytes are admitted as an actor-private Event:
    // no RealmCommit covers them (actor-private-effects.md section 1).
    match crate::state::admit_account_data_set(state, session, &set_event).await {
        Ok(_) => {}
        Err(error) if error.conflict_code() == Some(coland_storage::ConflictCode::CasConflict) => {
            let current = state
                .account_data()
                .entry(&account_key, account_data_key)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            return Err(account_data_cas_conflict(
                account_data_key,
                current.as_ref(),
            ));
        }
        Err(error) => return Err(crate::state::actor_private_refusal(error)),
    }
    Ok(revision)
}

fn validate_account_data_holder(
    event: &arkret_wire::Event,
    authenticated_actor: &arkret_wire::ActorId,
) -> Result<(), AppError> {
    if event.actor_id != *authenticated_actor {
        return Err(crate::app_error!(
            PolicyViolation,
            "set_event.actor_id must be the authenticated Account Actor",
        ));
    }
    Ok(())
}

#[endpoint(
    operation_id = "ak.self.account_data.resource.replace",
    summary = "Replace an account-data entry",
    tags("account_data")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.replace.v1"))]
async fn put_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    account_data_key: PathParam<String>,
    body: JsonBody<AccountDataReplaceRequestBody>,
) -> JsonResult<AccountDataEntry> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_data_key = account_data_key.into_inner();
    validate_account_data_key(&account_data_key)?;
    if is_service_internal_account_data_key(&account_data_key) {
        return Err(AppError::not_found("not found"));
    }
    validate_registered_account_data_key(&account_data_key)?;

    // AKP-0008 / AKP-0009: registered agent account-data types are
    // controller-private; Agent principals cannot write them directly,
    // and neither can an agent-granted session that presents the controller
    // as its actor.
    if let Some(spec) = registered_account_data_key_spec(&account_data_key)
        && spec.controller_private
        && session_is_agent_context(state, &session).await?
    {
        return Err(AppError::capability_denied(format!(
            "{} is controller-private; agent runtimes cannot write it",
            spec.account_data_key
        )));
    }

    let body = body.into_inner();
    let account_actor = super::session_actor::session_actor_from_credential(state, &session)?;
    validate_account_data_holder(&body.set_event.event, &account_actor)?;
    let account_key = account_actor.to_string();
    let content = body
        .set_event
        .event
        .payload
        .get("body")
        .or_else(|| body.set_event.event.payload.get("encrypted_payload"))
        .cloned()
        .ok_or_else(|| {
            crate::app_error!(
                SchemaViolation,
                "set_event payload must carry body or encrypted_payload",
            )
        })?;
    validate_private_account_data_content_for_actor(&account_actor, &account_data_key, &content)?;
    // Server-side guard against runaway payloads. Canonical serialisation is
    // the client's job; we just cap the wire size to keep one bad client from
    // filling the row with megabytes of base64.
    if serde_json::to_vec(&content)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
        > MAX_PAYLOAD_BYTES
    {
        return Err(crate::app_error!(
            PayloadTooLarge,
            "account_data payload exceeds 64 KiB",
        ));
    }

    let existed = state
        .account_data()
        .entry(&account_key, &account_data_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some_and(|record| !record.tombstone);

    // The accepted row is the signed write itself, so an exact retry answers
    // with the value it wrote even after a later revision replaced it.
    let updated_at = body
        .set_event
        .event
        .payload
        .get("updated_at")
        .cloned()
        .map(serde_json::from_value::<chrono::DateTime<chrono::Utc>>)
        .transpose()
        .map_err(|error| {
            AppError::schema_violation(format!("set_event payload.updated_at: {error}"))
        })?
        .unwrap_or(body.set_event.event.created_at);
    let revision = admit_caller_signed_account_data_set(
        state,
        &session,
        &account_data_key,
        body.set_event,
        false,
    )
    .await?;
    let record = AccountDataState {
        actor_id: account_key,
        account_data_key: account_data_key.clone(),
        revision,
        payload: content,
        tombstone: false,
        updated_at,
    };

    super::append_audit_log(
        state,
        Some(&session.actor),
        "account_data.set",
        serde_json::json!({"account_data_key": account_data_key}),
        "accepted",
    )
    .await;
    if !existed {
        res.status_code(StatusCode::CREATED);
    }
    json_ok(entry_from(record))
}

#[endpoint(
    operation_id = "ak.self.account_data.resource.get",
    summary = "Get an account-data entry",
    tags("account_data")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.get.v1"))]
async fn get_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_data_key: PathParam<String>,
) -> JsonResult<AccountDataEntry> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_key =
        super::session_actor::session_actor_from_credential(state, &session)?.to_string();
    let account_data_key = account_data_key.into_inner();
    validate_account_data_key(&account_data_key)?;
    if is_service_internal_account_data_key(&account_data_key) {
        return Err(AppError::not_found("not found"));
    }
    validate_readable_account_data_key(&account_data_key)?;

    // Controller-private entries are indistinguishable from absent ones for
    // Agent runtime sessions (fail closed, no existence disclosure). Same
    // predicate as put/delete: agent grant marker OR Agent principal.
    if is_controller_private_account_data_key(&account_data_key)
        && session_is_agent_context(state, &session).await?
    {
        return Err(AppError::not_found("not found"));
    }

    if matches!(
        account_data_key.as_str(),
        arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE
            | arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY
    ) {
        crate::routing::consent_private::refresh_holder_effects(state, &session).await?;
    }
    match state
        .account_data()
        .entry(&account_key, &account_data_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(record) if !record.tombstone => json_ok(entry_from(record)),
        current => Err(account_data_not_found(&account_data_key, current.as_ref())),
    }
}

#[endpoint(
    operation_id = "ak.self.account_data.read.list",
    summary = "List account-data entries",
    tags("account_data")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.read.list.v1"))]
async fn list_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountDataList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_key =
        super::session_actor::session_actor_from_credential(state, &session)?.to_string();
    // Same predicate as put/delete: agent grant marker OR Agent
    // principal (non-disclosure list filtering).
    let agent_context = session_is_agent_context(state, &session).await?;
    if !agent_context && session.human_device_id().is_some() {
        crate::routing::consent_private::refresh_holder_effects(state, &session).await?;
    }
    let entries = state
        .account_data()
        .entries_for_actor(&account_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .filter(|record| {
            !is_service_internal_account_data_key(&record.account_data_key)
                && !(agent_context
                    && is_controller_private_account_data_key(&record.account_data_key))
        })
        .map(entry_from)
        .collect();
    json_ok(AccountDataList {
        account_data_entries: entries,
    })
}

/// Service-owned coordination rows share the AccountData storage primitive so
/// they can use its durable CAS semantics, but they are not protocol account
/// data and must never cross a holder or Agent read/sync boundary.
pub(crate) fn is_service_internal_account_data_key(key: &str) -> bool {
    key.starts_with("ak.internal.")
}

#[endpoint(
    operation_id = "ak.self.account_data.resource.delete",
    summary = "Delete an account-data entry",
    tags("account_data")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account_data.resource.delete.v1"))]
async fn delete_account_data(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_data_key: PathParam<String>,
    body: JsonBody<AccountDataDeleteRequestBody>,
) -> JsonResult<AccountDataDeleteResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_data_key = account_data_key.into_inner();
    validate_account_data_key(&account_data_key)?;
    if is_service_internal_account_data_key(&account_data_key) {
        return Err(AppError::not_found("not found"));
    }
    validate_registered_account_data_key(&account_data_key)?;
    if is_controller_private_account_data_key(&account_data_key)
        && session_is_agent_context(state, &session).await?
    {
        return Err(AppError::capability_denied(format!(
            "{account_data_key} is controller-private; agent runtimes cannot delete it"
        )));
    }
    if arkret_schema::account_data_pattern(&account_data_key)
        .is_some_and(|descriptor| descriptor.deletion_mode == "value_tombstone")
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "this account data type requires an in-value tombstone",
        )
        .with_internal_reason("physical_delete_forbidden"));
    }

    let revision = admit_caller_signed_account_data_set(
        state,
        &session,
        &account_data_key,
        body.into_inner().set_event,
        true,
    )
    .await?;

    super::append_audit_log(
        state,
        Some(&session.actor),
        "account_data.delete",
        serde_json::json!({"account_data_key": account_data_key}),
        "accepted",
    )
    .await;
    json_ok(AccountDataDeleteResponseBody {
        account_data_key,
        revision,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use coland_services::ServiceResult;
    use coland_services::identity::{
        AccountIdentity, AccountLifecycleState, AccountLocalpartState, AccountLookupPort,
        AccountProfileState, AgentController, AgentDirectoryPort, DeviceDirectoryPort,
        DeviceIdentity, SaveDeviceCommand,
    };
    use coland_storage::AccountPk;
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn revision_problem_extensions_are_shared_flat_and_keep_tombstone_high_water() {
        let mut record = AccountDataState {
            actor_id: "holder".to_owned(),
            account_data_key: "ak.client.ui_state".to_owned(),
            revision: 7,
            payload: json!({"theme": "dark"}),
            tombstone: false,
            updated_at: DateTime::parse_from_rfc3339("2026-10-25T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        for tombstone in [false, true] {
            record.tombstone = tombstone;
            for error in [
                account_data_cas_conflict(&record.account_data_key, Some(&record)),
                account_data_not_found(&record.account_data_key, Some(&record)),
            ] {
                let value = serde_json::to_value(error.wire_details.as_deref().unwrap()).unwrap();
                assert!(value.get("details").is_none());
                let fields: AccountDataRevisionProblemExtensions =
                    serde_json::from_value(value).unwrap();
                assert_eq!(fields.current_revision, 7);
                assert_eq!(fields.current_entry.is_some(), !tombstone);
            }
        }
        let fields = account_data_revision_extensions(&record.account_data_key, None);
        assert_eq!(fields.current_revision, 0);
        assert!(fields.current_entry.is_none());
    }

    #[test]
    fn account_data_holder_requires_the_exact_station_account() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::AccountDataSet.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                )
                .unwrap(),
            },
            actor.clone(),
            json!({"key": "ak.dnd_schedule", "expected_server_revision": 0, "tombstone": true}),
            chrono::Utc::now(),
        )
        .unwrap();
        validate_account_data_holder(&event, &actor).unwrap();
        // Same principal at another Station is a different Account, and
        // account-data is per-Account.
        event.actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal,
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert_eq!(
            validate_account_data_holder(&event, &actor)
                .unwrap_err()
                .wire_code(),
            "policy_violation"
        );
    }

    struct NoAccounts;
    struct NoDevices;
    struct AgentClassifier;

    #[async_trait]
    impl AccountLookupPort for NoAccounts {
        async fn find_account_by_actor(
            &self,
            _account_id: &arkret_wire::AccountId,
        ) -> ServiceResult<Option<AccountIdentity>> {
            Ok(None)
        }

        async fn account_by_id(
            &self,
            _account_pk: AccountPk,
        ) -> ServiceResult<Option<AccountProfileState>> {
            Ok(None)
        }

        async fn register_account(
            &self,
            _command: coland_services::identity::RegisterAccountCommand,
        ) -> ServiceResult<AccountIdentity> {
            unreachable!("NoAccounts mock: register_account is not exercised by these tests")
        }

        async fn account(
            &self,
            _account_id: &arkret_wire::AccountId,
        ) -> ServiceResult<Option<AccountProfileState>> {
            Ok(None)
        }

        async fn accounts(&self) -> ServiceResult<Vec<AccountProfileState>> {
            Ok(Vec::new())
        }

        async fn save_account(&self, _account: AccountProfileState) -> ServiceResult<()> {
            Ok(())
        }

        async fn delete_account(&self, _account_id: &arkret_wire::AccountId) -> ServiceResult<()> {
            Ok(())
        }

        async fn account_localparts(
            &self,
            _account_pk: AccountPk,
        ) -> ServiceResult<Vec<AccountLocalpartState>> {
            Ok(Vec::new())
        }

        async fn localpart_owner(
            &self,
            _localpart: &str,
        ) -> ServiceResult<Option<AccountLocalpartState>> {
            Ok(None)
        }

        async fn add_localpart(
            &self,
            _account_pk: AccountPk,
            _localpart: &str,
            _primary: bool,
        ) -> ServiceResult<AccountLocalpartState> {
            unreachable!("NoAccounts mock: add_localpart is not exercised by these tests")
        }

        async fn remove_localpart(
            &self,
            _account_pk: AccountPk,
            _localpart: &str,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn clear_localparts(&self, _account_pk: AccountPk) -> ServiceResult<()> {
            Ok(())
        }

        async fn record_handle_release(
            &self,
            _localpart: &str,
            _released_at: DateTime<Utc>,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn save_account_lifecycle(
            &self,
            _account_pk: AccountPk,
            _actor_id: &str,
            _lifecycle: AccountLifecycleState,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn delete_account_lifecycle(
            &self,
            _account_pk: AccountPk,
            _actor_id: &str,
        ) -> ServiceResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceDirectoryPort for NoDevices {
        async fn list_active_device_actors(&self) -> ServiceResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn devices(&self) -> ServiceResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }

        async fn find_device(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ServiceResult<Option<DeviceIdentity>> {
            Ok(None)
        }

        async fn save_device(&self, _command: SaveDeviceCommand) -> ServiceResult<()> {
            Ok(())
        }

        async fn save_device_if_absent(&self, _device: DeviceIdentity) -> ServiceResult<bool> {
            Ok(true)
        }

        async fn devices_for_actor(&self, _actor_id: &str) -> ServiceResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl AgentDirectoryPort for AgentClassifier {
        async fn find_agent_controller(
            &self,
            agent_id: &str,
        ) -> ServiceResult<Option<AgentController>> {
            Ok(
                (agent_id == "did:web:agent.alice.example").then(|| AgentController {
                    controller_principal_id: "ak:did_core:web:alice.example".to_owned(),
                }),
            )
        }
    }

    fn encrypted_envelope(account_data_key: &str) -> Value {
        let actor_id =
            crate::test_account_actor(&arkret_wire::Did::new("did:web:alice.example").unwrap());
        serde_json::to_value(
            arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
                &[7u8; 32],
                &actor_id,
                account_data_key,
                &json!({"private": true}),
                [9u8; 24],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn private_account_data_key_patterns_are_validated() {
        assert!(
            validate_registered_account_data_key(
                "ak.scheduled_send.v1:ak:scheduled_send:01904100-0000-7000-8000-000000000001"
            )
            .is_ok()
        );
        assert!(
            validate_registered_account_data_key(
                "ak.file_transfer.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )
            .is_ok()
        );
        let err = validate_registered_account_data_key(
            "ak.draft.v1:message:ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19:main",
        )
        .unwrap_err();
        assert!(err.to_string().contains("registered private key pattern"));
    }

    #[test]
    fn account_data_get_accepts_only_registered_plaintext_service_cas_keys() {
        for key in [
            arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY,
            arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
        ] {
            assert!(validate_readable_account_data_key(key).is_ok());
            assert!(
                validate_registered_account_data_key(key).is_err(),
                "holder writes must remain forbidden for service-CAS key `{key}`"
            );
        }

        // The GET exception comes from an exact generated registry descriptor;
        // neither an unregistered key nor an extension of an exact key can use
        // the plaintext service-CAS path.
        for key in [
            "ak.account.unregistered",
            "ak.account.invite_delivery.extra",
        ] {
            let error = validate_readable_account_data_key(key).unwrap_err();
            assert!(error.to_string().contains("registered private key pattern"));
        }
    }

    #[test]
    fn service_internal_cas_keys_are_outside_holder_account_data() {
        assert!(is_service_internal_account_data_key(
            "ak.internal.fixture.v1"
        ));
        assert!(!is_service_internal_account_data_key(
            "ak.account.blocklist"
        ));
        assert!(!is_service_internal_account_data_key(
            "ak.agent.sidecar_view_state.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1:ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
        ));
    }

    #[test]
    fn private_account_data_requires_encrypted_content() {
        let key = "ak.saved.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert!(
            validate_private_account_data_content(
                key,
                &json!({"encrypted_payload": encrypted_envelope(key)}),
            )
            .is_ok()
        );
        assert!(
            validate_private_account_data_content(
                "ak.account.blocklist",
                &json!({"encrypted_payload": encrypted_envelope("ak.account.blocklist")}),
            )
            .is_ok()
        );
        assert!(
            validate_private_account_data_content(
                "ak.push_rules",
                &json!({"encrypted_payload": encrypted_envelope("ak.push_rules")}),
            )
            .is_ok()
        );
        assert!(
            validate_private_account_data_content(
                "ak.presence.preference",
                &json!({"encrypted_payload": encrypted_envelope("ak.presence.preference")}),
            )
            .is_ok()
        );
        assert!(validate_private_account_data_content(key, &json!({"tombstone": true})).is_ok());
        let err =
            validate_private_account_data_content("ak.dnd_schedule", &json!({"enabled": true}))
                .unwrap_err();
        assert!(err.to_string().contains("encrypted"));
        let err = validate_private_account_data_content(
            "ak.presence.preference",
            &json!({"manual_state": "dnd", "status_message": "In a meeting"}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("encrypted"));
        let err = validate_private_account_data_content(
            "ak.account.blocklist",
            &json!({"entries": [{"target": "did:web:bob.example"}]}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("encrypted"));
        let err = validate_private_account_data_content(
            key,
            &json!({"body": {"collection_title": "Leaks"}}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("plaintext"));

        let transfer_key = "ak.file_transfer.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = validate_private_account_data_content(
            transfer_key,
            &json!({"filename": "private.pdf", "encrypted_payload": encrypted_envelope(key)}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("plaintext"));
    }

    /// S-1 (spec review): the retired `ak.agent.sidecar_projection.v1` prefix
    /// must be rejected by the generic registry-membership check, not by a
    /// production alias list that silently becomes a second registry.
    #[test]
    fn retired_sidecar_projection_prefix_is_rejected_and_stays_controller_private() {
        for key in [
            "ak.agent.sidecar_projection.v1",
            "ak.agent.sidecar_projection.v1:did:web:alice.example",
            "ak.agent.sidecar_projection.v1:did:web:alice.example:ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
        ] {
            let err = validate_registered_account_data_key(key).unwrap_err();
            assert!(
                err.to_string().contains("registered private key pattern"),
                "retired key `{key}` must fail the shared key validator"
            );
        }
        // The active view-state surface is unaffected.
        assert!(
            validate_registered_account_data_key(
                "ak.agent.sidecar_view_state.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1:ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
            )
            .is_ok()
        );
        assert!(
            validate_registered_account_data_key(
                "ak.agent.sidecar_view_state.v1:did:web:alice.example"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn controller_private_writer_classifier_uses_agent_principal_projection() {
        let identity = IdentityService::new(
            Arc::new(NoAccounts),
            Arc::new(NoDevices),
            Arc::new(AgentClassifier),
        );
        let agent_id = "did:web:agent.alice.example";

        assert!(
            session_actor_is_agent_runtime(&identity, agent_id)
                .await
                .unwrap()
        );
        assert!(
            !session_actor_is_agent_runtime(&identity, "did:web:alice.example")
                .await
                .unwrap()
        );
    }
}
