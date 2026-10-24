//! Bounded current-pointer discovery and indexed metadata pages.
use arkret_models_crypto::{BackupActiveSeriesState, KeyBackupsListQuery};
use arkret_server::{CursorAuthority, CursorBindingContext};
use coland_services::identity::{KeyBackupListPosition, KeyBackupListQuery as StorageQuery};

use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PagePosition {
    revision: i64,
    after: KeyBackupListPosition,
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.backups.read.list", tags("identity"))]
pub(crate) async fn list_key_backups(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsPage> {
    let session = {
        let state = depot.get_typed::<AppState>().expect("state injected");
        aa.authenticated_session(state, req).await?
    };
    list(
        session,
        cursor,
        series_id,
        backup_kind,
        limit,
        depot,
        arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
    )
    .await
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.admin.key_backups.query.list",
    tags("admin")
)]
pub(crate) async fn list_key_backups_admin(
    admin: crate::routing::admin::AdminAuth,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
) -> JsonResult<KeysBackupsPage> {
    let session = admin.session()?;
    list(
        session,
        cursor,
        series_id,
        backup_kind,
        limit,
        depot,
        "org.arkret.coland.admin.key_backups.query.list",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
/// `session` is the caller already authenticated by the wrapping endpoint
/// (the self bearer path or the `RequireAdmin` gate).
async fn list(
    session: coland_services::identity::SessionIdentityState,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
    operation: &str,
) -> JsonResult<KeysBackupsPage> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
    )?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let account = actor
        .as_account_id()
        .ok_or_else(|| AppError::not_found("account backups unavailable"))?;
    let limit = limit.into_inner().unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(AppError::param_invalid("backup page limit must be 1..200"));
    }
    let query = KeyBackupsListQuery {
        series_id: series_id
            .into_inner()
            .map(arkret_wire::BackupSeriesId::new)
            .transpose()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        backup_kind: backup_kind
            .into_inner()
            .map(|kind| BackupKind::try_from(kind.as_str()))
            .transpose()
            .map_err(AppError::param_invalid)?,
        cursor: cursor
            .into_inner()
            .map(arkret_wire::Cursor::new)
            .transpose()
            .map_err(|error| {
                AppError::param_invalid(error.to_string())
                    .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR)
            })?,
        limit: Some(limit),
    };
    let decoded = query
        .cursor
        .as_ref()
        .map(|token| CursorAuthority::decode_stream(token.as_str()).map_err(cursor_authority_error))
        .transpose()?;
    // Recovery authentication has already bound a verified, unexpired session
    // and policy to this exact Account, grant/JKT and candidate device. That
    // candidate must not be required to exist in the PCR before completion.
    let recovery = session.session_grant.as_ref().is_some_and(|grant| {
        grant.credential_class
            == arkret_models_identity::SessionGrantCredentialClass::RecoverySession
    });
    let active_series = if recovery {
        active_pointers(state, account).await?
    } else {
        active_pointers_for_device(state, account, session.require_human_device_id()).await?
    };
    let filter = arkret_server::cursor_filter_digest(&json!({
        "operation":operation, "series_id":query.series_id, "backup_kind":query.backup_kind,
        "order":"backup_kind,series_id,series_sequence,backup_id", "active_series":active_series,
    }))
    .map_err(invalid_cursor)?;
    let context = CursorBindingContext::for_account(
        account,
        session.require_human_device_id().clone(),
        filter,
    )
    .map_err(invalid_cursor)?;
    let previous = if let Some(decoded) = &decoded {
        let stored = state.sync().cursor(&decoded.h).await.map_err(internal)?;
        let record = stored
            .clone()
            .map(coland_http::util::cursor_binding_record_from_state)
            .transpose()
            .map_err(cursor_authority_error)?;
        let position = CursorAuthority::resolve_stream(decoded, &context, record.as_ref())
            .map_err(cursor_authority_error)?;
        if crate::routing::events::sync::cursor_authority_revoked(
            state,
            decoded,
            stored.as_ref().expect("validated cursor record"),
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        .map_err(crate::routing::events::sync::cursor_revoke_error)?
        {
            return Err(crate::app_error!(
                CursorRevoked,
                "cursor authority has been revoked"
            ));
        }
        Some(serde_json::from_value::<PagePosition>(position).map_err(invalid_cursor)?)
    } else {
        None
    };
    let device_id = arkret_wire::DeviceId::new(session.require_human_device_id().clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let storage_query = StorageQuery {
        actor_id: actor.to_string(),
        backup_kind: query.backup_kind.map(|kind| kind.as_str().to_owned()),
        series_id: query.series_id.as_ref().map(ToString::to_string),
        after: previous.as_ref().map(|p| p.after.clone()),
        limit: limit + 1,
    };
    let confirmed = if recovery {
        state
            .key_backups()
            .confirmed_list_page_for_account(account, &storage_query)
            .await
    } else {
        state
            .key_backups()
            .confirmed_list_page_for_device(account, &device_id, chrono::Utc::now(), &storage_query)
            .await
    }
    .map_err(unavailable)?;
    if confirmed.active_series != active_series {
        return Err(unavailable(
            "KeyBackup PCR cut changed while resolving page cursor",
        ));
    }
    let page = confirmed.page;
    if previous
        .as_ref()
        .is_some_and(|p| p.revision != page.revision)
    {
        return Err(invalid_cursor("backup listing changed"));
    }
    let has_more = page.byte_limited || page.payloads.len() > limit as usize;
    let backups = page
        .payloads
        .into_iter()
        .take(limit as usize)
        .map(serde_json::from_value::<arkret_models_crypto::KeyBackupSummary>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    if backups.is_empty() && has_more {
        return Err(crate::app_error!(
            LimitExceeded,
            "one backup metadata row exceeds the page budget"
        ));
    }
    let next_cursor = if has_more {
        let last = backups.last().expect("nonempty continuation page");
        let position = PagePosition {
            revision: page.revision,
            after: KeyBackupListPosition {
                backup_kind: last.backup_kind.as_str().to_owned(),
                series_id: last.series_id.to_string(),
                series_sequence: i64::try_from(last.series_sequence).map_err(internal)?,
                backup_id: last.backup_id.to_string(),
            },
        };
        let (token, record) = CursorAuthority::mint_stream(
            context,
            serde_json::to_value(position).map_err(internal)?,
            60 * 60 * 1000,
        )
        .map_err(internal)?;
        state
            .sync()
            .upsert_cursor(&coland_services::sync::CursorState {
                handle: record.handle,
                binding_subject: Some(record.context.binding_subject),
                device_id: record.context.device_id,
                session_id: Some(session.token_hash.clone()),
                service_id: record.context.service_id,
                filter_digest: Some(record.context.filter_digest),
                purpose: "stream".to_owned(),
                positions: Some(record.positions),
                target: None,
                issued_at_ms: record.issued_at_ms,
                expires_at_ms: record.expires_at_ms,
            })
            .await
            .map_err(internal)?;
        Some(arkret_wire::Cursor::new(token).map_err(internal)?)
    } else {
        None
    };
    let result = KeysBackupsPage {
        backups,
        active_series,
        next_cursor,
        has_more,
    };
    json_ok(result)
}

/// The account's confirmed `secret_storage` pointer and the PCR head that
/// covers it, read by one PostgreSQL statement from the durable typed current
/// result. A missing, lagging or unverifiable cut is unavailable, never
/// `Absent`; destructive callers freeze this basis and recheck it in their own
/// storage transaction.
pub(super) async fn active_pointers(
    state: &AppState,
    account: &arkret_wire::AccountId,
) -> Result<BackupActiveSeriesState, AppError> {
    state
        .key_backups()
        .confirmed_active_series(account)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("confirmed PCR pointer cut is absent"))
}

async fn active_pointers_for_device(
    state: &AppState,
    account: &arkret_wire::AccountId,
    device_id: &str,
) -> Result<BackupActiveSeriesState, AppError> {
    let device_id = arkret_wire::DeviceId::new(device_id.to_owned())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    state
        .key_backups()
        .confirmed_active_series_for_device(account, &device_id, chrono::Utc::now())
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("confirmed PCR pointer cut is absent"))
}

fn invalid_cursor(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        CursorIntegrityInvalid,
        format!("invalid backup cursor: {error}")
    )
}
fn cursor_authority_error(error: arkret_server::CursorAuthorityError) -> AppError {
    match error {
        arkret_server::CursorAuthorityError::ParamInvalid(message) => {
            AppError::param_invalid(message)
                .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR)
        }
        arkret_server::CursorAuthorityError::Expired => {
            crate::app_error!(CursorExpired, "cursor has expired")
        }
        arkret_server::CursorAuthorityError::IntegrityInvalid => {
            invalid_cursor("issuance or request binding mismatch")
        }
    }
}
fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        RevisionUnavailable,
        format!("accepted backup state unavailable: {error}")
    )
}
fn internal(error: impl std::fmt::Display) -> AppError {
    AppError::internal(format!("backup listing: {error}"))
}

#[cfg(test)]
mod cursor_error_tests {
    use super::*;

    #[test]
    fn cursor_failure_stages_use_registered_codes() {
        use arkret_server::CursorAuthorityError;
        let syntax =
            cursor_authority_error(CursorAuthorityError::ParamInvalid("invalid wire".into()));
        assert_eq!(syntax.code, arkret_wire::ErrorCode::ParamInvalid);
        assert_eq!(
            syntax.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::INVALID_CURSOR)
        );
        assert_eq!(
            cursor_authority_error(CursorAuthorityError::Expired).code,
            arkret_wire::ErrorCode::CursorExpired
        );
        assert_eq!(
            cursor_authority_error(CursorAuthorityError::IntegrityInvalid).code,
            arkret_wire::ErrorCode::CursorIntegrityInvalid
        );
        assert_eq!(
            invalid_cursor("changed revision").code,
            arkret_wire::ErrorCode::CursorIntegrityInvalid
        );
    }
}
