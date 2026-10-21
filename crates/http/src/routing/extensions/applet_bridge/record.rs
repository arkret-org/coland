//! Applet record storage and request helpers.

use coland_http::error::AppError;
use salvo::prelude::*;

use super::types::{AppletIdentityRecord, AppletInstallationRecord, AppletRecord};
use crate::state::AppState;

fn decode_applet_record(
    identity: serde_json::Value,
    installation: serde_json::Value,
) -> Result<AppletRecord, AppError> {
    let identity: AppletIdentityRecord = serde_json::from_value(identity).map_err(|error| {
        AppError::internal(format!("stored applet identity winner is invalid: {error}"))
    })?;
    let installation: AppletInstallationRecord =
        serde_json::from_value(installation).map_err(|error| {
            AppError::internal(format!("stored applet installation is invalid: {error}"))
        })?;
    if installation.target_station_id != identity.target_station_id {
        return Err(AppError::internal(
            "stored Applet installation target differs from identity",
        ));
    }
    let record = AppletRecord::from_stored(identity, installation);
    record.validate_stored_bindings().map_err(|error| {
        AppError::internal(format!(
            "stored applet record bindings are invalid: {error}"
        ))
    })?;
    Ok(record)
}

pub(super) fn encode_applet_record(record: &AppletRecord) -> Result<serde_json::Value, AppError> {
    record.validate_stored_bindings().map_err(|error| {
        AppError::internal(format!("Applet record bindings are invalid: {error}"))
    })?;
    serde_json::to_value(record.stored_installation())
        .map_err(|error| AppError::internal(format!("Applet record serialize failed: {error}")))
}

pub(super) fn encode_applet_identity(
    identity: &AppletIdentityRecord,
) -> Result<serde_json::Value, AppError> {
    serde_json::to_value(identity)
        .map_err(|error| AppError::internal(format!("Applet identity serialize failed: {error}")))
}

pub(crate) async fn applet_identity(
    state: &AppState,
    applet_id: &str,
    target_station_id: &str,
) -> Result<Option<AppletIdentityRecord>, AppError> {
    state
        .event_queries()
        .applet_identity(applet_id, target_station_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, %target_station_id, "failed to read applet identity winner");
            AppError::internal("failed to read applet identity winner")
        })?
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!("stored applet identity winner is invalid: {error}"))
            })
        })
        .transpose()
}

pub(crate) async fn applet_record(
    state: &AppState,
    applet_id: &str,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<Option<AppletRecord>, AppError> {
    let effective_scope_key = coland_storage::applet_effective_scope_key(effective_scope)
        .map_err(|error| AppError::internal(format!("effective scope key failed: {error}")))?;
    let Some(value) = state
        .event_queries()
        .applet(applet_id, &effective_scope_key)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, "failed to read applet record");
            AppError::internal("failed to read applet record")
        })?
    else {
        return Ok(None);
    };
    // A planned governance handoff preserves the original installation target.
    let target_station_id = value
        .get("target_station_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AppError::internal("stored Applet installation omits target_station_id"))?;
    let identity = state
        .event_queries()
        .applet_identity(applet_id, target_station_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, "failed to read applet identity winner");
            AppError::internal("failed to read applet identity winner")
        })?
        .ok_or_else(|| AppError::internal("Applet installation has no identity winner"))?;
    let mut record = decode_applet_record(identity, value)?;
    load_realm_actors(state, &mut record).await?;
    Ok(Some(record))
}

pub(crate) async fn applet_records(state: &AppState) -> Result<Vec<AppletRecord>, AppError> {
    let installations = state.event_queries().applets().await.map_err(|error| {
        tracing::error!(%error, "failed to list applet records");
        AppError::internal("failed to list applet records")
    })?;
    let mut records = Vec::with_capacity(installations.len());
    for installation in installations {
        let applet_id = installation
            .get("applet_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AppError::internal("stored applet installation omits applet_id"))?;
        let target_station_id = installation
            .get("target_station_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AppError::internal("stored Applet installation omits target_station_id")
            })?;
        let identity = state
            .event_queries()
            .applet_identity(applet_id, target_station_id)
            .await
            .map_err(|error| {
                tracing::error!(%error, %applet_id, "failed to read applet identity winner");
                AppError::internal("failed to read applet identity winner")
            })?
            .ok_or_else(|| AppError::internal("Applet installation has no identity winner"))?;
        let mut record = decode_applet_record(identity, installation)?;
        load_realm_actors(state, &mut record).await?;
        records.push(record);
    }
    Ok(records)
}

pub(super) async fn persist_applet_record(
    state: &AppState,
    expected: &AppletRecord,
    replacement: &AppletRecord,
) -> Result<bool, AppError> {
    if expected.applet_id != replacement.applet_id {
        return Err(AppError::internal(
            "Applet record CAS cannot change applet_id",
        ));
    }
    if expected.effective_scope != replacement.effective_scope {
        return Err(AppError::internal(
            "Applet record CAS cannot change effective_scope",
        ));
    }
    let effective_scope_key =
        coland_storage::applet_effective_scope_key(&replacement.effective_scope)
            .map_err(|error| AppError::internal(format!("effective scope key failed: {error}")))?;
    let expected_value = encode_applet_record(expected)?;
    let replacement_value = encode_applet_record(replacement)?;
    state
        .event_queries()
        .compare_and_swap_applet(
            replacement.applet_id.as_str(),
            &effective_scope_key,
            &expected_value,
            replacement_value,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, applet_id = %replacement.applet_id, "failed to CAS applet record");
            AppError::internal("failed to persist applet record")
        })
}

pub(super) async fn fence_applet_record(
    state: &AppState,
    expected: &AppletRecord,
    replacement: &AppletRecord,
    fenced_at: chrono::DateTime<chrono::Utc>,
) -> Result<coland_storage::AppletInstallationFenceOutcome, AppError> {
    if expected.applet_id != replacement.applet_id
        || expected.effective_scope != replacement.effective_scope
    {
        return Err(AppError::internal(
            "Applet fence cannot change applet_id or effective_scope",
        ));
    }
    let effective_scope_key =
        coland_storage::applet_effective_scope_key(&replacement.effective_scope)
            .map_err(|error| AppError::internal(format!("effective scope key failed: {error}")))?;
    let expected_value = encode_applet_record(expected)?;
    let replacement_value = encode_applet_record(replacement)?;
    state
        .event_queries()
        .fence_applet_installation(
            replacement.applet_id.as_str(),
            &effective_scope_key,
            replacement.target_station_id.as_str(),
            &expected_value,
            replacement_value,
            fenced_at,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, applet_id = %replacement.applet_id, "failed to fence applet installation");
            AppError::internal("failed to fence applet installation")
        })
}

pub(super) fn ensure_not_revoked(record: &AppletRecord) -> Result<(), AppError> {
    if record.revoked_at.is_some() || record.status == "revoked" {
        return Err(crate::app_error!(AppletRevoked, "applet has been revoked"));
    }
    Ok(())
}

pub(super) fn query_value(req: &Request, key: &str) -> Option<String> {
    req.query::<String>(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(super) fn idempotency_key(req: &Request) -> Option<String> {
    req.headers()
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(super) fn applet_id_param(req: &Request) -> Result<String, AppError> {
    req.param::<String>("applet_id")
        .ok_or_else(|| AppError::param_missing("applet_id path segment required"))
}

async fn load_realm_actors(state: &AppState, record: &mut AppletRecord) -> Result<(), AppError> {
    let originals = state
        .authority_commits()
        .applet_realm_actor_creations(record.effective_scope.realm_id(), &record.applet_id)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    for full in originals {
        let candidate: arkret_models_integration::RealmActorCreatePayload =
            serde_json::from_value(serde_json::json!(full.event.payload))
                .map_err(|e| AppError::internal(e.to_string()))?;
        let creation_ref = arkret_wire::CommittedEventRef {
            event_id: full.event.event_id,
            commit_id: full.commit.commit_id,
            stream_ref: full.commit.stream_ref,
            stream_position: full.commit.stream_position,
        };
        match candidate.actor_role {
            arkret_models_integration::RealmActorCreatePayloadActorRole::Bot => {
                record.bots.push(super::types::BotActorRecord {
                    bot_actor_id: candidate.actor_id,
                    creation_ref,
                })
            }
            arkret_models_integration::RealmActorCreatePayloadActorRole::Ghost => {
                record.ghosts.push(super::types::GhostActorRecord {
                    ghost_actor_id: candidate.actor_id,
                    external_ref: {
                        let external = candidate.external_ref.ok_or_else(|| {
                            AppError::internal("accepted Ghost omits external tuple")
                        })?;
                        arkret_models_integration::GhostExternalTuple {
                            protocol: external.protocol,
                            instance_id: external.instance_id,
                            external_id: external.external_id,
                        }
                    },
                    display_name: None,
                    creation_ref,
                })
            }
        }
    }
    Ok(())
}
