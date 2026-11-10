//! Native episode identity is frozen by the accepted replacement transaction.

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload,
};
use arkret_models_crypto::{
    ContentEndpoint, ContentRecoveryPreparation, ContentRecoveryPreparationState,
};
use arkret_wire::{ActorId, CommittedEventRef, EventId, MlsWelcomeRecipientEndpoint};
use coland_storage::{
    AccountContentDeliveryGuard as _, HumanPcrHistoryRead, HumanPcrHistoryReader, PersistenceError,
    PersistenceResult, RecoveryUnitCommitWrite,
};
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Text, Timestamptz, Uuid};
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::account_content_delivery::DeliveryGuard;
use crate::{AsyncPgConnection, JsonPayloadRow, PgPool};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "revision_unavailable: recovery preparation {detail}"
    ))
}

fn replacement(
    account: &arkret_wire::AccountId,
    event: &arkret_wire::Event,
) -> PersistenceResult<ContentEndpoint> {
    let payload: DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
            .map_err(unavailable)?;
    arkret_signatures::verify_device_authorize_possession(&payload, account)
        .map_err(unavailable)?;
    if event.actor_id.as_account_id() != Some(account)
        || event.executed_by.is_some()
        || payload.authorization_binding_kind != DeviceAuthorizationBindingKind::PcrRecovery
    {
        return Err(unavailable("has no native Human replacement"));
    }
    let multibase = payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| unavailable("replacement key is not did:key"))?;
    let public = arkret_canonical::decode_ed25519_multibase(multibase).map_err(unavailable)?;
    let endpoint = ContentEndpoint {
        actor_id: ActorId::account(account.clone()),
        endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: payload.device_id,
        },
        authorization_event_ref: event.event_id.clone(),
        signature_key_base64url: arkret_canonical::base64url_encode(public),
    };
    endpoint.validate().map_err(unavailable)?;
    Ok(endpoint)
}

/// Runs after both accepted originals and their real signatures, but before
/// terminal consumption, on the same PCR-locked connection. A later failure
/// rolls the episode and its active membership-fence intent back as well.
pub(super) async fn retain_in_connection(
    conn: &mut AsyncPgConnection,
    write: &RecoveryUnitCommitWrite,
) -> PersistenceResult<()> {
    write.validate()?;
    let authorize = &write.commits[1];
    let endpoint = replacement(&write.transaction.resource.account_id, &authorize.event)?;
    let pcr_cut = CommittedEventRef {
        event_id: authorize.event.event_id.clone(),
        commit_id: authorize.commit.commit_id.clone(),
        stream_ref: authorize.commit.stream_ref.clone(),
        stream_position: authorize.commit.stream_position,
    };
    let value = ContentRecoveryPreparation {
        state: ContentRecoveryPreparationState::Pending,
        replacement: endpoint,
        pcr_cut,
        inventory_blob_ref: None,
    };
    value
        .validate_for_authorization(&authorize.event.event_id)
        .map_err(unavailable)?;
    sql_query("INSERT INTO content_recovery_episodes(authorization_event_ref,transaction_id,actor_id,state,replacement,pcr_cut,inventory_blob_ref,security_completed_at,created_at) VALUES($1,$2,$3,'pending',$4,$5,NULL,NULL,$6)")
        .bind::<Text,_>(authorize.event.event_id.as_str())
        .bind::<Uuid,_>(crate::ids::typed_uuid_part_expect_internal(write.transaction.resource.transaction_id.as_str()))
        .bind::<Jsonb,_>(serde_json::to_value(&value.replacement.actor_id).map_err(unavailable)?)
        .bind::<Jsonb,_>(serde_json::to_value(&value.replacement).map_err(unavailable)?)
        .bind::<Jsonb,_>(serde_json::to_value(&value.pcr_cut).map_err(unavailable)?)
        .bind::<Timestamptz,_>(authorize.commit.committed_at)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    super::recovery_census_cut::retain(conn, &value).await
}

pub(super) async fn read(
    pool: &PgPool,
    reader: &HumanPcrHistoryReader,
    authorization: &EventId,
) -> PersistenceResult<HumanPcrHistoryRead<ContentRecoveryPreparation>> {
    let mut held = DeliveryGuard::begin(pool).await?;
    let now = chrono::Utc::now();
    let current = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        held.connection(),
        &reader.account_id,
        &reader.device_id,
        now,
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?;
    let Some(current) = current else {
        held.finish().await?;
        return Ok(HumanPcrHistoryRead::NotApplicable);
    };
    let eligible = current.admission()
        == arkret_wire::AccountDeviceRevocationAdmissionDecision::Allow
        && reader.credential_expires_at > now
        && current
            .authority
            .authorization
            .as_ref()
            .is_some_and(|native| {
                native.event_id == *authorization
                    && native.payload.authorization_binding_kind
                        == DeviceAuthorizationBindingKind::PcrRecovery
                    && reader
                        .credential_device_binding
                        .as_ref()
                        .is_some_and(|binding| {
                            binding.device_id == reader.device_id
                                && binding.authorization_event_id == native.event_id
                                && Some(binding.model_generation_ref)
                                    == current.authority.current_generation
                        })
            });
    if !eligible {
        held.finish().await?;
        return Ok(HumanPcrHistoryRead::NotApplicable);
    }
    if reader.account_status_observation.is_none() {
        held.finish().await?;
        return Ok(HumanPcrHistoryRead::CurrentStatusRequired);
    }
    let realm = current.authority.realm_id;
    let expires_at = crate::pcr_history_read::qualify(
        held.connection(),
        reader,
        &realm,
        &reader.account_id.station_id,
    )
    .await?;
    let source = super::content_recovery_source::qualify_in_connection(held.connection(), reader)
        .await
        .map_err(unavailable)?;
    if source.device_authorization_event_ref.event_id != *authorization {
        return Err(unavailable(
            "native source differs from the requested episode",
        ));
    }
    let (event, _) =
        super::content_recovery_source::original(held.connection(), authorization, &realm).await?;
    let endpoint = replacement(&reader.account_id, &event)?;
    let row = sql_query("SELECT jsonb_build_object('state',state,'replacement',replacement,'pcr_cut',pcr_cut) || CASE WHEN inventory_blob_ref IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('inventory_blob_ref',inventory_blob_ref) END AS payload FROM content_recovery_episodes WHERE authorization_event_ref=$1 AND actor_id=$2 FOR SHARE")
        .bind::<Text,_>(authorization.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&endpoint.actor_id).map_err(unavailable)?)
        .get_result::<JsonPayloadRow>(held.connection()).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("accepted native episode is absent"))?;
    let value: ContentRecoveryPreparation =
        serde_json::from_value(row.payload).map_err(unavailable)?;
    value
        .validate_for_episode(
            authorization,
            &endpoint,
            &source.device_authorization_event_ref,
            None,
        )
        .map_err(unavailable)?;
    held.probe().await?;
    Ok(crate::pcr_history_read::guarded(held, expires_at, value))
}
