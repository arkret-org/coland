//! Shared forward-only source from independently verified native Device roots.

use arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind;
use arkret_models_crypto::{
    AccountDeviceEventAuthorization, DeviceAuthorizationWindow, DeviceStatus,
    ForwardDeviceProjectionAttestationCore,
};

use super::*;

pub(super) fn now() -> chrono::DateTime<chrono::Utc> {
    arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
}

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("device_unauthorized: {detail}"))
}

pub(crate) async fn current_cut(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
) -> Result<Option<crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut>, PgTransactionError>
{
    confirmed_pcr_device_status_cut_in_connection(conn, account, device, chrono::Utc::now()).await.map_err(|error| match error {
        PgTransactionError::Storage(PersistenceError::SchemaViolation(detail)) => PersistenceError::Conflict(format!("temporarily_unavailable: forward current Device material is incomplete: {detail}")).into(),
        other => other,
    })
}

/// Caller holds the actual PCR authority writer lock. The complete original
/// source verifier proves role, lineage, Event bytes and the real Device key.
pub(super) async fn prepare_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    destination: &arkret_wire::DidCoreId,
    body_digest: &arkret_wire::Hash,
    attested_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<ForwardDeviceProjectionAttestationCore>, PgTransactionError> {
    let producer = event
        .account_device_producer()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?
        .ok_or_else(|| denied("forward source has no Account Device producer"))?;
    let cut = current_cut(conn, &producer.account_id, &producer.device_id)
        .await?
        .ok_or_else(|| denied("forward source lost its locked native cut"))?;
    if let Some(code) = cut.admission().error_code() {
        return Err(PersistenceError::Conflict(format!(
            "{}: forward source is not currently admitted",
            code.as_str()
        ))
        .into());
    }
    let Some(fact) =
        crate::agent_producer_signer_keys::prepare_local_account_device_source_in_connection(
            conn,
            event,
            attested_at,
        )
        .await?
    else {
        return Ok(None);
    };
    let accepted = cut
        .authority
        .authorization
        .as_ref()
        .ok_or_else(|| denied("forward source has no original authorization"))?;
    let payload = &accepted.payload;
    if accepted.event_id != fact.key.authorization_ref.event_id
        || accepted.source_commit_id != fact.key.authorization_ref.commit_id
        || cut.authority.authority_commit_id != fact.key.revision.commit_id
        || cut.authority.current_generation != Some(payload.authorized_generation_ref)
    {
        return Err(denied("forward source differs from its exact native revision").into());
    }
    if payload.authorization_binding_kind == DeviceAuthorizationBindingKind::AppletManagedDelegation
    {
        let authority = crate::pcr_applet_device_authority::for_event_in_connection(
            conn,
            event,
            chrono::Utc::now(),
        )
        .await?
        .ok_or_else(|| denied("forward managed provenance is unavailable"))?;
        if event.kind == arkret_wire::EventKind::MessageCreate {
            let message: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
                serde_json::from_value(serde_json::to_value(&event.payload)
                    .map_err(PersistenceError::database)?)
                    .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
            let actual = crate::strand_current_results::locked_active_strand_scope(
                conn,
                &event.realm_id,
                &message.strand_id,
            )
            .await?;
            if actual != event.scope_ref {
                return Err(
                    denied("forward Message differs from its accepted Strand scope").into(),
                );
            }
        }
        let actions = crate::applet_device_admission::device_actions(event)?;
        if event.applet_id.as_ref() != Some(&authority.applet_id)
            || !authority.scopes.permits(&event.scope_ref, &actions)
        {
            return Err(
                denied("forward Event exceeds its original managed scope/action pair").into(),
            );
        }
    }
    let expires_at = (attested_at + chrono::Duration::minutes(5)).min(
        payload
            .expires_at
            .flatten()
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    if expires_at <= chrono::Utc::now() {
        return Err(denied("forward source deadline elapsed").into());
    }
    let core = ForwardDeviceProjectionAttestationCore {
        account_id: producer.account_id,
        device_id: producer.device_id,
        device_signing_key_did: arkret_wire::DidKey::new(payload.device_public_key_did.to_string())
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?,
        hpke_key: payload.hpke_key.clone(),
        device_authorize_event_id: accepted.event_id.clone(),
        authorized_generation_ref: payload.authorized_generation_ref,
        device_status: DeviceStatus::Active,
        attested_at,
        expires_at,
        authorization_window: DeviceAuthorizationWindow {
            not_before: payload.not_before,
            expires_at: payload.expires_at.flatten(),
        },
        event_authorization: AccountDeviceEventAuthorization {
            event_id: fact.event_id,
            verification_method: fact.verification_method,
            destination_service_id: destination.clone(),
            forward_body_digest: body_digest.clone(),
            authorization_ref: fact.key.authorization_ref,
            revision: fact.key.revision,
            governance_generation: fact.key.governance_generation,
            accepted_at: fact.accepted_at,
        },
    };
    core.validate_event_authorization()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    Ok(Some(core))
}
