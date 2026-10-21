//! Shared forward-only source from independently verified native Device roots.

use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
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

pub(super) struct PreparedForwardDeviceSource {
    pub account: arkret_wire::AccountId,
    pub device: arkret_wire::DeviceId,
    pub payload: DeviceAuthorizePayload,
    pub authorization_event_id: arkret_wire::EventId,
    pub fact: arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
    pub attested_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
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
pub(super) async fn prepare_context_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    attested_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<PreparedForwardDeviceSource>, PgTransactionError> {
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
    let expires_at = (attested_at + chrono::Duration::minutes(5)).min(
        payload
            .expires_at
            .flatten()
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    if expires_at <= chrono::Utc::now() {
        return Err(denied("forward source deadline elapsed").into());
    }
    Ok(Some(PreparedForwardDeviceSource {
        account: producer.account_id,
        device: producer.device_id,
        payload: payload.clone(),
        authorization_event_id: accepted.event_id.clone(),
        fact,
        attested_at,
        expires_at,
    }))
}

impl PreparedForwardDeviceSource {
    pub(super) fn attestation(
        &self,
        destination: &arkret_wire::DidCoreId,
        body_digest: &arkret_wire::Hash,
    ) -> Result<ForwardDeviceProjectionAttestationCore, PgTransactionError> {
        let payload = &self.payload;
        let fact = &self.fact;
        let core = ForwardDeviceProjectionAttestationCore {
            account_id: self.account.clone(),
            device_id: self.device.clone(),
            device_signing_key_did: arkret_wire::DidKey::new(
                payload.device_public_key_did.to_string(),
            )
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?,
            hpke_key: payload.hpke_key.clone(),
            device_authorize_event_id: self.authorization_event_id.clone(),
            authorized_generation_ref: payload.authorized_generation_ref,
            device_status: DeviceStatus::Active,
            attested_at: self.attested_at,
            expires_at: self.expires_at,
            authorization_window: DeviceAuthorizationWindow {
                not_before: payload.not_before,
                expires_at: payload.expires_at.flatten(),
            },
            event_authorization: AccountDeviceEventAuthorization {
                event_id: fact.event_id.clone(),
                verification_method: fact.verification_method.clone(),
                destination_service_id: destination.clone(),
                forward_body_digest: body_digest.clone(),
                authorization_ref: fact.key.authorization_ref.clone(),
                revision: fact.key.revision.clone(),
                governance_generation: fact.key.governance_generation,
                accepted_at: fact.accepted_at,
            },
        };
        core.validate_event_authorization()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        Ok(core)
    }
}

/// Existing Human callers retain exactly the same signed-core contract.
pub(super) async fn prepare_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    destination: &arkret_wire::DidCoreId,
    body_digest: &arkret_wire::Hash,
    attested_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<ForwardDeviceProjectionAttestationCore>, PgTransactionError> {
    prepare_context_in_connection(conn, event, attested_at)
        .await?
        .map(|prepared| prepared.attestation(destination, body_digest))
        .transpose()
}
