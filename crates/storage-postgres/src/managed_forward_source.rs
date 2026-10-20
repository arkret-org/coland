//! Exact ordinary Account forward source from the origin locked PCR cut.
use arkret_models_collaboration::authority_commit::*;
use arkret_wire::Event;
use coland_storage::{PersistenceError, PersistenceResult};
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "device_unauthorized: managed forward source: {error}"
    ))
}
/// Determine the complete ordered writer lock set before reading a source cut.
pub(super) async fn lock_source(
    conn: &mut diesel_async::AsyncPgConnection,
    event: &Event,
) -> Result<(), crate::PgTransactionError> {
    let Some(producer) = event.account_device_producer().map_err(invalid)? else {
        return Ok(());
    };
    let cut = crate::account_device_signer_evidence::forward_source::current_cut(
        conn,
        &producer.account_id,
        &producer.device_id,
    )
    .await?
    .ok_or_else(|| {
        PersistenceError::Conflict(
            "temporarily_unavailable: forward Device PCR is unavailable".into(),
        )
    })?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &cut.authority.realm_id)
        .await?;
    Ok(())
}

pub(super) fn event(request: &PeerAuthoritySubmitRequest) -> PersistenceResult<&Event> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => Ok(&v.event_submission.event),
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => Ok(&v.mls_submission.commit_event),
        _ => Err(invalid("source requested for a non-forward branch")),
    }
}
pub(super) fn device(
    request: &PeerAuthoritySubmitRequest,
) -> PersistenceResult<&arkret_models_identity::ForwardAccountDeviceSignerEvidence> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => v.producer_device_evidence.as_ref(),
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => v.producer_device_evidence.as_ref(),
        _ => None,
    }
    .ok_or_else(|| invalid("forward request has no Device evidence"))
}
pub(super) fn digest(request: &PeerAuthoritySubmitRequest) -> PersistenceResult<arkret_wire::Hash> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => authority_forward_body_digest(v),
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => authority_forward_body_digest(v),
        _ => return Err(invalid("non-forward digest")),
    }
    .map_err(invalid)
}
