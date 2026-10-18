//! Origin preparation of a complete first-forward body before network effects.

use super::*;

/// Attach the native managed source before calculating the signed body digest.
/// Human and Service producers retain their existing evidence contracts.
pub(super) async fn fresh_request(
    state: &AppState,
    mut request: PeerAuthoritySubmitRequest,
    destination: &DidCoreId,
) -> ServiceResult<PeerAuthoritySubmitRequest> {
    let event = match &request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(body) => &body.event_submission.event,
        PeerAuthoritySubmitRequest::AuthorityForwardMls(body) => &body.mls_submission.commit_event,
        _ => {
            return Err(ServiceError::SchemaViolation(
                "source preparation requires Event or MLS forwarding".into(),
            ));
        }
    };
    let managed = if event.applet_id.is_some()
        && event
            .account_device_producer()
            .map_err(wire_refusal)?
            .is_some()
    {
        state
            .persistence()
            .applet_managed_event_producer(event, crate::wire::now())
            .await?
    } else {
        None
    };
    if let Some(authority) = managed {
        if authority.account_id.station_id != state.service_core_id() {
            return Err(ServiceError::SchemaViolation(
                "only the native Account Station may issue its managed source".into(),
            ));
        }
        let prepared = state
            .persistence()
            .prepare_managed_forward(&request, destination)
            .await?;
        request = prepared.request;
        let source = match &request {
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(body) => {
                body.producer_managed_provenance.as_ref()
            }
            PeerAuthoritySubmitRequest::AuthorityForwardMls(body) => {
                body.producer_managed_provenance.as_ref()
            }
            _ => unreachable!("prepared closed forward branch"),
        }
        .ok_or_else(|| {
            ServiceError::Internal("managed source preparation returned no source".into())
        })?;
        // Preserve the registered size error before Station history retrieval,
        // signing, immutable retention or any business/network write.
        source.validate().map_err(wire_refusal)?;
        let service_resolution =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|error| temporarily_unavailable(error.message))?;
        let attestation =
            arkret_signatures::device_projection::sign_forward_device_projection_attestation(
                prepared.core,
                state
                    .service_verification_method("notary-key")
                    .map_err(ServiceError::internal)?,
                state.notary_signing_key().as_ref(),
            )
            .map_err(wire_refusal)?;
        let evidence = ForwardAccountDeviceSignerEvidence {
            device_projection_attestation: attestation,
            service_resolution,
        };
        match &mut request {
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(body) => {
                body.producer_device_evidence = Some(evidence)
            }
            PeerAuthoritySubmitRequest::AuthorityForwardMls(body) => {
                body.producer_device_evidence = Some(evidence)
            }
            _ => unreachable!("prepared closed forward branch"),
        }
        request.validate().map_err(wire_refusal)?;
        state.persistence().retain_managed_forward(&request).await?;
        return Ok(request);
    }
    match &mut request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(body) => {
            body.producer_agent_evidence =
                fresh_producer_agent_evidence(state, &body.event_submission.event).await?;
            let digest =
                arkret_models_collaboration::authority_commit::authority_forward_body_digest(body)
                    .map_err(wire_refusal)?;
            body.producer_device_evidence = fresh_producer_device_evidence(
                state,
                &body.event_submission.event,
                destination,
                &digest,
            )
            .await?;
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(body) => {
            body.producer_agent_evidence =
                fresh_producer_agent_evidence(state, &body.mls_submission.commit_event).await?;
            let digest =
                arkret_models_collaboration::authority_commit::authority_forward_body_digest(body)
                    .map_err(wire_refusal)?;
            body.producer_device_evidence = fresh_producer_device_evidence(
                state,
                &body.mls_submission.commit_event,
                destination,
                &digest,
            )
            .await?;
        }
        _ => unreachable!("checked closed forward branch"),
    }
    request.validate().map_err(wire_refusal)?;
    Ok(request)
}
