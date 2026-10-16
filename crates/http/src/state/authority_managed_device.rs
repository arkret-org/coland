//! Native Account Device ingress, without a Session or Service producer substitution.
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_integration::AppletManagedDeviceMetadata;
use arkret_wire::{ActorId, EventKind};
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{
    AppletManagedDeviceAuthority, AppletManagedDeviceEventGuard, SelfProducerCommitGuard,
};

use super::{AppState, authority_self_event_unit as unit};

fn denied(detail: &str) -> ServiceError {
    ServiceError::Conflict(format!("capability_denied: {detail}"))
}

pub(super) async fn submit(
    state: &AppState,
    metadata: &AppletManagedDeviceMetadata,
    authority: &AppletManagedDeviceAuthority,
    request: SelfAuthoritySubmitRequest,
) -> ServiceResult<SelfAuthoritySubmitOutcome> {
    request
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    metadata
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let SelfAuthoritySubmitRequest::Event(submission) = request else {
        return Err(ServiceError::UnsupportedEventKind(
            "this native submission branch has no accepting unit".into(),
        ));
    };
    let event = &submission.event;
    unit::validate_replay_event_identity(event)?;
    let producer = event
        .verify_producer_proof_self_consistency(event.realm_id.digest_suite_code().digest_suite())
        .map_err(|e| ServiceError::Conflict(format!("signature_invalid: {e}")))?
        .ok_or_else(|| denied("native Event has no Device producer"))?;
    if metadata.account_id != authority.account_id
        || metadata.device_id != authority.device_id
        || metadata.applet_id != authority.applet_id
        || metadata.authorization_event_id != authority.selector.authorization_ref.event_id
        || metadata.effective_scope != event.scope_ref
        || authority.account_id.station_id != state.service_core_id()
        || producer.account_id != authority.account_id
        || producer.device_id != authority.device_id
        || event.actor_id != ActorId::account(authority.account_id.clone())
        || event.executed_by.is_some()
        || event.applet_id.as_ref() != Some(&authority.applet_id)
    {
        return Err(denied(
            "native Event differs from the authenticated Account, Device, Applet or exact scope",
        ));
    }
    // Current transport still authenticates a replacement Device. Only the
    // complete stored original may recover its prior outcome before producer
    // or business current is rejudged; no new write follows this return.
    if let Some(original) = unit::exact_replay(state, event).await? {
        return Ok(SelfAuthoritySubmitOutcome::Ordinary(original));
    }
    if !matches!(
        event.kind,
        EventKind::MemberState | EventKind::ProfileCreate | EventKind::ProfileUpdate
    ) {
        return Err(ServiceError::UnsupportedEventKind(
            "native Event kind has no accepting domain unit".into(),
        ));
    }
    let current = state
        .persistence()
        .applet_managed_event_producer(event, chrono::Utc::now())
        .await?
        .ok_or_else(|| denied("native producer has no accepted current authority"))?;
    if &current != authority {
        return Err(denied(
            "native Device authority changed after transport authentication",
        ));
    }
    if super::authority_port::remote_governance(state, &event.realm_id)
        .await?
        .is_some()
    {
        return Err(ServiceError::Conflict(
            "temporarily_unavailable: native forwarded submission has no verified source consumer"
                .into(),
        ));
    }
    let record = crate::routing::extensions::applet_bridge::record::applet_record(
        state,
        authority.applet_id.as_str(),
        &event.scope_ref,
    )
    .await
    .map_err(|_| denied("exact Applet installation is unavailable"))?
    .ok_or_else(|| denied("exact Applet installation is absent"))?;
    let epoch = crate::routing::extensions::applet_bridge::registration_epoch_evidence_from_event(
        &record.registration_event,
    )
    .map_err(|_| denied("accepted registration epoch is invalid"))?;
    let service_did_document =
        crate::jws_verify::resolve_did_document(state, &epoch.did).map_err(|_| {
            ServiceError::Conflict(
                "temporarily_unavailable: current Service DID is unavailable".into(),
            )
        })?;
    let guard =
        SelfProducerCommitGuard::AppletManagedDevice(Box::new(AppletManagedDeviceEventGuard {
            authority: current,
            effective_scope: metadata.effective_scope.clone(),
            service_did_document,
        }));
    unit::commit_event_unit(
        state,
        &submission,
        unit::AdmittedProducer::Local(Box::new(guard)),
        unit::SelfEventUnitEffects::default(),
    )
    .await
    .map(SelfAuthoritySubmitOutcome::Ordinary)
}
