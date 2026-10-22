//! Realm Device ingress, without a Session or Service producer substitution.
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_integration::AppletManagedDeviceMetadata;
use arkret_wire::EventKind;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{
    AppletManagedDeviceAuthority, AppletManagedDeviceScopeGuard, SelfProducerCommitGuard,
};

use super::{AppState, authority_self_event_unit as unit};

#[path = "authority_managed_device_mls.rs"]
pub(super) mod mls;

fn denied(detail: &str) -> ServiceError {
    ServiceError::Conflict(format!("capability_denied: {detail}"))
}

#[inline(never)]
pub(super) fn submit<'a>(
    state: &'a AppState,
    metadata: &'a AppletManagedDeviceMetadata,
    authority: &'a AppletManagedDeviceAuthority,
    request: SelfAuthoritySubmitRequest,
) -> impl std::future::Future<Output = ServiceResult<SelfAuthoritySubmitOutcome>> + Send + 'a {
    crate::boxed_future(move || submit_inner(state, metadata, authority, request))
}

async fn submit_inner(
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
    let native_mls = mls::NativeMlsRequest::from_request(&request)?;
    let (submission, welcomes, typed_mls) = match request {
        SelfAuthoritySubmitRequest::Event(submission) => (submission, Vec::new(), false),
        SelfAuthoritySubmitRequest::MlsCommit(submission) => (
            arkret_wire::EventAdmissionSubmission::new(submission.commit_event),
            submission.welcomes,
            true,
        ),
        _ => {
            return Err(ServiceError::UnsupportedEventKind(
                "this native submission branch has no accepting unit".into(),
            ));
        }
    };
    let event = &submission.event;
    unit::validate_replay_event_identity(event)?;
    event
        .verify_producer_proof_self_consistency(event.realm_id.digest_suite_code().digest_suite())
        .map_err(|e| ServiceError::Conflict(format!("signature_invalid: {e}")))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| denied("native Event has no Device producer"))?;
    if metadata.actor_id != authority.actor_id
        || metadata.device_id != authority.device_id
        || metadata.applet_id != authority.applet_id
        || metadata.authorization_event_id != authority.authorization_ref.event_id
        || metadata.effective_scope != event.scope_ref
        || authority.governance_service_id != state.service_core_id()
        || proof.verification_method.as_str()
            != format!("{}#{}", authority.native_did, authority.device_id)
        || event.actor_id != authority.actor_id
        || event.executed_by.is_some()
        || event.applet_id.as_ref() != Some(&authority.applet_id)
    {
        return Err(denied(
            "native Event differs from the authenticated Realm actor, Device, Applet or exact scope",
        ));
    }
    if event.kind == EventKind::MlsCommit && !typed_mls {
        return Err(ServiceError::SchemaViolation(
            "native MLS Commit requires its complete MlsCommitSubmission".into(),
        ));
    }
    if matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit)
        && submission.approval_signatures.is_some()
    {
        return Err(ServiceError::SchemaViolation(
            "an MLS Event carries no approval signatures".into(),
        ));
    }
    if let Some(context) = native_mls.as_ref()
        && let Some(original) = context.replay(state).await?
    {
        return Ok(original);
    }
    // Current transport still authenticates a replacement Device. Only the
    // complete stored original may recover its prior outcome before producer
    // or business current is rejudged; no new write follows this return.
    if let Some(original) = unit::exact_replay(state, event).await? {
        let original = SelfAuthoritySubmitOutcome::Ordinary(original);
        return match native_mls.as_ref() {
            Some(context) => context.retain_outcome(state, original).await,
            None => Ok(original),
        };
    }
    if !matches!(
        event.kind,
        EventKind::MemberState
            | EventKind::CircleMemberState
            | EventKind::MessageCreate
            | EventKind::MessageRedact
            | EventKind::StrandCreate
            | EventKind::MlsGenesis
            | EventKind::MlsCommit
    ) {
        return Err(ServiceError::UnsupportedEventKind(
            "native Event kind has no accepting domain unit".into(),
        ));
    }
    if super::authority_port::remote_governance(state, &event.realm_id)
        .await?
        .is_some()
    {
        return Err(ServiceError::Conflict(
            "stale_authority: submit Realm Device originals to the current governor".into(),
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
    let record = crate::routing::extensions::applet_bridge::record::applet_record(
        state,
        authority.applet_id.as_str(),
        authority.source_service_id.as_str(),
        &event.scope_ref,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, applet_id = %authority.applet_id, service_id = %authority.source_service_id, "managed Device installation read failed");
        denied("exact Applet installation is unavailable")
    })?
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
        SelfProducerCommitGuard::AppletManagedDevice(Box::new(AppletManagedDeviceScopeGuard {
            authority: current,
            effective_scope: metadata.effective_scope.clone(),
            service_did_document,
        }));
    if matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit) {
        let producer_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: authority.public_key.to_vec(),
        };
        let result = super::authority_mls_unit::admit_native_mls_event(
            state,
            event,
            &welcomes,
            None,
            unit::AdmittedProducer::Local(Box::new(guard)),
            &producer_key,
            native_mls.clone(),
        )
        .await;
        // The losing attempt may have rolled back at an earlier domain fence.
        // A completed racing retry identity still decides its first result.
        if let Some(context) = native_mls.as_ref()
            && let Some(original) = context.replay(state).await?
        {
            return Ok(original);
        }
        let outcome = SelfAuthoritySubmitOutcome::Ordinary(result?);
        return match native_mls.as_ref() {
            Some(context) => context.retain_outcome(state, outcome).await,
            None => Ok(outcome),
        };
    }
    unit::commit_event_unit(
        state,
        &submission,
        unit::AdmittedProducer::Local(Box::new(guard)),
        unit::SelfEventUnitEffects::default(),
    )
    .await
    .map(SelfAuthoritySubmitOutcome::Ordinary)
}
