//! Admission of the registered local Applet fixed set.

use super::*;

pub(in crate::routing) async fn submit_applet_authoring_unit(
    state: &AppState,
    input: coland_storage::AppletAuthoringUnitWrite,
    finalize: coland_storage::AppletUnitFinalizer,
) -> Result<coland_storage::AppletAuthoringUnitOutcome, SubmitOneError> {
    // Only the native Account Station may attest its locked Device source.
    // Acquire complete method history before entering the acceptance transaction;
    // the callback signs at its actual locked Commit time, never at read time.
    let service_resolution = if matches!(
        &input.request,
        coland_storage::AppletAdmissionRequest::Install(_)
    ) {
        Some(
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    error.message,
                )
            })?,
        )
    } else {
        None
    };
    let station = state.clone();
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                error,
            )
        })?;
    let signing_key = state.notary_signing_key();
    let attester_key = signing_key.clone();
    let attester_method = verification_method.clone();
    let attester: coland_storage::AppletResolutionAttester = std::sync::Arc::new(move |core| {
        arkret_signatures::service_resolution::sign_principal_resolution_projection_attestation(
            core,
            attester_method.clone(),
            attester_key.as_ref(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    });
    let author: coland_storage::AppletCommitAuthor = std::sync::Arc::new(
        move |event, authority, head, at, producer_signer_fact, device_core| {
            if authority.service_id != station.service_core_id() {
                return Err(coland_storage::PersistenceError::Conflict(
                    "failed_precondition: this Station is not the current Applet authority"
                        .to_owned(),
                ));
            }
            let evidence = device_core.map(|core| {
                if core.account_id.station_id != station.service_core_id() {
                    return Err(coland_storage::PersistenceError::Conflict("failed_precondition: only the native Account Station may attest its Device".to_owned()));
                }
                Ok(arkret_models_identity::AccountDeviceSignerEvidence {
                    device_projection_attestation: arkret_signatures::device_projection::sign_device_projection_attestation(core.clone(), verification_method.clone(), signing_key.as_ref()).map_err(|error| coland_storage::PersistenceError::Conflict(error.to_string()))?,
                    service_resolution: service_resolution.clone().ok_or_else(|| coland_storage::PersistenceError::Conflict("failed_precondition: original Device Service history unavailable".to_owned()))?,
                })
            }).transpose()?;
            let commit = station
                .authority_commits()
                .sign_event_commit_at_authority_cut(
                    event,
                    authority,
                    head,
                    verification_method.clone(),
                    signing_key.as_ref(),
                    at,
                    producer_signer_fact,
                )
                .map_err(|error| coland_storage::PersistenceError::Conflict(error.to_string()))?;
            Ok((commit, evidence))
        },
    );
    state
        .event_queries()
        .admit_applet_authoring_unit(input, author, attester, finalize)
        .await
        .map_err(|error| {
            // The status is the semantic class a reducer reason code keeps when
            // it is not itself a registered top-level error code.
            let (status, code) = match error.kind() {
                coland_services::ServiceErrorKind::NotFound => (StatusCode::NOT_FOUND, "not_found"),
                coland_services::ServiceErrorKind::SchemaViolation => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "schema_violation")
                }
                coland_services::ServiceErrorKind::UnsupportedEventKind => {
                    (StatusCode::NOT_IMPLEMENTED, "unsupported_event_kind")
                }
                coland_services::ServiceErrorKind::Conflict => (
                    StatusCode::CONFLICT,
                    error
                        .conflict_code()
                        .map_or("failed_precondition", |code| code.as_str()),
                ),
                coland_services::ServiceErrorKind::Database
                | coland_services::ServiceErrorKind::Internal => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
                }
            };
            SubmitOneError::new(status, code, error.to_string())
        })
}

pub(in crate::routing) fn applet_committed_ref(
    references: &[arkret_wire::CommittedEventRef],
    event: &Event,
) -> coland_storage::PersistenceResult<arkret_wire::CommittedEventRef> {
    let mut matching = references
        .iter()
        .filter(|reference| reference.event_id == event.event_id);
    let reference = matching.next().ok_or_else(|| {
        coland_storage::PersistenceError::Conflict(
            "failed_precondition: Applet finalization lacks an accepted Event reference".to_owned(),
        )
    })?;
    if matching.next().is_some() || reference.stream_ref.realm_id() != &event.realm_id {
        return Err(coland_storage::PersistenceError::Conflict(
            "schema_violation: Applet accepted Event reference is not unique or has a foreign Realm".to_owned(),
        ));
    }
    Ok(reference.clone())
}
