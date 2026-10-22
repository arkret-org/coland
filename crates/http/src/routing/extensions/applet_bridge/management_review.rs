//! Receiver-derived original Event material for private Applet review.
use arkret_models_integration::management_review::ManagementReviewTarget;

use crate::state::AppState;

/// Resolver material for a real Device Event; no acceptance or current allow.
pub(crate) async fn prepare_event_current(
    state: &AppState,
    target: &ManagementReviewTarget,
) -> coland_services::ServiceResult<Option<Box<coland_storage::AppletEventReviewCurrent>>> {
    let ManagementReviewTarget::Event { event } = target;
    let Some(_) = &event.applet_id else {
        return Ok(None);
    };
    let registration = state
        .authority_commits()
        .applet_registration_for_event(event)
        .await?;
    let epoch = &registration.manifest.registration_epoch_evidence;
    let service_did_document = crate::jws_verify::resolve_did_document_async(state, &epoch.did)
        .await
        .map_err(|_| {
            coland_services::ServiceError::Conflict(
                "temporarily_unavailable: Service DID current is unavailable".into(),
            )
        })?;
    Ok(Some(Box::new(coland_storage::AppletEventReviewCurrent {
        realm_id: event.realm_id.clone(),
        service_did_document,
    })))
}
