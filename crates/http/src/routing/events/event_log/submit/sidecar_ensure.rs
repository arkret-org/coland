//! Sidecar ensure admission boundary.
//!
//! The current request carries producer-signed Events. An accepted result
//! requires their RealmCommits, Sidecar current state and any delivery intents
//! to commit in one authority transaction.

use arkret_wire::{Event, EventKind};
use salvo::http::StatusCode;

use super::{AppState, SessionRecord, SubmitOneError};

pub(crate) async fn submit_sidecar_ensure_batch(
    state: &AppState,
    session: &SessionRecord,
    create_event: Option<Event>,
    context_attach_event: Event,
) -> Result<(), SubmitOneError> {
    if context_attach_event.kind != EventKind::SidecarContextAttach {
        return Err(SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "Sidecar ensure requires a context attach Event",
        ));
    }
    arkret_schema::validate_event_for_submit(&context_attach_event).map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("invalid Sidecar attach Event: {error}"),
        )
    })?;
    if let Some(create_event) = &create_event {
        if create_event.kind != EventKind::SidecarCreate
            || create_event.realm_id != context_attach_event.realm_id
            || create_event.actor_id != context_attach_event.actor_id
        {
            return Err(SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "Sidecar create and attach Events must share Realm and controller",
            ));
        }
        arkret_schema::validate_event_for_submit(create_event).map_err(|error| {
            SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("invalid Sidecar create Event: {error}"),
            )
        })?;
    }
    crate::state::commit_sidecar_ensure_unit(state, session, create_event, context_attach_event)
        .await
        .map_err(|error| {
            let code = error
                .conflict_code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| match error {
                    coland_services::ServiceError::SchemaViolation(_) => "schema_violation".into(),
                    _ => "internal_error".into(),
                });
            SubmitOneError::new(StatusCode::CONFLICT, code, error.to_string())
        })
}
