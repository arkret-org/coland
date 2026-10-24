use super::*;

pub(in crate::routing) async fn submit_event_value(
    _state: &AppState,
    _session: &SessionRecord,
    envelope: Value,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let event: Event = serde_json::from_value(envelope).map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            error.to_string(),
        )
    })?;
    arkret_schema::validate_event_for_submit(&event).map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            error.to_string(),
        )
    })?;
    Err(SubmitOneError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "internal Event authoring awaits guarded Event/RealmCommit admission",
    ))
}
/// Internal boundary for one caller-signed Event admission submission made by
/// a dedicated self operation.
///
/// A kind enters only when it has a registered durable semantics and a guarded
/// Event/RealmCommit/current-state unit of work at the current governing
/// Station. `ak.self.moderation.report` (Realm scope) is the one such kind
/// here. Everything else — including the actor-private `ak.read_cursor.advance`,
/// which must never take a RealmCommit — stays closed with zero writes.
pub(in crate::routing) async fn submit_initial_event_submission(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventAdmissionSubmission,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submission.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("invalid Event admission submission: {error}"),
        )
    })?;
    let event = &submission.event;
    let realm_scope = matches!(
        &event.scope_ref,
        arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id
    );
    if event.kind != arkret_wire::EventKind::SelfModerationReport || !realm_scope {
        return Err(SubmitOneError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "internal Event submission has no guarded Event/RealmCommit unit for this kind or scope",
        ));
    }
    let event_id = event.event_id.to_string();
    let outcome = crate::state::submit_self_moderation_report(state, session, submission)
        .await
        .map_err(guarded_unit_error)?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted { status, .. } = outcome else {
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "guarded self Event unit returned a non-accepted outcome",
        ));
    };
    Ok(SubmittedEventOutcome {
        event_id,
        duplicate: status == arkret_wire::AuthorityCommitStatus::Duplicate,
    })
}

/// Submit only the caller-signed Event effects listed in an Applet revoke
/// plan. The Applet endpoint has already bound each submission to the current
/// plan; the ordinary self authority port still verifies its producer and
/// commits the Event, covering RealmCommit, and current result together.
pub(in crate::routing) fn submit_applet_revoke_event_submission<'a>(
    state: &'a AppState,
    session: &'a SessionRecord,
    submission: arkret_wire::EventAdmissionSubmission,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<SubmittedEventOutcome, SubmitOneError>> + Send + 'a,
    >,
> {
    Box::pin(async move {
        submission.validate().map_err(|error| {
            SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("invalid Applet revoke Event submission: {error}"),
            )
        })?;
        let event = &submission.event;
        if !matches!(
            event.kind,
            arkret_wire::EventKind::CapabilityRevoke | arkret_wire::EventKind::MemberState
        ) || !matches!(
            &event.scope_ref,
            arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id
        ) {
            return Err(SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "Applet revoke effects require an exact Realm-scope CapabilityRevoke or MemberState Event",
            ));
        }
        let request = arkret_wire::AuthoritySubmitRequestBody::Event(submission.clone());
        let event_id = event.event_id.to_string();
        let outcome = state
            .authority()
            .submit_self_event(session, submission)
            .await
            .map_err(guarded_unit_error)?;
        outcome.validate_for_request(&request).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Applet revoke authority outcome is invalid: {error}"),
            )
        })?;
        let arkret_wire::AuthoritySubmitResponseBody::Accepted { status, .. } = outcome else {
            return Err(SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "guarded Applet revoke Event unit returned a non-accepted outcome",
            ));
        };
        Ok(SubmittedEventOutcome {
            event_id,
            duplicate: status == arkret_wire::AuthorityCommitStatus::Duplicate,
        })
    })
}

/// Map a guarded unit failure onto the registered top-level wire codes.
fn guarded_unit_error(error: coland_services::ServiceError) -> SubmitOneError {
    use coland_services::ServiceError;
    use coland_storage::ConflictCode;
    let message = error.to_string();
    let (status, code) = match &error {
        ServiceError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
        ServiceError::SchemaViolation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "schema_violation"),
        ServiceError::UnsupportedEventKind(_) => (
            StatusCode::NOT_IMPLEMENTED,
            arkret_wire::ErrorCode::UNSUPPORTED_EVENT_KIND,
        ),
        ServiceError::Conflict(_) => match error.conflict_code() {
            Some(ConflictCode::DuplicateConflict) => (StatusCode::CONFLICT, "duplicate_conflict"),
            Some(ConflictCode::SnapshotCapacityExceeded) => (
                StatusCode::CONFLICT,
                arkret_wire::ReasonCode::SNAPSHOT_CAPACITY_EXCEEDED,
            ),
            Some(ConflictCode::TemporarilyUnavailable) => {
                (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
            }
            // Producer, authority-cut and admission refusals: the caller has
            // no current authority to append this Event.
            _ => (StatusCode::FORBIDDEN, "capability_denied"),
        },
        ServiceError::Database(_) | ServiceError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    };
    SubmitOneError::new(status, code, message)
}
