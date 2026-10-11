use arkret_identifiers::EventId;
#[cfg(test)]
use arkret_models_integration::AppletTransactionStatus;
use arkret_models_integration::applet_models::AppletEventTransactionRequestBody;
use arkret_models_integration::{
    AppletEventRejection, AppletNamespaceDomain, AppletTransactionOutcome,
    namespace_pattern_matches,
};
use arkret_wire::{CommittedEventRef, Event};
use coland_http::error::AppError;
use coland_services::events::{AppletTransactionReplayResult, AppletTransactionReplayState};

use super::record::applet_record;
use super::signature::VerifiedAppletServiceSignature;
use super::types::AppletRecord;
use crate::state::AppState;

pub(super) async fn process_verified_transaction(
    state: &AppState,
    transaction: AppletEventTransactionRequestBody,
    idempotency_key: &str,
    verified: VerifiedAppletServiceSignature,
) -> Result<AppletTransactionOutcome, AppError> {
    let applet_id = transaction.applet_id.clone();
    let source_id = transaction.source_id.to_string();
    // applet-integration.md 7.3: a saturated inbound queue is a protocol
    // outcome. The shed delivery comes back as a per-event `queue_full` with
    // `retry_after_ms`, and the slot is claimed BEFORE the replay record is
    // begun so the rejection leaves the idempotency identity unconsumed and the
    // sender may re-deliver the same bytes under the same key.
    let Some(_admission_slot) = state.try_claim_applet_transaction_slot() else {
        return Ok(queue_full_outcome(&transaction));
    };
    let begin = state
        .event_queries()
        .begin_applet_transaction(AppletTransactionReplayState {
            applet_id: applet_id.clone(),
            source_id: source_id.clone(),
            idempotency_key: idempotency_key.to_owned(),
            delivery_authentication_record: verified.delivery_authentication_record.clone(),
            delivery_authentication_record_digest: verified
                .delivery_authentication_record_digest
                .clone(),
            request_digest: verified.request_digest.clone(),
            outcome: None,
            received_at: chrono::Utc::now(),
            completed_at: None,
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to begin applet transaction replay record");
            AppError::internal("applet transaction replay store unavailable")
        })?;
    match begin {
        AppletTransactionReplayResult::Fresh => {}
        AppletTransactionReplayResult::Existing(existing) => {
            return replayed_transaction_outcome(*existing, &verified);
        }
    }

    let event_count = transaction.events.len();
    let mut committed_event_refs = Vec::new();
    let mut rejected = Vec::new();
    for event in transaction.events {
        let event_id = event.event_id.to_string();
        let install = match applet_record(state, applet_id.as_str(), &event.scope_ref).await? {
            Some(install) => install,
            None => {
                rejected.push(rejected_event(
                    &event_id,
                    "applet_registration_unauthorized",
                ));
                continue;
            }
        };
        if let Err(reason_code) = validate_transaction_event_binding(&install, &source_id, &event) {
            rejected.push(rejected_event(&event_id, reason_code));
            continue;
        }
        let registration: arkret_models_integration::AppletRegistrationPayload =
            serde_json::from_value(
                serde_json::to_value(&install.registration_event.payload)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
        let document = crate::jws_verify::resolve_did_document(
            state,
            &registration.manifest.registration_epoch_evidence.did,
        )
        .map_err(AppError::param_invalid)?;
        match crate::state::submit_applet_event(state, event.clone(), document).await {
            Ok(outcome) => {
                committed_event_refs.push(
                    durable_transaction_event_ref(state, &event.event_id, event.event_id.as_str())
                        .await?,
                );
                tracing::debug!(
                    event_id = %event.event_id,
                    outcome = ?outcome,
                    "applet transaction event accepted"
                );
            }
            Err(error) => {
                tracing::warn!(
                    event_id = %event_id,
                    error = %error,
                    "applet transaction event rejected"
                );
                rejected.push(rejected_event_with_detail(
                    &event_id,
                    error
                        .conflict_code()
                        .map(|code| code.as_str())
                        .unwrap_or("schema_violation"),
                    error.to_string(),
                ));
            }
        }
    }

    let outcome = if rejected.is_empty() {
        AppletTransactionOutcome::Accepted {
            committed_event_refs,
            rejections: rejected,
            retry_after_ms: None,
        }
    } else if rejected.len() == event_count {
        AppletTransactionOutcome::Rejected {
            rejections: rejected,
            retry_after_ms: None,
        }
    } else {
        AppletTransactionOutcome::Partial {
            committed_event_refs,
            rejections: rejected,
            retry_after_ms: None,
        }
    };
    let outcome_value = serde_json::to_value(&outcome).map_err(|error| {
        AppError::internal(format!("applet transaction outcome serialize: {error}"))
    })?;
    state
        .event_queries()
        .complete_applet_transaction(
            applet_id.as_str(),
            &source_id,
            idempotency_key,
            outcome_value,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to complete applet transaction replay record");
            AppError::internal("applet transaction replay store unavailable")
        })?;
    Ok(outcome)
}

async fn durable_transaction_event_ref(
    state: &AppState,
    submitted_event_id: &EventId,
    accepted_event_id: &str,
) -> Result<CommittedEventRef, AppError> {
    if accepted_event_id != submitted_event_id.as_str() {
        return Err(AppError::internal(
            "Event admission returned an identity different from the submitted Event",
        ));
    }
    let record = state
        .persistence()
        .committed_event(submitted_event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::internal(
                "Event admission succeeded without a durable governing-Station commit",
            )
        })?;
    if record.event.event_id != *submitted_event_id {
        return Err(AppError::internal(
            "durable committed Event record disagrees with the submitted Event identity",
        ));
    }
    Ok(CommittedEventRef {
        event_id: submitted_event_id.clone(),
        commit_id: record.commit.commit_id,
        stream_ref: record.commit.stream_ref,
        stream_position: record.commit.stream_position,
    })
}

fn replayed_transaction_outcome(
    existing: AppletTransactionReplayState,
    verified: &VerifiedAppletServiceSignature,
) -> Result<AppletTransactionOutcome, AppError> {
    let stored: arkret_models_integration::AppletDeliveryAuthenticationRecord =
        serde_json::from_value(existing.delivery_authentication_record.clone()).map_err(
            |error| AppError::internal(format!("stored delivery record is invalid: {error}")),
        )?;
    let current: arkret_models_integration::AppletDeliveryAuthenticationRecord =
        serde_json::from_value(verified.delivery_authentication_record.clone()).map_err(
            |error| AppError::internal(format!("verified delivery record is invalid: {error}")),
        )?;
    let stored_digest = stored.stable_digest().map_err(AppError::internal)?;
    let current_digest = current.stable_digest().map_err(AppError::internal)?;
    if stored_digest.as_str() != existing.delivery_authentication_record_digest
        || current_digest.as_str() != verified.delivery_authentication_record_digest
    {
        return Err(AppError::internal(
            "delivery authentication digest does not bind its record",
        ));
    }
    if existing.request_digest != verified.request_digest || stored_digest != current_digest {
        return Err(AppError::conflict(
            "Idempotency-Key was already used for a different applet transaction",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let Some(outcome) = existing.outcome else {
        return Err(
            AppError::conflict("applet transaction is already in progress")
                .with_internal_reason("applet_transaction_in_progress"),
        );
    };
    serde_json::from_value(outcome).map_err(|error| {
        AppError::internal(format!(
            "stored applet transaction outcome invalid: {error}"
        ))
    })
}

fn validate_transaction_event_binding(
    install: &AppletRecord,
    source_id: &str,
    event: &Event,
) -> Result<(), &'static str> {
    let package = &install.package;
    if package.service_id.as_str() != source_id {
        return Err("applet_registration_unauthorized");
    }
    if install.revoked_at.is_some()
        || !matches!(install.status.as_str(), "installed" | "partially_installed")
    {
        return Err("applet_revoked");
    }
    if event.realm_id.as_str() != install.portal_realm_id.as_str()
        || event.scope_ref != install.effective_scope
    {
        return Err("applet_effective_scope_mismatch");
    }
    if event.applet_id.as_ref().map(|id| id.as_str()) != Some(install.applet_id.as_str()) {
        return Err("applet_id_mismatch");
    }
    if event
        .authorization_ref
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err("authorization_ref_missing");
    }
    let actor_id = event.actor_id.signing_principal_id().as_str();
    if event.actor_id == arkret_wire::ActorId::service(package.service_id.clone()) {
        return if event.executed_by.is_none() {
            Ok(())
        } else {
            Err("applet_service_cannot_delegate_to_itself")
        };
    }
    if install
        .bots
        .iter()
        .any(|bot| bot.bot_actor_id == event.actor_id)
    {
        return Ok(());
    }
    if install
        .ghosts
        .iter()
        .any(|ghost| ghost.ghost_actor_id == event.actor_id)
    {
        return Ok(());
    }
    let matched = event.actor_id.route_service_id() == &install.target_station_id
        && install.package.namespaces.actors.iter().any(|entry| {
            !namespace_pattern_is_wildcard(&entry.pattern)
                && namespace_pattern_matches(
                    AppletNamespaceDomain::Actors,
                    &entry.pattern,
                    actor_id,
                )
        });
    if matched {
        Ok(())
    } else {
        Err("applet_namespace_mismatch")
    }
}

fn namespace_pattern_is_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.ends_with(':') || pattern.ends_with('/')
}

/// Retry window advertised with a shed delivery. It is a fixed, small window:
/// the sender re-delivers the exact same bytes under the same idempotency
/// identity, so a longer wait only delays work the Station still has to do.
const QUEUE_FULL_RETRY_AFTER_MS: u64 = 1_000;

/// Reject every event in the delivery for inbound backpressure, without
/// consuming the idempotency identity.
fn queue_full_outcome(transaction: &AppletEventTransactionRequestBody) -> AppletTransactionOutcome {
    AppletTransactionOutcome::Rejected {
        rejections: transaction
            .events
            .iter()
            .map(|event| AppletEventRejection {
                event_id: Some(event.event_id.clone()),
                reason_code: arkret_wire::ReasonCode::from_wire(
                    arkret_wire::ReasonCode::QUEUE_FULL,
                ),
                retry_after_ms: Some(QUEUE_FULL_RETRY_AFTER_MS),
            })
            .collect(),
        retry_after_ms: Some(QUEUE_FULL_RETRY_AFTER_MS),
    }
}

fn rejected_event(event_id: &str, reason_code: impl AsRef<str>) -> AppletEventRejection {
    AppletEventRejection {
        event_id: EventId::new(event_id.to_owned()).ok(),
        reason_code: arkret_wire::ReasonCode::from_wire(reason_code.as_ref()),
        retry_after_ms: None,
    }
}

fn rejected_event_with_detail(
    event_id: &str,
    reason_code: impl AsRef<str>,
    detail: impl Into<String>,
) -> AppletEventRejection {
    let _detail = detail.into();
    rejected_event(event_id, reason_code)
}

#[cfg(test)]
mod backpressure_tests {
    use super::*;

    fn transaction_state(capacity: usize) -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.applet_transaction_inflight_capacity = capacity;
        AppState::new(config, coland_storage_postgres::Db { pool: None })
    }

    #[test]
    fn a_saturated_station_sheds_the_delivery_without_taking_a_slot_it_cannot_release() {
        let state = transaction_state(1);
        let first = state
            .try_claim_applet_transaction_slot()
            .expect("the first delivery is admitted");
        assert!(
            state.try_claim_applet_transaction_slot().is_none(),
            "a full inbound queue must refuse the next delivery"
        );
        drop(first);
        assert!(
            state.try_claim_applet_transaction_slot().is_some(),
            "the slot must return when the delivery finishes"
        );
    }

    #[test]
    fn the_shed_outcome_rejects_every_event_with_queue_full_and_a_retry_window() {
        let event_ids = [
            "ak:event:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcf",
            "ak:event:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcg",
        ];
        let transaction = AppletEventTransactionRequestBody {
            applet_id: arkret_identifiers::AppletId::new(
                "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            source_id: arkret_wire::DidCoreId::new("ak:did_core:web:applet.example").unwrap(),
            events: event_ids
                .iter()
                .map(|event_id| {
                    let mut event = crate::test_event::raw_event(
                        arkret_wire::EventKind::MessageCreate.as_str(),
                        arkret_wire::ScopeRef::Realm {
                            realm_id: arkret_wire::RealmId::new(
                                "ak:realm:AQpwDm7ZXVTjUWCnaqcmxxZ49Y8CpzFJ-vLzmvCjBXfw",
                            )
                            .unwrap(),
                        },
                        arkret_wire::DidCoreId::new("ak:did_core:web:applet.example").unwrap(),
                        1,
                        arkret_wire::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
                        serde_json::json!({
                            "strand_id": "ak:strand:AQ9vwMrZNs64XfX4CVfhG2FPvja_JU2XLAIWCbvWK5kG",
                            "content": {"kind": "ak.content.text", "body": "hello"}
                        }),
                    )
                    .expect("test Event envelope");
                    event.event_id = EventId::new((*event_id).to_owned()).unwrap();
                    event
                })
                .collect(),
            committed_events: Vec::new(),
            signals: Vec::new(),
        };

        let outcome = queue_full_outcome(&transaction);
        assert_eq!(outcome.status(), AppletTransactionStatus::Rejected);
        assert!(outcome.committed_event_refs().is_empty());
        assert!(
            serde_json::to_value(&outcome)
                .unwrap()
                .get("committed_event_refs")
                .is_none()
        );
        assert_eq!(outcome.retry_after_ms(), Some(QUEUE_FULL_RETRY_AFTER_MS));
        assert_eq!(outcome.rejections().len(), event_ids.len());
        for (rejection, event_id) in outcome.rejections().iter().zip(event_ids) {
            assert_eq!(
                rejection.event_id.as_ref().map(EventId::as_str),
                Some(event_id)
            );
            assert_eq!(
                rejection.reason_code.as_str(),
                arkret_wire::ReasonCode::QUEUE_FULL
            );
            assert_eq!(rejection.retry_after_ms, Some(QUEUE_FULL_RETRY_AFTER_MS));
        }
    }
}
