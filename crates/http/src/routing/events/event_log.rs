//! Signed Event Envelope ingestion + read API (`/_arkret/self/events/*`).
//!
//! Surfaces:
//! - `QUERY /_arkret/self/events/describe` — declare the active event registry, schema/reducer
//!   profiles, and limits.
//! - `POST /_arkret/self/events`           — submit one canonical Event Envelope or an `events[]`
//!   account-client batch.
//! - `GET  /_arkret/self/committed-events/{event_id}` — fetch the committed Event/Commit pair.
//! - `GET /_arkret/self/committed-events/{event_id}` — one committed Event view.
//! - `GET  /_arkret/self/events`            — paginated list (filtered by actor / realm).
//!
//! The validator block (`validate_event_envelope` + helpers) lives in the
//! `validation` submodule.

use std::collections::BTreeMap;

use arkret_canonical as canonical;
use arkret_event_draft::ProjectedEventOperation as Operation;
#[cfg(test)]
use arkret_identifiers::DeviceId;
#[cfg(test)]
use arkret_identifiers::DidCoreId;
#[cfg(test)]
use arkret_identifiers::RealmId;
use arkret_identifiers::{EventId, OperationId};
#[cfg(test)]
use arkret_wire::CommittedEventWithheldView;
#[cfg(test)]
use arkret_wire::EventDisclosure;
#[cfg(test)]
use arkret_wire::EventDisclosureStatus;
use arkret_wire::{CommittedEventFullView, CommittedEventView, Event};
use chrono::{DateTime, Duration, Utc};
#[cfg(test)]
use coland_http::error::error_http_status;
use coland_http::error::{AppError, ErrorCode};
use coland_http::result::{JsonResult, json_ok};
use coland_services::events::AcceptedEvent;
use coland_services::identity::SessionIdentityState as SessionRecord;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

#[cfg(test)]
use super::projection::retention_tombstone_for_event;
#[cfg(test)]
use super::realm_allows_plaintext_service_for_data_class;
use super::realm_event_visible_to_session;
#[cfg(test)]
use super::validate_space_id;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

#[cfg(test)]
fn current_query_error(error: arkret_wire::WireError) -> AppError {
    let code = match error.error_code() {
        Some(ErrorCode::PayloadTooLarge) => ErrorCode::PayloadTooLarge,
        _ => ErrorCode::SchemaViolation,
    };
    AppError::from_rejection(code, error.to_string())
}

#[cfg(test)]
fn current_result_error(error: arkret_wire::WireError, fallback: ErrorCode) -> AppError {
    let code = match error.error_code() {
        Some(ErrorCode::LimitExceeded) => ErrorCode::LimitExceeded,
        _ => fallback,
    };
    AppError::from_rejection(code, error.to_string())
}

#[cfg(test)]
mod current_budget_error_tests {
    use arkret_wire::WireError;

    use super::*;

    #[test]
    fn current_query_budget_codes_do_not_depend_on_error_text() {
        let oversized = current_query_error(WireError::ProtocolCode {
            code: ErrorCode::PayloadTooLarge,
            message: "canonical request exceeds its budget".to_owned(),
        });
        assert_eq!(oversized.code, ErrorCode::PayloadTooLarge);
        assert_eq!(
            error_http_status(oversized.code),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let invalid = current_query_error(WireError::Protocol(
            "payload_too_large appears in this invalid field".to_owned(),
        ));
        assert_eq!(invalid.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn malformed_current_result_is_not_reported_as_a_budget_failure() {
        let invalid = current_result_error(
            WireError::Protocol("limit_exceeded is only diagnostic text".to_owned()),
            ErrorCode::StateMismatch,
        );
        assert_eq!(invalid.code, ErrorCode::StateMismatch);
        let oversized = current_result_error(
            WireError::ProtocolCode {
                code: ErrorCode::LimitExceeded,
                message: "response cannot fit".to_owned(),
            },
            ErrorCode::StateMismatch,
        );
        assert_eq!(oversized.code, ErrorCode::LimitExceeded);
    }
}

// ≤ 128, and the `authorized_by` role ≤ 64 within that total. These are the v1
// interop maxima a conformant receiver MUST accept; a stricter local cap would
// reject another node's valid wire object (spec §1).
#[cfg(test)]
mod admission;

#[cfg(test)]
pub use admission::frozen_realm_check;
#[cfg(test)]
pub use admission::realm_policy_bundle_check;
#[cfg(test)]
pub use admission::terminal_realm_check;

pub(crate) mod endpoints;

pub(in crate::routing::events) use endpoints::router;

#[cfg(test)]
mod inception;
#[cfg(test)]
use inception::resolve_event_root_anchor_method;

#[cfg(test)]
mod realm_index;

#[cfg(test)]
use realm_index::event_string_field;

mod submit;
#[cfg(test)]
use arkret_wire::MAX_SEMANTIC_REFS;
#[cfg(test)]
use submit::RealmBootstrapBatchContext;
#[cfg(test)]
pub(in crate::routing) use submit::ValidatedEventEnvelope;
use submit::event_validation_error;
pub(in crate::routing) use submit::{
    EventValidationError, applet_committed_ref, submit_applet_authoring_unit,
    submit_applet_revoke_event_submission, submit_event_value, submit_initial_event_submission,
    submit_one_error_to_app_error, submit_peer_pcr_genesis, submit_sidecar_ensure_batch,
};

#[cfg(test)]
mod validation;
#[cfg(test)]
use validation::*;
mod sdk_projection;
pub(crate) use sdk_projection::*;

#[cfg(test)]
#[path = "event_log/admission_tests.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "event_log_proof_strictness_tests.rs"]
mod proof_strictness_tests;
