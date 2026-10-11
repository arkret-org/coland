//! MIMI (Messaging Layer Interop) provider-facade handlers.
//!
//! Surfaces under `/_arkret/open/mimi/*` plus the well-known
//! `mimi-protocol-directory`. Writes from the MIMI side use their
//! operation-specific durable-effect contract:
//!
//!   * `POST /mimi/strands/{strand_id}/messages` -> emits a `MessageRecord` + a `ak.message.create`
//!     projection event so the MIMI ingress shows up on the canonical Arkret timeline.
//!   * `POST /mimi/strands/{strand_id}/update` -> emits a `ak.mimi.room_binding` projection event
//!     whenever the update body carries a `room_binding` block.
//!   * `POST /mimi/strands/{strand_id}/notify` -> broadcasts a synthetic
//!     `ak.open.mimi.command.notify.v1` projection event so live subscribers observe MIMI fanout.
//!   * `POST /mimi/report-abuse` -> verifies the closed reporter claim and current authority, then
//!     submits a facade-service-authored `ak.self.moderation.report` Event atomically.
//!
//! Canonical message-ingress Events carry `payload.mimi_provenance` metadata
//! (provider id, original MIMI envelope hash, MIMI message id) so the receiver
//! can distinguish MIMI ingress from a native signed Move.

use std::collections::BTreeMap;

use arkret_identifiers::{EventId, Hash};
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_models_collaboration::mimi_operations::{
    MimiIdentifierQueryOutcome, MimiIdentifierQueryRequestBody, MimiKeyMaterialOutcome,
    MimiKeyMaterialRequestBody, MimiNotifyOutcome, MimiNotifyRequestBody, MimiProxyDownloadOutcome,
    MimiProxyDownloadRequestBody, MimiReportAbuseOutcome, MimiReportAbuseRequestBody,
    MimiRequestConsentOutcome, MimiRequestConsentRequestBody, MimiRoomUpdateOutcome,
    MimiRoomUpdateRequestBody, MimiSubmitMessageOutcome, MimiSubmitMessageRequestBody,
    MimiUpdateConsentOutcome, MimiUpdateConsentRequestBody,
};
use arkret_models_collaboration::objects::mimi::{
    MimiCiphertext, MimiConsentPurpose, MimiDelivery, MimiDeliveryStatus, MimiIdentifierMatch,
    MimiKeyPackage, MimiOpaquePayload,
};
use arkret_signatures::http_signature::{
    HttpMessageVerificationError, HttpSignatureScenario, SignatureError, SignatureInput,
    SignaturePolicyError, SignatureVerificationPolicy,
};
use arkret_wire::{Audience, MimiRoomUri, MimiUri, MlsGroupId};
use chrono::Duration;
use coland_http::error::AppError;
use coland_http::http_signature;
use coland_http::result::{JsonResult, json_ok};
use coland_services::identity::MimiConsentCorrelation;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::{append_audit_log, now};
use crate::ids;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

struct MimiRoomBindingProjection {
    event_id: String,
    realm_id: String,
    binding: Value,
}

mod binding;
mod handlers;
mod payload;
mod signature;

use binding::*;
use handlers::*;
use payload::*;
use signature::*;

pub(super) fn router() -> Router {
    Router::with_path("mimi")
        .push(Router::with_path("provider-directory").get(mimi_provider_directory))
        .push(Router::with_path("key-material").post(mimi_key_material))
        .push(Router::with_path("strands/{strand_id}/update").post(mimi_room_update))
        .push(Router::with_path("strands/{strand_id}/notify").post(mimi_notify))
        .push(Router::with_path("strands/{strand_id}/messages").post(mimi_room_message))
        .push(Router::with_path("consent/request").post(mimi_consent_request))
        .push(Router::with_path("consent/update").post(mimi_consent_update))
        .push(Router::with_path("identifiers/query").post(mimi_identifiers_query))
        .push(Router::with_path("report-abuse").post(mimi_report_abuse))
        .push(Router::with_path("proxy-download").post(mimi_proxy_download))
}

pub(super) fn well_known_router() -> Router {
    Router::with_path(".well-known/mimi-protocol-directory").get(mimi_protocol_directory)
}
