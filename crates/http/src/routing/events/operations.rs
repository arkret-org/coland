//! Operation envelope + payload validators.
//!
//! Surfaces:
//! - `validate_operation_semantics` — the registry-backed entrypoint validator called from
//!   `event_log::submit_event`, `projection::project_accepted_operations`, and the federation
//!   ingest path.
//! - `validate_operation_policy` — high-level policy gate (plaintext-Space gating + B-09 redact
//!   constraints).
//! - `validate_canonical_json_value` (+ `_inner`) — the canonical number, timestamp, and byte
//!   encoding gate that operation payloads MUST pass. Field names and map-key grammars belong to
//!   the kind-specific JSON Schema pass so raw external documents retain their native lexicon.
//! - `validate_content_blocks` / `validate_mentions` / `validate_content_block` — message body
//!   shape. Mention admission is canonical-only: the SDK mention models own the `mention` /
//!   `audience_mention` AST node types.
//! - `validate_encrypted_payload_envelope` — `ak.profile.encrypted_envelope.v1` envelope shape (MLS
//!   sender / scheme / version / `key_ref`).
//! - canonical RFC 3339 UTC-Z timestamp shape for `*_at` fields accepts the SDK's ordinary
//!   whole-second profile and the Event-bound fixed-millisecond profile; kind-specific validators
//!   enforce narrower field requirements.
//! - `canonical_json_digest` — sha256 over canonical-JSON bytes.
//!
//! Spec items still pending here are tracked in `_todos.md` (notably
//! Stream-A19 for B-09 redact `actor_seq` preservation, B-22 for
//! encrypted-attachment `key_ref` shape, and the operation-schema gaps
//! around the 100+ event kinds the reducer doesn't cover yet).
//!
//! The implementation is split across submodules to keep each file small:
//! - `semantics` — operation-kind schema dispatch + the `validate_operation_semantics` entrypoint.
//! - `payload_validators` — the per-kind typed payload validators.
//! - `policy` / `policy_extra` — the `validate_operation_policy` gate and its helpers.
//! - `content` — canonical-JSON, content-block, mention, and device-message shape checks.

use arkret_event_draft::ProjectedEventOperation as Operation;
use coland_services::operation_semantics as kinds;
use serde_json::Value;

use crate::routing::interop::participant_binding;
use crate::state::AppState;

mod policy;
pub(crate) use policy::*;
mod policy_extra;
pub(crate) use policy_extra::*;
mod content;
pub(crate) use content::*;
mod semantics;
pub(crate) use semantics::*;
mod payload_validators;
pub(crate) use payload_validators::*;

#[cfg(test)]
mod mention_tests;
#[cfg(test)]
mod participant_binding_tests;
#[cfg(test)]
mod policy_tests;

#[cfg(test)]
#[path = "operations_wire_payload_tests.rs"]
mod wire_payload_tests;
