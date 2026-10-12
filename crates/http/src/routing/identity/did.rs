//! Identity / DID handlers.
//!
//! Surfaces:
//! - `GET  /_arkret/root/identity/describe`     — service identity capability descriptor
//! - `POST /_arkret/root/identity/resolve`      — resolve a DID via SDK + local store
//! - `GET  /_arkret/root/identity/document`     — fetch the locally-cached DID document
//! - `GET  /_arkret/root/identity/log`          — return the local key log for a DID
//! - `GET  /webvh/{local_id}/did.json` — embedded webvh DID document
//! - `GET  /webvh/{local_id}/did.jsonl` — embedded webvh log
//! - `POST /_arkret/root/identity/submit-did-operation` — submit a DID operation
//! - `GET  /_arkret/root/identity/receipts`     — issuer receipts for the local key log
//!
//! Long-term DID state is accessed through the identity application service; the
//! `did_resolver` remains an in-process bounded cache over durable records.

use arkret_identifiers::{Did, Hash};
use arkret_models_identity::http_bodies::IdentityDocumentViewOutcome;
use arkret_models_identity::identity::{
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, IdentityDocumentView,
    IdentityMethodEvidence, IdentityMethodEvidenceKind, IdentityResolveOutcome,
};
use arkret_wire::NonEmptyString;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::identity::{
    DidDocumentState as WebvhDocumentRecord, DidLogCommitResult as WebvhLogCommitOutcome,
    DidLogEvent as WebvhLogRecord,
};
use salvo::http::{StatusCode, header};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_rotation_authorization_for_log,
    validate_witness_policy_for_log, verify_log_subject, verify_scid_against_did,
    verify_webvh_log_proof,
};
use super::{append_audit_log, bearer_token, now, render_error, sha256_hex, validate_did};
use crate::state::AppState;
use crate::wire::{IdentityLogListOutcome, IdentityReceiptListOutcome, IdentityResolveRequestBody};

mod document;
mod endpoints;
pub(crate) use endpoints::IDENTITY_REGISTRY_OPERATION_BUNDLES;
mod webvh;

use document::{render_json_bytes, run_webvh_resolution_checks};
// Endpoint handlers referenced by identity/mod.rs router().
pub(super) use endpoints::{
    embedded_webvh_document, embedded_webvh_log, identity_describe, identity_document,
    identity_log, identity_receipts, identity_resolve, identity_submit_did_operation,
};
pub(in crate::routing::identity) use webvh::*;
