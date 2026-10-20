//! Applet package install, bot/ghost provisioning, and portal routing.
//!
//! Formal `/_arkret` operations consume SDK-owned Applet types and
//! caller-authored protocol Events. Coland never mints Applet-managed actor
//! identities and exposes no deployment-local Applet protocol.

mod authority_material;
mod bot;
mod endpoints;
mod ghost;
mod ghost_reuse;
mod install;
mod management_review;
pub(crate) mod record;
mod signature;
mod transaction;
mod types;

#[cfg(test)]
mod inbound_signature_tests;

pub(in crate::routing::extensions) use endpoints::protocol_router;
pub(crate) use management_review::prepare_event_current;
pub(crate) use signature::verify_self_control_service;
pub(crate) use types::registration_epoch_evidence_from_event;
pub use types::{AppletRecord, AppletRevokeRecordOutcome, GhostActorRecord};
