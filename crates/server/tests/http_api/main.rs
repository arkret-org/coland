//! `http_api` integration-test binary.
//!
//! The 9868-line monolithic test file was split into per-domain submodules
//! living alongside this entry point in `tests/http_api/`. Cargo auto-discovers
//! `tests/<name>/main.rs` as the integration-test binary `<name>`, so the
//! sibling submodules resolve through plain `mod` declarations (the directory
//! layout matches Rust's default module resolution — no `#[path]` needed).

#[path = "current_common.rs"]
mod common;

mod admin_b_track;
mod admin_production_queries;
mod blob_resumable;
mod blob_upload;
mod deactivation_push_fanout;
mod device_message_send_admission;
mod health;
mod openapi;
mod organization_registration;
mod push_registration_onboarding;
mod self_signer_keys_query;
