// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "../did_resolver_chain.rs"]
pub mod did_resolver_chain;

mod account_authority_device_pairing;
mod actor_private;
mod app_state;
mod applet_completion;
mod authority_accountability_grant;
mod authority_agent_control;
mod authority_agent_grant;
mod authority_agent_pcr_genesis;
pub(crate) mod authority_audit_unit;
mod authority_bootstrap_validation;
pub(crate) mod authority_consent;
mod authority_contact;
mod authority_direct_conversation;
mod authority_forward;
mod authority_franking;
mod authority_handoff;
mod authority_key_backup_pointer;
mod authority_managed_device;
mod authority_mls_unit;
pub(crate) mod authority_pcr;
mod authority_port;
mod authority_producer_validation;
mod authority_resolution;
mod authority_self_event_unit;
mod authority_sidecar_unit;
pub(crate) use authority_sidecar_unit::commit_sidecar_ensure_unit;
mod committed_replication;
pub(crate) mod foreign_direct_mls;
mod member_identity;
mod notification;
mod replica_anchor;
mod service_route_fetcher;
#[doc(hidden)]
pub use account_authority_device_pairing::AccountAuthorityDevicePairingPort;
pub(crate) use account_authority_device_pairing::LocalAccountAuthorityDevicePairing;
pub(crate) use actor_private::{
    actor_private_refusal, admit_account_data_set, canonical_event_digest,
};
pub use app_state::{
    AppState, AppStateRuntime, ConnectionDrain, DEVELOPMENT_DEMO_SUBJECT_DID,
    build_realm_directory, development_demo_genesis_event, development_demo_realm_id,
    getrandom_seed, realm_genesis_payload,
};
pub use applet_completion::{
    deliver_pending_applet_completions, spawn_pending_applet_completion_sweeper,
};
pub(crate) use authority_contact::{commit_contact_event_unit, verify_contact_producer};
#[cfg(feature = "test-support")]
pub(crate) use authority_forward::{
    admit_forwarded_event, admit_forwarded_mls, forward_self_event, fresh_device_request,
    fresh_forward_request, fresh_producer_agent_evidence, prepare_native_forward_request,
};
pub use authority_franking::spawn_pending_franking_sweeper;
#[cfg(feature = "test-support")]
pub(crate) use authority_handoff::install as install_test_handoff;
pub(crate) use authority_producer_validation::{
    verify_account_device_payload_proof, verify_account_device_producer,
    verify_mimi_binding_producer, verify_self_event_producer,
};
pub(crate) use authority_self_event_unit::{
    refresh_direct_conversation_peer_claim, submit_applet_event, submit_mimi_binding_event,
    submit_self_moderation_report,
};
pub use coland_services::events::{RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryQuery};
pub(crate) use member_identity::HandleClaimEvidenceRecord;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use member_identity::MemberIdentityEventRecord;
pub use notification::{
    EventBroadcast, EventNotification, EventNotificationKind, EventNotificationRelay, Mutex,
};
pub use replica_anchor::spawn_pending_anchor_sweeper;
pub(crate) use replica_anchor::{account_continuation_recoverable, refresh_account_snapshot};
pub(crate) use service_route_fetcher::VerifiedBindingRouteFetcher;

mod authority_mimi_unit;
pub(crate) use authority_mimi_unit::{
    author_mimi_event, commit_mimi_event, mimi_reporter_device_guard,
};
