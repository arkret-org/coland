#![recursion_limit = "256"]

#[cfg(feature = "test-support")]
extern crate self as coland_storage_postgres;

#[cfg(feature = "test-support")]
pub mod pin_conformance;

pub(crate) use std::collections::{BTreeMap, BTreeSet};

pub(crate) use arkret_event_draft::ProjectedEventOperation;
pub(crate) use arkret_identifiers::BlobRef;
pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub(crate) use coland_storage::*;
pub(crate) use diesel::sql_types::{
    Array, BigInt, Binary, Bool, Integer, Jsonb, Nullable, Text, Timestamptz,
};
pub(crate) use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
pub(crate) use diesel_async::pooled_connection::deadpool::Object;
pub(crate) use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
pub(crate) use serde_json::Value;
pub(crate) use uuid::Uuid;

pub mod db;
pub mod query_rows;
pub mod schema;

pub use db::{Db, PgPool, PoolTuning};
pub(crate) use query_rows::{ExistsRow, JsonPayloadRow, MaxSeqRow};

mod account_device_committed_evidence;
mod account_device_signer_evidence;
mod account_status;
mod account_stream_scan;
mod account_summary;
mod accounts;
mod actor_private_events;
mod actor_profiles;
mod agent_control;
mod agent_current_results;
mod agent_draft_pending_intents;
mod agent_interaction_current_results;
mod agent_membership_cascades;
mod agent_origin;
mod agent_participation_admission;
mod agent_pcr_genesis;
mod agent_principal_row;
mod agent_producer_evidence;
mod agent_producer_signer_keys;
mod agent_provisioning;
mod agents;
mod applet_admission;
mod applet_authority_material;
mod applet_current_results;
mod applet_widget_tokens;
mod applets;
mod audit;
mod authority_commit;
mod blobs;
mod capability_grant_current_results;
mod capability_quota;
mod committed_disclosure;
mod consent_current;
mod consent_request_quarantine;
pub use consent_current::PgConsentCurrentStore;
mod contacts;
pub use consent_request_quarantine::PgConsentRequestQuarantineStore;
#[cfg(test)]
#[path = "../../test-support/src/device_authorization_history.rs"]
#[expect(
    dead_code,
    reason = "The unit tests use only their subset of the shared device history fixture."
)]
mod device_authorization_history;
mod device_revocations;
mod devices;
mod direct_conversation_admission;
mod direct_conversation_founding;
#[cfg(feature = "test-support")]
pub use direct_conversation_founding::FoundingProfileAdmissionSpy;
mod agent_confirmation_admission;
mod agent_management_admission;
mod approval_admission;
mod event_notifications;
mod events;
mod federation;
mod governance;
mod grant_approval_admission;
mod idempotency;
mod invite_current_results;
mod policy_action_admission;
mod policy_current_results;
pub use invite_current_results::PgInviteCurrentResultStore;
mod applet_authoring_context;
mod call_state_current_results;
mod circle_current_results;
mod circle_reads;
mod invite_locators;
mod invite_new_source_ledger;
mod issued_realm_snapshots;
mod key_backup;
mod key_backup_current_results;
mod key_backup_unlock;
mod managed_message_actor;
mod member_identity;
mod member_identity_current_results;
mod member_state_admission;
mod message_interactions;
mod message_reactions_current_results;
mod message_revision_current_results;
mod mls;
mod mls_group_current_results;
mod mls_group_state_material_read;
mod mls_recipient_attestation_outbox;
mod mls_roster_attest_add;
mod mls_roster_authority_read;
mod moderation;
mod moderation_franking_proof_current_results;
mod moderation_report_current_results;
mod moderation_state_current_results;
mod notifications;
mod object_projection_reads;
mod object_redaction_current_results;
mod organization_moderation_gate;
mod organization_registration;
mod pcr_accepted_device_unit;
mod pcr_device_current_results;
mod pcr_device_revocation_proposals;
mod pcr_device_status_fold;
mod pcr_device_status_reader;
#[cfg(test)]
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
mod pcr_recovery_policy_unit;
mod pin_current_results;
mod policy;
mod poll_state;
mod principal_resolution;
mod projection;
mod publication_evidence;
mod push;
mod push_handoff;
#[cfg(test)]
mod read_capacity_tests;
mod read_cursors;
mod realm_authorization_cut;
mod realm_bootstrap_current_results;
mod realm_default_strand_current_results;
mod realm_fanout;
mod realm_identity;
mod realm_lifecycle_current_results;
mod recovery;
mod registry;
mod relation_current_results;
mod relation_disclosure;
mod replica_authorization;
mod replica_current;
mod replica_direct_mls;
mod replica_stream_listing;
mod rsvp_current_results;
mod security_transactions;
mod self_current_reads;
mod service_identity;
mod service_route;
mod sessions;
mod settings;
mod sidecar_access;
mod sidecar_authority_change_guard;
pub mod sidecar_authority_cut;
mod sidecar_current_results;
mod sidecar_effective_access;
mod sidecar_exchange_controls;
mod sidecar_mls_readiness;
mod sidecar_replica_authority;
mod sidecar_replica_current;
mod sidecars;
mod signal;
mod signal_scope_authority;
mod snapshot_disclosure_gate;
mod space_current_results;
mod strand_current_results;
mod strand_position_current_results;
mod strand_watch_current_results;
mod sync_cursor;
#[cfg(any(test, feature = "test-support"))]
pub mod test_database;
mod unit_of_work;
mod websocket_auth;
mod webvh;

pub use account_device_signer_evidence::PgAccountDeviceSignerEvidenceArchive;
pub(crate) use account_status::PgAccountStatusReplicaStore;
pub use accounts::*;
pub use actor_private_events::PgActorPrivateEventStore;
pub use actor_profiles::PgActorProfileStore;
pub use agent_draft_pending_intents::*;
pub use agent_membership_cascades::*;
pub(crate) use agent_principal_row::{AgentPrincipalRow, pack_runtime_key_material};
pub use agents::*;
pub use applets::*;
pub use audit::*;
pub use authority_commit::*;
pub use blobs::*;
pub use capability_grant_current_results::*;
pub use contacts::*;
pub use device_revocations::*;
pub(crate) use device_revocations::{
    ensure_gate_allowed_in_transaction, gate_status_in_transaction,
};
pub use devices::*;
pub use event_notifications::*;
pub use events::*;
pub use federation::*;
pub use governance::*;
pub use idempotency::*;
pub use invite_locators::*;
pub use invite_new_source_ledger::*;
pub use issued_realm_snapshots::*;
pub use key_backup::*;
pub use member_identity::*;
pub use mls::*;
pub use mls_group_current_results::PgMlsGroupCurrentStore;
pub use moderation::*;
pub use notifications::*;
pub use organization_registration::*;
pub use policy::*;
pub use principal_resolution::*;
pub use projection::*;
pub use publication_evidence::*;
pub use push::*;
pub use push_handoff::*;
pub use read_cursors::PgReadCursorStore;
pub use recovery::*;
pub use registry::PgPersistenceStore;
pub use relation_current_results::*;
pub use security_transactions::*;
pub use service_identity::*;
pub use service_route::*;
pub use sessions::*;
pub use settings::*;
pub use sidecars::*;
pub use signal::*;
pub use snapshot_disclosure_gate::*;
pub use sync_cursor::*;
#[cfg(any(test, feature = "test-support"))]
pub use test_database::TestDatabase;
pub use unit_of_work::*;
pub use websocket_auth::*;
pub use webvh::*;

#[derive(QueryableByName)]
struct DatabaseReadyRow {
    #[diesel(sql_type = Integer)]
    ok: i32,
}

pub async fn database_ready(pool: Option<&PgPool>) -> bool {
    match pool {
        Some(pool) => match pool.get().await {
            Ok(mut conn) => sql_query("SELECT 1 AS ok")
                .get_result::<DatabaseReadyRow>(&mut *conn)
                .await
                .is_ok_and(|row| row.ok == 1),
            Err(_) => false,
        },
        None => true,
    }
}

pub(crate) async fn pg_conn(pool: &PgPool) -> PersistenceResult<Object<AsyncPgConnection>> {
    pool.get()
        .await
        .map_err(|error| PersistenceError::Internal(format!("database pool error: {error}")))
}

pub(crate) fn json_string_array(value: Value) -> Vec<String> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) enum PgTransactionError {
    Storage(PersistenceError),
    Diesel(diesel::result::Error),
}

impl PgTransactionError {
    pub(crate) fn into_persistence(self) -> PersistenceError {
        match self {
            Self::Storage(error) => error,
            Self::Diesel(error) => PersistenceError::database(error),
        }
    }
}

impl From<PersistenceError> for PgTransactionError {
    fn from(error: PersistenceError) -> Self {
        Self::Storage(error)
    }
}

impl From<diesel::result::Error> for PgTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

mod ids {
    pub use coland_storage::ids::*;
}

mod mimi_admission;
