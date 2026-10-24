use arkret_models_identity::PrincipalResolutionProjection;
use arkret_wire::{AccountId, ActorId, Event, RealmId};

use super::{PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq)]
pub struct PrincipalResolutionRecord {
    pub account_id: AccountId,
    pub pcr_realm_id: RealmId,
    pub genesis_event: Event,
    pub current_event: Event,
    pub projection: PrincipalResolutionProjection,
}

pub fn validate_principal_resolution_record(
    record: &PrincipalResolutionRecord,
) -> PersistenceResult<()> {
    let projected = arkret_wire::project_did_to_core_id(&record.projection.did)
        .map_err(|error| super::PersistenceError::SchemaViolation(error.to_string()))?;
    let current_is_genesis = record.current_event.event_id == record.genesis_event.event_id;
    let account_actor_id = ActorId::account(record.account_id.clone());
    if projected != record.account_id.principal_id
        || record.projection.resolution_event_ref != record.current_event.event_id.as_str()
        || record.projection.method_history_head.is_empty()
        || record.projection.version_id.is_empty()
        || record.genesis_event.kind != arkret_wire::EventKind::RealmCreate
        || record.genesis_event.realm_id != record.pcr_realm_id
        || record.current_event.realm_id != record.pcr_realm_id
        || record.genesis_event.actor_id != account_actor_id
        || record.current_event.actor_id != account_actor_id
        || (current_is_genesis && record.current_event.kind != arkret_wire::EventKind::RealmCreate)
        || (!current_is_genesis
            && record.current_event.kind != arkret_wire::EventKind::IdentityResolutionUpdate)
    {
        return Err(super::PersistenceError::SchemaViolation(
            "principal resolution record does not bind its AccountId, PCR Realm, Event head and DID projection"
                .to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub enum PrincipalResolutionCasResult {
    Applied(PrincipalResolutionRecord),
    Conflict(Option<PrincipalResolutionRecord>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum CurrentPrincipalRead {
    Missing,
    Unavailable,
    Ready {
        pcr_realm_id: RealmId,
        projection: PrincipalResolutionProjection,
    },
}

/// Complete native evidence prepared before, and reverified within, the PCR cut.
#[derive(Clone, Debug)]
pub struct PrincipalResolutionUpdateWrite {
    pub transaction: crate::AuthorityCommitTransaction,
    pub log_entries: Vec<serde_json::Value>,
    pub witness_records: Vec<serde_json::Value>,
}

/// Durable, rebuildable read index over one PCR's committed resolution Events.
#[async_trait]
pub trait PrincipalResolutionStore: Send + Sync {
    async fn admit_update(
        &self,
        _write: PrincipalResolutionUpdateWrite,
    ) -> PersistenceResult<arkret_wire::AuthoritySubmitResponseBody> {
        Err(super::PersistenceError::Conflict(
            "temporarily_unavailable: PCR resolution admission unavailable".into(),
        ))
    }
    /// Immutable accepted Human creation, independent of resolution current.
    async fn registered_genesis(
        &self,
        _account_id: &AccountId,
    ) -> PersistenceResult<Option<Event>> {
        Err(super::PersistenceError::Conflict(
            "temporarily_unavailable: accepted Human creation unavailable".into(),
        ))
    }
    async fn current_principal(
        &self,
        account_id: &AccountId,
    ) -> PersistenceResult<CurrentPrincipalRead>;
    async fn by_account_id(
        &self,
        account_id: &AccountId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>>;

    async fn for_realm(
        &self,
        pcr_realm_id: &RealmId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>>;

    async fn compare_and_set(
        &self,
        expected_current_event_ref: Option<&str>,
        next: PrincipalResolutionRecord,
    ) -> PersistenceResult<PrincipalResolutionCasResult>;

    async fn history_newest_first(
        &self,
        account_id: &AccountId,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<Event>>;
}
