//! Real accepted PCR and independently signed ordinary producer material.
// Integration binaries consume different subsets of this shared fixture API.
#![allow(dead_code)]
#[path = "../../../test-support/src/device_authorization_history.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "This fixture is also compiled by test-support without a circular crate dependency."
)]
mod device_authorization_history;
#[path = "ordinary_realm.rs"]
#[allow(dead_code)]
pub mod ordinary_realm;
#[path = "../../../test-support/src/pcr_genesis.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "This fixture is also compiled by test-support without a circular crate dependency."
)]
mod pcr_genesis;
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_models_identity::{HistoricalSignerKeyQuerySender, SignerKeyQuerySelector};
use arkret_wire::{ActorId, CommittedEventRef, Did, EventKind};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, DeviceRevocationGateSelector,
    EventCommitRequest, OrdinaryRealmBootstrapCommitUnit, SelfProducerCommitGuard,
};
use coland_storage_postgres::{PgAuthorityCommitStore, PgPersistenceStore, PgPool};
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;

pub struct HumanFixture {
    pub pcr: pcr_genesis::PcrGenesisFixture,
    pub guard: DeviceRevocationGateSelector,
    pub unit: OrdinaryRealmBootstrapCommitUnit,
}

impl HumanFixture {
    pub async fn new(pool: &PgPool, station: Did) -> Self {
        let mut pcr = pcr_genesis::PcrGenesisFixture::new(station.clone());
        let mut previous = None;
        for (index, transaction) in pcr.unit.transactions.iter_mut().enumerate() {
            transaction.commit.previous_commit_ref = previous;
            seal_commit(&mut transaction.commit, &station);
            previous = Some(transaction.commit.commit_id.clone());
            pcr.history.commits[index] = transaction.commit.clone();
        }
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) ON CONFLICT(singleton) DO NOTHING")
            .bind::<Text,_>(pcr.history.account.station_id.as_str()).execute(&mut *conn).await.unwrap();
        drop(conn);
        let guard = pcr
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .unwrap();
        let mut unit = ordinary_realm::bootstrap_unit_for_account(
            &format!("human-history-{}", uuid::Uuid::now_v7()),
            &pcr.history.account,
            &station,
        );
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let mut previous = None;
        for (index, transaction) in unit.transactions.iter_mut().enumerate() {
            let original_id = transaction.event.event_id.clone();
            transaction.event = device_authorization_history::sign_event(
                transaction.event.clone(),
                pcr.history.device_verification_method.clone(),
                pcr.history.founding_device_signing_seed,
            );
            assert_eq!(
                transaction.event.event_id, original_id,
                "proof does not alter Event identity"
            );
            transaction.producer_signer_fact = store
                .prepare_account_device_signer_fact(
                    &transaction.event,
                    transaction.commit.committed_at,
                )
                .await
                .unwrap()
                .map(Into::into);
            transaction.commit.producer_signer_fact_digest = transaction
                .producer_signer_fact
                .as_ref()
                .map(|fact| fact.digest().unwrap());
            transaction.commit.previous_commit_ref = previous;
            seal_commit(&mut transaction.commit, &station);
            previous = Some(transaction.commit.commit_id.clone());
            unit.submission.events[index] =
                arkret_wire::EventAdmissionSubmission::new(transaction.event.clone());
        }
        unit.exact_request_body = serde_json::to_vec(
            &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone()),
        )
        .unwrap();
        Self { pcr, guard, unit }
    }

    pub async fn admit(&self, pool: &PgPool) {
        let guards = vec![
            SelfProducerCommitGuard::HumanDevice(self.guard.clone());
            self.unit.transactions.len()
        ];
        PgAuthorityCommitStore { pool: pool.clone() }
            .admit_self_ordinary_realm_bootstrap_unit(
                &self.unit,
                &guards,
                self.unit.transactions[0].commit.committed_at,
            )
            .await
            .unwrap();
    }

    pub fn next(
        &self,
        previous: &AuthorityCommitTransaction,
        seed: [u8; 32],
    ) -> EventCommitRequest {
        let at = previous.commit.committed_at + chrono::TimeDelta::seconds(1);
        let unsigned = ordinary_realm::next_request_for_actor(
            previous,
            EventKind::RealmProfile,
            ActorId::account(self.pcr.history.account.clone()),
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Historical producer fixture"}),
            at,
        );
        let event = device_authorization_history::sign_event(
            unsigned.authority_commit.event,
            self.pcr.history.device_verification_method.clone(),
            seed,
        );
        let mut request = ordinary_realm::request_for_event(previous, event, at);
        let mut fact = self
            .unit
            .transactions
            .last()
            .unwrap()
            .producer_signer_fact
            .as_ref()
            .and_then(|fact| fact.as_account_device())
            .cloned()
            .expect("real original PCR source");
        fact.event_id = request.authority_commit.event.event_id.clone();
        request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
        request.authority_commit.producer_signer_fact = Some(fact.into());
        seal_commit(
            &mut request.authority_commit.commit,
            &self.pcr.history.station_did,
        );
        request.self_producer_guard =
            Some(SelfProducerCommitGuard::HumanDevice(self.guard.clone()));
        request
    }

    pub fn selector(&self, transaction: &AuthorityCommitTransaction) -> SignerKeyQuerySelector {
        SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::AccountDevice {
                actor: transaction.event.actual_signer().clone(),
                device_id: self.pcr.history.founding_device_id.clone(),
                verification_method: self.pcr.history.device_verification_method.clone(),
                committed_event_ref: CommittedEventRef {
                    event_id: transaction.event.event_id.clone(),
                    commit_id: transaction.commit.commit_id.clone(),
                    stream_ref: transaction.commit.stream_ref.clone(),
                    stream_position: transaction.commit.stream_position,
                },
            },
        }
    }
}

pub fn seal_commit(commit: &mut arkret_wire::RealmCommit, station: &Did) {
    let body =
        arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&body).unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        arkret_wire::DidUrl::new(format!("{station}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(
            &device_authorization_history::STATION_AUTHORITY_SEED,
        ),
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
    let roundtrip: arkret_wire::RealmCommit =
        serde_json::from_slice(&serde_json::to_vec(commit).unwrap()).unwrap();
    assert_eq!(
        *commit, roundtrip,
        "canonical millisecond Commit wire round trip"
    );
}

/// Rebind an actual device-signed ordinary Event while keeping its original PCR source.
pub fn request_for_event(
    fixture: &HumanFixture,
    previous: &AuthorityCommitTransaction,
    event: arkret_wire::Event,
    at: chrono::DateTime<chrono::Utc>,
) -> EventCommitRequest {
    let mut request = ordinary_realm::request_for_event(previous, event, at);
    let mut fact = fixture
        .unit
        .transactions
        .last()
        .unwrap()
        .producer_signer_fact
        .as_ref()
        .and_then(|fact| fact.as_account_device())
        .cloned()
        .expect("actual accepted PCR original");
    fact.event_id = request.authority_commit.event.event_id.clone();
    request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    request.authority_commit.producer_signer_fact = Some(fact.into());
    request.self_producer_guard = Some(SelfProducerCommitGuard::HumanDevice(fixture.guard.clone()));
    seal_commit(
        &mut request.authority_commit.commit,
        &fixture.pcr.history.station_did,
    );
    request
}

pub fn station_authority_seed() -> [u8; 32] {
    device_authorization_history::STATION_AUTHORITY_SEED
}
pub fn signed_ordinary_event(
    fixture: &HumanFixture,
    previous: &AuthorityCommitTransaction,
    kind: arkret_wire::EventKind,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let request = ordinary_realm::next_request_for_actor(
        previous,
        kind,
        arkret_wire::ActorId::account(fixture.pcr.history.account.clone()),
        payload,
        at,
    );
    device_authorization_history::sign_event(
        request.authority_commit.event,
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    )
}
