//! Bootstrap fixtures use the governor's original durable Genesis and signer.

use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact;
use arkret_wire::{CommittedEventFullView, RealmId};
use coland_storage::AuthorityCommitStore;

pub fn genesis_from_unit(
    unit: &coland_storage::OrdinaryRealmBootstrapCommitUnit,
) -> (CommittedEventFullView, Option<HistoricalProducerSignerFact>) {
    let source = &unit.transactions[0];
    (
        CommittedEventFullView {
            event: source.event.clone(),
            commit: source.commit.clone(),
        },
        source.producer_signer_fact.clone(),
    )
}

pub async fn genesis_original(
    governor: &dyn AuthorityCommitStore,
    realm: &RealmId,
) -> (CommittedEventFullView, Option<HistoricalProducerSignerFact>) {
    let source = governor
        .committed_event(&realm.event_id())
        .await
        .expect("read original bootstrap Genesis")
        .expect("bootstrap governor holds its original Genesis");
    let fact = governor
        .producer_signer_fact(&source.event, &source.commit)
        .await
        .expect("read original bootstrap producer fact");
    let original = CommittedEventFullView {
        event: source.event,
        commit: source.commit,
    };
    arkret_models_collaboration::governance::realm_join_intake::validate_bootstrap_genesis_original(
        &original,
        fact.as_ref(),
    )
    .expect("fixture retains the exact original collaboration Genesis");
    (original, fact)
}
