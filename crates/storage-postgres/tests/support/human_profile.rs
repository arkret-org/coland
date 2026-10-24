//! Deterministic full Account fixtures whose PCR and Human Profile are accepted.

#[path = "../../../test-support/src/device_authorization_history.rs"]
#[allow(
    dead_code,
    clippy::duplicate_mod,
    reason = "This fixture is also compiled by test-support without a circular crate dependency."
)]
mod device_authorization_history;
#[path = "../../../test-support/src/pcr_genesis.rs"]
#[allow(
    dead_code,
    clippy::duplicate_mod,
    reason = "This fixture is also compiled by test-support without a circular crate dependency."
)]
mod pcr_genesis;

use arkret_wire::{
    AccountId, ActorId, DetachedSignatureContext, DidCoreId, DidUrl, EventKind, RealmCommitId,
};
use coland_storage::{ActorProfileAdmissionWrite, ActorProfileStore, AuthorityCommitTransaction};
use coland_storage_postgres::{PgActorProfileStore, PgPersistenceStore, PgPool};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;

// Test signing material only. No authorization, source fact, revision or
// acceptance result is cached here; each candidate reads its actual PG cut.
type FixtureSigners = std::sync::Mutex<std::collections::BTreeMap<String, (DidUrl, [u8; 32])>>;

fn fixture_signers() -> &'static FixtureSigners {
    static SIGNERS: std::sync::OnceLock<FixtureSigners> = std::sync::OnceLock::new();
    SIGNERS.get_or_init(Default::default)
}
pub fn register_fixture_signer(account: &AccountId, method: DidUrl, seed: [u8; 32]) {
    fixture_signers().lock().unwrap().insert(
        ActorId::account(account.clone()).to_string(),
        (method, seed),
    );
}
fn retain_signing_material(fixture: &pcr_genesis::PcrGenesisFixture) {
    register_fixture_signer(
        &fixture.history.account,
        fixture.history.device_verification_method.clone(),
        fixture.history.founding_device_signing_seed,
    );
}
pub fn sign_fixture_event(event: arkret_wire::Event) -> Option<arkret_wire::Event> {
    let (method, seed) = fixture_signers()
        .lock()
        .unwrap()
        .get(&event.actor_id.to_string())
        .cloned()?;
    Some(device_authorization_history::sign_event(
        event, method, seed,
    ))
}
pub async fn admit_without_profile(pool: &PgPool, station: &DidCoreId, label: &str) -> AccountId {
    let fixture = fixture(station, label);
    Box::pin(fixture.admit_founding_device(&PgPersistenceStore::new(pool.clone())))
        .await
        .unwrap();
    retain_signing_material(&fixture);
    fixture.history.account
}

pub fn fixture(station: &DidCoreId, label: &str) -> pcr_genesis::PcrGenesisFixture {
    fixture_for_did(
        device_authorization_history::did_web_station(station),
        label,
    )
}

fn fixture_for_did(station_did: arkret_wire::Did, label: &str) -> pcr_genesis::PcrGenesisFixture {
    let device_identity = arkret_canonical::canonical_json_bytes(&(&station_did, label)).unwrap();
    pcr_genesis::PcrGenesisFixture::new_with(
        station_did,
        device_authorization_history::DeviceHistoryFixtureOptions {
            local_id: label.to_owned(),
            founding_device_id: arkret_wire::DeviceId::new(format!(
                "ak:device:01904100-0000-7000-8000-{}",
                arkret_canonical::sha256_bytes(device_identity)[..6]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            ))
            .unwrap(),
            ..Default::default()
        },
    )
}

pub fn station_did(station: &DidCoreId) -> arkret_wire::Did {
    device_authorization_history::did_web_station(station)
}

pub fn account(station: &DidCoreId, label: &str) -> AccountId {
    fixture(station, label).history.account
}

/// Repeated calls retain the exact accepted Profile. Nothing is seeded into
/// a current table: the PCR unit and ProfileCreate use their production stores.
pub async fn admit(pool: &PgPool, station: &DidCoreId, label: &str) -> AccountId {
    Box::pin(admit_fixture(pool, fixture(station, label))).await
}

/// WebVH core IDs are not reversible; retain the caller's full Station DID.
pub async fn admit_for_station_did(
    pool: &PgPool,
    station_did: arkret_wire::Did,
    label: &str,
) -> AccountId {
    Box::pin(admit_fixture(pool, fixture_for_did(station_did, label))).await
}

async fn admit_fixture(pool: &PgPool, fixture: pcr_genesis::PcrGenesisFixture) -> AccountId {
    // Drive the independent fixture admission without retaining a large test
    // caller's poll frame. Dropping the JoinSet cancels the admission task;
    // the caller retains its database lease and immediately awaits completion.
    let pool = pool.clone();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move { Box::pin(admit_fixture_inner(&pool, fixture)).await });
    tasks.join_next().await.unwrap().unwrap()
}

async fn admit_fixture_inner(pool: &PgPool, fixture: pcr_genesis::PcrGenesisFixture) -> AccountId {
    let account = fixture.history.account.clone();
    let mut conn = pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Exists {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        present: bool,
    }
    let present = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM actor_profile_current_states p \
         JOIN realm_commits c ON c.commit_id=p.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE e.envelope->'actor_id'=$1 AND p.value->>'actor_kind'='user') AS present",
    )
    .bind::<Jsonb, _>(serde_json::to_value(ActorId::account(account.clone())).unwrap())
    .get_result::<Exists>(&mut *conn)
    .await
    .unwrap()
    .present;
    if present {
        retain_signing_material(&fixture);
        return account;
    }
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) \
         ON CONFLICT(singleton) DO NOTHING",
    )
    .bind::<Text, _>(account.station_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    Box::pin(fixture.admit_founding_device(&PgPersistenceStore::new(pool.clone())))
        .await
        .unwrap();
    retain_signing_material(&fixture);
    let previous = &fixture.unit.transactions[1].commit;
    let at = previous.committed_at + chrono::TimeDelta::seconds(1);
    let event = device_authorization_history::sign_event(
        arkret_wire::test_support::raw_event_at(
            EventKind::ProfileCreate.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id: previous.realm_id.clone() },
            account.principal_id.clone(), account.station_id.clone(),
            serde_json::json!({"object":{
                "principal_id":account.principal_id,"actor_kind":"user","display_name":"Verified Human fixture"
            }}), at,
        ).unwrap(),
        fixture.history.device_verification_method.clone(),
        fixture.history.founding_device_signing_seed,
    );
    let mut commit = previous.clone();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{}:profile", event.event_id, previous.commit_id).as_bytes(),
    ));
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = at;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{}#authority", fixture.history.station_did)).unwrap(),
        at,
        &SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED),
    )
    .unwrap();
    PgActorProfileStore { pool: pool.clone() }
        .admit_profile(ActorProfileAdmissionWrite {
            commit: AuthorityCommitTransaction {
                expected_authority: fixture.unit.transactions[1].expected_authority.clone(),
                event,
                commit,
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: at,
        })
        .await
        .unwrap();
    account
}

pub fn sign_original_device(
    event: arkret_wire::Event,
    method: arkret_wire::DidUrl,
) -> arkret_wire::Event {
    device_authorization_history::sign_event(
        event,
        method,
        device_authorization_history::DeviceHistoryFixtureOptions::default()
            .founding_device_signing_seed,
    )
}
