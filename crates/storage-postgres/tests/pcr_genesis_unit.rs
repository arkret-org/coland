#[path = "../../test-support/src/device_authorization_history.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared device history fixture."
)]
mod device_history_fixture;
#[path = "support/historical_control_source.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared control source fixture."
)]
mod historical_control_source;
#[path = "support/sql_fault_matrix.rs"]
mod sql_fault_matrix;
mod support;

#[path = "support/principal_resolution_update.rs"]
mod principal_resolution_update;

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizePayload, device_authorize_payload_digest,
};
use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput;
use arkret_models_crypto::{
    AcceptedSecurityTransactionStep, BackupActiveSeriesPointer, BackupObjectRef,
    BackupRotationBinding, BackupRotationKind, BackupRotationPlan, PreparedEventUnit,
    SecurityRotationRevokeCommandDecision, SecurityRotationRevokeCommandOutcome,
    SecurityRotationRevokeProposal, SecurityRotationTransactionCreateRequest,
    SecurityTransactionAcceptor, SecurityTransactionCreateRequest, SecurityTransactionPreparedPlan,
    SecurityTransactionStep, SecurityTransactionTerminalOutcome,
};
use arkret_models_identity::{
    IdentityBindingPurpose, IdentityCreationControlProofKind, PCR_GENESIS_UNIT_KINDS,
    UnsignedIdentityCreationControlProof, UnsignedIdentityCreationControlProofBody,
};
use arkret_wire::{
    BackupId, BackupSeriesId, DetachedSignatureContext, DeviceId, DidCoreId, DidUrl, EventKind,
    Hash, IdempotencyKey, PcrGenesisUnit, RealmCommitAuthorityRef, RealmCommitId, RealmId,
    TransactionId, TrustDomainId, WebOrigin,
};
use coland_storage::{
    AcceptedDeviceAuthorizationOutcome, AuthorityCommitStore, AuthorityCommitTransaction,
    ConflictCode, CurrentRealmAuthority, DeviceRevocationStore, KeyBackupListPosition,
    KeyBackupListQuery, KeyBackupStore, PcrGenesisCommitOutcome, PcrGenesisCommitUnit,
    PersistenceError, RevokeCommandTerminalWrite, RevokeProposalCommitWrite,
    SecurityTransactionRecord, SecurityTransactionStepOutcomeRecord, SecurityTransactionStore,
};
use coland_storage_postgres::{
    Db, PgAuthorityCommitStore, PgDeviceRevocationStore, PgKeyBackupStore, PgPool,
    PgSecurityTransactionStore,
};
use device_history_fixture::{DeviceHistoryFixture, DeviceHistoryFixtureOptions};
use diesel::sql_types::{BigInt, Jsonb, Text, Uuid};
use diesel_async::RunQueryDsl;
use ed25519_dalek::{Signer, SigningKey};

#[derive(diesel::QueryableByName)]
struct StationRow {
    #[diesel(sql_type = Text)]
    station_id: String,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn device_list_position(
    pool: &PgPool,
    recipient: &arkret_wire::AccountId,
    owner: &arkret_wire::AccountId,
) -> i64 {
    let recipient = arkret_wire::ActorId::account(recipient.clone())
        .canonical_key()
        .unwrap();
    let owner = arkret_wire::ActorId::account(owner.clone())
        .canonical_key()
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COALESCE(MAX(channel_position),0) AS count FROM account_global_versions WHERE actor_key=$1 AND channel='device_lists' AND item_key=$2")
        .bind::<Text,_>(recipient).bind::<Text,_>(owner)
        .get_result::<CountRow>(&mut conn).await.unwrap().count
}

#[derive(diesel::QueryableByName)]
struct DeviceCurrentRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// Every durable row a PCR genesis admission can write for one Realm and its
/// principal.
#[derive(Debug, PartialEq, Eq, diesel::QueryableByName)]
struct GenesisFootprint {
    #[diesel(sql_type = BigInt)]
    genesis_units: i64,
    #[diesel(sql_type = BigInt)]
    realm_authorities: i64,
    #[diesel(sql_type = BigInt)]
    canonical_events: i64,
    #[diesel(sql_type = BigInt)]
    realm_commits: i64,
    #[diesel(sql_type = BigInt)]
    authority_roots: i64,
    #[diesel(sql_type = BigInt)]
    principal_resolutions: i64,
    #[diesel(sql_type = BigInt)]
    devices: i64,
    #[diesel(sql_type = BigInt)]
    device_generations: i64,
    #[diesel(sql_type = BigInt)]
    device_authorizations: i64,
}

const NO_FOOTPRINT: GenesisFootprint = GenesisFootprint {
    genesis_units: 0,
    realm_authorities: 0,
    canonical_events: 0,
    realm_commits: 0,
    authority_roots: 0,
    principal_resolutions: 0,
    devices: 0,
    device_generations: 0,
    device_authorizations: 0,
};

const ACCEPTED_FOOTPRINT: GenesisFootprint = GenesisFootprint {
    genesis_units: 1,
    realm_authorities: 1,
    canonical_events: 2,
    realm_commits: 2,
    authority_roots: 1,
    principal_resolutions: 1,
    devices: 1,
    device_generations: 1,
    device_authorizations: 1,
};

async fn footprint(
    pool: &PgPool,
    realm_id: &RealmId,
    principal_id: &DidCoreId,
) -> GenesisFootprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT \
           (SELECT COUNT(*) FROM pcr_genesis_units WHERE realm_id=$1) AS genesis_units, \
           (SELECT COUNT(*) FROM realm_authorities WHERE realm_id=$1) AS realm_authorities, \
           (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS canonical_events, \
           (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS realm_commits, \
           (SELECT COUNT(*) FROM realm_authority_root_current_results WHERE realm_id=$1) \
             AS authority_roots, \
           (SELECT COUNT(*) FROM principal_resolutions WHERE principal_id=$2) \
             AS principal_resolutions, \
           (SELECT COUNT(*) FROM devices WHERE actor_id=$2) AS devices, \
           (SELECT COUNT(*) FROM pcr_device_generation_current_results WHERE realm_id=$1) \
             AS device_generations, \
           (SELECT COUNT(*) FROM pcr_device_authorization_current_results WHERE realm_id=$1) \
             AS device_authorizations",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(principal_id.as_str())
    .get_result::<GenesisFootprint>(&mut *conn)
    .await
    .unwrap()
}

async fn unit_footprint(pool: &PgPool, unit: &PcrGenesisCommitUnit) -> GenesisFootprint {
    footprint(
        pool,
        &unit.submission.pcr_realm_id,
        &unit.submission.principal_id,
    )
    .await
}

/// Contract database pool and the singleton Station every fixture commits for.
async fn contract_store() -> (PgPool, DidCoreId) {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let station = contract_station(&pool).await;
    (pool, station)
}

async fn contract_station(pool: &PgPool) -> DidCoreId {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) \
         VALUES(TRUE,'ak:did_core:web:pcr-contract.example') ON CONFLICT(singleton) DO NOTHING",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let station =
        diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
            .get_result::<StationRow>(&mut *conn)
            .await
            .unwrap();
    drop(conn);
    DidCoreId::new(station.station_id).unwrap()
}

fn page_fixture(
    id: &str,
    actor: &arkret_wire::ActorId,
    series: &str,
    seq: u64,
    previous: Option<&str>,
) -> serde_json::Value {
    let mut page = serde_json::json!({
        "backup_id":id, "actor_id":actor, "backup_kind":"secret_storage", "backup_version":"kb_1",
        "created_at":"2026-09-09T00:00:00.000Z", "series_id":series, "series_seq":seq,
        "encryption":{"recipient_method":"secret_storage_key", "recipient_key_ref":"backup-key", "aead":{"name":"xchacha20_poly1305", "nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "domain_separation":{"subdomain":"secret_storage"},
        "contents":[{"item_kind":"recovery_key_share", "secret_id":"share"}],
        "ciphertext":"AAAA", "ciphertext_digest":"sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c",
        "auth_data":{
            "device_id":"ak:device:01904100-0000-7000-8000-000000000001",
            "verification_method":"did:web:backup.example#device-signer",
            "signature_algorithm":"Ed25519", "signature":"AAAA",
            "device_authorize_event_id":"ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
        }
    });
    if let Some(previous) = previous {
        page["supersedes_id"] = serde_json::json!(previous);
        page["supersedes_digest"] = serde_json::json!(
            "sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c"
        );
    }
    page
}

fn hash(value: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(value.as_bytes())).unwrap()
}

fn fixture(station: &DidCoreId) -> DeviceHistoryFixture {
    let options = DeviceHistoryFixtureOptions {
        local_id: format!("pcr-{}", uuid::Uuid::now_v7().simple()),
        ..Default::default()
    };
    DeviceHistoryFixture::new_with(device_history_fixture::did_web_station(station), options)
}

fn unit(station: DidCoreId) -> PcrGenesisCommitUnit {
    let fixture = fixture(&station);
    assemble(station, fixture)
}

/// Re-author the genesis pair around a founding authorize payload that
/// claims `generation`.
///
/// The SDK refuses to build a registration-anchor possession transcript for any
/// generation other than one, so the candidate device signs the exact canonical
/// transcript with only that member changed. The root-committed descriptor
/// digest, both producer proofs, the derived PCR id and the commit chain are
/// all recomputed; the only defect left is the claimed generation.
fn reauthor_founding_generation(fixture: &mut DeviceHistoryFixture, generation: u64) {
    let payload = &fixture.events[1].payload;
    let typed: DeviceAuthorizePayload = serde_json::from_value(serde_json::Value::Object(
        payload.clone().into_iter().collect(),
    ))
    .unwrap();
    let transcript = typed
        .device_possession_signature_input(&fixture.account)
        .unwrap();
    let registered = br#""authorized_generation_ref":1,"#;
    let at = transcript
        .windows(registered.len())
        .position(|window| window == registered)
        .expect("the possession transcript carries the registration generation");
    let mut claimed = transcript[..at].to_vec();
    claimed.extend(format!(r#""authorized_generation_ref":{generation},"#).as_bytes());
    claimed.extend(&transcript[at + registered.len()..]);
    let device_signature = SigningKey::from_bytes(&fixture.founding_device_signing_seed)
        .sign(&claimed)
        .to_bytes();

    let mut payload = payload.clone();
    payload.insert(
        "authorized_generation_ref".to_owned(),
        serde_json::json!(generation),
    );
    payload.insert(
        "device_signature".to_owned(),
        serde_json::json!(arkret_canonical::base64url_encode(device_signature)),
    );
    let payload = serde_json::Value::Object(payload.into_iter().collect());
    let digest =
        device_authorize_payload_digest(&payload, arkret_canonical::DigestSuite::Sha256).unwrap();

    let mut create = fixture.events[0].clone();
    let descriptor = create
        .payload
        .get_mut("object")
        .and_then(|object| object.get_mut("founding_device_descriptor"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("a PCR create carries its founding device descriptor");
    assert!(descriptor.contains_key("founding_authorize_payload_digest"));
    descriptor.insert(
        "founding_authorize_payload_digest".to_owned(),
        serde_json::to_value(digest).unwrap(),
    );
    let root_seed = DeviceHistoryFixtureOptions::default().root_seed;
    let root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&root_seed)
            .verifying_key()
            .to_bytes(),
    );
    let create = device_history_fixture::sign_event(
        create,
        DidUrl::new(format!("did:key:{root}#{root}")).unwrap(),
        root_seed,
    );
    let authorize = fixture.raw_event(EventKind::DeviceAuthorize, payload, &create.realm_id);
    let authorize = device_history_fixture::sign_event(
        authorize,
        fixture.device_verification_method.clone(),
        fixture.founding_device_signing_seed,
    );
    fixture.events.clear();
    fixture.commits.clear();
    fixture.append(vec![create, authorize]);
}

/// Relay the fixture's genesis pair and its commits as the complete unit the
/// governance Station admits.
fn assemble(station: DidCoreId, fixture: DeviceHistoryFixture) -> PcrGenesisCommitUnit {
    let created_at = fixture.commits[0].committed_at;
    let evidence = arkret_signatures::webvh::sign_registration_did_evidence_draft(
        &fixture.inception,
        created_at,
        &[70; 32],
    )
    .unwrap()
    .accept(created_at)
    .unwrap();
    let create = fixture.events[0].clone();
    let authorize = fixture.events[1].clone();
    let authorize_value =
        serde_json::Value::Object(authorize.payload.clone().into_iter().collect());
    let create_digest =
        Hash::new(arkret_canonical::canonical_sha256(&create.payload).unwrap()).unwrap();
    let authorize_digest =
        device_authorize_payload_digest(&authorize_value, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    let proof = arkret_signatures::webvh::sign_identity_creation_control_proof(
        UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
            proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
            challenge_id: "fixture-challenge".to_owned(),
            challenge: "fixture-challenge-value".to_owned(),
            purpose: IdentityBindingPurpose::AccountBindingAndPcrGenesis,
            account_subject: hash("fixture-account"),
            principal_id: fixture.account.principal_id.clone(),
            did: fixture.did.clone(),
            registration_anchor_digest: fixture.registration_anchor.canonical_digest().unwrap(),
            did_version_id: evidence.version_id.clone(),
            control_key_digest: evidence.control_key_digest.clone(),
            pcr_realm_id: create.realm_id.clone(),
            realm_create_payload_digest: create_digest,
            founding_authorize_payload_digest: authorize_digest,
            initial_session_request_digest: hash("fixture-initial-session"),
            genesis_unit_kinds: PCR_GENESIS_UNIT_KINDS,
            identity_creation_lease_id: "fixture-lease".to_owned(),
            lease_fence: 1,
            dpop_jkt: "fixture-thumbprint".to_owned(),
            audience_id: station.clone(),
            origin: WebOrigin::new("https://principal.example").unwrap(),
            trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            issued_at: created_at,
            expires_at: created_at + chrono::TimeDelta::minutes(5),
            verification_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &ed25519_dalek::SigningKey::from_bytes(&[70; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        })
        .unwrap(),
        &[70; 32],
    )
    .unwrap();
    let submission = PcrGenesisAdmissionInput {
        account_authority_id: station.clone(),
        principal_id: fixture.account.principal_id.clone(),
        did: fixture.did.clone(),
        pcr_realm_id: create.realm_id.clone(),
        did_version_id: evidence.version_id.clone(),
        control_key_digest: evidence.control_key_digest.clone(),
        idempotency_key: IdempotencyKey::new(uuid::Uuid::now_v7().to_string()).unwrap(),
        registration_request_digest: hash("fixture-registration"),
        principal_registration_anchor: fixture.registration_anchor,
        registration_did_evidence: evidence,
        identity_creation_control_proof: proof,
        genesis_unit: PcrGenesisUnit {
            events: [create.clone(), authorize.clone()],
        },
    };
    let authority = CurrentRealmAuthority {
        realm_id: create.realm_id.clone(),
        generation: 0,
        service_id: station,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(create.event_id.clone()),
        last_handoff_ref: None,
    };
    let transactions = [
        (create, fixture.commits[0].clone()),
        (authorize, fixture.commits[1].clone()),
    ]
    .map(|(event, commit)| AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        event,
        commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    });
    let exact_request_body = serde_json::to_vec(&submission).unwrap();
    PcrGenesisCommitUnit {
        submission,
        exact_request_body,
        transactions,
    }
}

#[tokio::test]
async fn founding_device_conflict_rolls_back_both_commits_and_exact_replay_is_stable() {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) \
         VALUES(TRUE,'ak:did_core:web:pcr-contract.example') ON CONFLICT(singleton) DO NOTHING",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let station =
        diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
            .get_result::<StationRow>(&mut *conn)
            .await
            .unwrap();
    let unit = unit(DidCoreId::new(station.station_id.clone()).unwrap());
    unit.validate().unwrap();
    let device_id = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::DeviceAuthorizePayload,
    >(serde_json::Value::Object(
        unit.submission
            .genesis_unit
            .founding_authorize()
            .payload
            .clone()
            .into_iter()
            .collect(),
    ))
    .unwrap()
    .device_id;
    let principal = unit.submission.principal_id.as_str();
    diesel::sql_query(
        "INSERT INTO devices(id,station_id,actor_id,device_id,payload) VALUES($1,$2,$3,$4,'{}'::jsonb)",
    )
    .bind::<Uuid, _>(uuid::Uuid::now_v7())
    .bind::<Text, _>(&station.station_id)
    .bind::<Text, _>(principal)
    .bind::<Text, _>(device_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);

    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let at = unit.transactions[0].commit.committed_at;
    assert!(
        store
            .pcr_genesis_replay(&unit.submission, &unit.exact_request_body)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.admit_pcr_genesis_unit(&unit, at).await.is_err());
    assert!(
        store
            .current_authority(&unit.submission.pcr_realm_id)
            .await
            .unwrap()
            .is_none()
    );
    for transaction in &unit.transactions {
        assert!(
            store
                .queued_event(&transaction.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut conn = pool.get().await.unwrap();
    let remaining =
        diesel::sql_query("SELECT COUNT(*) AS count FROM pcr_genesis_units WHERE realm_id=$1")
            .bind::<Text, _>(unit.submission.pcr_realm_id.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap();
    assert_eq!(remaining.count, 0);
    let resolution = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(principal)
    .bind::<Text, _>(&station.station_id)
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(resolution.count, 0);
    let realm_root = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(unit.submission.pcr_realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(realm_root.count, 0);
    diesel::sql_query("DELETE FROM devices WHERE actor_id=$1 AND device_id=$2")
        .bind::<Text, _>(principal)
        .bind::<Text, _>(device_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);

    let committed = store.admit_pcr_genesis_unit(&unit, at).await.unwrap();
    let PcrGenesisCommitOutcome::Committed(result) = committed else {
        panic!("first PCR genesis must commit");
    };
    let mut conn = pool.get().await.unwrap();
    let generation = diesel::sql_query(
        "SELECT current_commit_id,value FROM pcr_device_generation_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(unit.submission.pcr_realm_id.as_str())
    .get_result::<DeviceCurrentRow>(&mut *conn)
    .await
    .unwrap();
    let authorization = diesel::sql_query(
        "SELECT current_commit_id,value FROM pcr_device_authorization_current_results \
         WHERE realm_id=$1 AND device_id=$2",
    )
    .bind::<Text, _>(unit.submission.pcr_realm_id.as_str())
    .bind::<Text, _>(device_id.as_str())
    .get_result::<DeviceCurrentRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        generation.current_commit_id,
        result.commits[1].commit_id.as_str()
    );
    assert_eq!(
        authorization.current_commit_id,
        result.commits[1].commit_id.as_str()
    );
    assert_eq!(
        generation.value,
        serde_json::json!({"current_device_generation_ref":1})
    );
    assert_eq!(authorization.value["authorized_generation_ref"], 1);
    assert_eq!(
        authorization.value["device_authorize_event_id"],
        serde_json::json!(unit.transactions[1].event.event_id)
    );
    assert!(authorization.value.get("device_id").is_none());
    drop(conn);
    assert_eq!(
        store
            .pcr_genesis_replay(&unit.submission, &unit.exact_request_body)
            .await
            .unwrap(),
        Some(result.clone()),
    );
    assert_eq!(
        store.admit_pcr_genesis_unit(&unit, at).await.unwrap(),
        PcrGenesisCommitOutcome::Duplicate(result),
    );
    let mut changed = unit;
    changed.exact_request_body.push(b' ');
    assert!(
        store
            .pcr_genesis_replay(&changed.submission, &changed.exact_request_body)
            .await
            .is_err()
    );
    assert!(store.admit_pcr_genesis_unit(&changed, at).await.is_err());
}

fn is_duplicate_conflict<T>(outcome: &Result<T, PersistenceError>) -> bool {
    matches!(outcome, Err(PersistenceError::Conflict(code)) if code == "duplicate_conflict")
}

#[tokio::test]
async fn every_pcr_genesis_write_rolls_back_and_restart_preserves_the_first_outcome() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let station = contract_station(&pool).await;
    let unit = unit(station);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let at = unit.transactions[0].commit.committed_at;
    let accepted = sql_fault_matrix::exhaust_writes(&pool, "pcr_genesis", || {
        store.admit_pcr_genesis_unit(&unit, at)
    })
    .await;
    let PcrGenesisCommitOutcome::Committed(result) = accepted else {
        panic!("fresh PCR unit");
    };
    result.validate_against(&unit.submission).unwrap();
    assert_eq!(unit_footprint(&pool, &unit).await, ACCEPTED_FOOTPRINT);
    let before = sql_fault_matrix::snapshot(&pool).await;
    let restarted = Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap();
    let reopened = PgAuthorityCommitStore {
        pool: restarted.pool.unwrap(),
    };
    assert_eq!(
        reopened.admit_pcr_genesis_unit(&unit, at).await.unwrap(),
        PcrGenesisCommitOutcome::Duplicate(result.clone())
    );
    assert_eq!(
        reopened
            .pcr_genesis_replay(&unit.submission, &unit.exact_request_body)
            .await
            .unwrap(),
        Some(result)
    );
    let mut different = unit.clone();
    different.submission.idempotency_key =
        IdempotencyKey::new(uuid::Uuid::now_v7().to_string()).unwrap();
    different.exact_request_body =
        arkret_canonical::canonical_json_bytes(&different.submission).unwrap();
    assert!(is_duplicate_conflict(
        &reopened.admit_pcr_genesis_unit(&different, at).await
    ));
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
}

fn unrelated_commit_id() -> RealmCommitId {
    RealmCommitId::from_digest(arkret_canonical::sha256_bytes(b"unrelated-commit"))
}

/// A genesis unit whose Commit pair is not the exact ordered chain over its
/// Event pair (`authority-commit-log.md` section 3) is rejected before any
/// durable write.
#[tokio::test]
async fn misbound_genesis_commit_chain_is_rejected_with_no_durable_write() {
    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let cases: [(&str, fn(&mut PcrGenesisCommitUnit)); 7] = [
        (
            "authorize commit does not chain to the create commit",
            |unit| {
                unit.transactions[1].commit.previous_commit_ref = Some(unrelated_commit_id());
            },
        ),
        ("authorize commit omits its predecessor", |unit| {
            unit.transactions[1].commit.previous_commit_ref = None;
        }),
        ("create commit claims a predecessor", |unit| {
            unit.transactions[0].commit.previous_commit_ref = Some(unrelated_commit_id());
        }),
        ("authorize commit skips a stream position", |unit| {
            unit.transactions[1].commit.stream_position = 2;
        }),
        ("create commit is not at stream position zero", |unit| {
            unit.transactions[0].commit.stream_position = 1;
            unit.transactions[1].commit.stream_position = 2;
        }),
        ("authorize commit orders the create Event", |unit| {
            unit.transactions[1].commit.event_ref = unit.transactions[0].event.event_id.clone();
        }),
        (
            "authorize commit claims a later governance generation",
            |unit| {
                unit.transactions[1].commit.governance_generation = 1;
            },
        ),
    ];
    for (case, corrupt) in cases {
        let mut unit = unit(station.clone());
        unit.validate().unwrap();
        corrupt(&mut unit);
        assert!(unit.validate().is_err(), "{case}: storage validation");
        let at = unit.transactions[0].commit.committed_at;
        let rejected = store.admit_pcr_genesis_unit(&unit, at).await;
        assert!(
            matches!(rejected, Err(PersistenceError::SchemaViolation(_))),
            "{case}: {rejected:?}"
        );
        assert_eq!(unit_footprint(&pool, &unit).await, NO_FOOTPRINT, "{case}");
        assert_eq!(
            store
                .pcr_genesis_replay(&unit.submission, &unit.exact_request_body)
                .await
                .unwrap(),
            None,
            "{case}: a rejected unit leaves no receipt"
        );
    }
}

/// A valid signed registration cannot be relayed as another full Account.
#[tokio::test]
async fn human_genesis_relay_cannot_replace_its_account_station_or_principal() {
    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    for change_station in [true, false] {
        let original = unit(station.clone());
        original.validate().unwrap();
        let mut request = original.clone();
        if change_station {
            request.submission.account_authority_id =
                DidCoreId::new("ak:did_core:web:foreign.example").unwrap();
        } else {
            request.submission.principal_id =
                DidCoreId::new("ak:did_core:web:other-principal.example").unwrap();
        }
        request.exact_request_body =
            arkret_canonical::canonical_json_bytes(&request.submission).unwrap();
        assert!(
            request
                .submission
                .validate()
                .unwrap_err()
                .to_string()
                .contains("Human genesis account differs")
        );
        let refused = store
            .admit_pcr_genesis_unit(&request, request.transactions[0].commit.committed_at)
            .await;
        assert!(
            matches!(refused, Err(PersistenceError::SchemaViolation(_))),
            "{refused:?}"
        );
        assert_eq!(unit_footprint(&pool, &original).await, NO_FOOTPRINT);
        assert_eq!(unit_footprint(&pool, &request).await, NO_FOOTPRINT);
        assert!(
            store
                .pcr_genesis_replay(&request.submission, &request.exact_request_body)
                .await
                .unwrap()
                .is_none()
        );
    }
}

/// `device-lifecycle.md` section 5: a `registration_anchor` authorize MUST
/// carry `authorized_generation_ref = 1`, the value the genesis unit
/// initializes. A fully re-signed unit claiming any other generation is
/// rejected with no durable write.
#[tokio::test]
async fn founding_authorize_generation_other_than_one_is_rejected_with_no_durable_write() {
    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };

    let mut registered = fixture(&station);
    let original = registered.events.clone();
    reauthor_founding_generation(&mut registered, 1);
    assert_eq!(
        registered.events, original,
        "re-authoring at the registered generation reproduces the exact unit"
    );
    assemble(station.clone(), registered).validate().unwrap();

    for generation in [2, 7] {
        let mut claimed = fixture(&station);
        reauthor_founding_generation(&mut claimed, generation);
        let unit = assemble(station.clone(), claimed);
        let reason = unit.validate().unwrap_err().to_string();
        assert!(
            reason.contains("device_authorize_registration_generation_ref_must_be_one"),
            "generation {generation}: {reason}"
        );
        let at = unit.transactions[0].commit.committed_at;
        let rejected = store.admit_pcr_genesis_unit(&unit, at).await;
        assert!(
            matches!(
                &rejected,
                Err(PersistenceError::SchemaViolation(reason))
                    if reason.contains("device_authorize_registration_generation_ref_must_be_one")
            ),
            "generation {generation}: {rejected:?}"
        );
        assert_eq!(
            unit_footprint(&pool, &unit).await,
            NO_FOOTPRINT,
            "generation {generation}"
        );
    }
}

/// `account-lifecycle.md` section 2.1.2: the same idempotency key with
/// different bytes, or the same PCR under a different key, is a zero-write
/// `duplicate_conflict`; only the exact first request replays its outcome.
#[tokio::test]
async fn reused_genesis_realm_or_idempotency_key_is_a_zero_write_duplicate_conflict() {
    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let accepted = unit(station.clone());
    let at = accepted.transactions[0].commit.committed_at;
    let PcrGenesisCommitOutcome::Committed(result) =
        store.admit_pcr_genesis_unit(&accepted, at).await.unwrap()
    else {
        panic!("first PCR genesis must commit");
    };
    assert_eq!(unit_footprint(&pool, &accepted).await, ACCEPTED_FOOTPRINT);

    let rekey = |mut unit: PcrGenesisCommitUnit, key: IdempotencyKey| {
        unit.submission.idempotency_key = key;
        unit.exact_request_body = serde_json::to_vec(&unit.submission).unwrap();
        unit.validate().unwrap();
        unit
    };

    let same_realm = rekey(
        accepted.clone(),
        IdempotencyKey::new(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    let replayed = store
        .pcr_genesis_replay(&same_realm.submission, &same_realm.exact_request_body)
        .await;
    assert!(is_duplicate_conflict(&replayed), "{replayed:?}");
    let admitted = store.admit_pcr_genesis_unit(&same_realm, at).await;
    assert!(is_duplicate_conflict(&admitted), "{admitted:?}");
    assert_eq!(unit_footprint(&pool, &accepted).await, ACCEPTED_FOOTPRINT);
    let mut conn = pool.get().await.unwrap();
    let foreign_key_receipts = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM pcr_genesis_units WHERE idempotency_key=$1",
    )
    .bind::<Text, _>(same_realm.submission.idempotency_key.to_string())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(foreign_key_receipts.count, 0);
    drop(conn);

    let same_key = rekey(
        unit(station.clone()),
        accepted.submission.idempotency_key.clone(),
    );
    let replayed = store
        .pcr_genesis_replay(&same_key.submission, &same_key.exact_request_body)
        .await;
    assert!(is_duplicate_conflict(&replayed), "{replayed:?}");
    let admitted = store.admit_pcr_genesis_unit(&same_key, at).await;
    assert!(is_duplicate_conflict(&admitted), "{admitted:?}");
    assert_eq!(unit_footprint(&pool, &same_key).await, NO_FOOTPRINT);

    assert_eq!(
        store.admit_pcr_genesis_unit(&accepted, at).await.unwrap(),
        PcrGenesisCommitOutcome::Duplicate(result),
    );
    assert_eq!(unit_footprint(&pool, &accepted).await, ACCEPTED_FOOTPRINT);
}

#[tokio::test]
async fn current_principal_survives_index_eviction_and_refuses_missing_typed_current() {
    use coland_storage::{CurrentPrincipalRead, PrincipalResolutionStore};

    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let accepted = unit(station.clone());
    let at = accepted.transactions[0].commit.committed_at;
    let PcrGenesisCommitOutcome::Committed(result) =
        store.admit_pcr_genesis_unit(&accepted, at).await.unwrap()
    else {
        panic!("PCR genesis must commit");
    };
    let account = arkret_wire::AccountId::new(
        accepted.submission.principal_id.clone(),
        accepted.submission.account_authority_id.clone(),
    );
    let resolutions = coland_storage_postgres::PgPrincipalResolutionStore { pool: pool.clone() };
    let initial = resolutions.current_principal(&account).await.unwrap();
    assert_eq!(
        initial,
        CurrentPrincipalRead::Ready {
            pcr_realm_id: result.pcr_realm_id.clone(),
            projection: result.resolution.clone(),
        }
    );

    let mut conn = pool.get().await.unwrap();
    let evicted = diesel::sql_query(
        "DELETE FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    assert_eq!(evicted, 1);
    drop(conn);

    // Typed current remains authoritative without rebuilding a query index.
    assert_eq!(
        resolutions.current_principal(&account).await.unwrap(),
        initial
    );
    assert_eq!(
        unit_footprint(&pool, &accepted).await,
        GenesisFootprint {
            principal_resolutions: 0,
            ..ACCEPTED_FOOTPRINT
        }
    );
    let record = resolutions
        .for_realm(&result.pcr_realm_id)
        .await
        .unwrap()
        .expect("typed current is found by its PCR");
    assert_eq!(record.account_id, account);
    assert_eq!(
        record.genesis_event.event_id,
        accepted.transactions[0].event.event_id
    );
    assert_eq!(record.current_event.event_id, record.genesis_event.event_id);

    let devices = PgDeviceRevocationStore { pool: pool.clone() };
    let device_id = accepted.transactions[1]
        .event
        .payload
        .get("device_id")
        .unwrap()
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let device_at = accepted.transactions[1].commit.committed_at + chrono::Duration::seconds(1);
    assert_eq!(
        devices.pcr_device_generation(&account).await.unwrap(),
        Some(coland_storage::PcrDeviceGeneration {
            current_device_generation_ref: 1
        })
    );
    assert_eq!(
        devices
            .pcr_device_admission(&account, &device_id, device_at)
            .await
            .unwrap(),
        arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    assert_eq!(
        resolutions.registered_genesis(&account).await.unwrap(),
        Some(accepted.transactions[0].event.clone())
    );

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "DELETE FROM principal_resolution_current_results WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        resolutions.current_principal(&account).await.unwrap(),
        CurrentPrincipalRead::Unavailable,
        "accepted genesis alone cannot replace missing typed current"
    );

    // Device authority has its own immutable origin and accepted family currents.
    assert_eq!(
        devices
            .pcr_device_admission(&account, &device_id, device_at)
            .await
            .unwrap(),
        arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    assert_eq!(
        resolutions.registered_genesis(&account).await.unwrap(),
        Some(accepted.transactions[0].event.clone())
    );

    assert!(matches!(
        resolutions
            .compare_and_set(None, record.clone())
            .await
            .unwrap(),
        coland_storage::PrincipalResolutionCasResult::Applied(_)
    ));
    assert_eq!(
        resolutions
            .compare_and_set(None, record.clone())
            .await
            .unwrap(),
        coland_storage::PrincipalResolutionCasResult::Conflict(Some(record))
    );
    assert_eq!(
        resolutions.current_principal(&account).await.unwrap(),
        CurrentPrincipalRead::Unavailable,
        "repairing a query index cannot establish typed current"
    );

    // An account without an accepted genesis anchor stays missing.
    let stranger = arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:no-genesis.example").unwrap(),
        station,
    );
    assert_eq!(
        resolutions.current_principal(&stranger).await.unwrap(),
        CurrentPrincipalRead::Missing
    );
}

#[tokio::test]
async fn security_rotation_revoke_proposal_is_one_atomic_pcr_write() {
    use arkret_models_collaboration::events_payloads::DeviceRevokePayload;
    use arkret_wire::RealmCommit;

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let station = contract_station(&pool).await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let authorizer = fixture.founding_device_id.clone();
    let device_method = fixture.device_verification_method.clone();
    let device_seed = fixture.founding_device_signing_seed;
    let station_did = fixture.station_did.clone();
    let genesis = assemble(station.clone(), fixture);
    let realm_id = genesis.submission.pcr_realm_id.clone();
    let at = genesis.transactions[1].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&genesis, at)
        .await
        .unwrap();
    let device_status = PgDeviceRevocationStore { pool: pool.clone() };
    assert!(
        device_status
            .pcr_device_admission(&account, &authorizer, at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let initial_pointer = backups
        .confirmed_active_series_for_device(&account, &authorizer, at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        initial_pointer.authority_commit_id,
        genesis.transactions[1].commit.commit_id
    );
    assert!(matches!(
        initial_pointer.secret_storage,
        BackupActiveSeriesPointer::Absent {}
    ));
    let list_query = KeyBackupListQuery {
        actor_id: arkret_wire::ActorId::account(account.clone()).to_string(),
        backup_kind: None,
        series_id: None,
        after: None,
        limit: 51,
    };
    let confirmed_page = backups
        .confirmed_list_page_for_device(&account, &authorizer, at, &list_query)
        .await
        .unwrap();
    assert_eq!(confirmed_page.active_series, initial_pointer);
    assert!(confirmed_page.page.payloads.is_empty());
    assert_eq!(confirmed_page.page.revision, 0);
    let mut wrong_actor = list_query.clone();
    wrong_actor.actor_id = "different-account".to_owned();
    assert!(
        backups
            .confirmed_list_page_for_device(&account, &authorizer, at, &wrong_actor)
            .await
            .is_err()
    );

    // Recovery metadata is authorized at the HTTP recovery-grant boundary,
    // and needs the confirmed account cut before its new device is active.
    let recovery_page = backups
        .confirmed_list_page_for_account(&account, &list_query)
        .await
        .unwrap();
    assert_eq!(recovery_page.active_series, initial_pointer);
    assert_eq!(recovery_page.page.revision, confirmed_page.page.revision);
    assert!(recovery_page.page.payloads.is_empty());
    assert!(
        backups
            .confirmed_list_page_for_account(&account, &wrong_actor)
            .await
            .is_err()
    );
    let candidate = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    assert!(
        backups
            .confirmed_list_page_for_device(&account, &candidate, at, &list_query)
            .await
            .is_err()
    );

    let actor = arkret_wire::ActorId::account(account.clone());
    let series = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let first_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let second_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    backups
        .put(
            first_id.clone(),
            page_fixture(&first_id, &actor, &series, 0, None),
        )
        .await
        .unwrap();
    backups
        .put(
            second_id.clone(),
            page_fixture(&second_id, &actor, &series, 1, Some(&first_id)),
        )
        .await
        .unwrap();
    let mut first_query = list_query.clone();
    first_query.limit = 1;
    let first_page = backups
        .confirmed_list_page_for_device(&account, &authorizer, at, &first_query)
        .await
        .unwrap();
    assert_eq!(first_page.active_series, initial_pointer);
    assert_eq!(first_page.page.revision, 2);
    assert_eq!(first_page.page.payloads.len(), 1);
    assert_eq!(first_page.page.payloads[0]["backup_id"], first_id);
    first_query.after = Some(KeyBackupListPosition {
        backup_kind: "secret_storage".to_owned(),
        series_id: series,
        series_seq: 0,
        backup_id: first_id,
    });
    let second_page = backups
        .confirmed_list_page_for_device(&account, &authorizer, at, &first_query)
        .await
        .unwrap();
    assert_eq!(second_page.active_series, initial_pointer);
    assert_eq!(second_page.page.revision, first_page.page.revision);
    assert_eq!(second_page.page.payloads.len(), 1);
    assert_eq!(second_page.page.payloads[0]["backup_id"], second_id);

    let target = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let payload = serde_json::json!({
        "device_id": target,
        "revoked_by": authorizer,
        "revoked_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "reason": "security_rotation"
    });
    let _: DeviceRevokePayload = serde_json::from_value(payload.clone()).unwrap();
    let revoke = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            payload,
        )
        .unwrap(),
        device_method.clone(),
        device_seed,
    );
    let active_series = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::KeyBackupActiveSeries.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({"fixture":"prepared-only"}),
        )
        .unwrap(),
        device_method.clone(),
        device_seed,
    );
    let mut covering: RealmCommit = genesis.transactions[1].commit.clone();
    covering.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:revoke", revoke.event_id).as_bytes(),
    ));
    covering.stream_position += 1;
    covering.previous_commit_ref = Some(genesis.transactions[1].commit.commit_id.clone());
    covering.event_ref = revoke.event_id.clone();
    covering.committed_at += chrono::TimeDelta::seconds(1);
    let station_key = SigningKey::from_bytes(&[83; 32]);
    let unsigned = arkret_canonical::canonical::unsigned_value(&covering, &["signature"]).unwrap();
    covering.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{}#authority", station_did)).unwrap(),
        covering.committed_at,
        &station_key,
    )
    .unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &covering.signature,
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: station_key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();

    let revoke_unit = PreparedEventUnit::new(
        arkret_canonical::DigestSuite::Sha256,
        arkret_wire::EventsSubmitBatchRequestBody {
            events: (vec![revoke.clone()])
                .into_iter()
                .map(arkret_wire::EventAdmissionSubmission::new)
                .collect(),
        },
    )
    .unwrap();
    let active_unit = PreparedEventUnit::new(
        arkret_canonical::DigestSuite::Sha256,
        arkret_wire::EventsSubmitBatchRequestBody {
            events: (vec![active_series.clone()])
                .into_iter()
                .map(arkret_wire::EventAdmissionSubmission::new)
                .collect(),
        },
    )
    .unwrap();
    let author = PointerAuthor {
        account: account.clone(),
        realm_id: realm_id.clone(),
        method: device_method.clone(),
        seed: device_seed,
    };
    let new_series_id =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let envelope = signed_backup(
        &author,
        &authorizer,
        &genesis.transactions[1].event.event_id,
        &new_series_id,
        0,
        None,
        device_seed,
    );
    let backup =
        |_suffix: &str| BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7())).unwrap();
    let binding = BackupRotationBinding {
        backup_kind: BackupRotationKind::SecretStorage,
        previous_series_id: BackupSeriesId::new(format!(
            "ak:backup_series:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        new_series_id,
        new_backups: vec![BackupObjectRef {
            backup_id: envelope.backup_id.clone(),
            ciphertext_digest: envelope.ciphertext_digest.clone(),
        }],
        active_series_event_id: active_series.event_id.clone(),
        old_backups: vec![BackupObjectRef {
            backup_id: backup("old"),
            ciphertext_digest: hash("old-backup"),
        }],
    };
    let rotation = BackupRotationPlan {
        binding,
        new_backup_envelopes: vec![envelope],
        active_series_unit: active_unit,
    };
    let request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        authorizer.clone(),
        at + chrono::TimeDelta::hours(1),
        revoke_unit,
        hash("new-secret"),
        vec![rotation],
    )
    .unwrap();
    let plan = SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan.clone());
    let (initial, canonical_request) = SecurityTransactionCreateRequest::SecurityRotation(request)
        .into_initial_resource(plan, at)
        .unwrap();
    let initial_record = SecurityTransactionRecord {
        resource: initial.clone(),
        canonical_request: canonical_request.clone(),
    };
    let transaction_id = initial.transaction_id.clone();
    let transactions = PgSecurityTransactionStore { pool: pool.clone() };
    transactions.create(initial_record).await.unwrap();
    let awaiting = |ids: Vec<String>| ids.contains(&transaction_id.to_string());
    assert!(
        awaiting(transactions.rotations_awaiting_worker(1000).await.unwrap()),
        "a created rotation awaits its coordinator-owned revoke"
    );
    let mut proposed = initial;
    proposed.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
    });
    let write = RevokeProposalCommitWrite {
        transaction: SecurityTransactionRecord {
            resource: proposed,
            canonical_request,
        },
        commit: AuthorityCommitTransaction {
            expected_authority: genesis.transactions[1].expected_authority.clone(),
            event: revoke.clone(),
            commit: covering.clone(),
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
        queued_at: at,
    };
    let mut conn = pool.get().await.unwrap();
    let mut bad_authorizer = write.clone();
    bad_authorizer.transaction.resource.authorizing_device_id = Some(target.clone());
    assert_eq!(
        transactions
            .commit_revoke_proposal(bad_authorizer)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition),
        "a producer other than the authorizing device is a registered precondition failure"
    );
    let mut bad_proof = write.clone();
    bad_proof.commit.event.producer_proof.as_mut().unwrap().jws = "invalid".to_owned();
    let bad_proof = transactions
        .commit_revoke_proposal(bad_proof)
        .await
        .unwrap_err();
    assert!(
        matches!(bad_proof, PersistenceError::SchemaViolation(_)),
        "an Event other than the prepared unit is refused before any read: {bad_proof}"
    );
    diesel::sql_query(
        "UPDATE pcr_device_generation_current_results SET value=jsonb_build_object('current_device_generation_ref',2) WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    assert!(
        transactions
            .commit_revoke_proposal(write.clone())
            .await
            .is_err()
    );
    diesel::sql_query(
        "UPDATE pcr_device_generation_current_results SET value=jsonb_build_object('current_device_generation_ref',1) WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    let before = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM pcr_device_revocation_proposals WHERE event_id=$1",
    )
    .bind::<Text, _>(revoke.event_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        before.count, 0,
        "rejected proposal leaked its immutable dot"
    );
    assert_eq!(
        sql_fault_matrix::exhaust_writes(&pool, "revoke_proposal", || transactions
            .commit_revoke_proposal(write.clone()))
        .await,
        covering
    );
    let restarted_pool = Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let reopened_transactions = PgSecurityTransactionStore {
        pool: restarted_pool,
    };
    let before_replay = sql_fault_matrix::snapshot(&pool).await;
    assert_eq!(
        reopened_transactions
            .commit_revoke_proposal(write.clone())
            .await
            .unwrap(),
        covering
    );
    let mut changed_proposal = write;
    changed_proposal.transaction.resource.created_at += chrono::TimeDelta::seconds(1);
    assert_eq!(
        reopened_transactions
            .commit_revoke_proposal(changed_proposal)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before_replay);
    assert!(
        awaiting(transactions.rotations_awaiting_worker(1000).await.unwrap()),
        "a pending proposal still awaits its terminal decision"
    );
    let dots = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM pcr_device_revocation_proposals WHERE event_id=$1",
    )
    .bind::<Text, _>(revoke.event_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(dots.count, 1);
    let stored = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.resource.revoke_proposal.unwrap().covering_commit_id,
        covering.commit_id
    );

    let mut accepted = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    accepted
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
            },
            accepted_at: at + chrono::TimeDelta::seconds(2),
        });
    accepted.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
        result: SecurityRotationRevokeCommandDecision::Accepted,
        decided_at: at + chrono::TimeDelta::seconds(2),
    });
    let terminal = RevokeCommandTerminalWrite {
        step_outcome: Some(SecurityTransactionStepOutcomeRecord {
            transaction_id: transaction_id.to_string(),
            step: SecurityTransactionStep::Revoke,
            canonical_request: b"revoke-worker-request".to_vec(),
            response: serde_json::to_value(&accepted.resource).unwrap(),
            participant_outcome: None,
        }),
        transaction: accepted,
    };
    let mut incomplete = terminal.clone();
    incomplete.step_outcome = None;
    assert!(
        transactions
            .commit_revoke_command_terminal(incomplete)
            .await
            .is_err()
    );
    let before_terminal = diesel::sql_query("SELECT COUNT(*) AS count FROM security_transaction_step_outcomes WHERE transaction_id=$1 AND step='revoke'")
        .bind::<Uuid,_>(uuid::Uuid::parse_str(transaction_id.as_str().strip_prefix("ak:transaction:").unwrap()).unwrap())
        .get_result::<CountRow>(&mut *conn).await.unwrap();
    assert_eq!(before_terminal.count, 0);
    let decided = sql_fault_matrix::exhaust_writes(&pool, "revoke_terminal_accepted", || {
        transactions.commit_revoke_command_terminal(terminal.clone())
    })
    .await;
    assert!(
        awaiting(transactions.rotations_awaiting_worker(1000).await.unwrap()),
        "an accepted revoke stays queued for the worker-owned upload step"
    );
    assert_eq!(
        decided
            .resource
            .revoke_command_outcome
            .as_ref()
            .unwrap()
            .result,
        SecurityRotationRevokeCommandDecision::Accepted
    );
    assert_eq!(
        transactions
            .commit_revoke_command_terminal(terminal.clone())
            .await
            .unwrap()
            .resource,
        decided.resource,
    );
    let reopened = Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let restarted = PgSecurityTransactionStore { pool: reopened };
    let before_replay = sql_fault_matrix::snapshot(&pool).await;
    assert_eq!(
        restarted
            .commit_revoke_command_terminal(terminal.clone())
            .await
            .unwrap()
            .resource,
        decided.resource
    );
    let mut changed = terminal;
    changed
        .transaction
        .resource
        .revoke_command_outcome
        .as_mut()
        .unwrap()
        .decided_at += chrono::TimeDelta::seconds(1);
    changed.step_outcome.as_mut().unwrap().response =
        serde_json::to_value(&changed.transaction.resource).unwrap();
    assert_eq!(
        restarted
            .commit_revoke_command_terminal(changed)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before_replay);
    let terminal_rows = diesel::sql_query("SELECT COUNT(*) AS count FROM security_transaction_step_outcomes WHERE transaction_id=$1 AND step='revoke'")
        .bind::<Uuid,_>(uuid::Uuid::parse_str(transaction_id.as_str().strip_prefix("ak:transaction:").unwrap()).unwrap())
        .get_result::<CountRow>(&mut *conn).await.unwrap();
    assert_eq!(terminal_rows.count, 1);
    // A decided proposal for another target does not revoke the authorizer.
    assert!(
        device_status
            .pcr_device_admission(&account, &authorizer, at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );

    let reject_target = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let reject_event = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({
                "device_id": reject_target,
                "revoked_by": authorizer,
                "revoked_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "reason": "security_rotation"
            }),
        )
        .unwrap(),
        device_method.clone(),
        device_seed,
    );
    let mut reject_commit = covering.clone();
    reject_commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:rejected", reject_event.event_id).as_bytes(),
    ));
    reject_commit.stream_position += 1;
    reject_commit.previous_commit_ref = Some(covering.commit_id.clone());
    reject_commit.event_ref = reject_event.event_id.clone();
    reject_commit.committed_at += chrono::TimeDelta::seconds(1);
    let unsigned =
        arkret_canonical::canonical::unsigned_value(&reject_commit, &["signature"]).unwrap();
    reject_commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{}#authority", station_did)).unwrap(),
        reject_commit.committed_at,
        &station_key,
    )
    .unwrap();
    let reject_request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        authorizer.clone(),
        at + chrono::TimeDelta::hours(1),
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::EventsSubmitBatchRequestBody {
                events: (vec![reject_event.clone()])
                    .into_iter()
                    .map(arkret_wire::EventAdmissionSubmission::new)
                    .collect(),
            },
        )
        .unwrap(),
        hash("second-secret"),
        decided
            .resource
            .security_rotation_plan()
            .unwrap()
            .backup_rotations
            .clone(),
    )
    .unwrap();
    let reject_plan =
        SecurityTransactionPreparedPlan::SecurityRotation(reject_request.prepared_plan.clone());
    let (reject_initial, reject_request_bytes) =
        SecurityTransactionCreateRequest::SecurityRotation(reject_request)
            .into_initial_resource(reject_plan, at)
            .unwrap();
    let reject_id = reject_initial.transaction_id.clone();
    transactions
        .create(SecurityTransactionRecord {
            resource: reject_initial.clone(),
            canonical_request: reject_request_bytes.clone(),
        })
        .await
        .unwrap();
    let mut reject_proposed = reject_initial;
    reject_proposed.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: reject_event.event_id.clone(),
        covering_commit_id: reject_commit.commit_id.clone(),
    });
    transactions
        .commit_revoke_proposal(RevokeProposalCommitWrite {
            transaction: SecurityTransactionRecord {
                resource: reject_proposed,
                canonical_request: reject_request_bytes,
            },
            commit: AuthorityCommitTransaction {
                expected_authority: genesis.transactions[1].expected_authority.clone(),
                event: reject_event.clone(),
                commit: reject_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: at,
        })
        .await
        .unwrap();
    let mut rejected = transactions.get(reject_id.as_str()).await.unwrap().unwrap();
    rejected.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: reject_event.event_id,
        covering_commit_id: reject_commit.commit_id.clone(),
        result: SecurityRotationRevokeCommandDecision::Rejected,
        decided_at: at + chrono::TimeDelta::seconds(3),
    });
    rejected.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Aborted {
        completed_at: at + chrono::TimeDelta::seconds(3),
        reason_code: Some("rejected".to_owned()),
    });
    let rejected_write = RevokeCommandTerminalWrite {
        transaction: rejected,
        step_outcome: None,
    };
    let before_rejected_list = device_list_position(&pool, &account, &account).await;
    let before_rejected_rows = sql_fault_matrix::snapshot(&pool).await;
    let rejected_result =
        sql_fault_matrix::exhaust_writes(&pool, "revoke_terminal_rejected", || {
            transactions.commit_revoke_command_terminal(rejected_write.clone())
        })
        .await;
    let after_rejected_rows = sql_fault_matrix::snapshot(&pool).await;
    for (table, rows) in &before_rejected_rows {
        if table != "security_transactions" {
            assert_eq!(
                &after_rejected_rows[table], rows,
                "rejected terminal wrote to {table}"
            );
        }
    }
    assert_eq!(
        device_list_position(&pool, &account, &account).await,
        before_rejected_list,
        "rejected revoke terminal does not publish a device-list change"
    );
    assert_eq!(
        rejected_result
            .resource
            .revoke_command_outcome
            .as_ref()
            .unwrap()
            .result,
        SecurityRotationRevokeCommandDecision::Rejected
    );
    assert_eq!(
        transactions
            .commit_revoke_command_terminal(rejected_write.clone())
            .await
            .unwrap()
            .resource,
        rejected_result.resource
    );
    assert_eq!(
        device_list_position(&pool, &account, &account).await,
        before_rejected_list,
        "rejected terminal replay does not publish a device-list change"
    );
    let reopened = Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let restarted = PgSecurityTransactionStore { pool: reopened };
    let before_replay = sql_fault_matrix::snapshot(&pool).await;
    assert_eq!(
        restarted
            .commit_revoke_command_terminal(rejected_write.clone())
            .await
            .unwrap()
            .resource,
        rejected_result.resource
    );
    let mut changed_terminal = rejected_write;
    changed_terminal
        .transaction
        .resource
        .revoke_command_outcome
        .as_mut()
        .unwrap()
        .decided_at += chrono::TimeDelta::seconds(1);
    assert_eq!(
        transactions
            .commit_revoke_command_terminal(changed_terminal)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict),
        "a different terminal for the same proposal is a duplicate conflict"
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before_replay);
    assert_eq!(
        transactions
            .get(reject_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .resource,
        rejected_result.resource,
    );
    let rejected_rows = diesel::sql_query("SELECT COUNT(*) AS count FROM security_transaction_step_outcomes WHERE transaction_id=$1 AND step='revoke'")
        .bind::<Uuid,_>(uuid::Uuid::parse_str(reject_id.as_str().strip_prefix("ak:transaction:").unwrap()).unwrap())
        .get_result::<CountRow>(&mut *conn).await.unwrap();
    assert_eq!(rejected_rows.count, 0);
    assert!(
        device_status
            .pcr_device_admission(&account, &authorizer, at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
}

/// Station-sign one PCR successor Commit for `event` directly after `previous`.
fn station_successor(
    previous: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    offset_seconds: i64,
) -> arkret_wire::RealmCommit {
    let mut commit = previous.clone();
    commit.stream_position = previous.stream_position + 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = previous.committed_at + chrono::TimeDelta::seconds(offset_seconds);
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

struct PointerAuthor {
    account: arkret_wire::AccountId,
    realm_id: RealmId,
    method: DidUrl,
    seed: [u8; 32],
}

impl PointerAuthor {
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        series: &BackupSeriesId,
        version: u64,
        previous: Vec<BackupSeriesId>,
        source: &RealmCommitId,
        authorize_event_id: &arkret_wire::EventId,
        generation: u64,
        signing_seed: [u8; 32],
    ) -> serde_json::Value {
        use arkret_models_collaboration::events_payloads::{
            ControllerBackupTrustAnchor, UnsignedKeyBackupActiveSeries,
        };
        let unsigned = UnsignedKeyBackupActiveSeries::new(
            arkret_wire::ActorId::account(self.account.clone()),
            arkret_models_crypto::BackupKind::SecretStorage,
            series.clone(),
            version,
            previous,
            source.clone(),
            chrono::DateTime::parse_from_rfc3339("2026-09-24T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            self.method.clone(),
            ControllerBackupTrustAnchor {
                authorize_event_id: authorize_event_id.clone(),
                generation_ref: generation,
            },
        )
        .unwrap();
        let signature = SigningKey::from_bytes(&signing_seed)
            .sign(&unsigned.signing_payload_bytes().unwrap())
            .to_bytes();
        serde_json::to_value(
            unsigned
                .attach_signature(
                    arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                        signature,
                    ))
                    .unwrap(),
                )
                .unwrap(),
        )
        .unwrap()
    }

    fn event(&self, payload: serde_json::Value, nonce: u32) -> arkret_wire::Event {
        let mut event = arkret_wire::test_support::raw_event(
            EventKind::KeyBackupActiveSeries.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: self.realm_id.clone(),
            },
            self.account.principal_id.clone(),
            self.account.station_id.clone(),
            payload,
        )
        .unwrap();
        event.created_at += chrono::TimeDelta::milliseconds(i64::from(nonce));
        device_history_fixture::sign_event(event, self.method.clone(), self.seed)
    }
}

#[derive(diesel::QueryableByName)]
struct PointerFootprint {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    pointers: i64,
}

async fn pointer_footprint(pool: &PgPool, realm_id: &RealmId) -> (i64, i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS events, \
                (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS commits, \
                (SELECT COUNT(*) FROM key_backup_active_series_current_results WHERE realm_id=$1) \
                  AS pointers",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<PointerFootprint>(&mut *conn)
    .await
    .unwrap();
    (row.events, row.commits, row.pointers)
}

#[tokio::test]
async fn key_backup_active_series_pointer_unit_commits_only_at_the_active_device_cut() {
    use coland_storage::{KeyBackupActiveSeriesCommitOutcome, KeyBackupActiveSeriesCommitWrite};

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let author = PointerAuthor {
        account: fixture.account.clone(),
        realm_id: RealmId::new(fixture.events[0].realm_id.to_string()).unwrap(),
        method: fixture.device_verification_method.clone(),
        seed: fixture.founding_device_signing_seed,
    };
    let device = fixture.founding_device_id.clone();
    let station_did = fixture.station_did.clone();
    let did = fixture.did.clone();
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&genesis, at)
        .await
        .unwrap();
    let head = genesis.transactions[1].commit.clone();
    let authorize_id = genesis.transactions[1].event.event_id.clone();
    let create_id = genesis.transactions[0].event.event_id.clone();
    let authority = genesis.transactions[1].expected_authority.clone();
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let series = BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let write = |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        KeyBackupActiveSeriesCommitWrite {
            commit: AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event,
                commit,
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: at,
        }
    };
    let baseline = pointer_footprint(&pool, &author.realm_id).await;
    assert_eq!(baseline, (2, 2, 0));

    // Every rejected candidate leaves no Event, Commit or pointer behind.
    let mut rejected = Vec::new();
    let other_seed = [91; 32];
    let cases: [(&str, serde_json::Value); 6] = [
        (
            "stale generation",
            author.record(
                &series,
                1,
                vec![],
                &head.commit_id,
                &authorize_id,
                2,
                author.seed,
            ),
        ),
        (
            "non-current authorization Event",
            author.record(
                &series,
                1,
                vec![],
                &head.commit_id,
                &create_id,
                1,
                author.seed,
            ),
        ),
        (
            "foreign record signature",
            author.record(
                &series,
                1,
                vec![],
                &head.commit_id,
                &authorize_id,
                1,
                other_seed,
            ),
        ),
        (
            "unaccepted source checkpoint",
            author.record(
                &series,
                1,
                vec![],
                &unrelated_commit_id(),
                &authorize_id,
                1,
                author.seed,
            ),
        ),
        (
            "source before device authorization",
            author.record(
                &series,
                1,
                vec![],
                &genesis.transactions[0].commit.commit_id,
                &authorize_id,
                1,
                author.seed,
            ),
        ),
        (
            "first pointer version gap",
            author.record(
                &series,
                2,
                vec![],
                &head.commit_id,
                &authorize_id,
                1,
                author.seed,
            ),
        ),
    ];
    for (nonce, (label, payload)) in cases.into_iter().enumerate() {
        let event = author.event(payload, nonce as u32 + 1);
        let commit = station_successor(&head, &event, &station_did, 1);
        rejected.push((
            label,
            backups
                .commit_active_series_pointer(write(event, commit))
                .await,
        ));
    }
    let valid = author.record(
        &series,
        1,
        vec![],
        &head.commit_id,
        &authorize_id,
        1,
        author.seed,
    );
    // A different device fragment has no current authorization at this cut.
    let foreign_method = author_with_method(
        &author,
        DidUrl::new(format!(
            "{did}#{}",
            DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap()
        ))
        .unwrap(),
    );
    let foreign_payload = foreign_method.record(
        &series,
        1,
        vec![],
        &head.commit_id,
        &authorize_id,
        1,
        author.seed,
    );
    let foreign_event = foreign_method.event(foreign_payload, 20);
    let foreign_commit = station_successor(&head, &foreign_event, &station_did, 1);
    rejected.push((
        "unauthorized device method",
        backups
            .commit_active_series_pointer(write(foreign_event, foreign_commit))
            .await,
    ));
    // The Commit must extend the confirmed PCR head, not an older position.
    let event = author.event(valid.clone(), 30);
    let mut behind = station_successor(&genesis.transactions[0].commit, &event, &station_did, 1);
    behind.stream_position = head.stream_position + 1;
    rejected.push((
        "Commit behind head",
        backups
            .commit_active_series_pointer(write(event, behind))
            .await,
    ));
    // A tampered producer proof is rejected even when the record is valid.
    let mut tampered = author.event(valid.clone(), 31);
    tampered.producer_proof.as_mut().unwrap().jws = "invalid".to_owned();
    let tampered_commit = station_successor(&head, &tampered, &station_did, 1);
    rejected.push((
        "tampered producer proof",
        backups
            .commit_active_series_pointer(write(tampered, tampered_commit))
            .await,
    ));
    let expected_reasons = [
        ("stale generation", "backup_revision_stale"),
        (
            "non-current authorization Event",
            "device authorization that is not current",
        ),
        (
            "foreign record signature",
            "signature does not match the device key",
        ),
        (
            "unaccepted source checkpoint",
            "source checkpoint is not an accepted PCR Commit",
        ),
        (
            "source before device authorization",
            "source checkpoint is not an accepted PCR Commit",
        ),
        (
            "first pointer version gap",
            "key_backup_active_series_pointer_version_gap",
        ),
        ("unauthorized device method", "has no current authorization"),
        (
            "Commit behind head",
            "does not extend the confirmed PCR head",
        ),
        (
            "tampered producer proof",
            "producer proof does not match the device key",
        ),
    ];
    assert_eq!(rejected.len(), expected_reasons.len());
    for ((label, outcome), (expected_label, reason)) in rejected.iter().zip(expected_reasons) {
        assert_eq!(*label, expected_label);
        let error = outcome
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("{label} was accepted"))
            .to_string();
        assert!(
            error.contains(reason),
            "{label} failed for another reason: {error}"
        );
    }
    assert_eq!(
        pointer_footprint(&pool, &author.realm_id).await,
        baseline,
        "a rejected pointer candidate left a durable write"
    );
    assert!(matches!(
        backups
            .confirmed_active_series_for_device(&author.account, &device, at)
            .await
            .unwrap()
            .unwrap()
            .secret_storage,
        BackupActiveSeriesPointer::Absent {}
    ));

    // The generic authority path still refuses the pointer kind.
    let first = author.event(valid, 40);
    let first_commit = station_successor(&head, &first, &station_did, 1);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .admit_event_transaction(&write(first.clone(), first_commit.clone()).commit, at)
            .await
            .is_err()
    );

    let committed = backups
        .commit_active_series_pointer(write(first.clone(), first_commit.clone()))
        .await
        .unwrap();
    assert_eq!(
        committed,
        KeyBackupActiveSeriesCommitOutcome::Committed(first_commit.clone())
    );
    assert_eq!(
        backups
            .commit_active_series_pointer(write(first.clone(), first_commit.clone()))
            .await
            .unwrap(),
        KeyBackupActiveSeriesCommitOutcome::Duplicate(first_commit.clone())
    );
    let mut other_commit = station_successor(&head, &first, &station_did, 2);
    other_commit.commit_id = unrelated_commit_id();
    assert!(
        backups
            .commit_active_series_pointer(write(first.clone(), other_commit))
            .await
            .is_err(),
        "the same Event under a different Commit is not a replay"
    );
    assert_eq!(pointer_footprint(&pool, &author.realm_id).await, (3, 3, 1));
    let active = backups
        .confirmed_active_series_for_device(&author.account, &device, at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.authority_commit_id, first_commit.commit_id);
    assert_eq!(
        active.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: series.clone(),
            series_pointer_version: 1,
        }
    );
    let page = backups
        .confirmed_list_page_for_device(
            &author.account,
            &device,
            at,
            &KeyBackupListQuery {
                actor_id: arkret_wire::ActorId::account(author.account.clone()).to_string(),
                backup_kind: None,
                series_id: None,
                after: None,
                limit: 50,
            },
        )
        .await
        .unwrap();
    assert_eq!(page.active_series, active);

    // Successor: exactly +1 with the prior series retained. A same-version
    // fork and a version gap at the new head are both rejected.
    let next_series =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let fork = author.event(
        author.record(
            &next_series,
            1,
            vec![],
            &first_commit.commit_id,
            &authorize_id,
            1,
            author.seed,
        ),
        50,
    );
    let fork_commit = station_successor(&first_commit, &fork, &station_did, 1);
    assert!(
        backups
            .commit_active_series_pointer(write(fork, fork_commit))
            .await
            .is_err()
    );
    let gap = author.event(
        author.record(
            &next_series,
            3,
            vec![series.clone()],
            &first_commit.commit_id,
            &authorize_id,
            1,
            author.seed,
        ),
        51,
    );
    let gap_commit = station_successor(&first_commit, &gap, &station_did, 1);
    assert!(
        backups
            .commit_active_series_pointer(write(gap, gap_commit))
            .await
            .is_err()
    );
    assert_eq!(pointer_footprint(&pool, &author.realm_id).await, (3, 3, 1));
    // An earlier accepted checkpoint under the same generation is not stale.
    let second = author.event(
        author.record(
            &next_series,
            2,
            vec![series.clone()],
            &head.commit_id,
            &authorize_id,
            1,
            author.seed,
        ),
        52,
    );
    let second_commit = station_successor(&first_commit, &second, &station_did, 1);
    backups
        .commit_active_series_pointer(write(second, second_commit.clone()))
        .await
        .unwrap();

    // A fresh pool reads the same durable pointer and status cut.
    let restarted = Db::connect(Some(&support::contract_database_url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let reread = PgKeyBackupStore { pool: restarted }
        .confirmed_active_series_for_device(&author.account, &device, at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reread.authority_commit_id, second_commit.commit_id);
    assert_eq!(
        reread.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: next_series,
            series_pointer_version: 2,
        }
    );
    assert!(
        PgDeviceRevocationStore { pool: pool.clone() }
            .pcr_device_admission(&author.account, &device, at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );

    // The account-scoped read that freezes delete/unlock bases names the same
    // durable pointer and PCR head.
    assert_eq!(
        backups
            .confirmed_active_series(&author.account)
            .await
            .unwrap()
            .unwrap(),
        reread
    );
    // A typed row that lags the latest accepted pointer Commit, or is missing
    // while one exists, is unavailable -- never the older pointer or Absent.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE key_backup_active_series_current_results \
         SET current_commit_id=$2,current_event_id=$3,current_stream_position=$4 \
         WHERE realm_id=$1",
    )
    .bind::<Text, _>(author.realm_id.as_str())
    .bind::<Text, _>(first_commit.commit_id.as_str())
    .bind::<Text, _>(first.event_id.as_str())
    .bind::<BigInt, _>(first_commit.stream_position as i64)
    .execute(&mut *conn)
    .await
    .unwrap();
    assert!(
        backups
            .confirmed_active_series(&author.account)
            .await
            .is_err(),
        "a lagging typed pointer must not be served"
    );
    diesel::sql_query("DELETE FROM key_backup_active_series_current_results WHERE realm_id=$1")
        .bind::<Text, _>(author.realm_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(
        backups
            .confirmed_active_series(&author.account)
            .await
            .is_err(),
        "a missing typed pointer after an accepted pointer Commit is not Absent"
    );
}

fn author_with_method(author: &PointerAuthor, method: DidUrl) -> PointerAuthor {
    PointerAuthor {
        account: author.account.clone(),
        realm_id: author.realm_id.clone(),
        method,
        seed: author.seed,
    }
}

#[derive(Debug, PartialEq, Eq, diesel::QueryableByName)]
struct AcceptedDeviceFootprint {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    authorizations: i64,
    #[diesel(sql_type = BigInt)]
    devices: i64,
}

async fn accepted_device_footprint(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &arkret_wire::AccountId,
) -> AcceptedDeviceFootprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS events, \
                (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS commits, \
                (SELECT COUNT(*) FROM pcr_device_authorization_current_results WHERE realm_id=$1) \
                  AS authorizations, \
                (SELECT COUNT(*) FROM devices WHERE actor_id=$2 AND verification_state='verified') \
                  AS devices",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(account.principal_id.as_str())
    .get_result::<AcceptedDeviceFootprint>(&mut *conn)
    .await
    .unwrap()
}

/// One `accepted_device` authorization of a fresh device, approved by
/// `approver` and signed with `producer_seed` under `method`. The target's
/// possession signature binds `possession_account`.
#[allow(clippy::too_many_arguments)]
fn accepted_device_event(
    account: &arkret_wire::AccountId,
    possession_account: &arkret_wire::AccountId,
    realm_id: &RealmId,
    approver: &DeviceId,
    method: &DidUrl,
    producer_seed: [u8; 32],
    device_seed: [u8; 32],
    not_before: chrono::DateTime<chrono::Utc>,
    generation: u64,
) -> (DeviceId, arkret_wire::Event) {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef,
    };

    let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let payload = device_history_fixture::possession_with(
        possession_account,
        device_history_fixture::DeviceAuthorizationSpec {
            device_id: device.clone(),
            signing_seed: device_seed,
            hpke_seed: [device_seed[0].wrapping_add(1); 32],
            authorized_by: DeviceOrPrincipalRef::DeviceId(approver.clone()),
            not_before,
            expires_at: None,
            binding: DeviceAuthorizationBindingKind::AcceptedDevice,
            authorized_generation_ref: generation,
            applet_id: None,
        },
    );
    let event = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceAuthorize.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::to_value(&payload).unwrap(),
        )
        .unwrap(),
        method.clone(),
        producer_seed,
    );
    (device, event)
}

#[tokio::test]
async fn accepted_device_unit_admits_only_a_current_active_approver() {
    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let realm_id = RealmId::new(fixture.events[0].realm_id.to_string()).unwrap();
    let did = fixture.did.clone();
    let station_did = fixture.station_did.clone();
    let device_a = fixture.founding_device_id.clone();
    let method_a = fixture.device_verification_method.clone();
    let seed_a = fixture.founding_device_signing_seed;
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store.admit_pcr_genesis_unit(&genesis, at).await.unwrap();
    let head = genesis.transactions[1].commit.clone();
    let authority = genesis.transactions[1].expected_authority.clone();
    let tx =
        |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
    // The typed device_generation current is readable at the confirmed cut.
    assert_eq!(
        PgDeviceRevocationStore { pool: pool.clone() }
            .pcr_device_generation(&account)
            .await
            .unwrap(),
        Some(coland_storage::PcrDeviceGeneration {
            current_device_generation_ref: 1,
        })
    );
    let before = accepted_device_footprint(&pool, &realm_id, &account).await;
    let refusal = async |event: &arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        let error = store
            .admit_accepted_device_authorization(&tx(event.clone(), commit), at)
            .await
            .unwrap_err();
        assert_eq!(
            accepted_device_footprint(&pool, &realm_id, &account).await,
            before,
            "a refused accepted-device admission must write nothing"
        );
        error.conflict_code()
    };

    // The payload names a generation other than the current one.
    let (_, stale) = accepted_device_event(
        &account, &account, &realm_id, &device_a, &method_a, seed_a, [41; 32], at, 2,
    );
    assert_eq!(
        refusal(&stale, station_successor(&head, &stale, &station_did, 1)).await,
        Some(ConflictCode::DeviceGenerationFenced)
    );
    // A's method, but the producer proof is made with another key.
    let (_, forged) = accepted_device_event(
        &account, &account, &realm_id, &device_a, &method_a, [0x66; 32], [42; 32], at, 1,
    );
    assert_eq!(
        refusal(&forged, station_successor(&head, &forged, &station_did, 1)).await,
        Some(ConflictCode::SignatureInvalid)
    );
    // Signed by A's key under a method that names another device.
    let other_method = DidUrl::new(format!("{did}#ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let (_, misnamed) = accepted_device_event(
        &account,
        &account,
        &realm_id,
        &device_a,
        &other_method,
        seed_a,
        [43; 32],
        at,
        1,
    );
    assert_eq!(
        refusal(
            &misnamed,
            station_successor(&head, &misnamed, &station_did, 1)
        )
        .await,
        Some(ConflictCode::SignatureInvalid)
    );
    // The target possession signature commits to another account.
    let mallory = arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:mallory.example").unwrap(),
        account.station_id.clone(),
    );
    let (_, foreign) = accepted_device_event(
        &account, &mallory, &realm_id, &device_a, &method_a, seed_a, [44; 32], at, 1,
    );
    assert_eq!(
        refusal(
            &foreign,
            station_successor(&head, &foreign, &station_did, 1)
        )
        .await,
        Some(ConflictCode::SignatureInvalid)
    );
    // A Commit that does not extend the confirmed PCR head.
    let (_, detached) = accepted_device_event(
        &account, &account, &realm_id, &device_a, &method_a, seed_a, [45; 32], at, 1,
    );
    assert_eq!(
        refusal(
            &detached,
            station_successor(&genesis.transactions[0].commit, &detached, &station_did, 1)
        )
        .await,
        Some(ConflictCode::CasConflict)
    );

    // A approves D at the current head: Event, Commit, typed authorization
    // and mirror are written together.
    let (device_d, approve_d) = accepted_device_event(
        &account, &account, &realm_id, &device_a, &method_a, seed_a, [46; 32], at, 1,
    );
    let commit_d = station_successor(&head, &approve_d, &station_did, 1);
    assert_eq!(
        store
            .admit_accepted_device_authorization(&tx(approve_d.clone(), commit_d.clone()), at)
            .await
            .unwrap(),
        AcceptedDeviceAuthorizationOutcome::Committed(commit_d.clone())
    );
    let accepted = accepted_device_footprint(&pool, &realm_id, &account).await;
    assert_eq!(
        accepted,
        AcceptedDeviceFootprint {
            events: before.events + 1,
            commits: before.commits + 1,
            authorizations: before.authorizations + 1,
            devices: before.devices + 1,
        }
    );
    // An exact retry reads the stored Commit, whatever Commit it presents.
    assert_eq!(
        store
            .admit_accepted_device_authorization(
                &tx(
                    approve_d.clone(),
                    station_successor(&commit_d, &approve_d, &station_did, 5)
                ),
                at
            )
            .await
            .unwrap(),
        AcceptedDeviceAuthorizationOutcome::Duplicate(commit_d.clone())
    );
    // A second authorization of the same device is a duplicate conflict.
    let mut again = approve_d.clone();
    again.created_at += chrono::TimeDelta::milliseconds(1);
    let again = device_history_fixture::sign_event(again, method_a.clone(), seed_a);
    let error = store
        .admit_accepted_device_authorization(
            &tx(
                again.clone(),
                station_successor(&commit_d, &again, &station_did, 1),
            ),
            at,
        )
        .await
        .unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::DuplicateConflict));
    assert_eq!(
        accepted_device_footprint(&pool, &realm_id, &account).await,
        accepted
    );

    // D is active at the cut, including after a fresh pool rebuilds it.
    let restarted = Db::connect(Some(&support::contract_database_url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    assert!(
        PgDeviceRevocationStore { pool: restarted }
            .pcr_device_admission(&account, &device_d, commit_d.committed_at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
}

#[tokio::test]
async fn accepted_revoke_terminal_stops_only_the_target_of_two_active_devices() {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef,
    };
    use coland_storage::{KeyBackupActiveSeriesCommitOutcome, KeyBackupActiveSeriesCommitWrite};

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let realm_id = RealmId::new(fixture.events[0].realm_id.to_string()).unwrap();
    let did = fixture.did.clone();
    let station_did = fixture.station_did.clone();
    let device_a = fixture.founding_device_id.clone();
    let author_a = PointerAuthor {
        account: account.clone(),
        realm_id: realm_id.clone(),
        method: fixture.device_verification_method.clone(),
        seed: fixture.founding_device_signing_seed,
    };
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&genesis, at)
        .await
        .unwrap();
    let authority = genesis.transactions[1].expected_authority.clone();
    let authorize_a = genesis.transactions[1].event.event_id.clone();
    let status = PgDeviceRevocationStore { pool: pool.clone() };
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let transactions = PgSecurityTransactionStore { pool: pool.clone() };
    let tx =
        |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };

    // Device B is approved by A under the current generation.
    let device_b = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let seed_b = [97; 32];
    let payload_b = device_history_fixture::possession_with(
        &account,
        device_history_fixture::DeviceAuthorizationSpec {
            device_id: device_b.clone(),
            signing_seed: seed_b,
            hpke_seed: [7; 32],
            authorized_by: DeviceOrPrincipalRef::DeviceId(device_a.clone()),
            not_before: at,
            expires_at: None,
            binding: DeviceAuthorizationBindingKind::AcceptedDevice,
            authorized_generation_ref: 1,
            applet_id: None,
        },
    );
    arkret_signatures::verify_device_authorize_possession(&payload_b, &account).unwrap();
    let authorize_b = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceAuthorize.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::to_value(&payload_b).unwrap(),
        )
        .unwrap(),
        author_a.method.clone(),
        author_a.seed,
    );
    let commit_b = station_successor(
        &genesis.transactions[1].commit,
        &authorize_b,
        &station_did,
        1,
    );
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .admit_event_transaction(&tx(authorize_b.clone(), commit_b.clone()), at)
            .await
            .is_err(),
        "generic admission must not authorize an accepted device"
    );
    assert_eq!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .admit_accepted_device_authorization(&tx(authorize_b.clone(), commit_b.clone()), at)
            .await
            .unwrap(),
        AcceptedDeviceAuthorizationOutcome::Committed(commit_b.clone())
    );
    let now = commit_b.committed_at;
    assert!(
        status
            .pcr_device_admission(&account, &device_a, now)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    assert!(
        status
            .pcr_device_admission(&account, &device_b, now)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    let author_b = PointerAuthor {
        account: account.clone(),
        realm_id: realm_id.clone(),
        method: DidUrl::new(format!("{did}#{device_b}")).unwrap(),
        seed: seed_b,
    };
    let before_proposal_list = device_list_position(&pool, &account, &account).await;
    assert!(
        before_proposal_list >= 2,
        "genesis and accepted-device each publish once"
    );

    // B, as an active device, may select the first series at this cut.
    let series_one =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let pointer_b = author_b.event(
        author_b.record(
            &series_one,
            1,
            vec![],
            &commit_b.commit_id,
            &authorize_b.event_id,
            1,
            seed_b,
        ),
        1,
    );
    let pointer_b_commit = station_successor(&commit_b, &pointer_b, &station_did, 1);
    assert!(matches!(
        backups
            .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
                commit: tx(pointer_b, pointer_b_commit.clone()),
                queued_at: now,
            })
            .await
            .unwrap(),
        KeyBackupActiveSeriesCommitOutcome::Committed(_)
    ));

    // A proposes revoking B through the SecurityRotation proposal unit.
    let revoke = device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::DeviceRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({
                "device_id": device_b,
                "revoked_by": device_a,
                "revoked_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "reason": "security_rotation"
            }),
        )
        .unwrap(),
        author_a.method.clone(),
        author_a.seed,
    );
    let covering = station_successor(&pointer_b_commit, &revoke, &station_did, 1);
    let rotation_series =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let envelope = signed_backup(
        &author_a,
        &device_a,
        &authorize_a,
        &rotation_series,
        0,
        None,
        author_a.seed,
    );
    let rotation_pointer = author_a.event(
        author_a.record(
            &rotation_series,
            2,
            vec![series_one.clone()],
            &covering.commit_id,
            &authorize_a,
            1,
            author_a.seed,
        ),
        2,
    );
    let request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        device_a.clone(),
        now + chrono::TimeDelta::hours(1),
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::EventsSubmitBatchRequestBody {
                events: (vec![revoke.clone()])
                    .into_iter()
                    .map(arkret_wire::EventAdmissionSubmission::new)
                    .collect(),
            },
        )
        .unwrap(),
        hash("rotated-secret"),
        vec![BackupRotationPlan {
            binding: BackupRotationBinding {
                backup_kind: BackupRotationKind::SecretStorage,
                previous_series_id: series_one.clone(),
                new_series_id: rotation_series.clone(),
                new_backups: vec![BackupObjectRef {
                    backup_id: envelope.backup_id.clone(),
                    ciphertext_digest: envelope.ciphertext_digest.clone(),
                }],
                active_series_event_id: rotation_pointer.event_id.clone(),
                old_backups: vec![BackupObjectRef {
                    backup_id: BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7()))
                        .unwrap(),
                    ciphertext_digest: hash("old-backup"),
                }],
            },
            new_backup_envelopes: vec![envelope],
            active_series_unit: PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                arkret_wire::EventsSubmitBatchRequestBody {
                    events: (vec![rotation_pointer.clone()])
                        .into_iter()
                        .map(arkret_wire::EventAdmissionSubmission::new)
                        .collect(),
                },
            )
            .unwrap(),
        }],
    )
    .unwrap();
    let plan = SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan.clone());
    let (initial, canonical_request) = SecurityTransactionCreateRequest::SecurityRotation(request)
        .into_initial_resource(plan, now)
        .unwrap();
    let transaction_id = initial.transaction_id.clone();
    transactions
        .create(SecurityTransactionRecord {
            resource: initial.clone(),
            canonical_request: canonical_request.clone(),
        })
        .await
        .unwrap();
    let mut proposed = initial;
    proposed.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
    });
    transactions
        .commit_revoke_proposal(RevokeProposalCommitWrite {
            transaction: SecurityTransactionRecord {
                resource: proposed,
                canonical_request,
            },
            commit: tx(revoke.clone(), covering.clone()),
            queued_at: now,
        })
        .await
        .unwrap();

    assert_eq!(
        device_list_position(&pool, &account, &account).await,
        before_proposal_list,
        "a pending proposal does not publish a revoked device list"
    );

    // Pending: B stops authenticating and cannot move the pointer; A goes on.
    let pending_at = covering.committed_at;
    assert!(
        status
            .pcr_device_admission(&account, &device_b, pending_at)
            .await
            .unwrap()
            != arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    assert!(
        status
            .pcr_device_admission(&account, &device_a, pending_at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    assert!(
        backups
            .confirmed_active_series_for_device(&account, &device_b, pending_at)
            .await
            .is_err()
    );
    let pending_pointer = author_b.event(
        author_b.record(
            &rotation_series,
            2,
            vec![series_one.clone()],
            &covering.commit_id,
            &authorize_b.event_id,
            1,
            seed_b,
        ),
        3,
    );
    let pending_commit = station_successor(&covering, &pending_pointer, &station_did, 1);
    let refused = backups
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            commit: tx(pending_pointer, pending_commit),
            queued_at: pending_at,
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("not active at the PCR cut"), "{refused}");
    // Nor may the pending device approve another device.
    let (_, pending_approval) = accepted_device_event(
        &account,
        &account,
        &realm_id,
        &device_b,
        &author_b.method,
        seed_b,
        [51; 32],
        pending_at,
        1,
    );
    let pending_error = PgAuthorityCommitStore { pool: pool.clone() }
        .admit_accepted_device_authorization(
            &tx(
                pending_approval.clone(),
                station_successor(&covering, &pending_approval, &station_did, 1),
            ),
            pending_at,
        )
        .await
        .unwrap_err();
    assert_eq!(
        pending_error.conflict_code(),
        Some(ConflictCode::DeviceRevocationPending)
    );

    // The accepted terminal result revokes B; it never touches A.
    let mut accepted = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let decided_at = pending_at + chrono::TimeDelta::seconds(1);
    accepted
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
            },
            accepted_at: decided_at,
        });
    accepted.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
        result: SecurityRotationRevokeCommandDecision::Accepted,
        decided_at,
    });
    let terminal = RevokeCommandTerminalWrite {
        step_outcome: Some(SecurityTransactionStepOutcomeRecord {
            transaction_id: transaction_id.to_string(),
            step: SecurityTransactionStep::Revoke,
            canonical_request: b"revoke-worker-request".to_vec(),
            response: serde_json::to_value(&accepted.resource).unwrap(),
            participant_outcome: None,
        }),
        transaction: accepted,
    };
    transactions
        .commit_revoke_command_terminal(terminal.clone())
        .await
        .unwrap();
    assert_eq!(
        device_list_position(&pool, &account, &account).await,
        before_proposal_list + 1,
        "the accepted terminal publishes exactly one device-list change"
    );
    transactions
        .commit_revoke_command_terminal(terminal)
        .await
        .unwrap();
    assert_eq!(
        device_list_position(&pool, &account, &account).await,
        before_proposal_list + 1,
        "exact terminal replay does not republish the device list"
    );
    assert!(
        status
            .pcr_device_admission(&account, &device_b, decided_at)
            .await
            .unwrap()
            != arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    assert!(
        status
            .pcr_device_admission(&account, &device_a, decided_at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    assert!(
        backups
            .confirmed_active_series_for_device(&account, &device_b, decided_at)
            .await
            .is_err()
    );

    // A revoked device can no longer approve a new device.
    let (_, revoked_approval) = accepted_device_event(
        &account,
        &account,
        &realm_id,
        &device_b,
        &author_b.method,
        seed_b,
        [52; 32],
        decided_at,
        1,
    );
    let revoked_error = PgAuthorityCommitStore { pool: pool.clone() }
        .admit_accepted_device_authorization(
            &tx(
                revoked_approval.clone(),
                station_successor(&covering, &revoked_approval, &station_did, 2),
            ),
            decided_at,
        )
        .await
        .unwrap_err();
    assert_eq!(
        revoked_error.conflict_code(),
        Some(ConflictCode::DeviceRevoked)
    );

    // Replaying B's accepted authorization after the revocation returns the
    // stored Commit and re-admits nothing: B stays revoked at the new cut.
    assert_eq!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .admit_accepted_device_authorization(
                &tx(authorize_b.clone(), commit_b.clone()),
                decided_at,
            )
            .await
            .unwrap(),
        AcceptedDeviceAuthorizationOutcome::Duplicate(commit_b.clone())
    );
    assert!(
        status
            .pcr_device_admission(&account, &device_b, decided_at)
            .await
            .unwrap()
            != arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );

    // The rotation reserved its own pointer Event: the self path cannot
    // switch it outside the rotation's switch step, and writes nothing.
    let before_reserved = pointer_footprint(&pool, &realm_id).await;
    let reserved = backups
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            commit: tx(
                rotation_pointer.clone(),
                station_successor(&covering, &rotation_pointer, &station_did, 2),
            ),
            queued_at: decided_at,
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(
        reserved.contains("reserved by a SecurityRotation"),
        "{reserved}"
    );
    assert_eq!(pointer_footprint(&pool, &realm_id).await, before_reserved);

    // A, still active, commits an unreserved successor pointer. Its source
    // is the covering Commit; the generation did not move, so it is fresh.
    let free_pointer = author_a.event(
        author_a.record(
            &rotation_series,
            2,
            vec![series_one.clone()],
            &covering.commit_id,
            &authorize_a,
            1,
            author_a.seed,
        ),
        4,
    );
    let pointer_a_commit = station_successor(&covering, &free_pointer, &station_did, 2);
    backups
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            commit: tx(free_pointer, pointer_a_commit.clone()),
            queued_at: decided_at,
        })
        .await
        .unwrap();
    let after = backups
        .confirmed_active_series_for_device(&account, &device_a, decided_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.authority_commit_id, pointer_a_commit.commit_id);
    assert_eq!(
        after.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: rotation_series,
            series_pointer_version: 2,
        }
    );
    // A fresh pool rebuilds the same fold from durable rows only.
    let restarted = Db::connect(Some(&support::contract_database_url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let restarted_status = PgDeviceRevocationStore { pool: restarted };
    assert!(
        restarted_status
            .pcr_device_admission(&account, &device_b, decided_at)
            .await
            .unwrap()
            != arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    assert!(
        restarted_status
            .pcr_device_admission(&account, &device_a, decided_at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
}

/// One `secret_storage` envelope of `series`, signed by `author`'s device key
/// with the device's current authorization, chained after `predecessor`.
#[allow(clippy::too_many_arguments)]
fn signed_backup(
    author: &PointerAuthor,
    device_id: &DeviceId,
    authorize_event_id: &arkret_wire::EventId,
    series: &BackupSeriesId,
    seq: u64,
    predecessor: Option<&arkret_models_crypto::KeyBackup>,
    signing_seed: [u8; 32],
) -> arkret_models_crypto::KeyBackup {
    let backup_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let mut value = page_fixture(
        &backup_id,
        &arkret_wire::ActorId::account(author.account.clone()),
        series.as_str(),
        seq,
        None,
    );
    value["auth_data"]["device_id"] = serde_json::json!(device_id);
    value["auth_data"]["verification_method"] = serde_json::json!(author.method);
    value["auth_data"]["device_authorize_event_id"] = serde_json::json!(authorize_event_id);
    if let Some(previous) = predecessor {
        value["supersedes_id"] = serde_json::json!(previous.backup_id);
        value["supersedes_digest"] = serde_json::json!(arkret_canonical::sha256_digest(
            previous.signing_payload_bytes().unwrap()
        ));
    }
    let mut backup: arkret_models_crypto::KeyBackup = serde_json::from_value(value).unwrap();
    let signature = SigningKey::from_bytes(&signing_seed)
        .sign(&backup.signing_payload_bytes().unwrap())
        .to_bytes();
    backup.auth_data.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(signature)).unwrap();
    backup
}

#[derive(diesel::QueryableByName)]
struct RotationFootprintRow {
    #[diesel(sql_type = BigInt)]
    backups: i64,
    #[diesel(sql_type = BigInt)]
    outcomes: i64,
    #[diesel(sql_type = BigInt)]
    attempts: i64,
}

/// Replacement envelopes stored in `series`, and the step outcome/attempt
/// rows of `transaction_id`.
async fn rotation_footprint(
    pool: &PgPool,
    series: &BackupSeriesId,
    transaction_id: &TransactionId,
) -> (i64, i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let uuid = uuid::Uuid::parse_str(
        transaction_id
            .as_str()
            .strip_prefix("ak:transaction:")
            .unwrap(),
    )
    .unwrap();
    let row = diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM key_backups WHERE series_id=$1) AS backups, \
                (SELECT COUNT(*) FROM security_transaction_step_outcomes WHERE transaction_id=$2) \
                  AS outcomes, \
                (SELECT COUNT(*) FROM security_transaction_step_attempts WHERE transaction_id=$2) \
                  AS attempts",
    )
    .bind::<Text, _>(series.as_str())
    .bind::<Uuid, _>(uuid)
    .get_result::<RotationFootprintRow>(&mut *conn)
    .await
    .unwrap();
    (row.backups, row.outcomes, row.attempts)
}

/// Append the worker's accepted position exactly as the Station does.
fn with_rotation_step(
    record: &SecurityTransactionRecord,
    station: &DidCoreId,
    accepted_at: chrono::DateTime<chrono::Utc>,
    step: SecurityTransactionStep,
) -> (
    SecurityTransactionRecord,
    SecurityTransactionStepOutcomeRecord,
) {
    let mut next = record.clone();
    next.resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
            },
            accepted_at,
        });
    let outcome = SecurityTransactionStepOutcomeRecord {
        transaction_id: next.resource.transaction_id.to_string(),
        step,
        canonical_request: next.canonical_request.clone(),
        response: serde_json::to_value(&next.resource).unwrap(),
        participant_outcome: None,
    };
    (next, outcome)
}

#[tokio::test]
async fn security_rotation_worker_units_and_local_commit_are_atomic() {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef,
    };
    use coland_storage::{
        KeyBackupActiveSeriesCommitOutcome, KeyBackupActiveSeriesCommitWrite,
        RotationPointerSwitchWrite, RotationUploadCommitWrite,
    };

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let realm_id = RealmId::new(fixture.events[0].realm_id.to_string()).unwrap();
    let station_did = fixture.station_did.clone();
    let device_a = fixture.founding_device_id.clone();
    let author_a = PointerAuthor {
        account: account.clone(),
        realm_id: realm_id.clone(),
        method: fixture.device_verification_method.clone(),
        seed: fixture.founding_device_signing_seed,
    };
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&genesis, at)
        .await
        .unwrap();
    let authority = genesis.transactions[1].expected_authority.clone();
    let authorize_a = genesis.transactions[1].event.event_id.clone();
    let status = PgDeviceRevocationStore { pool: pool.clone() };
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let transactions = PgSecurityTransactionStore { pool: pool.clone() };
    let tx =
        |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };

    // Two further devices B and C, both approved by A under generation 1.
    let mut head = genesis.transactions[1].commit.clone();
    let mut install = async |seed: [u8; 32], hpke: [u8; 32]| {
        let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        let payload = device_history_fixture::possession_with(
            &account,
            device_history_fixture::DeviceAuthorizationSpec {
                device_id: device.clone(),
                signing_seed: seed,
                hpke_seed: hpke,
                authorized_by: DeviceOrPrincipalRef::DeviceId(device_a.clone()),
                not_before: at,
                expires_at: None,
                binding: DeviceAuthorizationBindingKind::AcceptedDevice,
                authorized_generation_ref: 1,
                applet_id: None,
            },
        );
        let event = device_history_fixture::sign_event(
            arkret_wire::test_support::raw_event(
                EventKind::DeviceAuthorize.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                account.principal_id.clone(),
                account.station_id.clone(),
                serde_json::to_value(&payload).unwrap(),
            )
            .unwrap(),
            author_a.method.clone(),
            author_a.seed,
        );
        let commit = station_successor(&head, &event, &station_did, 1);
        assert_eq!(
            PgAuthorityCommitStore { pool: pool.clone() }
                .admit_accepted_device_authorization(&tx(event.clone(), commit.clone()), at)
                .await
                .unwrap(),
            AcceptedDeviceAuthorizationOutcome::Committed(commit.clone())
        );
        head = commit;
        device
    };
    let device_b = install([97; 32], [7; 32]).await;
    let device_c = install([98; 32], [8; 32]).await;
    let now = head.committed_at;

    // A selects the first series; it holds one old envelope.
    let series_one =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    let pointer_one = author_a.event(
        author_a.record(
            &series_one,
            1,
            vec![],
            &head.commit_id,
            &authorize_a,
            1,
            author_a.seed,
        ),
        1,
    );
    let pointer_one_commit = station_successor(&head, &pointer_one, &station_did, 1);
    assert!(matches!(
        backups
            .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
                commit: tx(pointer_one, pointer_one_commit.clone()),
                queued_at: now,
            })
            .await
            .unwrap(),
        KeyBackupActiveSeriesCommitOutcome::Committed(_)
    ));
    head = pointer_one_commit;
    let old = signed_backup(
        &author_a,
        &device_a,
        &authorize_a,
        &series_one,
        0,
        None,
        author_a.seed,
    );
    backups
        .put(
            old.backup_id.to_string(),
            serde_json::to_value(&old).unwrap(),
        )
        .await
        .unwrap();

    // Build a rotation that revokes `target` and replaces series_one with a
    // two-envelope series signed by `signing_seed` under A's method.
    let mut nonce = 10;
    let mut rotation = async |target: &DeviceId, signing_seed: [u8; 32]| {
        nonce += 1;
        let revoke = device_history_fixture::sign_event(
            arkret_wire::test_support::raw_event(
                EventKind::DeviceRevoke.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                account.principal_id.clone(),
                account.station_id.clone(),
                serde_json::json!({
                    "device_id": target,
                    "revoked_by": device_a,
                    "revoked_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "reason": "security_rotation"
                }),
            )
            .unwrap(),
            author_a.method.clone(),
            author_a.seed,
        );
        let covering = station_successor(&head, &revoke, &station_did, 1);
        let series =
            BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
        let first = signed_backup(
            &author_a,
            &device_a,
            &authorize_a,
            &series,
            0,
            None,
            signing_seed,
        );
        let second = signed_backup(
            &author_a,
            &device_a,
            &authorize_a,
            &series,
            1,
            Some(&first),
            signing_seed,
        );
        let pointer = author_a.event(
            author_a.record(
                &series,
                2,
                vec![series_one.clone()],
                &covering.commit_id,
                &authorize_a,
                1,
                author_a.seed,
            ),
            nonce,
        );
        let mut envelopes = vec![first, second];
        envelopes.sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
        let refs = envelopes
            .iter()
            .map(|backup| BackupObjectRef {
                backup_id: backup.backup_id.clone(),
                ciphertext_digest: backup.ciphertext_digest.clone(),
            })
            .collect();
        let request = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
            account.clone(),
            device_a.clone(),
            now + chrono::TimeDelta::hours(1),
            PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                arkret_wire::EventsSubmitBatchRequestBody {
                    events: (vec![revoke.clone()])
                        .into_iter()
                        .map(arkret_wire::EventAdmissionSubmission::new)
                        .collect(),
                },
            )
            .unwrap(),
            hash("rotated-secret"),
            vec![BackupRotationPlan {
                binding: BackupRotationBinding {
                    backup_kind: BackupRotationKind::SecretStorage,
                    previous_series_id: series_one.clone(),
                    new_series_id: series.clone(),
                    new_backups: refs,
                    active_series_event_id: pointer.event_id.clone(),
                    old_backups: vec![BackupObjectRef {
                        backup_id: old.backup_id.clone(),
                        ciphertext_digest: old.ciphertext_digest.clone(),
                    }],
                },
                new_backup_envelopes: envelopes,
                active_series_unit: PreparedEventUnit::new(
                    arkret_canonical::DigestSuite::Sha256,
                    arkret_wire::EventsSubmitBatchRequestBody {
                        events: (vec![pointer.clone()])
                            .into_iter()
                            .map(arkret_wire::EventAdmissionSubmission::new)
                            .collect(),
                    },
                )
                .unwrap(),
            }],
        )
        .unwrap();
        let plan = SecurityTransactionPreparedPlan::SecurityRotation(request.prepared_plan.clone());
        let (initial, canonical_request) =
            SecurityTransactionCreateRequest::SecurityRotation(request)
                .into_initial_resource(plan, now)
                .unwrap();
        let record = transactions
            .create(SecurityTransactionRecord {
                resource: initial,
                canonical_request,
            })
            .await
            .unwrap();
        // The revoke proposal and its accepted terminal, as the worker does.
        let mut proposed = record.clone();
        proposed.resource.revoke_proposal = Some(SecurityRotationRevokeProposal {
            proposal_event_id: revoke.event_id.clone(),
            covering_commit_id: covering.commit_id.clone(),
        });
        transactions
            .commit_revoke_proposal(RevokeProposalCommitWrite {
                transaction: proposed.clone(),
                commit: tx(revoke.clone(), covering.clone()),
                queued_at: now,
            })
            .await
            .unwrap();
        let decided_at = covering.committed_at;
        let mut accepted = proposed;
        accepted
            .resource
            .accepted_steps
            .push(AcceptedSecurityTransactionStep {
                acceptor: SecurityTransactionAcceptor::Principal {
                    principal_id: station.clone(),
                },
                accepted_at: decided_at,
            });
        accepted.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
            proposal_event_id: revoke.event_id.clone(),
            covering_commit_id: covering.commit_id.clone(),
            result: SecurityRotationRevokeCommandDecision::Accepted,
            decided_at,
        });
        let decided = transactions
            .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
                step_outcome: Some(SecurityTransactionStepOutcomeRecord {
                    transaction_id: accepted.resource.transaction_id.to_string(),
                    step: SecurityTransactionStep::Revoke,
                    canonical_request: accepted.canonical_request.clone(),
                    response: serde_json::to_value(&accepted.resource).unwrap(),
                    participant_outcome: None,
                }),
                transaction: accepted,
            })
            .await
            .unwrap();
        head = covering.clone();
        (decided, series, pointer, covering)
    };

    // A rotation whose replacement envelopes are not signed by A's key is
    // refused by the upload unit with no envelope, step or attempt written.
    let (forged, forged_series, ..) = rotation(&device_c, [0x66; 32]).await;
    let (forged_next, forged_outcome) = with_rotation_step(
        &forged,
        &station,
        now,
        SecurityTransactionStep::UploadNewMaterial,
    );
    let before = rotation_footprint(&pool, &forged_series, &forged.resource.transaction_id).await;
    let refused = transactions
        .commit_rotation_upload(RotationUploadCommitWrite {
            transaction: forged_next,
            step_outcome: forged_outcome,
        })
        .await
        .unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(coland_storage::ConflictCode::SignatureInvalid),
        "{refused}"
    );
    assert_eq!(
        rotation_footprint(&pool, &forged_series, &forged.resource.transaction_id).await,
        before
    );
    let unchanged = transactions
        .get(forged.resource.transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.resource.accepted_steps.len(), 1);
    // The worker then stops the rotation; its accepted revoke stays.
    let mut aborted = unchanged;
    aborted.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Aborted {
        completed_at: now,
        reason_code: Some("proof_invalid".to_owned()),
    });
    transactions.update(aborted).await.unwrap();

    // The genuine rotation revokes B.
    let (decided, series, pointer, covering) = rotation(&device_b, author_a.seed).await;
    let transaction_id = decided.resource.transaction_id.clone();
    let plan = decided.resource.security_rotation_plan().unwrap().clone();
    assert!(
        status
            .pcr_device_admission(&account, &device_b, covering.committed_at)
            .await
            .unwrap()
            != arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );

    // The generic accepted-step writer cannot stand in for the worker unit.
    let (upload_next, upload_outcome) = with_rotation_step(
        &decided,
        &station,
        covering.committed_at,
        SecurityTransactionStep::UploadNewMaterial,
    );
    assert!(
        transactions
            .accept_step(upload_next.clone(), upload_outcome.clone())
            .await
            .is_err()
    );
    // The switch cannot run before the upload step is accepted.
    let early = station_successor(&covering, &pointer, &station_did, 1);
    let (early_next, early_outcome) = with_rotation_step(
        &decided,
        &station,
        covering.committed_at,
        SecurityTransactionStep::SwitchAuthoritativePointer,
    );
    assert!(
        transactions
            .commit_rotation_pointer_switch(RotationPointerSwitchWrite {
                transaction: early_next,
                step_outcome: early_outcome,
                commit: tx(pointer.clone(), early),
                queued_at: covering.committed_at,
            })
            .await
            .is_err()
    );
    // A reserved id that already holds other bytes refuses the whole upload.
    let reserved_id = &plan.backup_rotations[0].binding.new_backups[0].backup_id;
    let squatter = {
        let mut value = serde_json::to_value(signed_backup(
            &author_a,
            &device_a,
            &authorize_a,
            &BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap(),
            0,
            None,
            author_a.seed,
        ))
        .unwrap();
        value["backup_id"] = serde_json::json!(reserved_id);
        value
    };
    backups
        .put(reserved_id.to_string(), squatter.clone())
        .await
        .unwrap();
    let before = rotation_footprint(&pool, &series, &transaction_id).await;
    let squatted = transactions
        .commit_rotation_upload(RotationUploadCommitWrite {
            transaction: upload_next.clone(),
            step_outcome: upload_outcome.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        squatted.conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict),
        "{squatted}"
    );
    assert_eq!(
        rotation_footprint(&pool, &series, &transaction_id).await,
        before
    );
    assert_eq!(
        backups.get(reserved_id.as_str()).await.unwrap(),
        Some(squatter)
    );
    assert!(backups.delete(reserved_id.as_str()).await.unwrap());

    // Upload: both envelopes and accepted_steps[1] in one write.
    let uploaded = transactions
        .commit_rotation_upload(RotationUploadCommitWrite {
            transaction: upload_next.clone(),
            step_outcome: upload_outcome.clone(),
        })
        .await
        .unwrap();
    assert_eq!(uploaded.resource.accepted_steps.len(), 2);
    assert_eq!(
        rotation_footprint(&pool, &series, &transaction_id).await,
        (2, 2, 2)
    );
    // An exact replay computed later reads the first stored result.
    let (replay_next, replay_outcome) = with_rotation_step(
        &decided,
        &station,
        covering.committed_at + chrono::TimeDelta::seconds(9),
        SecurityTransactionStep::UploadNewMaterial,
    );
    let replayed = transactions
        .commit_rotation_upload(RotationUploadCommitWrite {
            transaction: replay_next,
            step_outcome: replay_outcome,
        })
        .await
        .unwrap();
    assert_eq!(replayed.resource, uploaded.resource);
    assert_eq!(
        rotation_footprint(&pool, &series, &transaction_id).await,
        (2, 2, 2)
    );
    // The pointer still names series_one: nothing switched yet.
    let before_switch = backups
        .confirmed_active_series_for_device(&account, &device_a, covering.committed_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before_switch.authority_commit_id, covering.commit_id);
    assert!(matches!(
        &before_switch.secret_storage,
        BackupActiveSeriesPointer::Active { active_series_id, series_pointer_version: 1 }
            if *active_series_id == series_one
    ));

    // A Commit signed at a stale head is retryable and writes nothing.
    let stale = station_successor(
        &commit_at_position(&pool, &realm_id, 1).await,
        &pointer,
        &station_did,
        3,
    );
    let (stale_next, stale_outcome) = with_rotation_step(
        &uploaded,
        &station,
        covering.committed_at,
        SecurityTransactionStep::SwitchAuthoritativePointer,
    );
    let pointers = pointer_footprint(&pool, &realm_id).await;
    let moved = transactions
        .commit_rotation_pointer_switch(RotationPointerSwitchWrite {
            transaction: stale_next,
            step_outcome: stale_outcome,
            commit: tx(pointer.clone(), stale),
            queued_at: covering.committed_at,
        })
        .await
        .unwrap_err();
    assert_eq!(
        moved.conflict_code(),
        Some(coland_storage::ConflictCode::TemporarilyUnavailable),
        "{moved}"
    );
    assert_eq!(pointer_footprint(&pool, &realm_id).await, pointers);

    // Switch: Event, Commit, pointer v2 and accepted_steps[2] together.
    let switch_commit = station_successor(&covering, &pointer, &station_did, 2);
    let (switch_next, switch_outcome) = with_rotation_step(
        &uploaded,
        &station,
        switch_commit.committed_at,
        SecurityTransactionStep::SwitchAuthoritativePointer,
    );
    let switched = transactions
        .commit_rotation_pointer_switch(RotationPointerSwitchWrite {
            transaction: switch_next.clone(),
            step_outcome: switch_outcome.clone(),
            commit: tx(pointer.clone(), switch_commit.clone()),
            queued_at: switch_commit.committed_at,
        })
        .await
        .unwrap();
    assert_eq!(switched.resource.accepted_steps.len(), 3);
    assert_eq!(
        switched.resource.accepted_steps[2].accepted_at,
        switch_commit.committed_at
    );
    let (events, commits, pointer_rows) = pointers;
    assert_eq!(
        pointer_footprint(&pool, &realm_id).await,
        (events + 1, commits + 1, pointer_rows)
    );
    let after = backups
        .confirmed_active_series_for_device(&account, &device_a, switch_commit.committed_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.authority_commit_id, switch_commit.commit_id);
    assert_eq!(
        after.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: series.clone(),
            series_pointer_version: 2,
        }
    );
    // Exact replay of the switch returns the first result and adds nothing.
    let replayed = transactions
        .commit_rotation_pointer_switch(RotationPointerSwitchWrite {
            transaction: switch_next,
            step_outcome: switch_outcome,
            commit: tx(pointer, switch_commit),
            queued_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    assert_eq!(replayed.resource, switched.resource);
    assert_eq!(
        pointer_footprint(&pool, &realm_id).await,
        (events + 1, commits + 1, pointer_rows)
    );
    assert_eq!(
        transactions
            .get(transaction_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .resource
            .next_required_step()
            .unwrap(),
        Some(SecurityTransactionStep::EraseOldMaterial)
    );

    // Erase, as the worker accepts it once the old series is gone.
    let switched_record = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let erase_request = coland_storage::BackupSeriesEraseWorkerRequest {
        transaction_id: transaction_id.clone(),
        transaction_request_digest: switched_record.resource.request_digest.clone(),
        prepared_plan_digest: switched_record.resource.prepared_plan_digest.clone(),
        erase_confirmation_digest: plan.erase_confirmation_digest.clone(),
        series: vec![plan.backup_rotations[0].binding.clone()],
        authority_commit_id: after.authority_commit_id.clone(),
    };
    let erase_bytes = arkret_canonical::canonical_json_bytes(&erase_request).unwrap();
    let erase_progress = coland_storage::BackupSeriesEraseProgressRecord {
        transaction_id: transaction_id.to_string(),
        canonical_request: erase_bytes.clone(),
        outcome: coland_storage::BackupSeriesEraseOutcome {
            transaction_id: transaction_id.clone(),
            request_digest: Hash::new(arkret_canonical::canonical_sha256(&erase_request).unwrap())
                .unwrap(),
            status: coland_storage::BackupSeriesEraseStatus::Partial,
            series_records: vec![coland_storage::BackupSeriesEraseRow {
                backup_kind: BackupRotationKind::SecretStorage,
                previous_series_id: series_one.clone(),
                new_series_id: series.clone(),
                status: coland_storage::BackupSeriesEraseRowStatus::Pending,
                erased_backups: vec![],
                remaining_backups: erase_request.series[0].old_backups.clone(),
                reason_code: None,
            }],
            confirmation: None,
        },
    };
    let persisted = transactions
        .begin_backup_erase(erase_progress.clone())
        .await
        .unwrap();
    assert_eq!(persisted.outcome, erase_progress.outcome);
    let reloaded = transactions
        .backup_erase_progress(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.canonical_request, erase_progress.canonical_request);
    assert_eq!(reloaded.outcome, erase_progress.outcome);
    assert_eq!(
        transactions
            .update_backup_erase(reloaded.clone())
            .await
            .unwrap()
            .outcome,
        reloaded.outcome
    );
    assert_eq!(
        transactions
            .begin_backup_erase(erase_progress)
            .await
            .unwrap()
            .outcome,
        reloaded.outcome
    );
    transactions
        .begin_step(coland_storage::SecurityTransactionStepAttemptRecord {
            transaction_id: transaction_id.to_string(),
            step: SecurityTransactionStep::EraseOldMaterial,
            canonical_request: erase_bytes.clone(),
        })
        .await
        .unwrap();
    let mut erased = switched_record.clone();
    erased
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: station.clone(),
            },
            accepted_at: switched_record.resource.accepted_steps[2].accepted_at
                + chrono::TimeDelta::seconds(1),
        });
    transactions
        .accept_step(
            erased.clone(),
            SecurityTransactionStepOutcomeRecord {
                transaction_id: transaction_id.to_string(),
                step: SecurityTransactionStep::EraseOldMaterial,
                canonical_request: erase_bytes,
                response: serde_json::to_value(&erased.resource).unwrap(),
                participant_outcome: None,
            },
        )
        .await
        .unwrap();
    let erased = transactions
        .get(transaction_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        erased.resource.next_required_step().unwrap(),
        Some(SecurityTransactionStep::LocalCommit)
    );

    // local_commit: the attestation is verified only against the attesting
    // device's current accepted PCR authorization key, under a DID URL of the
    // Account's principal DID whose fragment is exactly that device.
    let (did, _) = author_a.method.as_str().rsplit_once('#').unwrap();
    let method_of = |device: &DeviceId| DidUrl::new(format!("{did}#{device}")).unwrap();
    let local_commit = |device: &DeviceId,
                        method: DidUrl,
                        seed: [u8; 32],
                        committed_at: chrono::DateTime<chrono::Utc>| {
        let artifact = arkret_models_crypto::SecurityRotationLocalCommit {
            schema: arkret_wire::SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1.to_owned(),
            transaction_id: transaction_id.clone(),
            transaction_request_digest: erased.resource.request_digest.clone(),
            prepared_plan_digest: erased.resource.prepared_plan_digest.clone(),
            local_commit_digest: plan.local_commit_digest.clone(),
            device_id: device.clone(),
            committed_at,
        };
        let mut attestation = arkret_models_crypto::ClientStepAttestation {
            step: SecurityTransactionStep::LocalCommit,
            output_ref: plan.local_commit_digest.to_string(),
            transaction_id: transaction_id.clone(),
            transaction_request_digest: erased.resource.request_digest.clone(),
            prepared_plan_digest: erased.resource.prepared_plan_digest.clone(),
            artifact: arkret_models_crypto::ClientStepAttestationArtifact::SecurityRotation(
                artifact.clone(),
            ),
            auth_data: arkret_models_crypto::ClientStepAttestationAuthData {
                verification_method: method,
                signature_algorithm: "Ed25519".to_owned(),
                signature: arkret_wire::Base64UrlString::new("AA").unwrap(),
            },
        };
        let signature = SigningKey::from_bytes(&seed)
            .sign(&attestation.signing_bytes().unwrap())
            .to_bytes();
        attestation.auth_data.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(signature))
                .unwrap();
        let mut next = erased.clone();
        next.resource
            .accepted_steps
            .push(AcceptedSecurityTransactionStep {
                acceptor: SecurityTransactionAcceptor::Principal {
                    principal_id: station.clone(),
                },
                accepted_at: committed_at,
            });
        next.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Completed {
            completed_at: committed_at,
            receipt_id: None,
            completion_attestation: None,
        });
        let continue_request = arkret_models_crypto::SecurityTransactionContinueRequest {
            request_digest: erased.resource.request_digest.clone(),
            prepared_plan_digest: erased.resource.prepared_plan_digest.clone(),
            expected_accepted_step_count: 4,
            client_attestation: attestation.clone(),
        };
        coland_storage::RotationLocalCommitWrite {
            step_outcome: SecurityTransactionStepOutcomeRecord {
                transaction_id: transaction_id.to_string(),
                step: SecurityTransactionStep::LocalCommit,
                canonical_request: arkret_canonical::canonical_json_bytes(&continue_request)
                    .unwrap(),
                response: serde_json::to_value(&next.resource).unwrap(),
                participant_outcome: Some(serde_json::to_value(&artifact).unwrap()),
            },
            transaction: next,
            attestation,
        }
    };
    let committed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let footprint = rotation_footprint(&pool, &series, &transaction_id).await;
    let refused_with = async |write: coland_storage::RotationLocalCommitWrite| {
        let error = transactions
            .commit_rotation_local_commit(write)
            .await
            .unwrap_err();
        let unchanged = transactions
            .get(transaction_id.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.resource, erased.resource, "{error}");
        error.conflict_code()
    };
    // The generic accepted-step writer cannot accept a local commit.
    let genuine = local_commit(&device_a, method_of(&device_a), author_a.seed, committed_at);
    assert!(
        transactions
            .accept_step(genuine.transaction.clone(), genuine.step_outcome.clone())
            .await
            .is_err()
    );
    // A key that is not the device's accepted authorization key.
    assert_eq!(
        refused_with(local_commit(
            &device_a,
            method_of(&device_a),
            [0x66; 32],
            committed_at
        ))
        .await,
        Some(coland_storage::ConflictCode::SignatureInvalid)
    );
    // A method naming another device, or not a DID of this principal.
    assert_eq!(
        refused_with(local_commit(
            &device_a,
            method_of(&device_c),
            author_a.seed,
            committed_at
        ))
        .await,
        Some(coland_storage::ConflictCode::SignatureInvalid)
    );
    assert_eq!(
        refused_with(local_commit(
            &device_a,
            DidUrl::new(format!("did:web:other.example#{device_a}")).unwrap(),
            author_a.seed,
            committed_at
        ))
        .await,
        Some(coland_storage::ConflictCode::SignatureInvalid)
    );
    // The revoked device B, even with its own authorized key and method.
    assert_eq!(
        refused_with(local_commit(
            &device_b,
            method_of(&device_b),
            [97; 32],
            committed_at
        ))
        .await,
        Some(coland_storage::ConflictCode::DeviceRevoked)
    );
    assert_eq!(
        rotation_footprint(&pool, &series, &transaction_id).await,
        footprint
    );

    // The genuine local commit completes the rotation in one write.
    let completed = transactions
        .commit_rotation_local_commit(genuine.clone())
        .await
        .unwrap();
    assert_eq!(completed.resource, genuine.transaction.resource);
    assert!(matches!(
        completed.resource.terminal_outcome,
        Some(SecurityTransactionTerminalOutcome::Completed { .. })
    ));
    let (backups_n, outcomes, attempts) = footprint;
    assert_eq!(
        rotation_footprint(&pool, &series, &transaction_id).await,
        (backups_n, outcomes + 1, attempts + 1)
    );
    // Exact replay reads the first result; other bytes are a conflict.
    assert_eq!(
        transactions
            .commit_rotation_local_commit(genuine)
            .await
            .unwrap()
            .resource,
        completed.resource
    );
    let other = local_commit(
        &device_a,
        method_of(&device_a),
        author_a.seed,
        committed_at + chrono::TimeDelta::seconds(1),
    );
    assert_eq!(
        transactions
            .commit_rotation_local_commit(other)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    assert_eq!(
        transactions
            .get(transaction_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .resource,
        completed.resource
    );
}

/// The PCR Commit at `position`, read back from durable rows.
async fn commit_at_position(
    pool: &PgPool,
    realm_id: &RealmId,
    position: i64,
) -> arkret_wire::RealmCommit {
    #[derive(diesel::QueryableByName)]
    struct CommitRow {
        #[diesel(sql_type = Jsonb)]
        commit_json: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT commit_json FROM realm_commits WHERE realm_id=$1 AND stream_position=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<BigInt, _>(position)
    .get_result::<CommitRow>(&mut *conn)
    .await
    .unwrap();
    serde_json::from_value(row.commit_json).unwrap()
}

#[derive(Debug, PartialEq, Eq, diesel::QueryableByName)]
struct PolicyFootprint {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    policies: i64,
    #[diesel(sql_type = BigInt)]
    policy_currents: i64,
}

async fn policy_footprint(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &arkret_wire::AccountId,
) -> PolicyFootprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS events, \
                (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS commits, \
                (SELECT COUNT(*) FROM recovery_policies WHERE principal_id=$2 AND station_id=$3) \
                  AS policies, \
                (SELECT COUNT(*) FROM policy_current_results WHERE realm_id=$1) \
                  AS policy_currents",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<PolicyFootprint>(&mut *conn)
    .await
    .unwrap()
}

/// One `ak.policy.set` recovery policy Event whose policy and producer proof
/// are both signed with `seed` under `method`.
#[allow(clippy::too_many_arguments)]
fn recovery_policy_event(
    account: &arkret_wire::AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    policy_id: &str,
    version: u64,
    supersedes: Option<&str>,
    quorum: &[&DeviceId],
) -> arkret_wire::Event {
    let mut policy: arkret_models_crypto::RecoveryPolicy =
        serde_json::from_value(serde_json::json!({
            "schema": "ak.schema.recovery_policy.v1",
            "policy_id": policy_id,
            "account_id": account,
            "version": version,
            "supersedes_id": supersedes,
            "trust_domain": "ak:trust_domain:station.example",
            "issued_at": "2026-09-25T00:00:00.000Z",
            "auth_data": {
                "verification_method": method,
                "signature_algorithm": "Ed25519",
                "signature": "AA"
            },
            "methods": [{"kind": "device_quorum", "k": 2, "member_ids": quorum}]
        }))
        .unwrap();
    let transcript =
        arkret_models_crypto::recovery_policy_signature_transcript_bytes(&policy).unwrap();
    policy.auth_data.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            SigningKey::from_bytes(&seed).sign(&transcript).to_bytes(),
        ))
        .unwrap();
    let payload = serde_json::json!({"policy_id": policy_id, "value": policy});
    device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::PolicySet.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            payload,
        )
        .unwrap(),
        method.clone(),
        seed,
    )
}

#[tokio::test]
async fn recovery_policy_publication_unit_ratchets_under_the_pcr_cut() {
    use coland_storage::{
        RecoveryPolicyPublicationOutcome, RecoveryPolicyPublicationWrite, RecoveryPolicyStore,
    };

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let realm_id = RealmId::new(fixture.events[0].realm_id.to_string()).unwrap();
    let did = fixture.did.clone();
    let station_did = fixture.station_did.clone();
    let device_a = fixture.founding_device_id.clone();
    let method_a = fixture.device_verification_method.clone();
    let seed_a = fixture.founding_device_signing_seed;
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store.admit_pcr_genesis_unit(&genesis, at).await.unwrap();
    let authority = genesis.transactions[1].expected_authority.clone();
    let tx =
        |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
    // A second device D, accepted by the founding device.
    let seed_d = [51; 32];
    let (device_d, approve_d) = accepted_device_event(
        &account, &account, &realm_id, &device_a, &method_a, seed_a, seed_d, at, 1,
    );
    let head = station_successor(&genesis.transactions[1].commit, &approve_d, &station_did, 1);
    store
        .admit_accepted_device_authorization(&tx(approve_d, head.clone()), at)
        .await
        .unwrap();
    let method_d = DidUrl::new(format!("{did}#{device_d}")).unwrap();
    let policies = coland_storage_postgres::PgRecoveryPolicyStore { pool: pool.clone() };
    let publish = async |event: &arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        policies
            .commit_publication(RecoveryPolicyPublicationWrite {
                commit: tx(event.clone(), commit),
                queued_at: at,
            })
            .await
    };
    let before = policy_footprint(&pool, &realm_id, &account).await;
    let refusal = async |event: &arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        let error = publish(event, commit).await.unwrap_err();
        assert_eq!(
            policy_footprint(&pool, &realm_id, &account).await,
            before,
            "a refused recovery policy publication must write nothing"
        );
        error.conflict_code()
    };
    let genesis_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let members = [&device_a, &device_d];

    // Only the founding device may sign the genesis policy.
    let by_d = recovery_policy_event(
        &account,
        &realm_id,
        &method_d,
        seed_d,
        &genesis_id,
        1,
        None,
        &members,
    );
    assert_eq!(
        refusal(&by_d, station_successor(&head, &by_d, &station_did, 1)).await,
        Some(ConflictCode::DeviceUnauthorized)
    );
    // The first policy of an account is version 1.
    let late = recovery_policy_event(
        &account,
        &realm_id,
        &method_a,
        seed_a,
        &genesis_id,
        2,
        Some(&format!("ak:policy:{}", uuid::Uuid::now_v7())),
        &members,
    );
    assert_eq!(
        refusal(&late, station_successor(&head, &late, &station_did, 1)).await,
        Some(ConflictCode::RecoveryPolicyGenesisNotV1)
    );
    // A quorum member that is not an active device leaves k unreachable.
    let unknown = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let unreachable = recovery_policy_event(
        &account,
        &realm_id,
        &method_a,
        seed_a,
        &genesis_id,
        1,
        None,
        &[&device_a, &unknown],
    );
    assert_eq!(
        refusal(
            &unreachable,
            station_successor(&head, &unreachable, &station_did, 1)
        )
        .await,
        Some(ConflictCode::FailedPrecondition)
    );
    // A's method, but the policy and proof are signed with another key.
    let forged = recovery_policy_event(
        &account,
        &realm_id,
        &method_a,
        [0x77; 32],
        &genesis_id,
        1,
        None,
        &members,
    );
    assert_eq!(
        refusal(&forged, station_successor(&head, &forged, &station_did, 1)).await,
        Some(ConflictCode::SignatureInvalid)
    );
    // The generic Event path cannot commit recovery policy control state.
    let v1 = recovery_policy_event(
        &account,
        &realm_id,
        &method_a,
        seed_a,
        &genesis_id,
        1,
        None,
        &members,
    );
    let commit_v1 = station_successor(&head, &v1, &station_did, 1);
    assert!(
        store
            .admit_event_transaction(&tx(v1.clone(), commit_v1.clone()), at)
            .await
            .is_err()
    );
    assert_eq!(policy_footprint(&pool, &realm_id, &account).await, before);

    // Imported current-row collision tests the recovery writer's family guard;
    // it does not model an admitted Agent management Policy.
    {
        use diesel::sql_types::Text;
        use diesel_async::RunQueryDsl;
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO policy_current_results(realm_id,policy_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) VALUES($1,$2,$3,0,'imported-agent-policy','{\"schema\":\"ak.schema.policy.v1\",\"policy_kind\":\"agent\"}',now())")
            .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(&genesis_id)
            .bind::<Text,_>(head.commit_id.as_str()).execute(&mut conn).await.unwrap();
        let collision = policy_footprint(&pool, &realm_id, &account).await;
        let error = publish(&v1, commit_v1.clone()).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(ConflictCode::FailedPrecondition)
        );
        assert_eq!(
            policy_footprint(&pool, &realm_id, &account).await,
            collision
        );
        diesel::sql_query("DELETE FROM policy_current_results WHERE policy_id=$1")
            .bind::<Text, _>(&genesis_id)
            .execute(&mut conn)
            .await
            .unwrap();
        assert_eq!(policy_footprint(&pool, &realm_id, &account).await, before);
    }

    // The founding device publishes v1: Event, Commit and policy together.
    let RecoveryPolicyPublicationOutcome::Committed(accepted) =
        publish(&v1, commit_v1.clone()).await.unwrap()
    else {
        panic!("the first publication commits");
    };
    assert_eq!(accepted.acceptance_basis, commit_v1.commit_id);
    assert_eq!(accepted.version, 1);
    let after_v1 = policy_footprint(&pool, &realm_id, &account).await;
    assert_eq!(
        after_v1,
        PolicyFootprint {
            events: before.events + 1,
            commits: before.commits + 1,
            policies: before.policies + 1,
            policy_currents: before.policy_currents + 1,
        }
    );
    // An exact retry returns the accepted policy without a second write.
    let RecoveryPolicyPublicationOutcome::Duplicate(replayed) =
        publish(&v1, station_successor(&commit_v1, &v1, &station_did, 3))
            .await
            .unwrap()
    else {
        panic!("an exact retry is a duplicate");
    };
    assert_eq!(replayed.acceptance_basis, commit_v1.commit_id);
    assert_eq!(policy_footprint(&pool, &realm_id, &account).await, after_v1);

    // A successor must name v1 and advance its version.
    let v2_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let stale = recovery_policy_event(
        &account,
        &realm_id,
        &method_d,
        seed_d,
        &v2_id,
        2,
        Some(&format!("ak:policy:{}", uuid::Uuid::now_v7())),
        &members,
    );
    let error = publish(
        &stale,
        station_successor(&commit_v1, &stale, &station_did, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(ConflictCode::RecoveryPolicySupersedesInvalid)
    );
    // A current-generation device other than the founder may rotate it.
    let v2 = recovery_policy_event(
        &account,
        &realm_id,
        &method_d,
        seed_d,
        &v2_id,
        2,
        Some(&genesis_id),
        &members,
    );
    let commit_v2 = station_successor(&commit_v1, &v2, &station_did, 1);
    assert!(matches!(
        publish(&v2, commit_v2.clone()).await.unwrap(),
        RecoveryPolicyPublicationOutcome::Committed(_)
    ));
    let active = policies
        .get_active_for_account(&account)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.policy_id, v2_id);
    assert_eq!(active.acceptance_basis, commit_v2.commit_id);
    let after_v2 = policy_footprint(&pool, &realm_id, &account).await;
    assert_eq!(after_v2.events, before.events + 2);
    assert_eq!(after_v2.commits, before.commits + 2);
    assert_eq!(after_v2.policies, before.policies + 2);
    assert_eq!(after_v2.policy_currents, before.policy_currents + 2);
    let material = store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .expect("PCR snapshot material");
    let current = material
        .current_state_entries
        .iter()
        .find(|entry| {
            matches!(
                entry,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::Policy { policy_id },
                    ..
                } if policy_id.as_str() == v2_id
            )
        })
        .expect("recovery policy is materialized as registered policy current");
    let arkret_wire::TypedCurrentRow::Value {
        revision,
        source_stream_ref,
        value,
        ..
    } = current;
    assert_eq!(revision.commit_id, commit_v2.commit_id);
    assert_eq!(revision.stream_position, commit_v2.stream_position);
    assert_eq!(source_stream_ref, &commit_v2.stream_ref);
    assert_eq!(value, &active.raw_payload);
    // The PCR conflict-index marker followed both Commits: device status is
    // still readable at the new head.
    assert!(
        PgDeviceRevocationStore { pool: pool.clone() }
            .pcr_device_admission(&account, &device_a, commit_v2.committed_at)
            .await
            .unwrap()
            == arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
}

#[derive(Debug, PartialEq, Eq, diesel::QueryableByName)]
struct ProfileFootprint {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    profiles: i64,
    #[diesel(sql_type = BigInt)]
    versions: i64,
    #[diesel(sql_type = BigInt)]
    endorsements: i64,
}

/// Every durable row a profile or accountability admission can write for
/// these Realms.
async fn profile_footprint(pool: &PgPool, realms: &[&RealmId]) -> ProfileFootprint {
    let realms = realms
        .iter()
        .map(|realm| realm.as_str().to_owned())
        .collect::<Vec<_>>();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=ANY($1)) AS events, \
                (SELECT COUNT(*) FROM realm_commits WHERE realm_id=ANY($1)) AS commits, \
                (SELECT COUNT(*) FROM actor_profile_current_results WHERE realm_id=ANY($1)) \
                  AS profiles, \
                (SELECT COUNT(*) FROM actor_profile_result_versions v \
                   JOIN realm_commits c ON c.commit_id=v.commit_id \
                  WHERE c.realm_id=ANY($1)) AS versions, \
                (SELECT COUNT(*) FROM identity_accountability_current_results \
                  WHERE realm_id=ANY($1)) AS endorsements",
    )
    .bind::<diesel::sql_types::Array<Text>, _>(realms)
    .get_result::<ProfileFootprint>(&mut *conn)
    .await
    .unwrap()
}

/// One device-signed profile Event of `account` in its PCR.
fn profile_event(
    account: &arkret_wire::AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    kind: EventKind,
    payload: serde_json::Value,
) -> arkret_wire::Event {
    device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            kind.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            payload,
        )
        .unwrap(),
        method.clone(),
        seed,
    )
}

/// One issuer-signed accountability grant whose inner proof is a compact
/// detached JWS by `proof_seed` over the registered binding transcript.
#[allow(clippy::too_many_arguments)]
fn accountability_grant_event(
    issuer: &arkret_wire::AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    proof_seed: [u8; 32],
    subject: &DidCoreId,
    scope: serde_json::Value,
    status: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> arkret_wire::Event {
    use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
    let mut value = serde_json::json!({
        "schema": "ak.schema.accountability_grant.v1",
        "issuer_id": issuer.principal_id,
        "subject_id": subject,
        "accountability_scope": scope,
        "not_before": arkret_canonical::format_timestamp_canonical(not_before),
        "grant_status": status,
        "proof": {
            "kind": "detached_jws",
            "verification_method": method,
            "payload_digest": format!("sha256:{}", "0".repeat(64)),
            "created_at": arkret_canonical::format_timestamp_canonical(not_before),
            "jws": ""
        }
    });
    if let Some(expires_at) = expires_at {
        value["expires_at"] =
            serde_json::json!(arkret_canonical::format_timestamp_canonical(expires_at));
    }
    let mut grant: AccountabilityGrantPayload = serde_json::from_value(value).unwrap();
    grant.proof.payload_digest = grant.payload_digest().unwrap();
    grant.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &SigningKey::from_bytes(&proof_seed),
        &grant.canonical_proof_binding_bytes().unwrap(),
    )
    .unwrap();
    device_history_fixture::sign_event(
        arkret_wire::test_support::raw_event(
            EventKind::IdentityAccountabilityGrant.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            issuer.principal_id.clone(),
            issuer.station_id.clone(),
            serde_json::to_value(&grant).unwrap(),
        )
        .unwrap(),
        method.clone(),
        seed,
    )
}

#[tokio::test]
async fn profile_update_commits_actor_profile_current_and_rejects_forbidden_patch() {
    use coland_storage::{
        ActorProfileAdmissionOutcome, ActorProfileAdmissionWrite, ActorProfileStore,
    };

    let (pool, station) = contract_store().await;
    let fixture = fixture(&station);
    let account = fixture.account.clone();
    let realm_id = RealmId::new(fixture.events[0].realm_id.to_string()).unwrap();
    let station_did = fixture.station_did.clone();
    let method = fixture.device_verification_method.clone();
    let seed = fixture.founding_device_signing_seed;
    let genesis = assemble(station.clone(), fixture);
    let at = genesis.transactions[1].commit.committed_at;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store.admit_pcr_genesis_unit(&genesis, at).await.unwrap();
    let authority = genesis.transactions[1].expected_authority.clone();
    let head = genesis.transactions[1].commit.clone();
    let tx =
        |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let admit = async |event: &arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        profiles
            .admit_profile(ActorProfileAdmissionWrite {
                commit: tx(event.clone(), commit),
                queued_at: at,
            })
            .await
    };

    let create = profile_event(
        &account,
        &realm_id,
        &method,
        seed,
        EventKind::ProfileCreate,
        serde_json::json!({"object": {
            "principal_id": account.principal_id,
            "actor_kind": "user",
            "display_name": "Alice",
            "profile_fields": {"bio": "first"}
        }}),
    );
    // The generic Event path cannot commit profile state.
    let create_commit = station_successor(&head, &create, &station_did, 1);
    assert!(
        store
            .admit_event_transaction(&tx(create.clone(), create_commit.clone()), at)
            .await
            .is_err()
    );
    let empty = profile_footprint(&pool, &[&realm_id]).await;
    let ActorProfileAdmissionOutcome::Committed(created) =
        admit(&create, create_commit.clone()).await.unwrap()
    else {
        panic!("the first profile Event commits");
    };
    let profile_id = arkret_wire::ActorProfileId::from_event_id(&create.event_id);
    assert_eq!(created.profile.id.as_ref(), Some(&profile_id));
    assert_eq!(created.profile.realm_id.as_ref(), Some(&realm_id));
    assert_eq!(created.commit, create_commit);
    assert_eq!(
        profiles
            .current_profile(&account)
            .await
            .unwrap()
            .unwrap()
            .profile,
        created.profile
    );
    let after_create = profile_footprint(&pool, &[&realm_id]).await;
    assert_eq!(
        after_create,
        ProfileFootprint {
            events: empty.events + 1,
            commits: empty.commits + 1,
            profiles: 1,
            versions: 1,
            endorsements: 0,
        }
    );
    // Exact replay returns the stored outcome and writes nothing.
    let ActorProfileAdmissionOutcome::Duplicate(replayed) = admit(
        &create,
        station_successor(&create_commit, &create, &station_did, 2),
    )
    .await
    .unwrap() else {
        panic!("an exact retry is a duplicate");
    };
    assert_eq!(replayed.commit, create_commit);
    assert_eq!(profile_footprint(&pool, &[&realm_id]).await, after_create);

    let refusal = async |event: &arkret_wire::Event| {
        let error = admit(
            event,
            station_successor(&create_commit, event, &station_did, 1),
        )
        .await
        .unwrap_err();
        assert_eq!(
            profile_footprint(&pool, &[&realm_id]).await,
            after_create,
            "a refused profile Event must write nothing"
        );
        error.conflict_code()
    };
    let update = |payload: serde_json::Value| {
        profile_event(
            &account,
            &realm_id,
            &method,
            seed,
            EventKind::ProfileUpdate,
            payload,
        )
    };
    // A second create against the PCR's accepted lineage.
    let second = profile_event(
        &account,
        &realm_id,
        &method,
        seed,
        EventKind::ProfileCreate,
        serde_json::json!({"object": {
            "principal_id": account.principal_id,
            "actor_kind": "user",
            "display_name": "Alice again"
        }}),
    );
    assert_eq!(
        refusal(&second).await,
        Some(ConflictCode::FailedPrecondition)
    );
    // target_ref that is not the accepted create-derived id.
    let foreign = update(serde_json::json!({
        "target_ref": arkret_wire::ActorProfileId::from_event_id(&second.event_id),
        "patch": {"display_name": "Mallory"}
    }));
    assert_eq!(
        refusal(&foreign).await,
        Some(ConflictCode::FailedPrecondition)
    );
    // Create-locked and reducer-managed patch paths.
    for patch in [
        serde_json::json!({"principal_id": "ak:did_core:web:mallory.example"}),
        serde_json::json!({"actor_kind": "agent"}),
        serde_json::json!({"resolution.did": "did:web:mallory.example"}),
        serde_json::json!({"created_at": "2026-01-01T00:00:00.000Z"}),
    ] {
        let forbidden = update(serde_json::json!({"target_ref": profile_id, "patch": patch}));
        assert_eq!(
            refusal(&forbidden).await,
            Some(ConflictCode::SchemaViolation),
            "{patch}"
        );
    }
    // A stale expected_state_digest.
    let stale = update(serde_json::json!({
        "target_ref": profile_id,
        "patch": {"display_name": "Alice C."},
        "expected_state_digest": format!("sha256:{}", "0".repeat(64))
    }));
    assert_eq!(
        refusal(&stale).await,
        Some(ConflictCode::FailedPrecondition)
    );

    // A guarded delta commits with its derived update members.
    let digest =
        arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload::state_digest(
            &created.profile,
        )
        .unwrap();
    let delta = update(serde_json::json!({
        "target_ref": profile_id,
        "patch": {"display_name": "Alice C.", "profile_fields.bio": {"$op": "unset"}},
        "expected_state_digest": digest
    }));
    let delta_commit = station_successor(&create_commit, &delta, &station_did, 1);
    let ActorProfileAdmissionOutcome::Committed(updated) =
        admit(&delta, delta_commit.clone()).await.unwrap()
    else {
        panic!("the guarded update commits");
    };
    assert_eq!(updated.profile.display_name, "Alice C.");
    assert!(updated.profile.profile_fields.is_empty());
    assert_eq!(updated.profile.updated_by.as_ref(), Some(&delta.actor_id));
    assert_eq!(updated.profile.created_at, created.profile.created_at);
    let current = profiles.current_profile(&account).await.unwrap().unwrap();
    assert_eq!(current.profile, updated.profile);
    assert_eq!(current.event.event_id, delta.event_id);
    assert_eq!(current.commit, delta_commit);
    // Replaying the older create still answers with what that Event produced.
    let ActorProfileAdmissionOutcome::Duplicate(old) = admit(
        &create,
        station_successor(&delta_commit, &create, &station_did, 1),
    )
    .await
    .unwrap() else {
        panic!("an exact retry of the create is a duplicate");
    };
    assert_eq!(old.profile, created.profile);
}

#[tokio::test]
async fn profile_accountability_requires_active_grant_at_commit_cut() {
    use coland_storage::{
        AccountabilityGrantAdmissionOutcome, AccountabilityGrantAdmissionWrite,
        ActorProfileAdmissionOutcome, ActorProfileAdmissionWrite, ActorProfileStore,
    };

    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let admit_genesis = async |fixture: DeviceHistoryFixture| {
        let genesis = assemble(station.clone(), fixture);
        store
            .admit_pcr_genesis_unit(&genesis, genesis.transactions[1].commit.committed_at)
            .await
            .unwrap();
        genesis
    };
    let issuer_fixture = fixture(&station);
    let issuer = issuer_fixture.account.clone();
    let issuer_realm = RealmId::new(issuer_fixture.events[0].realm_id.to_string()).unwrap();
    let issuer_method = issuer_fixture.device_verification_method.clone();
    let issuer_seed = issuer_fixture.founding_device_signing_seed;
    let station_did = issuer_fixture.station_did.clone();
    let issuer_genesis = admit_genesis(issuer_fixture).await;
    let subject_fixture = fixture(&station);
    let subject = subject_fixture.account.clone();
    let subject_realm = RealmId::new(subject_fixture.events[0].realm_id.to_string()).unwrap();
    let subject_method = subject_fixture.device_verification_method.clone();
    let subject_seed = subject_fixture.founding_device_signing_seed;
    let subject_genesis = admit_genesis(subject_fixture).await;

    let tx = |authority: &coland_storage::CurrentRealmAuthority,
              event: arkret_wire::Event,
              commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        event,
        commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    };
    let issuer_authority = issuer_genesis.transactions[1].expected_authority.clone();
    let subject_authority = subject_genesis.transactions[1].expected_authority.clone();
    let issuer_head = issuer_genesis.transactions[1].commit.clone();
    let subject_head = subject_genesis.transactions[1].commit.clone();
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let admit_profile = async |event: &arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        profiles
            .admit_profile(ActorProfileAdmissionWrite {
                commit: tx(&subject_authority, event.clone(), commit.clone()),
                queued_at: commit.committed_at,
            })
            .await
    };
    let admit_grant = async |event: &arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        profiles
            .admit_accountability_grant(AccountabilityGrantAdmissionWrite {
                commit: tx(&issuer_authority, event.clone(), commit.clone()),
                queued_at: commit.committed_at,
            })
            .await
    };
    let realms = [&issuer_realm, &subject_realm];
    // The profile's Commit instant is subject_head + 60s unless stated.
    let t0 = subject_head.committed_at;
    let expires_at = t0 + chrono::TimeDelta::seconds(120);
    let accountable_create = profile_event(
        &subject,
        &subject_realm,
        &subject_method,
        subject_seed,
        EventKind::ProfileCreate,
        serde_json::json!({"object": {
            "principal_id": subject.principal_id,
            "actor_kind": "service",
            "display_name": "Endorsed service",
            "accountable_principal_ids": [issuer.principal_id]
        }}),
    );

    // No committed record: the whole Event is refused with zero writes.
    let before = profile_footprint(&pool, &realms).await;
    let missing = admit_profile(
        &accountable_create,
        station_successor(&subject_head, &accountable_create, &station_did, 60),
    )
    .await
    .unwrap_err();
    assert_eq!(
        missing.conflict_code(),
        Some(ConflictCode::AccountabilityGrantMissing)
    );
    assert_eq!(profile_footprint(&pool, &realms).await, before);

    // An inner proof by a key other than the issuer's active device fails.
    let forged = accountability_grant_event(
        &issuer,
        &issuer_realm,
        &issuer_method,
        issuer_seed,
        [0x5a; 32],
        &subject.principal_id,
        serde_json::json!("employment"),
        "active",
        t0 - chrono::TimeDelta::days(1),
        Some(expires_at),
    );
    assert_eq!(
        admit_grant(
            &forged,
            station_successor(&issuer_head, &forged, &station_did, 1)
        )
        .await
        .unwrap_err()
        .conflict_code(),
        Some(ConflictCode::SignatureInvalid)
    );
    assert_eq!(profile_footprint(&pool, &realms).await, before);

    // The issuer endorses the subject; the typed current row lands with the
    // Commit and an exact retry writes nothing.
    let grant = accountability_grant_event(
        &issuer,
        &issuer_realm,
        &issuer_method,
        issuer_seed,
        issuer_seed,
        &subject.principal_id,
        serde_json::json!(["employment"]),
        "active",
        t0 - chrono::TimeDelta::days(1),
        Some(expires_at),
    );
    let grant_commit = station_successor(&issuer_head, &grant, &station_did, 1);
    let AccountabilityGrantAdmissionOutcome::Committed(endorsed) =
        admit_grant(&grant, grant_commit.clone()).await.unwrap()
    else {
        panic!("the issuer's grant commits");
    };
    assert_eq!(endorsed.commit, grant_commit);
    assert_eq!(endorsed.realm_id, issuer_realm);
    let endorsed_footprint = profile_footprint(&pool, &realms).await;
    assert_eq!(endorsed_footprint.endorsements, 1);
    assert!(matches!(
        admit_grant(
            &grant,
            station_successor(&grant_commit, &grant, &station_did, 1)
        )
        .await
        .unwrap(),
        AccountabilityGrantAdmissionOutcome::Duplicate(_)
    ));
    assert_eq!(profile_footprint(&pool, &realms).await, endorsed_footprint);

    // A Commit instant after expires_at is outside the grant, whatever the
    // Event's own signed time says.
    let late = admit_profile(
        &accountable_create,
        station_successor(&subject_head, &accountable_create, &station_did, 180),
    )
    .await
    .unwrap_err();
    assert_eq!(
        late.conflict_code(),
        Some(ConflictCode::AccountabilityGrantMissing)
    );
    assert_eq!(profile_footprint(&pool, &realms).await, endorsed_footprint);

    // Inside the window the profile commits.
    let create_commit = station_successor(&subject_head, &accountable_create, &station_did, 60);
    let ActorProfileAdmissionOutcome::Committed(created) =
        admit_profile(&accountable_create, create_commit.clone())
            .await
            .unwrap()
    else {
        panic!("an endorsed profile commits");
    };
    assert_eq!(
        created.profile.accountable_principal_ids,
        Some(vec![issuer.principal_id.clone()])
    );

    // The issuer revokes the same exact set, spelled as the singleton string;
    // the revoke replaces the same typed current row.
    let revoke = accountability_grant_event(
        &issuer,
        &issuer_realm,
        &issuer_method,
        issuer_seed,
        issuer_seed,
        &subject.principal_id,
        serde_json::json!("employment"),
        "revoked",
        t0 - chrono::TimeDelta::days(1),
        Some(expires_at),
    );
    let revoke_commit = station_successor(&grant_commit, &revoke, &station_did, 1);
    assert!(matches!(
        admit_grant(&revoke, revoke_commit).await.unwrap(),
        AccountabilityGrantAdmissionOutcome::Committed(_)
    ));
    let revoked_footprint = profile_footprint(&pool, &realms).await;
    assert_eq!(revoked_footprint.endorsements, 1);

    // A later update that keeps the declaration is refused at its Commit.
    let rename = profile_event(
        &subject,
        &subject_realm,
        &subject_method,
        subject_seed,
        EventKind::ProfileUpdate,
        serde_json::json!({
            "target_ref": created.profile.id,
            "patch": {"display_name": "Renamed service"}
        }),
    );
    let refused = admit_profile(
        &rename,
        station_successor(&create_commit, &rename, &station_did, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(ConflictCode::AccountabilityGrantMissing)
    );
    assert_eq!(profile_footprint(&pool, &realms).await, revoked_footprint);

    // Dropping the declaration is always admissible.
    let drop_declaration = profile_event(
        &subject,
        &subject_realm,
        &subject_method,
        subject_seed,
        EventKind::ProfileUpdate,
        serde_json::json!({
            "target_ref": created.profile.id,
            "patch": {"accountable_principal_ids": {"$op": "unset"}}
        }),
    );
    let ActorProfileAdmissionOutcome::Committed(cleared) = admit_profile(
        &drop_declaration,
        station_successor(&create_commit, &drop_declaration, &station_did, 1),
    )
    .await
    .unwrap() else {
        panic!("removing accountable principals commits");
    };
    assert_eq!(cleared.profile.accountable_principal_ids, None);
}

#[derive(Debug, PartialEq, Eq, diesel::QueryableByName)]
struct ProvisionFootprint {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    provisionings: i64,
    #[diesel(sql_type = BigInt)]
    endorsements: i64,
    #[diesel(sql_type = BigInt)]
    selectors: i64,
    #[diesel(sql_type = BigInt)]
    declarations: i64,
}

/// Every durable row an Agent provision admission can write for these
/// controller PCRs.
async fn provision_footprint(pool: &PgPool, realms: &[&RealmId]) -> ProvisionFootprint {
    let realms = realms
        .iter()
        .map(|realm| realm.as_str().to_owned())
        .collect::<Vec<_>>();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=ANY($1)) AS events, \
                (SELECT COUNT(*) FROM realm_commits WHERE realm_id=ANY($1)) AS commits, \
                (SELECT COUNT(*) FROM agent_provisioning_current_results \
                  WHERE realm_id=ANY($1)) AS provisionings, \
                (SELECT COUNT(*) FROM identity_accountability_current_results \
                  WHERE realm_id=ANY($1)) AS endorsements, \
                (SELECT COUNT(*) FROM agent_selector_claim_current_results \
                  WHERE realm_id=ANY($1)) AS selectors, \
                (SELECT COUNT(*) FROM agent_pcr_genesis_declaration_current_results \
                  WHERE realm_id=ANY($1)) AS declarations",
    )
    .bind::<diesel::sql_types::Array<Text>, _>(realms)
    .get_result::<ProvisionFootprint>(&mut *conn)
    .await
    .unwrap()
}

/// A forward-declared Agent PCR id: the retype of an event id no Event has.
fn declared_pcr_id(label: &str) -> RealmId {
    RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(label.as_bytes()),
    ))
}

/// One controller-signed `ak.agent.provision` in the controller's own PCR.
#[allow(clippy::too_many_arguments)]
fn agent_provision_event(
    controller: &arkret_wire::AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    agent_id: &DidCoreId,
    agent_pcr_id: &RealmId,
    slug: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    payload_created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_at(
        EventKind::AgentProvision.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        controller.principal_id.clone(),
        controller.station_id.clone(),
        serde_json::json!({
            "schema": "ak.schema.agent_provision.v1",
            "agent_id": agent_id,
            "controller_principal_id": controller.principal_id,
            "principal_control_realm_id": agent_pcr_id,
            "controller_authorization_ref": "did:webvh:z6mkfixture:agent.example#managed-controller",
            "agent_slug": slug,
            "accountability_scope": "agent_operator",
            "requested_scope_digest": format!("sha256:{}", "b".repeat(64)),
            "selector_visibility": "private",
            "created_at": arkret_canonical::format_timestamp_canonical(payload_created_at)
        }),
        created_at,
    )
    .unwrap();
    event.created_at = created_at;
    device_history_fixture::sign_event(event, method.clone(), seed)
}

#[tokio::test]
async fn agent_provision_commits_four_families_or_none() {
    use coland_storage::{
        ActorProfileStore, AgentProvisionAdmissionOutcome, AgentProvisionAdmissionWrite,
    };

    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let admit_genesis = async |fixture: DeviceHistoryFixture| {
        let genesis = assemble(station.clone(), fixture);
        store
            .admit_pcr_genesis_unit(&genesis, genesis.transactions[1].commit.committed_at)
            .await
            .unwrap();
        genesis
    };
    let controller_fixture = fixture(&station);
    let controller = controller_fixture.account.clone();
    let controller_realm = RealmId::new(controller_fixture.events[0].realm_id.to_string()).unwrap();
    let method = controller_fixture.device_verification_method.clone();
    let seed = controller_fixture.founding_device_signing_seed;
    let station_did = controller_fixture.station_did.clone();
    let controller_genesis = admit_genesis(controller_fixture).await;
    let other_fixture = fixture(&station);
    let other = other_fixture.account.clone();
    let other_realm = RealmId::new(other_fixture.events[0].realm_id.to_string()).unwrap();
    let other_method = other_fixture.device_verification_method.clone();
    let other_seed = other_fixture.founding_device_signing_seed;
    let other_genesis = admit_genesis(other_fixture).await;

    let tx = |authority: &coland_storage::CurrentRealmAuthority,
              event: arkret_wire::Event,
              commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        event,
        commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    };
    let controller_authority = controller_genesis.transactions[1]
        .expected_authority
        .clone();
    let other_authority = other_genesis.transactions[1].expected_authority.clone();
    let head = controller_genesis.transactions[1].commit.clone();
    let other_head = other_genesis.transactions[1].commit.clone();
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let admit = async |authority: &coland_storage::CurrentRealmAuthority,
                       event: &arkret_wire::Event,
                       commit: arkret_wire::RealmCommit| {
        profiles
            .admit_agent_provision(AgentProvisionAdmissionWrite {
                commit: tx(authority, event.clone(), commit.clone()),
                queued_at: commit.committed_at,
            })
            .await
    };
    let realms = [&controller_realm, &other_realm];
    let signed_at = head.committed_at;
    let agent = DidCoreId::new(format!(
        "ak:did_core:webvh:z6mkfixture:agent-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let agent_pcr = declared_pcr_id(&format!("{agent}:genesis"));
    let provision = |agent: &DidCoreId, pcr: &RealmId, slug: &str, payload_at| {
        agent_provision_event(
            &controller,
            &controller_realm,
            &method,
            seed,
            agent,
            pcr,
            slug,
            signed_at,
            payload_at,
        )
    };
    let before = provision_footprint(&pool, &realms).await;

    // Two signed times that disagree: refused before anything is written.
    let skewed = provision(
        &agent,
        &agent_pcr,
        "summary",
        signed_at + chrono::TimeDelta::milliseconds(1),
    );
    assert_eq!(
        admit(
            &controller_authority,
            &skewed,
            station_successor(&head, &skewed, &station_did, 1)
        )
        .await
        .unwrap_err()
        .conflict_code(),
        Some(ConflictCode::SchemaViolation)
    );
    assert_eq!(provision_footprint(&pool, &realms).await, before);

    // The accepted provision writes the Event, its Commit and all four
    // typed results together; an exact retry writes nothing.
    let accepted = provision(&agent, &agent_pcr, "summary", signed_at);
    let accepted_commit = station_successor(&head, &accepted, &station_did, 1);
    let AgentProvisionAdmissionOutcome::Committed(record) =
        admit(&controller_authority, &accepted, accepted_commit.clone())
            .await
            .unwrap()
    else {
        panic!("the controller's provision commits");
    };
    assert_eq!(record.commit, accepted_commit);
    assert_eq!(record.declaration.agent_id, agent);
    assert_eq!(record.provisioning.principal_control_realm_id, agent_pcr);
    assert_eq!(
        record.selector.subject_account_id,
        arkret_wire::AccountId::new(agent.clone(), controller.station_id.clone())
    );
    assert_eq!(record.accountability.issuer_id, controller.principal_id);
    let committed = provision_footprint(&pool, &realms).await;
    assert_eq!(
        committed,
        ProvisionFootprint {
            events: before.events + 1,
            commits: before.commits + 1,
            provisionings: before.provisionings + 1,
            endorsements: before.endorsements + 1,
            selectors: before.selectors + 1,
            declarations: before.declarations + 1,
        }
    );
    assert!(matches!(
        admit(
            &controller_authority,
            &accepted,
            station_successor(&accepted_commit, &accepted, &station_did, 1)
        )
        .await
        .unwrap(),
        AgentProvisionAdmissionOutcome::Duplicate(_)
    ));
    assert_eq!(provision_footprint(&pool, &realms).await, committed);

    // Re-declaring the same Agent in this controller PCR, even for another
    // Agent PCR id, widens nothing and writes nothing.
    let redeclared = provision(
        &agent,
        &declared_pcr_id(&format!("{agent}:second")),
        "summary-2",
        signed_at,
    );
    assert_eq!(
        admit(
            &controller_authority,
            &redeclared,
            station_successor(&accepted_commit, &redeclared, &station_did, 1)
        )
        .await
        .unwrap_err()
        .conflict_code(),
        Some(ConflictCode::AgentProvisioningAlreadyDeclared)
    );
    assert_eq!(provision_footprint(&pool, &realms).await, committed);

    // Another Agent claiming the same Agent PCR id is refused in this PCR
    // and, through the Station's uniqueness index, from another controller.
    let second_agent = DidCoreId::new(format!("{agent}-b")).unwrap();
    let squatted = provision(&second_agent, &agent_pcr, "second", signed_at);
    assert_eq!(
        admit(
            &controller_authority,
            &squatted,
            station_successor(&accepted_commit, &squatted, &station_did, 1)
        )
        .await
        .unwrap_err()
        .conflict_code(),
        Some(ConflictCode::AgentPcrGenesisDeclarationConflict)
    );
    let foreign = agent_provision_event(
        &other,
        &other_realm,
        &other_method,
        other_seed,
        &second_agent,
        &agent_pcr,
        "second",
        other_head.committed_at,
        other_head.committed_at,
    );
    assert_eq!(
        admit(
            &other_authority,
            &foreign,
            station_successor(&other_head, &foreign, &station_did, 1)
        )
        .await
        .unwrap_err()
        .conflict_code(),
        Some(ConflictCode::AgentPcrGenesisDeclarationConflict)
    );
    assert_eq!(provision_footprint(&pool, &realms).await, committed);

    // The generic commit path never writes a provision on its own.
    let generic = provision(
        &second_agent,
        &declared_pcr_id(&format!("{agent}:generic")),
        "generic",
        signed_at,
    );
    store
        .queue_event(&generic, accepted_commit.committed_at)
        .await
        .unwrap();
    assert!(
        store
            .commit_transaction(&tx(
                &controller_authority,
                generic.clone(),
                station_successor(&accepted_commit, &generic, &station_did, 1),
            ))
            .await
            .is_err()
    );
    assert_eq!(
        provision_footprint(&pool, &realms).await.provisionings,
        committed.provisionings
    );
}

#[tokio::test]
async fn agent_profile_accountability_follows_the_provision_projection() {
    use coland_storage::{
        AccountabilityGrantAdmissionOutcome, AccountabilityGrantAdmissionWrite,
        ActorProfileAdmissionOutcome, ActorProfileAdmissionWrite, ActorProfileStore,
        AgentProvisionAdmissionOutcome, AgentProvisionAdmissionWrite,
    };

    let (pool, station) = contract_store().await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let admit_genesis = async |fixture: DeviceHistoryFixture| {
        let genesis = assemble(station.clone(), fixture);
        store
            .admit_pcr_genesis_unit(&genesis, genesis.transactions[1].commit.committed_at)
            .await
            .unwrap();
        genesis
    };
    let controller_fixture = fixture(&station);
    let controller = controller_fixture.account.clone();
    let controller_realm = RealmId::new(controller_fixture.events[0].realm_id.to_string()).unwrap();
    let controller_method = controller_fixture.device_verification_method.clone();
    let controller_seed = controller_fixture.founding_device_signing_seed;
    let station_did = controller_fixture.station_did.clone();
    let controller_genesis = admit_genesis(controller_fixture).await;
    // The endorsed subject: the profile unit decides accountability by the
    // profile principal, which the provision names as its agent_id.
    let agent_fixture = fixture(&station);
    let agent = agent_fixture.account.clone();
    let agent_realm = RealmId::new(agent_fixture.events[0].realm_id.to_string()).unwrap();
    let agent_method = agent_fixture.device_verification_method.clone();
    let agent_seed = agent_fixture.founding_device_signing_seed;
    let agent_genesis = admit_genesis(agent_fixture).await;

    let tx = |authority: &coland_storage::CurrentRealmAuthority,
              event: arkret_wire::Event,
              commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        event,
        commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    };
    let controller_authority = controller_genesis.transactions[1]
        .expected_authority
        .clone();
    let agent_authority = agent_genesis.transactions[1].expected_authority.clone();
    let controller_head = controller_genesis.transactions[1].commit.clone();
    let agent_head = agent_genesis.transactions[1].commit.clone();
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let realms = [&controller_realm, &agent_realm];
    let t0 = agent_head.committed_at;

    let before_authorization = agent_provision_event(
        &controller,
        &controller_realm,
        &controller_method,
        controller_seed,
        &agent.principal_id,
        &declared_pcr_id(&format!("{}:genesis", agent.principal_id)),
        "endorsed",
        t0 - chrono::TimeDelta::days(1),
        t0 - chrono::TimeDelta::days(1),
    );
    let unchanged = profile_footprint(&pool, &realms).await;
    let unchanged_provision = provision_footprint(&pool, &realms).await;
    let before_authorization_commit =
        station_successor(&controller_head, &before_authorization, &station_did, 1);
    let error = profiles
        .admit_agent_provision(AgentProvisionAdmissionWrite {
            commit: tx(
                &controller_authority,
                before_authorization,
                before_authorization_commit.clone(),
            ),
            queued_at: before_authorization_commit.committed_at,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&error, PersistenceError::Conflict(reason) if reason == "Account Device historical producer is outside its accepted authorization window"),
        "a later target Commit cannot authorize an earlier producer proof: {error}"
    );
    assert_eq!(
        profile_footprint(&pool, &realms).await,
        unchanged,
        "pre-authorization proof leaves no durable admission"
    );
    assert_eq!(
        provision_footprint(&pool, &realms).await,
        unchanged_provision,
        "pre-authorization proof rolls back every provision family"
    );
    let provision = agent_provision_event(
        &controller,
        &controller_realm,
        &controller_method,
        controller_seed,
        &agent.principal_id,
        &declared_pcr_id(&format!("{}:genesis", agent.principal_id)),
        "endorsed",
        t0,
        t0,
    );
    let provision_commit = station_successor(&controller_head, &provision, &station_did, 1);
    let AgentProvisionAdmissionOutcome::Committed(provisioned) = profiles
        .admit_agent_provision(AgentProvisionAdmissionWrite {
            commit: tx(
                &controller_authority,
                provision.clone(),
                provision_commit.clone(),
            ),
            queued_at: provision_commit.committed_at,
        })
        .await
        .unwrap()
    else {
        panic!("the provision commits");
    };
    assert_eq!(provisioned.accountability.subject_id, agent.principal_id);
    let provisioned_footprint = profile_footprint(&pool, &realms).await;

    // The provision projection alone satisfies accountable_principal_ids.
    let create = profile_event(
        &agent,
        &agent_realm,
        &agent_method,
        agent_seed,
        EventKind::ProfileCreate,
        serde_json::json!({"object": {
            "principal_id": agent.principal_id,
            "actor_kind": "service",
            "display_name": "Provisioned agent",
            "accountable_principal_ids": [controller.principal_id]
        }}),
    );
    let create_commit = station_successor(&agent_head, &create, &station_did, 60);
    let ActorProfileAdmissionOutcome::Committed(created) = profiles
        .admit_profile(ActorProfileAdmissionWrite {
            commit: tx(&agent_authority, create.clone(), create_commit.clone()),
            queued_at: create_commit.committed_at,
        })
        .await
        .unwrap()
    else {
        panic!("a provision-endorsed profile commits");
    };
    assert_eq!(
        created.profile.accountable_principal_ids,
        Some(vec![controller.principal_id.clone()])
    );

    // An independent grant on the same exact set, spelled as a one-element
    // array, replaces the same row: here it revokes the endorsement.
    let revoke = accountability_grant_event(
        &controller,
        &controller_realm,
        &controller_method,
        controller_seed,
        controller_seed,
        &agent.principal_id,
        serde_json::json!(["agent_operator"]),
        "revoked",
        t0 - chrono::TimeDelta::days(1),
        None,
    );
    let revoke_commit = station_successor(&provision_commit, &revoke, &station_did, 1);
    assert!(matches!(
        profiles
            .admit_accountability_grant(AccountabilityGrantAdmissionWrite {
                commit: tx(&controller_authority, revoke.clone(), revoke_commit.clone()),
                queued_at: revoke_commit.committed_at,
            })
            .await
            .unwrap(),
        AccountabilityGrantAdmissionOutcome::Committed(_)
    ));
    let revoked_footprint = profile_footprint(&pool, &realms).await;
    assert_eq!(
        revoked_footprint.endorsements,
        provisioned_footprint.endorsements
    );

    // The next update that keeps the declaration is refused at its Commit.
    let rename = profile_event(
        &agent,
        &agent_realm,
        &agent_method,
        agent_seed,
        EventKind::ProfileUpdate,
        serde_json::json!({
            "target_ref": created.profile.id,
            "patch": {"display_name": "Renamed agent"}
        }),
    );
    let refused = profiles
        .admit_profile(ActorProfileAdmissionWrite {
            commit: tx(
                &agent_authority,
                rename.clone(),
                station_successor(&create_commit, &rename, &station_did, 1),
            ),
            queued_at: create_commit.committed_at,
        })
        .await
        .unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(ConflictCode::AccountabilityGrantMissing)
    );
    assert_eq!(profile_footprint(&pool, &realms).await, revoked_footprint);
}

/// The position-zero Commit this Station signs for a new Realm's genesis.
fn station_genesis_commit(
    template: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::RealmCommit {
    let realm_id = RealmId::from_event_id(&event.event_id);
    let mut commit = template.clone();
    commit.realm_id = realm_id.clone();
    commit.stream_ref = arkret_wire::CommitStreamRef::Realm { realm_id };
    commit.stream_position = 0;
    commit.previous_commit_ref = None;
    commit.event_ref = event.event_id.clone();
    commit.governance_generation = 0;
    commit.authority_ref =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    commit.committed_at = committed_at;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

#[derive(Debug, PartialEq, Eq, diesel::QueryableByName)]
struct AgentPcrFootprint {
    #[diesel(sql_type = BigInt)]
    authorities: i64,
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    singletons: i64,
    #[diesel(sql_type = BigInt)]
    roots: i64,
    #[diesel(sql_type = BigInt)]
    statuses: i64,
    #[diesel(sql_type = BigInt)]
    resolutions: i64,
}

async fn agent_pcr_footprint(pool: &PgPool, realm: &RealmId) -> AgentPcrFootprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM realm_authorities WHERE realm_id=$1) AS authorities, \
                (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS events, \
                (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS commits, \
                (SELECT COUNT(*) FROM realm_bootstrap_current_results WHERE realm_id=$1) \
                  AS singletons, \
                (SELECT COUNT(*) FROM realm_authority_root_current_results WHERE realm_id=$1) \
                  AS roots, \
                (SELECT COUNT(*) FROM agent_status_current_results \
                  WHERE realm_id=$1 AND value #>> '{}' = 'active') AS statuses, \
                (SELECT COUNT(*) FROM principal_resolutions WHERE pcr_realm_id=$1) AS resolutions",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<AgentPcrFootprint>(&mut *conn)
    .await
    .unwrap()
}

#[tokio::test]
async fn agent_pcr_genesis_requires_its_provision_declaration() {
    use coland_storage::{
        ActorProfileStore, AgentPcrGenesisAdmissionOutcome, AgentPcrGenesisAdmissionWrite,
        AgentProvisionAdmissionOutcome, AgentProvisionAdmissionWrite,
    };

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station =
        historical_control_source::HistoricalControlStation::new("pcr-native-control", [83; 32]);
    let station = historical_station.core.clone();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(station.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let controller_fixture = DeviceHistoryFixture::new_with(
        historical_station.did.clone(),
        DeviceHistoryFixtureOptions {
            local_id: format!("pcr-{}", uuid::Uuid::now_v7().simple()),
            ..Default::default()
        },
    );
    historical_control_source::register_device(
        &controller_fixture.account,
        &controller_fixture.founding_device_id,
        &controller_fixture.events[1].event_id,
    );
    let controller = controller_fixture.account.clone();
    let controller_realm = RealmId::new(controller_fixture.events[0].realm_id.to_string()).unwrap();
    let method = controller_fixture.device_verification_method.clone();
    let seed = controller_fixture.founding_device_signing_seed;
    let station_did = controller_fixture.station_did.clone();
    let controller_genesis = assemble(station.clone(), controller_fixture);
    store
        .admit_pcr_genesis_unit(
            &controller_genesis,
            controller_genesis.transactions[1].commit.committed_at,
        )
        .await
        .unwrap();
    let controller_authority = controller_genesis.transactions[1]
        .expected_authority
        .clone();
    let head = controller_genesis.transactions[1].commit.clone();
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };

    let agent_did = arkret_wire::Did::new(format!(
        "did:web:agent-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let authorization_ref = "did:webvh:z6mkfixture:agent.example#managed-controller";
    let genesis_at = head.committed_at + chrono::TimeDelta::seconds(5);
    let author = |executed_by: arkret_wire::ActorId, signing_seed: [u8; 32]| {
        let authored =
            arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
                payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                    agent_id: agent_id.clone(),
                    governance_station_id: station.clone(),
                    initial_resolution: arkret_models_identity::ResolutionCommitment {
                        did: agent_did.clone(),
                        method_history_head: format!("sha256:{}", "c".repeat(64)),
                        version_id: "1-agent".to_owned(),
                    },
                    genesis_salt: arkret_wire::GenesisSalt::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    )
                    .unwrap(),
                    trust_domain: arkret_wire::TrustDomainId::new(
                        "ak:trust_domain:pcr-contract.example".to_owned(),
                    )
                    .unwrap(),
                    initial_join_rule: arkret_wire::JoinRule::Closed,
                    initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                    initial_discoverability: arkret_wire::Discoverability::Secret,
                },
                executed_by,
                authorization_ref: arkret_wire::AuthorizationRef::new(authorization_ref.to_owned())
                    .unwrap(),
                created_at: head.committed_at,
            })
            .unwrap();
        device_history_fixture::sign_event(authored.into_event(), method.clone(), signing_seed)
    };
    let genesis = author(arkret_wire::ActorId::account(controller.clone()), seed);
    let agent_pcr = RealmId::from_event_id(&genesis.event_id);
    let authority = coland_storage::CurrentRealmAuthority {
        realm_id: agent_pcr.clone(),
        generation: 0,
        service_id: station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            genesis.event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let admit = async |event: &arkret_wire::Event| {
        let commit = station_genesis_commit(&head, event, &station_did, genesis_at);
        let transaction = AuthorityCommitTransaction {
            expected_authority: coland_storage::CurrentRealmAuthority {
                realm_id: RealmId::from_event_id(&event.event_id),
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    event.event_id.clone(),
                ),
                ..authority.clone()
            },
            event: event.clone(),
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
        historical_control_source::stage_registered_signed_candidate(&pool, &transaction).await;
        profiles
            .admit_agent_pcr_genesis(AgentPcrGenesisAdmissionWrite {
                commit: transaction,
                queued_at: genesis_at,
            })
            .await
    };
    let empty = agent_pcr_footprint(&pool, &agent_pcr).await;
    assert_eq!(empty.authorities + empty.events + empty.resolutions, 0);

    // No accepted provision declares this realm id: nothing materializes.
    assert_eq!(
        admit(&genesis).await.unwrap_err().conflict_code(),
        Some(ConflictCode::AgentPcrGenesisDeclarationMissing)
    );
    assert_eq!(agent_pcr_footprint(&pool, &agent_pcr).await, empty);

    // The controller provisions the Agent, forward-declaring this realm id.
    let provision = agent_provision_event(
        &controller,
        &controller_realm,
        &method,
        seed,
        &agent_id,
        &agent_pcr,
        "genesis",
        head.committed_at,
        head.committed_at,
    );
    let provision_commit = station_successor(&head, &provision, &station_did, 1);
    assert!(matches!(
        profiles
            .admit_agent_provision(AgentProvisionAdmissionWrite {
                commit: AuthorityCommitTransaction {
                    expected_authority: controller_authority.clone(),
                    event: provision.clone(),
                    commit: provision_commit.clone(),
                    producer_signer_fact: None,
                    mls_state: None,
                    welcomes: Vec::new(),
                    recipient_queue_capacity: 0,
                },
                queued_at: provision_commit.committed_at,
            })
            .await
            .unwrap(),
        AgentProvisionAdmissionOutcome::Committed(_)
    ));

    // A service executor is not a controller account.
    let mut service_executed = genesis.clone();
    service_executed.executed_by = Some(arkret_wire::ActorId::service(
        controller.principal_id.clone(),
    ));
    let service_executed =
        device_history_fixture::sign_event(service_executed, method.clone(), seed);
    assert_eq!(
        admit(&service_executed).await.unwrap_err().conflict_code(),
        Some(ConflictCode::SchemaViolation)
    );
    // The Agent's service actor is not the Agent's account.
    let mut service_actor = genesis.clone();
    service_actor.actor_id = arkret_wire::ActorId::service(agent_id.clone());
    let service_actor = device_history_fixture::sign_event(service_actor, method.clone(), seed);
    assert!(admit(&service_actor).await.is_err());
    // A key other than the controller's active device does not sign it.
    let forged = author(
        arkret_wire::ActorId::account(controller.clone()),
        [0x5b; 32],
    );
    assert_eq!(forged.event_id, genesis.event_id);
    assert_eq!(
        admit(&forged).await.unwrap_err().conflict_code(),
        Some(ConflictCode::SignatureInvalid)
    );
    assert_eq!(agent_pcr_footprint(&pool, &agent_pcr).await, empty);

    // With the declaration accepted, the genesis creates the Agent PCR and
    // every registered create result at position zero.
    let AgentPcrGenesisAdmissionOutcome::Committed(commit) = admit(&genesis).await.unwrap() else {
        panic!("the declared Agent PCR genesis commits");
    };
    assert_eq!(commit.stream_position, 0);
    assert_eq!(commit.realm_id, agent_pcr);
    assert_eq!(
        agent_pcr_footprint(&pool, &agent_pcr).await,
        AgentPcrFootprint {
            authorities: 1,
            events: 1,
            commits: 1,
            singletons: 2,
            roots: 1,
            statuses: 1,
            resolutions: 1,
        }
    );
    let created = agent_pcr_footprint(&pool, &agent_pcr).await;
    assert!(matches!(
        admit(&genesis).await.unwrap(),
        AgentPcrGenesisAdmissionOutcome::Duplicate(stored) if stored == commit
    ));
    assert_eq!(agent_pcr_footprint(&pool, &agent_pcr).await, created);
}

/// One controller-executed Event in the Agent's PCR.
fn agent_control_event(
    controller_method: &DidUrl,
    signing_seed: [u8; 32],
    executed_by: &arkret_wire::AccountId,
    agent: &arkret_wire::AccountId,
    agent_pcr: &RealmId,
    authorization_ref: &str,
    kind: EventKind,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr.clone(),
        },
        arkret_wire::ActorId::account(agent.clone()),
        payload,
        at,
    )
    .unwrap();
    event.executed_by = Some(arkret_wire::ActorId::account(executed_by.clone()));
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.to_owned()).unwrap());
    device_history_fixture::sign_event(event, controller_method.clone(), signing_seed)
}

fn agent_key_authorization(
    agent_did: &arkret_wire::Did,
    controller: &DidCoreId,
    fragment: &str,
    runtime_seed: [u8; 32],
    supersedes: Vec<(String, arkret_wire::EventId)>,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let method = format!("{agent_did}#{fragment}");
    let submit = arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1;
    let mut value = serde_json::json!({
        "agent_id": arkret_wire::project_did_to_core_id(agent_did).unwrap(),
        "key_id": method,
        "verification_method": method,
        "public_key": {
            "kty": "OKP",
            "kid": method,
            "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&runtime_seed).verifying_key().as_bytes()
            )
        },
        "accountable_principal_id": controller,
        "agent_key_scope": {
            "actions": [submit],
            "resources": [{"kind": "operation", "operation": submit}]
        },
        "audience": ["ak:did_core:web:pcr-contract.example"],
        "issued_at": arkret_canonical::format_timestamp_canonical(at),
        "approval_evidence": {
            "kind": "pairing_request",
            "request_canonical_digest": format!("sha256:{}", "d".repeat(64)),
            "pairing_request_id": format!("agent_pairing_request:{}", uuid::Uuid::now_v7()),
            "approved_by": controller
        }
    });
    if !supersedes.is_empty() {
        value["supersedes"] = serde_json::Value::Array(
            supersedes
                .into_iter()
                .map(|(key_id, event_id)| {
                    serde_json::json!({"key_id": key_id, "authorized_event_ref": event_id})
                })
                .collect(),
        );
    }
    value
}

#[derive(Debug, PartialEq, Eq, diesel::QueryableByName)]
struct AgentControlFootprint {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    active_keys: i64,
    #[diesel(sql_type = Text)]
    status: String,
}

async fn agent_control_footprint(pool: &PgPool, realm: &RealmId) -> AgentControlFootprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS events, \
                (SELECT COUNT(*) FROM agent_key_current_results k, \
                   jsonb_array_elements(k.value->'authorizations') a \
                  WHERE k.realm_id=$1 AND a->'value' ? 'verification_method') AS active_keys, \
                (SELECT value #>> '{}' FROM agent_status_current_results WHERE realm_id=$1) \
                  AS status",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<AgentControlFootprint>(&mut *conn)
    .await
    .unwrap()
}

#[tokio::test]
async fn agent_key_and_lifecycle_commit_only_through_the_control_unit() {
    use coland_storage::{
        ActorProfileStore, AgentControlAdmissionOutcome, AgentControlAdmissionWrite,
        AgentPcrGenesisAdmissionWrite, AgentProvisionAdmissionWrite,
    };

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station =
        historical_control_source::HistoricalControlStation::new("pcr-native-control", [83; 32]);
    let station = historical_station.core.clone();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(station.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let admit_genesis = async |fixture: DeviceHistoryFixture| {
        let genesis = assemble(station.clone(), fixture);
        store
            .admit_pcr_genesis_unit(&genesis, genesis.transactions[1].commit.committed_at)
            .await
            .unwrap();
        genesis
    };
    let controller_fixture = DeviceHistoryFixture::new_with(
        historical_station.did.clone(),
        DeviceHistoryFixtureOptions {
            local_id: format!("pcr-{}", uuid::Uuid::now_v7().simple()),
            ..Default::default()
        },
    );
    historical_control_source::register_device(
        &controller_fixture.account,
        &controller_fixture.founding_device_id,
        &controller_fixture.events[1].event_id,
    );
    let controller = controller_fixture.account.clone();
    let controller_realm = RealmId::new(controller_fixture.events[0].realm_id.to_string()).unwrap();
    let method = controller_fixture.device_verification_method.clone();
    let seed = controller_fixture.founding_device_signing_seed;
    let station_did = controller_fixture.station_did.clone();
    let controller_device = controller_fixture.founding_device_id.clone();
    let controller_genesis = admit_genesis(controller_fixture).await;
    let stranger_fixture = DeviceHistoryFixture::new_with(
        historical_station.did.clone(),
        DeviceHistoryFixtureOptions {
            local_id: format!("pcr-{}", uuid::Uuid::now_v7().simple()),
            ..Default::default()
        },
    );
    historical_control_source::register_device(
        &stranger_fixture.account,
        &stranger_fixture.founding_device_id,
        &stranger_fixture.events[1].event_id,
    );
    let stranger = stranger_fixture.account.clone();
    let stranger_method = stranger_fixture.device_verification_method.clone();
    let stranger_seed = stranger_fixture.founding_device_signing_seed;
    admit_genesis(stranger_fixture).await;
    let head = controller_genesis.transactions[1].commit.clone();
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let tx = |event: arkret_wire::Event, commit: arkret_wire::RealmCommit| {
        let authority = coland_storage::CurrentRealmAuthority {
            realm_id: commit.realm_id.clone(),
            generation: 0,
            service_id: station.clone(),
            authority_ref: commit.authority_ref.clone(),
            last_handoff_ref: None,
        };
        AuthorityCommitTransaction {
            expected_authority: authority,
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        }
    };

    // Provision and found the Agent.
    let agent_did = arkret_wire::Did::new(format!(
        "did:web:agent-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let agent = arkret_wire::AccountId::new(agent_id.clone(), station.clone());
    let delegation = format!("{agent_did}#managed-controller");
    let genesis = device_history_fixture::sign_event(
        arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
            payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                agent_id: agent_id.clone(),
                governance_station_id: station.clone(),
                initial_resolution: arkret_models_identity::ResolutionCommitment {
                    did: agent_did.clone(),
                    method_history_head: format!("sha256:{}", "c".repeat(64)),
                    version_id: "1-agent".to_owned(),
                },
                genesis_salt: arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                )
                .unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new(
                    "ak:trust_domain:pcr-contract.example".to_owned(),
                )
                .unwrap(),
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
            },
            executed_by: arkret_wire::ActorId::account(controller.clone()),
            authorization_ref: arkret_wire::AuthorizationRef::new(delegation.clone()).unwrap(),
            created_at: head.committed_at,
        })
        .unwrap()
        .into_event(),
        method.clone(),
        seed,
    );
    let agent_pcr = RealmId::from_event_id(&genesis.event_id);
    let mut provision = agent_provision_event(
        &controller,
        &controller_realm,
        &method,
        seed,
        &agent_id,
        &agent_pcr,
        "control",
        head.committed_at,
        head.committed_at,
    );
    provision.payload.insert(
        "controller_authorization_ref".to_owned(),
        serde_json::json!(delegation),
    );
    let provision = device_history_fixture::sign_event(provision, method.clone(), seed);
    let provision_commit = station_successor(&head, &provision, &station_did, 1);
    profiles
        .admit_agent_provision(AgentProvisionAdmissionWrite {
            commit: tx(provision.clone(), provision_commit.clone()),
            queued_at: provision_commit.committed_at,
        })
        .await
        .unwrap();
    let genesis_commit = station_genesis_commit(
        &head,
        &genesis,
        &station_did,
        head.committed_at + chrono::TimeDelta::seconds(2),
    );
    historical_control_source::admit_genesis(
        &profiles,
        &pool,
        AgentPcrGenesisAdmissionWrite {
            commit: tx(genesis.clone(), genesis_commit.clone()),
            queued_at: genesis_commit.committed_at,
        },
    )
    .await
    .unwrap();

    let historical_store = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
    let producer_selector = |event: &arkret_wire::Event, commit: &arkret_wire::RealmCommit| {
        arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
            sender: arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                actor: event.actual_signer().clone(),
                device_id: controller_device.clone(),
                verification_method: method.clone(),
                committed_event_ref: arkret_wire::CommittedEventRef {
                    event_id: event.event_id.clone(),
                    commit_id: commit.commit_id.clone(),
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                },
            },
        }
    };
    for (original, accepted) in [(&provision, &provision_commit), (&genesis, &genesis_commit)] {
        let selector = producer_selector(original, accepted);
        let frozen = coland_storage::AuthorityCommitStore::historical_self_pcr_producer_signer_key(
            &historical_store,
            &original.realm_id,
            &selector,
            &controller,
        )
        .await
        .unwrap()
        .expect("original self admission freezes a key-only fact");
        assert_eq!(
            frozen
                .key()
                .unwrap()
                .authorization_ref
                .stream_ref
                .realm_id(),
            &controller_realm
        );
        let mut foreign = controller.clone();
        foreign.station_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign-history.example").unwrap();
        assert!(
            coland_storage::AuthorityCommitStore::historical_self_pcr_producer_signer_key(
                &historical_store,
                &original.realm_id,
                &selector,
                &foreign
            )
            .await
            .unwrap()
            .is_none(),
            "recipient must equal complete actual Human producer"
        );
        let mut wrong = selector.clone();
        if let arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
            sender:
                arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                    committed_event_ref,
                    ..
                },
        } = &mut wrong
        {
            committed_event_ref.stream_position += 1;
        }
        assert!(
            coland_storage::AuthorityCommitStore::historical_self_pcr_producer_signer_key(
                &historical_store,
                &original.realm_id,
                &wrong,
                &controller
            )
            .await
            .unwrap()
            .is_none(),
            "target must preserve all four original coordinates"
        );
    }
    // Removing the original provenance must not be repaired from the still
    // present Agent/current delegation rows or from its canonical envelope.
    {
        let mut conn = pool.get().await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct FrozenSource {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            value: serde_json::Value,
        }
        let source: FrozenSource = diesel::sql_query("SELECT self_admission_provenance AS value FROM agent_producer_signer_keys WHERE commit_id=$1").bind::<diesel::sql_types::Text,_>(genesis_commit.commit_id.as_str()).get_result(&mut *conn).await.unwrap();
        let mut wrong_source = source.value.clone();
        wrong_source["controller_delegation_ref"] =
            serde_json::json!(format!("{agent_did}#wrong-controller"));
        diesel::sql_query(
            "UPDATE agent_producer_signer_keys SET self_admission_provenance=$2 WHERE commit_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(genesis_commit.commit_id.as_str())
        .bind::<diesel::sql_types::Jsonb, _>(wrong_source)
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);
        assert!(
            coland_storage::AuthorityCommitStore::historical_self_pcr_producer_signer_key(
                &historical_store,
                &genesis.realm_id,
                &producer_selector(&genesis, &genesis_commit),
                &controller
            )
            .await
            .unwrap()
            .is_none(),
            "current accepted Agent rows cannot replace the original delegation fact"
        );
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("UPDATE agent_producer_signer_keys SET self_admission_provenance=NULL,self_admission_account=NULL,self_admission_kind=NULL WHERE commit_id=$1").bind::<diesel::sql_types::Text,_>(genesis_commit.commit_id.as_str()).execute(&mut *conn).await.unwrap();
        drop(conn);
        assert!(
            coland_storage::AuthorityCommitStore::historical_self_pcr_producer_signer_key(
                &historical_store,
                &genesis.realm_id,
                &producer_selector(&genesis, &genesis_commit),
                &controller
            )
            .await
            .unwrap()
            .is_none(),
            "missing original admission provenance cannot be recovered from current state"
        );
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "UPDATE agent_producer_signer_keys SET self_admission_provenance=$2,self_admission_account=$3,self_admission_kind='agent_pcr_genesis' WHERE commit_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(genesis_commit.commit_id.as_str())
        .bind::<diesel::sql_types::Jsonb, _>(source.value)
        .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(&controller).unwrap())
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    let t0 = genesis_commit.committed_at;
    let control = |executed_by: &arkret_wire::AccountId,
                   signer_method: &DidUrl,
                   signing_seed: [u8; 32],
                   kind: EventKind,
                   payload: serde_json::Value| {
        agent_control_event(
            signer_method,
            signing_seed,
            executed_by,
            &agent,
            &agent_pcr,
            &delegation,
            kind,
            payload,
            t0,
        )
    };
    let admit = async |event: &arkret_wire::Event, previous: &arkret_wire::RealmCommit| {
        let transaction = tx(
            event.clone(),
            station_successor(previous, event, &station_did, 1),
        );
        historical_control_source::stage_registered_signed_candidate(&pool, &transaction).await;
        profiles
            .admit_agent_control_event(AgentControlAdmissionWrite {
                commit: transaction,
                queued_at: previous.committed_at,
            })
            .await
    };
    let committed =
        |outcome: Result<AgentControlAdmissionOutcome, PersistenceError>| match outcome.unwrap() {
            AgentControlAdmissionOutcome::Committed(commit) => commit,
            AgentControlAdmissionOutcome::Duplicate(_) => panic!("expected a fresh commit"),
        };
    let founded = agent_control_footprint(&pool, &agent_pcr).await;
    assert_eq!(founded.status, "active");
    assert_eq!(founded.active_keys, 0);

    // The first runtime key.
    let first = control(
        &controller,
        &method,
        seed,
        EventKind::AgentKeyAuthorize,
        agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            "runtime-1",
            [0x61; 32],
            Vec::new(),
            t0,
        ),
    );
    let first_commit = committed(admit(&first, &genesis_commit).await);
    assert!(
        coland_storage::AuthorityCommitStore::historical_self_pcr_producer_signer_key(
            &historical_store,
            &agent_pcr,
            &producer_selector(&first, &first_commit),
            &controller
        )
        .await
        .unwrap()
        .is_some(),
        "controller Agent PCR Event keeps its original accepted provision/delegation fact"
    );
    assert!(matches!(
        admit(&first, &first_commit).await.unwrap(),
        AgentControlAdmissionOutcome::Duplicate(stored) if stored == first_commit
    ));
    let keyed = agent_control_footprint(&pool, &agent_pcr).await;
    assert_eq!(keyed.active_keys, 1);

    // A second key that names a stale (empty) active set, a key the
    // controller's device did not sign, and an Event executed by another
    // account the provision does not bind all write nothing.
    let stale = control(
        &controller,
        &method,
        seed,
        EventKind::AgentKeyAuthorize,
        agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            "runtime-2",
            [0x62; 32],
            Vec::new(),
            t0,
        ),
    );
    assert_eq!(
        admit(&stale, &first_commit)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::ReducerProjectionFailed)
    );
    let forged = control(
        &controller,
        &method,
        [0x5c; 32],
        EventKind::AgentKeyAuthorize,
        agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            "runtime-2",
            [0x62; 32],
            vec![(format!("{agent_did}#runtime-1"), first.event_id.clone())],
            t0,
        ),
    );
    assert_eq!(
        admit(&forged, &first_commit)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::SignatureInvalid)
    );
    let hijacked = control(
        &stranger,
        &stranger_method,
        stranger_seed,
        EventKind::AgentKeyAuthorize,
        agent_key_authorization(
            &agent_did,
            &stranger.principal_id,
            "runtime-2",
            [0x62; 32],
            vec![(format!("{agent_did}#runtime-1"), first.event_id.clone())],
            t0,
        ),
    );
    assert_eq!(
        admit(&hijacked, &first_commit)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(agent_control_footprint(&pool, &agent_pcr).await, keyed);

    // Replacement names the exact active set and swaps the key atomically.
    let second = control(
        &controller,
        &method,
        seed,
        EventKind::AgentKeyAuthorize,
        agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            "runtime-2",
            [0x62; 32],
            vec![(format!("{agent_did}#runtime-1"), first.event_id.clone())],
            t0,
        ),
    );
    let second_commit = committed(admit(&second, &first_commit).await);
    assert_eq!(
        agent_control_footprint(&pool, &agent_pcr).await.active_keys,
        1
    );

    // Revoking the superseded key finds nothing active; revoking the current
    // key empties the set.
    let revoke = |key: &str| {
        control(
            &controller,
            &method,
            seed,
            EventKind::AgentKeyRevoke,
            serde_json::json!({
                "agent_id": agent_id,
                "key_id": format!("{agent_did}#{key}"),
                "revoked_by": controller.principal_id,
                "revoked_at": arkret_canonical::format_timestamp_canonical(t0)
            }),
        )
    };
    assert_eq!(
        admit(&revoke("runtime-1"), &second_commit)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::ReducerProjectionFailed)
    );
    let revoked_commit = committed(admit(&revoke("runtime-2"), &second_commit).await);
    assert_eq!(
        agent_control_footprint(&pool, &agent_pcr).await.active_keys,
        0
    );

    // The lifecycle follows the registered FSM from its accepted status.
    let status = |kind: EventKind, transition: &str, previous: &str| {
        control(
            &controller,
            &method,
            seed,
            kind,
            serde_json::json!({
                "transition": transition,
                "previous_status": previous,
                "status_changed_at": arkret_canonical::format_timestamp_canonical(t0)
            }),
        )
    };
    let paused_commit = committed(
        admit(
            &status(EventKind::SelfAgentPause, "pause", "active"),
            &revoked_commit,
        )
        .await,
    );
    assert_eq!(
        agent_control_footprint(&pool, &agent_pcr).await.status,
        "paused"
    );
    assert_eq!(
        admit(
            &status(EventKind::SelfAgentResume, "resume", "active"),
            &paused_commit,
        )
        .await
        .unwrap_err()
        .conflict_code(),
        Some(ConflictCode::ReducerProjectionFailed)
    );
    let deactivated_commit = committed(
        admit(
            &status(EventKind::SelfAgentDeactivate, "deactivate", "paused"),
            &paused_commit,
        )
        .await,
    );
    let terminal = agent_control_footprint(&pool, &agent_pcr).await;
    assert_eq!(terminal.status, "deactivated");

    // Terminal: no key may be attached again.
    let after = control(
        &controller,
        &method,
        seed,
        EventKind::AgentKeyAuthorize,
        agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            "runtime-3",
            [0x63; 32],
            Vec::new(),
            t0,
        ),
    );
    assert_eq!(
        admit(&after, &deactivated_commit)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );

    // The generic commit path never writes an Agent control Event.
    store
        .queue_event(&after, deactivated_commit.committed_at)
        .await
        .unwrap();
    assert!(
        store
            .commit_transaction(&tx(
                after.clone(),
                station_successor(&deactivated_commit, &after, &station_did, 1),
            ))
            .await
            .is_err()
    );
    assert_eq!(
        agent_control_footprint(&pool, &agent_pcr).await.active_keys,
        0
    );
    assert_eq!(terminal.status, "deactivated");
}

#[tokio::test]
async fn genesis_resolution_uses_event_time_when_station_acceptance_is_later() {
    use coland_storage::{CurrentPrincipalRead, PrincipalResolutionStore};
    let (pool, station) = contract_store().await;
    let mut accepted = unit(station);
    let mut previous = None;
    for tx in &mut accepted.transactions {
        tx.commit.committed_at += chrono::TimeDelta::seconds(30);
        tx.commit.previous_commit_ref = previous.clone();
        let identity =
            arkret_canonical::canonical::unsigned_value(&tx.commit, &["commit_id", "signature"])
                .unwrap();
        tx.commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&identity).unwrap(),
        ));
        tx.commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::canonical::unsigned_value(&tx.commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            tx.commit.signature.verification_method.clone(),
            tx.commit.committed_at,
            &SigningKey::from_bytes(&device_history_fixture::STATION_AUTHORITY_SEED),
        )
        .unwrap();
        previous = Some(tx.commit.commit_id.clone());
    }
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let PcrGenesisCommitOutcome::Committed(result) = store
        .admit_pcr_genesis_unit(&accepted, accepted.transactions[1].commit.committed_at)
        .await
        .unwrap()
    else {
        panic!("genesis must commit")
    };
    assert_ne!(
        accepted.transactions[0].event.created_at,
        result.commits[0].committed_at
    );
    assert_eq!(
        result.resolution.updated_at,
        accepted.transactions[0].event.created_at
    );
    let account = arkret_wire::AccountId::new(
        result.principal_id.clone(),
        accepted.submission.account_authority_id.clone(),
    );
    let read = coland_storage_postgres::PgPrincipalResolutionStore { pool };
    assert_eq!(
        read.current_principal(&account).await.unwrap(),
        CurrentPrincipalRead::Ready {
            pcr_realm_id: result.pcr_realm_id,
            projection: result.resolution
        }
    );
}
