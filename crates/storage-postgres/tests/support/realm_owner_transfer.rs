//! Native Human source, finite C observation and the actual Owner Event UoW.
//!
//! This exercises the PostgreSQL boundary. It does not replace an
//! independently deployed peer/HTTP source acquisition test.

use arkret_models_crypto::realm_owner_transfer::{
    RealmOwnerTransferAcceptance, RealmOwnerTransferAcceptanceIntent, RealmOwnerTransferPatch,
    RealmOwnerTransferUnsignedPayload,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_signatures::device_projection::sign_device_projection_attestation;
use arkret_signatures::realm_owner_transfer::sign_realm_owner_transfer_acceptance;
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception,
};
use arkret_wire::{
    AccountId, ActorId, Did, DidCoreId, DidUrl, Event, EventKind, Hash, RealmCommit, RealmId,
    ScopeRef, ServiceKind,
};
use chrono::{DateTime, Utc};
use coland_storage::{
    AccountDeviceSignerEvidenceStore, AccountPk, AccountRecord, AccountStore,
    AuthorityCommitTransaction, EventCommitRequest, EventCommitUnitOfWork,
    OwnerTransferSuccessorSource,
};
use coland_storage_postgres::{
    PgAccountDeviceSignerEvidenceArchive, PgAccountStore, PgAuthorityCommitStore,
    PgEventCommitUnitOfWork, PgPool,
};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl as _;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};

use super::ordinary_realm::{self, human_profile};

pub fn now() -> DateTime<Utc> {
    arkret_canonical::normalize_timestamp_canonical(Utc::now())
}

pub struct NativeOwnerTransfer {
    pub pool: PgPool,
    pub store: PgAuthorityCommitStore,
    pub realm: RealmId,
    pub author: AccountId,
    pub successor: AccountId,
    pub request: EventCommitRequest,
    pub component: RealmOwnerTransferAcceptance,
    pub w1: AccountDeviceSignerEvidence,
    accepted_predecessor: Box<AuthorityCommitTransaction>,
    c_log_entry: Value,
    c_method: DidUrl,
    c_seed: [u8; 32],
    c_did: Did,
}

impl NativeOwnerTransfer {
    pub fn event(&self) -> &Event {
        assert_eq!(
            self.request
                .authority_commit
                .commit
                .previous_commit_ref
                .as_ref(),
            Some(&self.accepted_predecessor().commit.commit_id),
            "the Owner candidate extends the retained accepted original"
        );
        &self.request.authority_commit.event
    }
    pub fn accepted_predecessor(&self) -> &AuthorityCommitTransaction {
        self.accepted_predecessor.as_ref()
    }
    pub fn commit(&self) -> &RealmCommit {
        &self.request.authority_commit.commit
    }
    pub async fn accept(&self) {
        PgEventCommitUnitOfWork::new(self.pool.clone())
            .commit_event(self.request.clone())
            .await
            .expect("accept native successor proof and freeze W1 with its Owner Commit");
    }
    pub async fn fresh_witness(&self) -> AccountDeviceSignerEvidence {
        // A second observation uses the real source again. Only the test
        // scheduling waits; no future timestamp or synthesized current is used.
        while now()
            <= self
                .w1
                .device_projection_attestation
                .attestation
                .attested_at
        {
            tokio::task::yield_now().await;
        }
        witness(
            &self.pool,
            &self.component,
            &self.c_log_entry,
            &self.c_method,
            &self.c_seed,
        )
        .await
    }
    pub async fn reciprocal_realm(&self, label: &str) -> Self {
        let discussion = ordinary_realm::case_future(|| {
            ordinary_realm::open_discussion_unit(
                &self.pool,
                ordinary_realm::bootstrap_unit_for_account(label, &self.successor, &self.c_did),
            )
        })
        .await;
        let head = join(&self.pool, &discussion.head.authority_commit, &self.author).await;
        self.transfer_after(&head, &self.successor, &self.author, "ordinary-founder")
            .await
    }
    pub async fn transfer_after(
        &self,
        head: &AuthorityCommitTransaction,
        author: &AccountId,
        successor: &AccountId,
        successor_fixture_label: &str,
    ) -> Self {
        // The label selects deterministic test custody only. request checks
        // its full Account against successor, then obtains the real C source.
        request(
            self.pool.clone(),
            head.clone(),
            author.clone(),
            successor.clone(),
            &self.c_did,
            successor_fixture_label,
            self.c_log_entry.clone(),
            self.c_method.clone(),
            self.c_seed,
        )
        .await
    }

    /// Admit a third Human's real PCR, founding Device and Profile, then join
    /// the business Realm through the same public membership admission.
    pub async fn joined_human_after(
        &self,
        head: &AuthorityCommitTransaction,
        label: &str,
    ) -> (AccountId, AuthorityCommitTransaction) {
        let member = ordinary_realm::case_future(|| {
            human_profile::admit_for_station_did(&self.pool, self.c_did.clone(), label)
        })
        .await;
        account(&self.pool, &member).await;
        let joined = ordinary_realm::case_future(|| join(&self.pool, head, &member)).await;
        (member, joined)
    }
}

async fn account(pool: &PgPool, account: &AccountId) {
    PgAccountStore { pool: pool.clone() }
        .put(&AccountRecord {
            pk: AccountPk(0), // put allocates the private primary key.
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: now(),
        })
        .await
        .unwrap();
}

async fn join(
    pool: &PgPool,
    head: &AuthorityCommitTransaction,
    member: &AccountId,
) -> AuthorityCommitTransaction {
    let actor = ActorId::account(member.clone());
    let candidate = ordinary_realm::next_human_request_for_actor(
        head,
        EventKind::MemberState,
        actor.clone(),
        json!({"realm_id":head.event.realm_id,"member_id":actor,"membership":"join"}),
        now(),
    );
    let candidate =
        ordinary_realm::case_future(|| ordinary_realm::source_request(pool, candidate)).await;
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(candidate.clone())
        .await
        .expect("join via the accepted public join rule and the member's real Device");
    candidate.authority_commit
}

#[derive(diesel::QueryableByName)]
struct Root {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

pub async fn root_value(pool: &PgPool, realm: &RealmId) -> Value {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query("SELECT jsonb_build_object('controller_actor_id',controller_actor_id,'controller_epoch',controller_epoch,'authority_generation',authority_generation::text,'authority_event_ref',authority_event_ref) AS value FROM realm_authority_root_current_states WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Root>(&mut conn)
        .await
        .unwrap();
    let root: arkret_wire::RealmAuthorityRootValue = serde_json::from_value(row.value).unwrap();
    root.validate().unwrap();
    serde_json::to_value(root).unwrap()
}

async fn witness(
    pool: &PgPool,
    component: &RealmOwnerTransferAcceptance,
    log_entry: &Value,
    method: &DidUrl,
    seed: &[u8; 32],
) -> AccountDeviceSignerEvidence {
    let archive = PgAccountDeviceSignerEvidenceArchive::new(pool.clone());
    let (core, authorization) = archive
        .prepare_owner_transfer_current(component)
        .await
        .unwrap()
        .expect("C obtains the real Human Account/Device/membership/current source");
    let service_resolution = arkret_identity::build_authenticated_webvh_service_resolution(
        core.account_id.station_id.clone(),
        "station".into(),
        serde_json::from_value(log_entry["state"].clone()).unwrap(),
        vec![log_entry.clone()],
        vec![],
        core.attested_at,
    )
    .unwrap();
    let evidence = AccountDeviceSignerEvidence {
        device_projection_attestation: sign_device_projection_attestation(
            core,
            method.clone(),
            &SigningKey::from_bytes(seed),
        )
        .unwrap(),
        service_resolution,
    };
    archive
        .retain_owner_transfer_current(&evidence, &authorization, component)
        .await
        .expect("retain the actual C-signed source after independently repeating its native cut");
    evidence
}

async fn request(
    pool: PgPool,
    head: AuthorityCommitTransaction,
    author: AccountId,
    successor: AccountId,
    c_did: &Did,
    successor_label: &str,
    c_log_entry: Value,
    c_method: DidUrl,
    c_seed: [u8; 32],
) -> NativeOwnerTransfer {
    let realm = head.event.realm_id.clone();
    let intent = RealmOwnerTransferAcceptanceIntent {
        scope_ref: ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor_id: ActorId::account(author.clone()),
        payload_without_successor_acceptance: RealmOwnerTransferUnsignedPayload {
            realm_id: realm.clone(),
            expected_state_digest: Hash::new(
                arkret_canonical::canonical_sha256(&root_value(&pool, &realm).await).unwrap(),
            )
            .unwrap(),
            patch: RealmOwnerTransferPatch {
                controller_actor_id: ActorId::account(successor.clone()),
            },
        },
    };
    let signer = human_profile::fixture_for_did(c_did.clone(), successor_label);
    assert_eq!(signer.history.account, successor);
    let acceptance = sign_realm_owner_transfer_acceptance(
        &intent,
        signer.history.device_verification_method.clone(),
        now(),
        &SigningKey::from_bytes(&signer.history.founding_device_signing_seed),
    )
    .unwrap();
    let component = RealmOwnerTransferAcceptance { intent, acceptance };
    let w1 = witness(&pool, &component, &c_log_entry, &c_method, &c_seed).await;
    let mut payload =
        serde_json::to_value(&component.intent.payload_without_successor_acceptance).unwrap();
    payload["successor_acceptance"] = serde_json::to_value(&component.acceptance).unwrap();
    let candidate = ordinary_realm::next_human_request_for_actor(
        &head,
        EventKind::RealmOwnerTransfer,
        ActorId::account(author.clone()),
        payload,
        now(),
    );
    let mut candidate =
        ordinary_realm::case_future(|| ordinary_realm::source_request(&pool, candidate)).await;
    candidate.owner_transfer_successor = Some(
        OwnerTransferSuccessorSource::for_event(&candidate.authority_commit.event, w1.clone())
            .unwrap(),
    );
    NativeOwnerTransfer {
        store: PgAuthorityCommitStore { pool: pool.clone() },
        pool,
        realm,
        author,
        successor,
        request: candidate,
        component,
        w1,
        accepted_predecessor: Box::new(head),
        c_log_entry,
        c_method,
        c_seed,
        c_did: c_did.clone(),
    }
}

pub async fn prepared(pool: &PgPool, label: &str) -> NativeOwnerTransfer {
    let inception_at: DateTime<Utc> = "2026-09-11T00:00:00Z".parse().unwrap();
    let mut rng = ChaCha20Rng::from_seed(arkret_canonical::sha256_bytes(label.as_bytes()));
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new("https://owner-station.example/").unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_created_at: inception_at,
            did_key_fragment: None,
        },
    )
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let station: DidCoreId = arkret_wire::project_did_to_core_id(&did).unwrap();
    let discussion = ordinary_realm::case_future(|| {
        ordinary_realm::open_discussion_for_station(pool, label, &station, &did)
    })
    .await;
    let author = discussion.unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let successor_label = format!("owner-successor-{label}");
    let successor = ordinary_realm::case_future(|| {
        human_profile::admit_for_station_did(pool, did.clone(), &successor_label)
    })
    .await;
    account(pool, &author).await;
    account(pool, &successor).await;
    let head = join(pool, &discussion.head.authority_commit, &successor).await;
    request(
        pool.clone(),
        head,
        author,
        successor,
        &did,
        &successor_label,
        inception.log_entry.clone(),
        DidUrl::new(inception.did_key_id.clone()).unwrap(),
        inception.did_key_seed,
    )
    .await
}

pub async fn accepted(pool: &PgPool, label: &str) -> NativeOwnerTransfer {
    let fixture = ordinary_realm::case_future(|| prepared(pool, label)).await;
    fixture.accept().await;
    fixture
}
