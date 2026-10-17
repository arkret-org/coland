//! MLS lifecycle over the Station's current HTTP surfaces, formal authority
//! units and a restart, on real PostgreSQL (encryption-and-audit §2,
//! device-lifecycle §9, client-sync §10).
//!
//! Alice founds a public Realm and activates its scope; Bob joins by his own
//! `ak.member.state`. Over HTTP Bob publishes device KeyPackages (a mislabeled
//! suite is refused), Alice self-claims one (exact replay is byte-identical, a
//! conflicting reuse of the claim identity is `duplicate_conflict`), and Bob
//! later reads the Welcome from his recipient queue, joins from it against the
//! accepted Commit, ACKs it and consumes the claim against its Welcome binding
//! (a tampered digest or epoch is `conflict`, the exact receipt replays).
//! Every Realm fact -- the bootstrap unit, the joins, `ak.mls.genesis` and the
//! inline Add `ak.mls.commit` with its Welcome -- is a formal Event with its
//! RealmCommit admitted through the authority store's own unit of work, with
//! the public MLS state computed from the real Commit bytes and the Welcome
//! bound to the ledger row the HTTP claim wrote. A second `AppState` over the
//! same database then proves the claim ledger, the MLS current and the queue
//! survive a restart.
//!
//! The self-submit admission of the MLS Events needs an Account-Authority
//! standard grant and runs live in Cotest `keypackage_lifecycle`
//! (`scenarios::mls_lifecycle_live`).

#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use std::sync::Arc;

use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsPublicGroupTracker};
use arkret_models_collaboration::authority_commit::{
    OrdinaryRealmBootstrapUnitKind, OrdinaryRealmBootstrapUnitSubmission,
    SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::device_messages::{
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, RecipientDelivery,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
use arkret_models_crypto::{
    KeyPackagesClaimOutcome, KeyPackagesClaimQueryRequestBody, KeyPackagesClaimRequestBody,
    KeyPackagesUploadOutcome, MlsCommitPayload, MlsGovernanceBindingPayload,
};
use arkret_wire::{AccountId, ActorId, EventKind, MlsWelcomeDelivery, RealmId, ScopeRef};
use base64::Engine as _;
use coland_http::config::AppConfig;
use coland_http::service;
use coland_http::state::AppState;
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority, EventCommitRequest,
    EventCommitUnitOfWork, MlsInstalledBase, MlsStateInstallation, MlsWelcomeClaimLedgerKey,
    OrdinaryRealmBootstrapCommitUnit, PersistenceStore, VerifiedMlsWelcome,
};
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPersistenceStore, PgPool, TestDatabase,
};
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use ed25519_dalek::{Signer as _, SigningKey};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

const ACTIVE_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
const RESERVED_SUITE: &str = "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519";
const REGISTRATION_BEARER: &str = "fixture-registration";

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some(REGISTRATION_BEARER.to_owned()),
        ..coland_test_support::app_config()
    }
}

/// One accepted PCR Account with a development session bound to its
/// founding device, and that device's key.
struct Member {
    account: AccountId,
    actor: ActorId,
    device: arkret_wire::DeviceId,
    method: arkret_wire::DidUrl,
    authorize_event_id: arkret_wire::EventId,
    seed: [u8; 32],
    key: SigningKey,
    token: String,
}

impl Member {
    async fn provision(
        state: &AppState,
        persistence: &dyn PersistenceStore,
        name: &str,
        index: u8,
    ) -> Self {
        let fixture = PcrGenesisFixture::new_with(
            state.service_did(),
            coland_test_support::device_authorization_history::DeviceHistoryFixtureOptions {
                local_id: format!("mls-{index}-{}", uuid::Uuid::now_v7().simple()),
                founding_device_id: coland_test_support::device_authorization_history::device(
                    index,
                ),
                founding_device_signing_seed: [0x80 + index; 32],
                founding_device_hpke_seed: [0x90 + index; 32],
                ..Default::default()
            },
        );
        fixture
            .admit_into(persistence)
            .await
            .expect("durable PCR genesis");
        ordinary_realm::human_profile::register_fixture_signer(
            &fixture.history.account,
            fixture.history.device_verification_method.clone(),
            fixture.history.founding_device_signing_seed,
        );
        let app = service(state.clone());
        let mut registration = TestClient::post("http://server/_coland/gate/account/project")
            .add_header(
                "authorization",
                format!("Bearer {REGISTRATION_BEARER}"),
                true,
            )
            .json(&json!({
                "principal_id": fixture.history.account.principal_id,
                "did": fixture.history.did,
                "display_name": name,
            }))
            .send(&app)
            .await;
        assert!(
            matches!(
                registration.status_code,
                Some(StatusCode::OK | StatusCode::CONFLICT)
            ),
            "account projection: {:?}",
            registration.take_string().await
        );
        let mut login = TestClient::post("http://server/_coland/gate/auth/dev-login")
            .json(&json!({
                "actor": fixture.history.account.principal_id,
                "device_id": fixture.history.founding_device_id,
                "display_name": name,
            }))
            .send(&app)
            .await;
        assert_eq!(login.status_code, Some(StatusCode::OK));
        let body: Value = login.take_json().await.expect("dev-login JSON");
        Self {
            actor: ActorId::account(fixture.history.account.clone()),
            account: fixture.history.account.clone(),
            device: fixture.history.founding_device_id.clone(),
            method: fixture.history.device_verification_method.clone(),
            authorize_event_id: fixture
                .unit
                .transactions
                .iter()
                .find(|transaction| transaction.event.kind == EventKind::DeviceAuthorize)
                .expect("the accepted founding Device authorization")
                .event
                .event_id
                .clone(),
            seed: fixture.history.founding_device_signing_seed,
            key: SigningKey::from_bytes(&fixture.history.founding_device_signing_seed),
            token: body["session_credential"]
                .as_str()
                .expect("session credential")
                .to_owned(),
        }
    }

    /// One Event by this Account, signed by its founding device.
    fn signed_event(
        &self,
        kind: EventKind,
        scope_ref: ScopeRef,
        payload: Value,
        at: chrono::DateTime<chrono::Utc>,
    ) -> arkret_wire::Event {
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            scope_ref,
            self.actor.clone(),
            payload,
            at,
        )
        .expect("fixture Event");
        coland_test_support::device_authorization_history::sign_event(
            event,
            self.method.clone(),
            self.seed,
        )
    }

    /// Replace the fixture's structural producer proof of `request` with
    /// this Account's device signature.
    fn sign_request(&self, request: &mut EventCommitRequest) {
        let event = coland_test_support::device_authorization_history::sign_event(
            request.authority_commit.event.clone(),
            self.method.clone(),
            self.seed,
        );
        assert_eq!(event.event_id, request.authority_commit.event.event_id);
        request.event.envelope = serde_json::to_value(&event).expect("signed envelope");
        request.authority_commit.event = event;
    }

    fn mls_identity(&self) -> ArkretMlsIdentity {
        ArkretMlsIdentity::new_human_device(
            self.actor.clone(),
            self.device.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(self.key.clone()),
        )
        .expect("device MLS identity")
    }

    async fn post(
        &self,
        state: &AppState,
        path: &str,
        operation: &str,
        body: &impl serde::Serialize,
    ) -> Response {
        let mut response = TestClient::post(format!("http://server{path}"))
            .add_header("authorization", format!("Bearer {}", self.token), true)
            .add_header("arkret-operation", operation, true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(body).expect("canonical body"))
            .send(&service(state.clone()))
            .await;
        Response::take(&mut response).await
    }

    async fn claim(&self, state: &AppState, body: &KeyPackagesClaimRequestBody) -> Response {
        let mut response = TestClient::post("http://server/_arkret/self/keys/keypackages/claim")
            .add_header("authorization", format!("Bearer {}", self.token), true)
            .add_header(
                "arkret-operation",
                arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
                true,
            )
            .add_header("idempotency-key", body.claim_request_id.as_str(), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(body).expect("canonical claim"))
            .send(&service(state.clone()))
            .await;
        Response::take(&mut response).await
    }

    async fn claim_query(&self, state: &AppState, claim_id: &str) -> Response {
        self.post(
            state,
            "/_arkret/self/keys/keypackages/claims/query",
            arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
            &KeyPackagesClaimQueryRequestBody {
                claim_id: arkret_wire::KeypackageClaimId::new(claim_id.to_owned())
                    .expect("claim id"),
            },
        )
        .await
    }

    async fn recipient_queue(&self, state: &AppState) -> DeviceMessagesGetOutcome {
        let mut response = TestClient::get("http://server/_arkret/self/device_messages")
            .add_header("authorization", format!("Bearer {}", self.token), true)
            .add_header(
                "arkret-operation",
                arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
                true,
            )
            .send(&service(state.clone()))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        response.take_json().await.expect("recipient queue page")
    }
}

struct Response {
    status: StatusCode,
    bytes: Vec<u8>,
}

impl Response {
    async fn take(response: &mut salvo::Response) -> Self {
        Self {
            status: response.status_code.expect("status"),
            bytes: response.take_bytes(None).await.expect("body").to_vec(),
        }
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).expect("JSON body")
    }

    fn problem(&self) -> String {
        self.json()["type"]
            .as_str()
            .and_then(|kind| kind.rsplit('/').next())
            .unwrap_or_default()
            .to_owned()
    }
}

/// The ordinary bootstrap unit of a public Realm Alice founds, governed by
/// the Station under test.
/// The governing Station's detached signature over one fixture RealmCommit.
fn commit_signature(
    station_did: &arkret_wire::Did,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        verification_method: arkret_wire::DidUrl::new(format!("{station_did}#authority"))
            .expect("Station method"),
        ..ordinary_realm::signature(
            &arkret_wire::DidCoreId::new("ak:did_core:web:unused.example").unwrap(),
            at,
        )
    }
}

fn seal_fixture_commit(state: &AppState, commit: &mut arkret_wire::RealmCommit) {
    let identity = coland_test_support::fixture_service_identity(state.config());
    let key = SigningKey::from_bytes(&coland_test_support::fixture_signing_seed(
        state.config(),
        &identity,
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_did())).unwrap(),
        commit.committed_at,
        &key,
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
}

fn bootstrap(
    founder: &Member,
    station: &arkret_wire::DidCoreId,
    station_did: &arkret_wire::Did,
) -> OrdinaryRealmBootstrapCommitUnit {
    let at = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
        .expect("fixture time");
    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    );
    let genesis = founder.signed_event(
        EventKind::RealmCreate,
        ScopeRef::RealmGenesis,
        json!({"object":{
            "schema":"ak.schema.realm_genesis.v1",
            "purpose":"collaboration",
            "genesis_salt":salt,
            "trust_domain":"ak:trust_domain:mls-lifecycle.example",
            "security_class":"high_assurance",
            "governance_station_id":station,
            "initial_join_rule":"public",
            "initial_history_access":"since_join",
            "initial_discoverability":"invite_only"
        }}),
        at,
    );
    let realm_id = genesis.realm_id.clone();
    let realm_scope = || ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let mut events = vec![genesis];
    for (kind, payload) in [
        (
            EventKind::RealmProfile,
            json!({"schema":"ak.schema.realm_profile.v1","title":"MLS lifecycle"}),
        ),
        (
            EventKind::RealmPolicyBundle,
            json!({"policy_revision":1,"federation_policy":"closed"}),
        ),
        (EventKind::RealmJoinRule, json!({"value":"public"})),
        (
            EventKind::RealmHistoryAccess,
            json!({"from":null,"to":"since_join"}),
        ),
        (
            EventKind::RealmDiscovery,
            json!({"value":{"discoverability":"invite_only"}}),
        ),
        (
            EventKind::MemberState,
            json!({"member_id":founder.actor,"membership":"join"}),
        ),
    ] {
        events.push(founder.signed_event(kind, realm_scope(), payload, at));
    }
    let authority = CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            events[0].event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let mut previous = None;
    let transactions = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let commit_id = arkret_wire::RealmCommitId::from_digest(
                arkret_canonical::sha256_bytes(format!("{}:{index}", event.event_id).as_bytes()),
            );
            let transaction = AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: event.clone(),
                commit: arkret_wire::RealmCommit {
                    producer_signer_fact_digest: None,
                    commit_id: commit_id.clone(),
                    realm_id: realm_id.clone(),
                    stream_ref: arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    },
                    stream_position: index as u64,
                    previous_commit_ref: previous.clone(),
                    event_ref: event.event_id.clone(),
                    governance_generation: 0,
                    authority_ref: authority.authority_ref.clone(),
                    committed_at: at,
                    signature: commit_signature(station_did, at),
                },
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            };
            previous = Some(commit_id);
            transaction
        })
        .collect();
    let submission = OrdinaryRealmBootstrapUnitSubmission {
        unit_kind: OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
        events: events
            .into_iter()
            .map(arkret_wire::EventAdmissionSubmission::new)
            .collect(),
    };
    let exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(submission.clone()),
    )
    .unwrap();
    OrdinaryRealmBootstrapCommitUnit {
        event_approvals: Vec::new(),
        submission,
        exact_request_body,
        transactions,
    }
}

/// Commit one Event after `previous` through the authority unit of work.
async fn commit_next(
    pool: &PgPool,
    previous: &AuthorityCommitTransaction,
    state: &AppState,
    kind: EventKind,
    actor: &Member,
    mut payload: Value,
    mls_state: Option<MlsStateInstallation>,
) -> EventCommitRequest {
    let label = kind.as_str().to_owned();
    if kind == EventKind::MlsGenesis {
        payload["created_at"] = serde_json::to_value(previous.commit.committed_at).unwrap();
    }
    let mut request = ordinary_realm::next_request_for_actor(
        previous,
        kind,
        actor.actor.clone(),
        payload,
        previous.commit.committed_at,
    );
    actor.sign_request(&mut request);
    request.authority_commit.commit.signature = commit_signature(
        &state.service_did(),
        request.authority_commit.commit.committed_at,
    );
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request.authority_commit.mls_state = mls_state;
    let mut request = Box::pin(ordinary_realm::source_request(pool, request)).await;
    seal_fixture_commit(state, &mut request.authority_commit.commit);
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request.clone())
        .await
        .unwrap_or_else(|error| panic!("commit {label}: {error}"));
    request
}

fn blob_ref(bytes: &[u8]) -> arkret_wire::BlobRef {
    arkret_wire::BlobRef::new(format!(
        "ak:blob:{}",
        arkret_canonical::sha256_digest(bytes)
    ))
    .expect("content-addressed Blob ref")
}

/// A self claim for Bob's device package, signed by Alice's device over the
/// exact request and the local service binding.
fn claim_request(
    requester: &Member,
    target: &Member,
    station: &arkret_wire::DidCoreId,
    realm_id: &RealmId,
    mls_group_id: &str,
    claim_request_id: [u8; 16],
    lifetime: chrono::Duration,
) -> KeyPackagesClaimRequestBody {
    let signed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut body: KeyPackagesClaimRequestBody = serde_json::from_value(json!({
        "claim_request_id": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(claim_request_id),
        "target_account_id": target.account,
        "target_device_ids": [target.device],
        "requester_account_id": requester.account,
        "intended_realm_id": realm_id,
        "mls_group_id": mls_group_id,
        "claim_purpose": "realm_membership",
        "required_capabilities": ["ak.content.v1"],
        "expires_at": arkret_canonical::format_timestamp_canonical(signed_at + lifetime),
        "service_binding": {"source_id": station, "destination_id": station},
        "requester_authorization": {
            "kind": "device",
            "verification_method": requester.method,
            "requester_device_id": requester.device,
            "device_authorize_event_id": requester.authorize_event_id,
            "signed_at": arkret_canonical::format_timestamp_canonical(signed_at),
            "signature": {"kid": requester.method, "signature_algorithm": "Ed25519", "sig": "AA"},
        },
    }))
    .expect("typed claim request");
    let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        &body.requester_authorization,
    )
    .expect("claim authorization transcript");
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut body.requester_authorization
    else {
        unreachable!("the fixture builds the device branch");
    };
    signature.sig = arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(requester.key.sign(&bytes).to_bytes()),
    )
    .expect("signature encoding");
    body
}

async fn station_state(pool: &PgPool) -> (AppState, Arc<dyn PersistenceStore>) {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(PgPersistenceStore::new(pool.clone()));
    let state =
        coland_test_support::app_state_with_persistence(test_config(), persistence.clone()).await;
    (state, persistence)
}

/// Finish native future construction before polling the fixture on the default test stack.
#[inline(never)]
fn heap_future<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

/// Probe the closed upload contract through the registered production router.
async fn assert_closed_upload_boundary(
    client: &Member,
    state: &AppState,
    upload: &arkret_models_crypto::KeyPackagesUploadRequestBody,
    key: &SigningKey,
    database_url: &str,
) -> anyhow::Result<arkret_models_crypto::KeyPackagesUploadRequestBody> {
    let original = serde_json::to_value(upload)?;
    let before = upload_durable_cut(database_url).await?;
    let mut negatives = Vec::new();
    for field in ["pairwise_verification_method", "intended_realm_id"] {
        for value in [Value::Null, json!("retired")] {
            let mut candidate = original.clone();
            candidate[field] = value;
            negatives.push((field.to_owned(), candidate));
        }
    }
    for field in [
        "device_id",
        "agent_verification_method",
        "agent_key_authorize_event_id",
        "expires_at",
        "strand_id",
        "mls_group_id",
    ] {
        let mut candidate = original.clone();
        candidate[field] = Value::Null;
        negatives.push((format!("null_{field}"), candidate));
    }
    let mut mixed = original.clone();
    mixed["device_id"] = serde_json::to_value(&client.device)?;
    mixed["agent_verification_method"] = original["endpoint_signature"]["kid"].clone();
    mixed["agent_key_authorize_event_id"] =
        json!("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM");
    negatives.push(("mixed_authority".to_owned(), mixed));
    let mut no_endpoint = original.clone();
    for field in [
        "device_id",
        "agent_verification_method",
        "agent_key_authorize_event_id",
    ] {
        no_endpoint.as_object_mut().unwrap().remove(field);
    }
    negatives.push(("missing_endpoint".to_owned(), no_endpoint));
    for algorithm in [Value::Null, json!("EdDSA")] {
        let mut candidate = original.clone();
        candidate["endpoint_signature"]["signature_algorithm"] = algorithm;
        negatives.push(("invalid_signature_algorithm".to_owned(), candidate));
    }
    let mut candidate = original.clone();
    candidate["endpoint_signature"]
        .as_object_mut()
        .unwrap()
        .remove("signature_algorithm");
    negatives.push(("missing_signature_algorithm".to_owned(), candidate));
    let mut candidate = original.clone();
    candidate["endpoint_signature"]["sig"] = json!("AA");
    negatives.push(("invalid_signature_bytes".to_owned(), candidate));
    let mut signed_optional = upload.unsigned();
    signed_optional.expires_at = Some(arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::days(3),
    ));
    signed_optional.strand_id = Some(arkret_wire::StrandId::new(
        "ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7",
    )?);
    signed_optional.mls_group_id = Some(
        arkret_wire::MlsGroupId::new("_eWozxgdBxDHaOyjY_q0ZstYlzkfbmcnpTqLf9g2aDQ")
            .map_err(anyhow::Error::msg)?,
    );
    signed_optional.keypackages[0].last_resort = Some(false);
    let signature = arkret_signatures::keypackages::sign_keypackages_upload_request(
        &signed_optional,
        upload.endpoint_signature.kid.as_str(),
        &key.to_bytes(),
    )?;
    let full = serde_json::to_value(signed_optional.into_signed(signature))?;
    for field in ["expires_at", "strand_id", "mls_group_id"] {
        let mut candidate = full.clone();
        candidate.as_object_mut().unwrap().remove(field);
        negatives.push((format!("unsigned_optional_{field}"), candidate));
    }
    let mut candidate = full.clone();
    candidate["keypackages"][0]
        .as_object_mut()
        .unwrap()
        .remove("last_resort");
    negatives.push(("unsigned_entry_last_resort".to_owned(), candidate));
    let mut reversed = original.clone();
    reversed["keypackages"].as_array_mut().unwrap().reverse();
    negatives.push(("reordered_entries".to_owned(), reversed));
    let mut truncated = original.clone();
    truncated["keypackages"].as_array_mut().unwrap().pop();
    negatives.push(("truncated_entries".to_owned(), truncated));
    let mut wrong_station = upload.unsigned();
    wrong_station.actor_id = ActorId::account(AccountId::new(
        upload.principal_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:another-station.example")?,
    ));
    let signature = arkret_signatures::keypackages::sign_keypackages_upload_request(
        &wrong_station,
        upload.endpoint_signature.kid.as_str(),
        &key.to_bytes(),
    )?;
    negatives.push((
        "signed_wrong_station".to_owned(),
        serde_json::to_value(wrong_station.into_signed(signature))?,
    ));
    for (name, candidate) in negatives {
        let response = client
            .post(
                state,
                "/_arkret/self/keys/keypackages/upload",
                arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
                &candidate,
            )
            .await;
        anyhow::ensure!(
            matches!(
                response.status,
                StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "{name} was not refused: {:?} {}",
            response.status,
            String::from_utf8_lossy(&response.bytes)
        );
        anyhow::ensure!(
            upload_durable_cut(database_url).await? == before,
            "{name} wrote durable state"
        );
    }
    Ok(serde_json::from_value(full)?)
}

async fn upload_durable_cut(database_url: &str) -> anyhow::Result<Value> {
    let (client, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls).await?;
    let driver = tokio::spawn(connection);
    let cut: String = client.query_one("SELECT jsonb_build_object('inventory', (SELECT COALESCE(jsonb_agg(to_jsonb(k) ORDER BY id), '[]'::jsonb) FROM mls_key_packages k), 'claims', (SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY source_id, claim_request_id), '[]'::jsonb) FROM peer_keypackage_claims c), 'bindings', (SELECT COALESCE(jsonb_agg(to_jsonb(b)), '[]'::jsonb) FROM keypackage_claim_welcome_bindings b), 'welcomes', (SELECT COALESCE(jsonb_agg(to_jsonb(w)), '[]'::jsonb) FROM mls_welcome_deliveries w))::text", &[]).await?.get(0);
    drop(client);
    driver.await??;
    Ok(serde_json::from_str(&cut)?)
}

#[tokio::test]
async fn mls_lifecycle_runs_over_http_formal_units_and_a_restart() {
    heap_future(mls_lifecycle_body).await;
}

async fn mls_lifecycle_body() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (state, persistence) = station_state(&pool).await;
    let station = state.service_core_id();
    let alice = Member::provision(&state, persistence.as_ref(), "MLS Alice", 1).await;
    let bob = Member::provision(&state, persistence.as_ref(), "MLS Bob", 2).await;

    // The public Realm Alice founds on this Station, and Bob's own join.
    let station_did = state.service_did();
    let mut unit = Box::pin(ordinary_realm::source_bootstrap(
        &pool,
        bootstrap(&alice, &station, &station_did),
    ))
    .await;
    for transaction in &mut unit.transactions {
        seal_fixture_commit(&state, &mut transaction.commit);
    }
    unit.validate().expect("bootstrap unit shape");
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .expect("admit the Realm bootstrap unit");
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let group_id = scope.canonical_mls_group_id().expect("Realm MLS group id");
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let join = commit_next(
        &pool,
        unit.transactions.last().unwrap(),
        &state,
        EventKind::MemberState,
        &bob,
        MembershipPayload::join(realm_id.clone(), bob.actor.clone(), "MLS lifecycle member")
            .to_value()
            .expect("join payload"),
        None,
    )
    .await;

    // Publish: two device packages, and one whose outer label names a suite
    // its bytes do not declare.
    let bob_identity = bob.mls_identity();
    let first = bob_identity.key_package_record().unwrap();
    let second = bob_identity.key_package_record().unwrap();
    let third = bob_identity.key_package_record().unwrap();
    let mut unsigned = bob_identity
        .signed_key_packages_upload_request(
            &[first.clone(), second.clone(), third],
            bob.method.as_str(),
        )
        .unwrap()
        .unsigned();
    // Sign the adversarial outer label with the generated SDK preimage so the
    // HTTP refusal exercises the receiver, not the producer's own validator.
    unsigned.keypackages[2].cipher_suites = vec![RESERVED_SUITE.to_owned()];
    let signing_input = arkret_models_crypto::keypackages_upload_signing_input(&unsigned).unwrap();
    let signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
        bob.method.as_str(),
        &bob.key.sign(&signing_input).to_bytes(),
    )
    .unwrap();
    let upload = unsigned.into_signed(signature);
    let upload = assert_closed_upload_boundary(&bob, &state, &upload, &bob.key, database.url())
        .await
        .unwrap();
    let uploaded = bob
        .post(
            &state,
            "/_arkret/self/keys/keypackages/upload",
            arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
            &upload,
        )
        .await;
    assert_eq!(
        uploaded.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&uploaded.bytes)
    );
    let uploaded: KeyPackagesUploadOutcome = serde_json::from_slice(&uploaded.bytes).unwrap();
    assert_eq!(uploaded.accepted, 2, "{uploaded:?}");
    assert_eq!(uploaded.rejections.len(), 1, "{uploaded:?}");
    assert_eq!(
        uploaded.rejections[0].reason_code.as_str(),
        "unsupported_ciphersuite"
    );

    // Claim: one CAS, exact replay, conflicting reuse, a genuinely new attempt.
    let request = claim_request(
        &alice,
        &bob,
        &station,
        &realm_id,
        group_id.as_str(),
        [0x51; 16],
        chrono::Duration::minutes(4),
    );
    for value in [
        serde_json::Value::Null,
        serde_json::json!("did:key:z6Mkretired#z6Mkretired"),
    ] {
        let before = upload_durable_cut(database.url()).await.unwrap();
        let mut retired = serde_json::to_value(&request).unwrap();
        retired["target_pairwise_verification_method"] = value;
        let rejected = alice
            .post(
                &state,
                "/_arkret/self/keys/keypackages/claim",
                arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
                &retired,
            )
            .await;
        assert_eq!(
            rejected.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            String::from_utf8_lossy(&rejected.bytes)
        );
        assert_eq!(upload_durable_cut(database.url()).await.unwrap(), before);
    }
    let claimed = alice.claim(&state, &request).await;
    assert_eq!(
        claimed.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&claimed.bytes)
    );
    let outcome: KeyPackagesClaimOutcome = serde_json::from_slice(&claimed.bytes).unwrap();
    outcome.validate_shape().unwrap();
    assert_eq!(outcome.claims.len(), 1);
    let claim = outcome.claims[0].clone();
    assert!(
        [
            first.keypackage_ref.to_string(),
            second.keypackage_ref.to_string()
        ]
        .contains(&claim.keypackage_ref)
    );
    assert_eq!(claim.actor_id, bob.actor);
    let replay = alice.claim(&state, &request).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.json(),
        claimed.json(),
        "exact replay is the stored outcome"
    );
    heap_future(|| async {
        let before = upload_durable_cut(database.url()).await.unwrap();
        let cached = state.test_projections().mls_key_package_records();
        let replay = bob
            .post(
                &state,
                "/_arkret/self/keys/keypackages/upload",
                arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
                &upload,
            )
            .await;
        assert_eq!(
            replay.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&replay.bytes)
        );
        assert_eq!(before, upload_durable_cut(database.url()).await.unwrap());
        assert_eq!(
            cached,
            state.test_projections().mls_key_package_records(),
            "publication retry must preserve the real accepted claim in memory"
        );
    })
    .await;
    let conflicting = claim_request(
        &alice,
        &bob,
        &station,
        &realm_id,
        group_id.as_str(),
        [0x51; 16],
        chrono::Duration::minutes(3),
    );
    let conflict = alice.claim(&state, &conflicting).await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    assert_eq!(conflict.problem(), "duplicate_conflict");

    // Claim read (device-lifecycle §9 `claims/query`): Bob's own endpoint reads
    // the byte-identical outcome; the requester and an unknown id read the
    // same `keypackage_unknown`.
    let read = bob.claim_query(&state, &claim.claim_id).await;
    assert_eq!(
        read.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&read.bytes)
    );
    assert_eq!(
        read.bytes, claimed.bytes,
        "the claim read is the stored outcome"
    );
    for refused in [
        alice.claim_query(&state, &claim.claim_id).await,
        bob.claim_query(
            &state,
            &format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7()),
        )
        .await,
    ] {
        assert_eq!(refused.problem(), "keypackage_unknown");
        assert_eq!(refused.status, StatusCode::NOT_FOUND);
    }

    // Genesis: Alice's epoch-0 group with herself as the only leaf.
    let alice_identity = alice.mls_identity();
    let genesis_binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0).unwrap();
    let mut alice_group = alice_identity
        .create_group_with_governance_binding(&scope, &genesis_binding)
        .unwrap();
    let (group_info, tree) = alice_group.public_group_state_bytes().unwrap();
    let tracker = MlsPublicGroupTracker::from_external(&group_info, &tree, group_id.as_str(), 0)
        .expect("Genesis public state");
    let genesis_state = tracker.export_state().unwrap();
    let genesis = commit_next(
        &pool,
        &join.authority_commit,
        &state,
        EventKind::MlsGenesis,
        &alice,
        json!({
            "cipher_suite": ACTIVE_SUITE,
            "group_info_ref": blob_ref(&group_info),
            "ratchet_tree_ref": blob_ref(&tree),
            "creator_leaf_authority": arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
                    arkret_canonical::base64url_encode(alice.key.verifying_key().as_bytes()),
                ).unwrap(),
                endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                    device_id: alice.device.clone(),
                },
                authorization_event_ref: alice.authorize_event_id.clone(),
            },
            "governance_binding": genesis_binding,
            "created_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        }),
        Some(MlsStateInstallation {
            effective_scope: scope.clone(),
            base: None,
            epoch: 0,
            public_state: genesis_state.clone(),
            member_principals: arkret_mls::validate_public_group_state(
                &group_info, &tree, group_id.as_str(), 0,
            ).unwrap().into_iter().map(|leaf| leaf.actor_id).collect(),
            consumed_proposals: Vec::new(),
            public_blobs: Vec::new(),
        }),
    )
    .await;
    alice_group
        .install_local_creator_binding(alice.actor.clone(), Some(alice.authorize_event_id.clone()))
        .unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();

    // The inline Add Commit whose Welcome names the HTTP claim's ledger row.
    let add_binding =
        MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis_ref.clone()), 0, 1, 0)
            .unwrap();
    let claimed_record = arkret_mls::mls_key_package_record_from_claim(&claim).unwrap();
    assert_eq!(claimed_record.actor_id, bob.actor);
    let add = alice_group
        .add_member_with_governance_binding(&claimed_record, &add_binding)
        .unwrap();
    let mut public = MlsPublicGroupTracker::restore(&genesis_state, group_id.as_str(), 0).unwrap();
    public
        .process_public_handshake(
            &arkret_canonical::base64url_decode(add.commit.commit.as_str()).unwrap(),
        )
        .expect("the Add Commit is a valid public transition");
    let ledger = persistence
        .mls_key_packages()
        .get_peer_claim_by_claim_id(&claim.claim_id)
        .await
        .unwrap()
        .expect("the HTTP claim wrote its ledger row");
    let commit_payload =
        MlsCommitPayload::new(genesis_ref.clone(), 0, &add.commit, add_binding).unwrap();
    let mut commit_request = ordinary_realm::next_request_for_actor(
        &genesis.authority_commit,
        EventKind::MlsCommit,
        alice.actor.clone(),
        serde_json::to_value(&commit_payload).unwrap(),
        genesis.authority_commit.commit.committed_at,
    );
    alice.sign_request(&mut commit_request);
    commit_request.authority_commit.commit.signature = commit_signature(
        &station_did,
        commit_request.authority_commit.commit.committed_at,
    );
    let commit_event = commit_request.authority_commit.event.clone();
    let mut welcome = MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: realm_id.clone(),
        effective_scope: scope.clone(),
        commit_event_ref: commit_event.event_id.clone(),
        recipient_actor_id: bob.actor.clone(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: bob.device.clone(),
        },
        keypackage_claim_ref: add.welcome.keypackage_claim_ref.clone(),
        ciphertext_b64: add.welcome.ciphertext_b64.clone(),
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: commit_event
                .producer_proof
                .as_ref()
                .unwrap()
                .verification_method
                .clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap(),
            created_at: commit_request.authority_commit.commit.committed_at,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
        },
    };
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        alice.method.clone(),
        commit_request.authority_commit.commit.committed_at,
        &alice.key,
    )
    .unwrap();
    commit_request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        commit_event.clone(),
    ));
    let current_tree = public.ratchet_tree_bytes().unwrap();
    let current_tree_sha256 = arkret_canonical::sha256_digest(&current_tree)
        .strip_prefix("sha256:")
        .unwrap()
        .to_owned();
    commit_request.authority_commit.mls_state = Some(MlsStateInstallation {
        effective_scope: scope.clone(),
        base: Some(MlsInstalledBase {
            current_mls_commit_event_ref: genesis_ref.clone(),
            epoch: 0,
        }),
        epoch: 1,
        public_state: public.export_state().unwrap(),
        member_principals: Default::default(),
        consumed_proposals: Vec::new(),
        public_blobs: vec![coland_storage::MlsPublicBlob {
            blob_ref: blob_ref(&current_tree),
            sha256: current_tree_sha256.clone(),
            size_bytes: current_tree.len() as i64,
            storage_backend: "local".to_owned(),
            storage_key: format!("sha256/{current_tree_sha256}"),
        }],
    });
    commit_request.authority_commit.welcomes = vec![VerifiedMlsWelcome {
        delivery: welcome.clone(),
        claim: Some(MlsWelcomeClaimLedgerKey {
            source_id: ledger.source_id.clone(),
            claim_request_id: ledger.claim_request_id.clone(),
            request_digest: ledger.request_digest.clone(),
        }),
        applet_device_scope_guard: None,
        roster_witness: None,
    }];
    commit_request.authority_commit.recipient_queue_capacity = 16;
    let mut commit_request = Box::pin(ordinary_realm::source_request(&pool, commit_request)).await;
    seal_fixture_commit(&state, &mut commit_request.authority_commit.commit);
    uow.commit_event(commit_request.clone())
        .await
        .expect("the Add Commit and its Welcome commit together");
    let accepted = arkret_wire::CommittedEventFullView {
        commit: commit_request.authority_commit.commit.clone(),
        event: commit_event.clone(),
    };

    // Bob reads the Welcome from his own queue and joins from it.
    let page = bob.recipient_queue(&state).await;
    let queued = page
        .deliveries
        .iter()
        .filter_map(|delivery| match delivery {
            RecipientDelivery::MlsWelcome { mls_welcome } => Some(mls_welcome.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(queued, vec![welcome.clone()]);
    let mut bob_group =
        ArkretMlsGroup::join_from_verified_welcome_delivery(bob_identity, &welcome, &accepted)
            .expect("Bob joins from the queued Welcome");
    assert_eq!(bob_group.epoch(), 1);
    let base = arkret_wire::MlsGroupCurrent {
        effective_scope: scope.clone(),
        genesis_event_ref: genesis_ref.clone(),
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        current_mls_commit_event_ref: genesis_ref.clone(),
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: blob_ref(&tree),
    };
    assert_eq!(
        alice_group
            .install_accepted_commit(&accepted, &base)
            .unwrap(),
        1
    );
    let header = arkret_models_crypto::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret_wire::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        EventKind::MessageCreate.as_str(),
        1,
        commit_event.event_id.clone(),
        alice_group.local_content_sender_domain().unwrap(),
        arkret_models_crypto::EventContentRoutingContext::None,
    )
    .unwrap();
    let sealed =
        arkret_mls::MessageCrypto::encrypt(&mut alice_group, "mls-lifecycle", header, b"epoch 1")
            .unwrap();
    assert_eq!(
        arkret_mls::MessageCrypto::decrypt(&mut bob_group, &sealed).unwrap(),
        b"epoch 1"
    );

    // ACK first: consume reads the claim's Welcome binding, never the queue
    // row, so it has no order against the ACK (decision 0121).
    let ack_token = page
        .ack_token
        .clone()
        .expect("a non-empty page carries its ack token");
    let acked = bob
        .post(
            &state,
            "/_arkret/self/device_messages/ack",
            arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
            &DeviceMessagesAckRequestBody { ack_token },
        )
        .await;
    assert_eq!(acked.status, StatusCode::OK);

    // Consume after the durable group state: a receipt naming another digest
    // or epoch than the bound Welcome is `conflict` and the claim stays live;
    // the exact receipt consumes it and replays byte-identically.
    let signer = bob.mls_identity();
    let consume = |welcome_digest: arkret_wire::Hash, mls_epoch: u64| {
        let receipt = arkret_models_crypto::RecipientMlsDurableReceipt {
            domain: arkret_wire::NonEmptyString::new(
                arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
            )
            .unwrap(),
            claim_request_id: request.claim_request_id.clone(),
            key_package_ref: arkret_wire::NonEmptyString::new(claim.keypackage_ref.clone())
                .unwrap(),
            recipient: arkret_models_crypto::RecipientMlsDurableSigner::Device {
                recipient_account_id: bob.account.clone(),
                recipient_device_id: bob.device.clone(),
                device_verification_method: bob.method.clone(),
            },
            recipient_id: station.clone(),
            realm_id: realm_id.clone(),
            mls_group_id: group_id.clone(),
            mls_epoch,
            welcome_ref: welcome.welcome_id.clone(),
            welcome_digest,
            durable_at: chrono::Utc::now(),
            signature: arkret_models_crypto::KeyOperationSignature {
                kid: arkret_wire::NonEmptyString::new(bob.method.to_string()).unwrap(),
                signature_algorithm: None,
                sig: arkret_wire::Base64UrlString::new("AA".to_owned()).unwrap(),
            },
        };
        signer
            .signed_key_packages_consume_request(
                arkret_wire::KeypackageClaimId::new(claim.claim_id.clone()).unwrap(),
                signer.sign_recipient_mls_durable_receipt(receipt).unwrap(),
            )
            .unwrap()
    };
    let digest = welcome.durable_receipt_digest().unwrap();
    for value in [
        serde_json::Value::Null,
        serde_json::json!("did:key:z6Mkretired#z6Mkretired"),
    ] {
        let before = upload_durable_cut(database.url()).await.unwrap();
        let mut retired = serde_json::to_value(consume(digest.clone(), 1)).unwrap();
        retired["recipient_durable_receipt"]["recipient_pairwise_verification_method"] = value;
        let rejected = bob
            .post(
                &state,
                "/_arkret/self/keys/keypackages/consume",
                arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
                &retired,
            )
            .await;
        assert_eq!(
            rejected.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            String::from_utf8_lossy(&rejected.bytes)
        );
        assert_eq!(upload_durable_cut(database.url()).await.unwrap(), before);
    }
    for (name, tampered) in [
        (
            "welcome_digest",
            consume(
                arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap(),
                1,
            ),
        ),
        ("mls_epoch", consume(digest.clone(), 2)),
    ] {
        let refused = bob
            .post(
                &state,
                "/_arkret/self/keys/keypackages/consume",
                arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
                &tampered,
            )
            .await;
        assert_eq!(refused.status, StatusCode::CONFLICT, "{name}");
        assert_eq!(refused.problem(), "conflict", "{name}");
        let ledger = persistence
            .mls_key_packages()
            .get_peer_claim_by_claim_id(&claim.claim_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ledger.state, "claimed", "{name} left the claim live");
    }
    let exact = consume(digest, 1);
    let consumed = bob
        .post(
            &state,
            "/_arkret/self/keys/keypackages/consume",
            arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
            &exact,
        )
        .await;
    assert_eq!(
        consumed.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&consumed.bytes)
    );
    let outcome: arkret_models_crypto::KeyPackagesConsumeOutcome =
        serde_json::from_slice(&consumed.bytes).unwrap();
    assert_eq!(
        outcome.consume_receipt.claim_id.as_str(),
        claim.claim_id.as_str()
    );
    let replayed = bob
        .post(
            &state,
            "/_arkret/self/keys/keypackages/consume",
            arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
            &exact,
        )
        .await;
    assert_eq!(replayed.status, StatusCode::OK);
    assert_eq!(
        replayed.bytes, consumed.bytes,
        "an exact consume replay returns the first receipt"
    );
    drop(state);

    // Restart: a new Station process over the same database.
    let (restarted, restarted_persistence) = station_state(&pool).await;
    let replay = alice.claim(&restarted, &request).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.json(),
        claimed.json(),
        "the claim ledger replays its stored outcome after restart"
    );
    let conflict = alice.claim(&restarted, &conflicting).await;
    assert_eq!(conflict.problem(), "duplicate_conflict");
    let replayed = bob
        .post(
            &restarted,
            "/_arkret/self/keys/keypackages/consume",
            arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
            &exact,
        )
        .await;
    assert_eq!(
        replayed.bytes, consumed.bytes,
        "the durable consume receipt replays after restart"
    );
    let read = bob.claim_query(&restarted, &claim.claim_id).await;
    assert_eq!(
        read.bytes, claimed.bytes,
        "the claim read survives restart and stays read-only"
    );
    let current = restarted_persistence
        .mls_groups()
        .current(&scope)
        .await
        .unwrap()
        .expect("the scope's MLS current survives restart");
    assert_eq!(current.value.epoch, 1);
    assert_eq!(
        current.value.current_mls_commit_event_ref,
        commit_event.event_id
    );
    assert_eq!(current.value.genesis_event_ref, genesis_ref);
    let page = bob.recipient_queue(&restarted).await;
    assert!(
        page.deliveries
            .iter()
            .all(|delivery| !matches!(delivery, RecipientDelivery::MlsWelcome { .. })),
        "the ACKed Welcome is not delivered again after restart"
    );
}
