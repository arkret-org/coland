//! Account data writes use a caller-signed actor-private Event on an accepted
//! PCR. The fixture never inserts an uncommitted Event as accepted state.

use arkret_wire::{EventKind, ScopeRef};
use coland_http::config::AppConfig;
use coland_http::service;
use coland_http::state::AppState;
use coland_test_support::AppStateTestExt as _;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

const ACCOUNT_DATA_PATH: &str = "/_arkret/self/account_data/ak.push_rules";

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some("fixture-registration".to_owned()),
        ..coland_test_support::app_config()
    }
}

async fn account_session(state: &AppState, fixture: &PcrGenesisFixture) -> String {
    fixture.admit(state).await.expect("durable PCR genesis");
    let app = service(state.clone());
    let mut registration = TestClient::post("http://server/_coland/gate/account/project")
        .add_header("authorization", "Bearer fixture-registration", true)
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(&json!({
                "principal_id": fixture.history.account.principal_id,
                "did": fixture.history.did,
                "display_name": "Account Data fixture",
            }))
            .unwrap(),
        )
        .send(&app)
        .await;
    let status = registration.status_code;
    let body = registration.take_string().await;
    assert!(
        matches!(status, Some(StatusCode::OK | StatusCode::CONFLICT)),
        "account projection: {body:?}"
    );
    let mut login = TestClient::post("http://server/_coland/gate/auth/dev-login")
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(&json!({
                "actor": fixture.history.account.principal_id,
                "device_id": fixture.history.founding_device_id,
                "display_name": "Account Data fixture",
            }))
            .unwrap(),
        )
        .send(&app)
        .await;
    assert_eq!(login.status_code, Some(StatusCode::OK));
    let body: Value = login.take_json().await.expect("dev-login JSON");
    body["session_credential"]
        .as_str()
        .expect("session credential")
        .to_owned()
}

fn signed_account_data_event(
    state: &AppState,
    fixture: &PcrGenesisFixture,
    key: &str,
) -> arkret_wire::Event {
    let actor = arkret_wire::ActorId::account(fixture.history.account.clone());
    let encrypted = arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
        &[7; 32],
        &actor,
        key,
        &json!({"enabled": true}),
        [9; 24],
    )
    .expect("encrypted account data value");
    let realm_id = fixture.unit.transactions[0].event.realm_id.clone();
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::AccountDataSet.as_str(),
        ScopeRef::Realm { realm_id },
        fixture.history.account.principal_id.clone(),
        state.service_core_id(),
        json!({
            "key": key,
            "expected_server_revision": 0,
            "body": encrypted,
            "updated_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        }),
        chrono::Utc::now(),
    )
    .expect("typed account data Event");
    coland_test_support::signed_event::sign_fixture_event(
        event,
        fixture.history.did.as_str(),
        fixture.history.founding_device_id.as_str(),
        fixture.history.founding_device_signing_seed,
    )
}

fn signed_account_data_tombstone(
    state: &AppState,
    fixture: &PcrGenesisFixture,
    key: &str,
    expected_revision: u64,
) -> arkret_wire::Event {
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::AccountDataSet.as_str(),
        ScopeRef::Realm {
            realm_id: fixture.unit.transactions[0].event.realm_id.clone(),
        },
        fixture.history.account.principal_id.clone(),
        state.service_core_id(),
        json!({
            "key": key,
            "expected_server_revision": expected_revision,
            "tombstone": true,
        }),
        chrono::Utc::now(),
    )
    .expect("typed account data tombstone Event");
    coland_test_support::signed_event::sign_fixture_event(
        event,
        fixture.history.did.as_str(),
        fixture.history.founding_device_id.as_str(),
        fixture.history.founding_device_signing_seed,
    )
}

async fn spawn_account_status_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("introspection mock binds");
    let address = listener.local_addr().expect("introspection mock address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut expected = None;
                loop {
                    let mut chunk = [0_u8; 2048];
                    let read = stream
                        .read(&mut chunk)
                        .await
                        .expect("read introspection request");
                    assert!(read > 0, "introspection request ended early");
                    request.extend_from_slice(&chunk[..read]);
                    if expected.is_none()
                        && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&request[..index]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        expected = Some(index + 4 + length);
                    }
                    if expected.is_some_and(|total| request.len() >= total) {
                        break;
                    }
                }
                let split = request
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .unwrap();
                let body = if String::from_utf8_lossy(&request[..split])
                    .starts_with("POST /_arkret/peer/account-status/resolve ")
                {
                    let query: Value = serde_json::from_slice(&request[split + 4..]).unwrap();
                    serde_json::to_vec(&json!({"account_authority_id":query["account_authority_id"], "account_id":query["account_id"], "records":[], "has_more":false})).unwrap()
                } else {
                    panic!("component peer only implements registered account status resolution")
                };
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            });
        }
    });
    format!("http://{address}")
}

struct GrantSession {
    state: AppState,
    token: String,
    holder_key: SigningKey,
    authority: std::sync::Arc<coland_test_support::account_authority::ComponentAccountAuthority>,
}

async fn account_grant_session(fixture: &PcrGenesisFixture) -> GrantSession {
    account_grant_session_at(fixture, None).await
}

async fn account_grant_session_at(
    fixture: &PcrGenesisFixture,
    base: Option<String>,
) -> GrantSession {
    let holder_key = SigningKey::from_bytes(&Sha256::digest(b"account-data-sync").into());
    let token = format!("account-data-grant.{}", uuid::Uuid::now_v7().simple());
    let holder_jwk =
        arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&holder_key.verifying_key());
    let cnf_jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&holder_jwk).expect("holder jkt");
    let device_id = fixture.history.founding_device_id.clone();
    let outcome = json!({
        "active": true,
        "status": "active",
        "proof_required": false,
        "one_time_use_consumed": false,
        "grant": {
            "id": arkret_identifiers::SessionGrantId::from_issuance_digest(
                Sha256::digest(token.as_bytes()).into(),
            ),
            "issuer_id": fixture.history.account.station_id,
            "account_id": fixture.history.account,
            "device_id": device_id,
            "audience_id": fixture.history.account.station_id,
            "scopes": [
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_GET_V1,
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_DELETE_V1,
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_READ_LIST_V1,
                "ak.self.realm.resource.get.v1",
                "ak.self.realm.read.export.v1",
                "ak.self.realm_link.read.list.v1",
                "ak.self.read_cursor.command.advance.v1",
                "ak.self.read_cursor.read.list.v1",
            ],
            "expires_at": arkret_canonical::format_timestamp_canonical(
                chrono::Utc::now() + chrono::Duration::minutes(5),
            ),
            "revocation_ref": format!("ak:session:{}", uuid::Uuid::now_v7().simple()),
            "session_public_key": format!(
                "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
                arkret_canonical::base64url_encode(holder_key.verifying_key().to_bytes()),
            ),
            "cnf_jkt": cnf_jkt,
            "credential_class": "standard",
            "holder_binding": {"kind": "human_device", "device_binding": device_id},
            "device_binding": {
                "device_id": device_id,
                "authorization_event_id": fixture.history.events[1].event_id,
                "model_generation_ref": 1,
            },
        }
    });
    let origin = spawn_account_status_mock().await;
    let mut config = test_config();
    if let Some(base) = base {
        config.public_base_url = base;
    }
    config.account_authority_url = Some(origin);
    config.register_test_internal_authority_channel("account-data-sync".to_owned());
    let state = coland_test_support::app_state(config);
    let authority =
        coland_test_support::account_authority::ComponentAccountAuthority::from_json_slot(
            state.service_core_id(),
            std::sync::Arc::new(std::sync::Mutex::new(outcome)),
        );
    let state = state
        .with_local_account_authority(authority.clone())
        .unwrap();
    fixture.admit(&state).await.expect("accepted PCR genesis");
    state
        .test_persistence()
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: fixture.history.account.principal_id.clone(),
            station_id: state.service_core_id(),
            localpart: format!("account-data-{}", uuid::Uuid::now_v7().simple()),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("seed Account for grant lookup");
    GrantSession {
        state,
        token,
        holder_key,
        authority,
    }
}

/// Exercise the public SDK over TCP against the production router and real PG.
/// Service-owned cells have no holder Event and must still be enumerable.
#[tokio::test]
async fn sdk_lists_live_cas_only_and_encrypted_registers_without_disclosing_internal_or_other_holder_rows()
 {
    use salvo::conn::Listener;
    let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0")
        .try_bind()
        .await
        .unwrap();
    let address = acceptor.local_addr().unwrap();
    let base = format!("http://{address}");
    let mut config = test_config();
    config.public_base_url = base.clone();
    let service_did = coland_test_support::fixture_service_identity(&config)
        .identity()
        .unwrap()
        .did
        .clone();
    let fixture = PcrGenesisFixture::new(service_did);
    let session = account_grant_session_at(&fixture, Some(base.clone())).await;
    let persistence = session.state.test_persistence();
    let holder = arkret_wire::ActorId::account(fixture.history.account.clone()).to_string();
    let other = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        fixture.history.account.station_id.clone(),
    ))
    .to_string();
    let now = chrono::Utc::now();
    for (actor, key, tombstone) in [
        (holder.as_str(), "ak.account.invite_delivery", false),
        (holder.as_str(), "ak.account.holder_quarantine", true),
        (holder.as_str(), "ak.internal.test", false),
        (other.as_str(), "ak.account.invite_delivery", false),
    ] {
        persistence
            .account_data()
            .compare_and_set(
                &coland_storage::AccountDataRecord {
                    actor: actor.into(),
                    account_data_key: key.into(),
                    revision: 1,
                    payload: if key == "ak.account.invite_delivery" {
                        serde_json::to_value(
                            arkret_models_collaboration::governance::invite_addressing::InviteDelivery::new(now, Vec::new()),
                        ).unwrap()
                    } else { Value::Null },
                    tombstone,
                    updated_at: now,
                },
                0,
            )
            .await
            .unwrap();
    }
    let event = signed_account_data_event(&session.state, &fixture, "ak.push_rules");
    let (status, _) = session
        .request(
            "PUT",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            Some(json!({"set_event":arkret_wire::EventAdmissionSubmission::new(event.clone())})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let position = persistence
        .account_data()
        .latest_change_position(&holder)
        .await
        .unwrap();
    let state = session.state.clone();
    let server = tokio::spawn(async move {
        salvo::Server::new(acceptor).serve(service(state)).await;
    });
    let token = session.token.clone();
    let key = session.holder_key.clone();
    let client = arkret_http_client::Client::builder(url::Url::parse(&base).unwrap())
        .allow_insecure_localhost()
        .auth(arkret_http_client::Auth::Dpop(
            arkret_http_client::DpopAuth::with_dpop_token(token.clone(), move |request| {
                arkret_signatures::dpop::build_dpop_proof(&request, &key)
                    .map(|proof| proof.header_value)
                    .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
            }),
        ))
        .build()
        .unwrap();
    for _ in 0..2 {
        let list = client.account_data_list().await.unwrap();
        assert_eq!(list.account_data_entries.len(), 2, "{list:?}");
        let cas = list
            .account_data_entries
            .iter()
            .find(|row| row.account_data_key == "ak.account.invite_delivery")
            .unwrap();
        let read = client
            .account_data_get(&cas.account_data_key)
            .await
            .unwrap();
        assert_eq!(&read, cas);
        let encrypted = list
            .account_data_entries
            .iter()
            .find(|row| row.account_data_key == "ak.push_rules")
            .unwrap();
        assert_eq!(encrypted.content, event.payload["body"]);
        assert_eq!(encrypted.revision, 1);
    }
    assert_eq!(
        persistence
            .account_data()
            .latest_change_position(&holder)
            .await
            .unwrap(),
        position
    );
    server.abort();
    let _ = server.await;
}

impl GrantSession {
    async fn request(
        &self,
        method: &str,
        operation: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.request_path(method, ACCOUNT_DATA_PATH, operation, body)
            .await
    }

    async fn request_path(
        &self,
        method: &str,
        path: &str,
        operation: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let htu = format!(
            "{}{}",
            self.state.config().public_base_url.trim_end_matches('/'),
            path.split('?').next().unwrap()
        );
        let proof = arkret_signatures::dpop::build_dpop_proof(
            &arkret_signatures::dpop::DpopProofRequest::new(method, htu)
                .access_token(self.token.clone()),
            &self.holder_key,
        )
        .expect("DPoP proof builds");
        let url = format!("http://server{path}");
        let request = match method {
            "PUT" => TestClient::put(url),
            "DELETE" => TestClient::delete(url),
            "GET" => TestClient::get(url),
            "POST" => TestClient::post(url),
            _ => panic!("unexpected method"),
        }
        .add_header("authorization", format!("DPoP {}", self.token), true)
        .add_header("dpop", proof.header_value, true)
        .add_header("Arkret-Operation", operation, true);
        let request = if let Some(body) = body {
            request
                .add_header("content-type", "application/json", true)
                .body(arkret_canonical::canonical_json_bytes(&body).unwrap())
        } else {
            request
        };
        let mut response = request.send(&service(self.state.clone())).await;
        let status = response.status_code.expect("HTTP status");
        let body = response.take_json().await.expect("JSON body");
        (status, body)
    }
}

/// The PCR genesis is admitted as a two-Event/two-RealmCommit authority unit;
/// only its authorized founding device signs these actor-private Events.
/// The resource handlers must preserve the exact retry, revision CAS and
/// tombstone visibility rules over that accepted producer history.
#[tokio::test]
async fn signed_account_data_round_trip_enforces_cas_and_tombstone() {
    let service_did = coland_test_support::fixture_service_identity(&test_config())
        .identity()
        .expect("fixture Station identity")
        .did
        .clone();
    let fixture = PcrGenesisFixture::new(service_did);
    let session = account_grant_session(&fixture).await;
    let key = arkret_wire::AccountDataKey::PUSH_RULES;
    let set = signed_account_data_event(&session.state, &fixture, key);
    let body = serde_json::to_value(
        arkret_models_identity::account::AccountDataReplaceRequestBody {
            set_event: arkret_wire::EventAdmissionSubmission::new(set.clone()),
        },
    )
    .unwrap();
    let (status, created) = session
        .request(
            "PUT",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["revision"], 1, "{created}");
    assert_eq!(created["content"], set.payload["body"], "{created}");

    let (status, replay) = session
        .request(
            "PUT",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["revision"], 1, "{replay}");
    assert_eq!(replay["content"], created["content"], "{replay}");

    let stale = signed_account_data_event(&session.state, &fixture, key);
    let (status, conflict) = session
        .request(
            "PUT",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            Some(
                serde_json::to_value(
                    arkret_models_identity::account::AccountDataReplaceRequestBody {
                        set_event: arkret_wire::EventAdmissionSubmission::new(stale),
                    },
                )
                .unwrap(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(
        conflict["type"].as_str().and_then(|v| v.rsplit('/').next()),
        Some("cas_conflict"),
        "{conflict}"
    );

    let (status, read) = session
        .request(
            "GET",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_GET_V1,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["revision"], 1, "{read}");
    assert_eq!(read["content"], created["content"], "{read}");

    let tombstone = signed_account_data_tombstone(&session.state, &fixture, key, 1);
    let (status, deleted) = session
        .request(
            "DELETE",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_DELETE_V1,
            Some(
                serde_json::to_value(
                    arkret_models_identity::account::AccountDataDeleteRequestBody {
                        set_event: arkret_wire::EventAdmissionSubmission::new(tombstone),
                    },
                )
                .unwrap(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(deleted["revision"], 2, "{deleted}");

    let (status, missing) = session
        .request(
            "GET",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_GET_V1,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
    assert_eq!(missing["current_revision"], 2, "{missing}");
}

/// `device-lifecycle.md` §10.1: a verified device_summary's provenance is
/// exactly `verification_source` plus `authorized_event_ref`, so the account
/// projection returns the verified founding device instead of failing closed.
#[tokio::test]
async fn verified_device_summary_carries_only_authorization_provenance() {
    let state = coland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    fixture.admit(&state).await.expect("durable PCR genesis");
    let app = service(state.clone());
    let mut projection = TestClient::post("http://server/_coland/gate/account/project")
        .add_header("authorization", "Bearer fixture-registration", true)
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(&json!({
                "principal_id": fixture.history.account.principal_id,
                "did": fixture.history.did,
                "display_name": "Device summary fixture",
            }))
            .unwrap(),
        )
        .send(&app)
        .await;
    let status = projection.status_code;
    let body: Value = projection
        .take_json()
        .await
        .expect("account projection JSON");
    assert_eq!(status, Some(StatusCode::OK), "account projection: {body}");
    let device = body["devices"]
        .as_array()
        .expect("account projection devices")
        .iter()
        .find(|device| device["device_id"] == fixture.history.founding_device_id.as_str())
        .unwrap_or_else(|| panic!("the founding device is listed: {body}"));
    assert_eq!(device["verification_state"], "verified", "{device}");
    assert!(device["verification_source"].is_string(), "{device}");
    assert!(
        device["authorized_event_ref"]
            .as_str()
            .is_some_and(|reference| reference.starts_with("ak:event:")),
        "{device}"
    );
    assert!(
        device.get("signer_resolution_evidence_ref").is_none(),
        "device_summary carries no signer evidence reference: {device}"
    );
}

/// An account-data write is an actor-private Event whose producer is the
/// holder's device under a standard DPoP SessionGrant. A development bearer
/// session binds no device grant, so it cannot produce the Event and nothing
/// is stored. The admitted path runs live in Cotest `protocol_payloads`.
#[tokio::test]
async fn development_bearer_session_cannot_produce_account_data_events() {
    let state = coland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    let token = account_session(&state, &fixture).await;
    let app = service(state.clone());
    let key = arkret_wire::AccountDataKey::PUSH_RULES;
    let event = signed_account_data_event(&state, &fixture, key);
    let mut response = TestClient::put(format!("http://server/_arkret/self/account_data/{key}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            true,
        )
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(
                &arkret_models_identity::account::AccountDataReplaceRequestBody {
                    set_event: arkret_wire::EventAdmissionSubmission::new(event),
                },
            )
            .unwrap(),
        )
        .send(&app)
        .await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::FORBIDDEN), "{body}");
    let actor = arkret_wire::ActorId::account(fixture.history.account.clone()).to_string();
    assert!(
        state
            .test_persistence()
            .account_data()
            .get(&actor, key)
            .await
            .expect("account data read")
            .is_none(),
        "a refused producer writes nothing"
    );
}

#[tokio::test]
async fn account_data_write_rejects_another_actors_signed_event() {
    let service_did = coland_test_support::fixture_service_identity(&test_config())
        .identity()
        .unwrap()
        .did
        .clone();
    let holder = PcrGenesisFixture::new(service_did);
    let session = account_grant_session(&holder).await;
    let other = PcrGenesisFixture::new(session.state.service_did());
    other
        .admit(&session.state)
        .await
        .expect("second accepted PCR");
    let key = arkret_wire::AccountDataKey::PUSH_RULES;
    let event = signed_account_data_event(&session.state, &other, key);
    let (status, body) = session
        .request(
            "PUT",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            Some(
                serde_json::to_value(
                    arkret_models_identity::account::AccountDataReplaceRequestBody {
                        set_event: arkret_wire::EventAdmissionSubmission::new(event),
                    },
                )
                .unwrap(),
            ),
        )
        .await;
    assert!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST),
        "holder isolation must reject a different actor's Event: {body}"
    );
    for account in [&holder.history.account, &other.history.account] {
        assert!(
            session
                .state
                .test_persistence()
                .account_data()
                .get(
                    &arkret_wire::ActorId::account(account.clone()).to_string(),
                    key
                )
                .await
                .unwrap()
                .is_none(),
            "holder isolation refuses before writing either account"
        );
    }
}

#[tokio::test]
async fn signed_read_cursor_round_trip_replays_without_entering_the_realm_log() {
    let service_did = coland_test_support::fixture_service_identity(&test_config())
        .identity()
        .unwrap()
        .did
        .clone();
    let fixture = PcrGenesisFixture::new(service_did);
    let session = account_grant_session(&fixture).await;
    let persistence = session.state.test_persistence();
    let mut unit = ordinary_realm::bootstrap_unit_for_account(
        &format!("read-cursor-{}", uuid::Uuid::now_v7()),
        &fixture.history.account,
        &session.state.service_did(),
    );
    let identity = coland_test_support::fixture_service_identity(session.state.config());
    let station_key = SigningKey::from_bytes(&coland_test_support::fixture_signing_seed(
        session.state.config(),
        &identity,
    ));
    let mut previous = None;
    // Freeze the real device source before signing each final Station Commit.
    for (index, transaction) in unit.transactions.iter_mut().enumerate() {
        transaction.event.producer_proof = None;
        transaction.event = coland_test_support::signed_event::sign_fixture_event(
            transaction.event.clone(),
            fixture.history.did.as_str(),
            fixture.history.founding_device_id.as_str(),
            fixture.history.founding_device_signing_seed,
        );
        transaction.producer_signer_fact = persistence
            .authority_commits()
            .prepare_account_device_signer_fact(&transaction.event, transaction.commit.committed_at)
            .await
            .unwrap()
            .map(Into::into);
        assert!(transaction.producer_signer_fact.is_some());
        transaction.commit.producer_signer_fact_digest = transaction
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        transaction.commit.previous_commit_ref = previous;
        transaction.commit.commit_id =
            arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(
                    &arkret_canonical::canonical::unsigned_value(
                        &transaction.commit,
                        &["commit_id", "signature"],
                    )
                    .unwrap(),
                )
                .unwrap(),
            ));
        transaction.commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::canonical::unsigned_value(&transaction.commit, &["signature"])
                .unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            arkret_wire::DidUrl::new(format!("{}#notary-key", session.state.service_did()))
                .unwrap(),
            transaction.commit.committed_at,
            &station_key,
        )
        .unwrap();
        previous = Some(transaction.commit.commit_id.clone());
        unit.submission.events[index] =
            arkret_wire::EventAdmissionSubmission::new(transaction.event.clone());
    }
    unit.exact_request_body = arkret_canonical::canonical_json_bytes(
        &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(
            unit.submission.clone(),
        ),
    )
    .unwrap();
    unit.validate().unwrap();
    persistence
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let initial = unit.transactions.last().unwrap();
    let realm_id = initial.event.realm_id.clone();
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::ReadCursorAdvance.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        fixture.history.account.principal_id.clone(),
        session.state.service_core_id(),
        json!({
            "schema":"ak.schema.read_cursor.v1",
            "actor_id":arkret_wire::ActorId::account(fixture.history.account.clone()),
            "device_id":fixture.history.founding_device_id, "realm_id":realm_id,
            "read_scope":{"kind":"realm"},
            "position":{"event_id":initial.event.event_id,"hlc":"019041000000-0001-1dae0001"},
        }),
        chrono::Utc::now(),
    )
    .unwrap();
    let event = coland_test_support::signed_event::sign_fixture_event(
        event,
        fixture.history.did.as_str(),
        fixture.history.founding_device_id.as_str(),
        fixture.history.founding_device_signing_seed,
    );
    let advance_id = event.event_id.clone();
    let created_at = arkret_canonical::format_timestamp_canonical(event.created_at);
    let body = arkret_models_collaboration::objects::read_receipts::ReadCursorAdvanceRequestBody {
        advance_event: arkret_wire::EventAdmissionSubmission::new(event),
    };
    let body = serde_json::to_value(body).unwrap();
    let (status, first) = session
        .request_path(
            "POST",
            "/_arkret/self/read-cursors",
            "ak.self.read_cursor.command.advance.v1",
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(
        first["position"]["event_id"],
        initial.event.event_id.as_str()
    );
    assert_eq!(first["updated_at"], created_at);
    let (status, replay) = session
        .request_path(
            "POST",
            "/_arkret/self/read-cursors",
            "ak.self.read_cursor.command.advance.v1",
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay, first);
    let (status, list) = session
        .request_path(
            "GET",
            &format!("/_arkret/self/read-cursors?realm_id={realm_id}"),
            "ak.self.read_cursor.read.list.v1",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["markers"], json!([first]));
    let stream = arkret_wire::CommitStreamRef::Realm { realm_id };
    assert_eq!(
        persistence
            .authority_commits()
            .stream_head(&stream)
            .await
            .unwrap()
            .unwrap()
            .commit_id,
        initial.commit.commit_id
    );
    assert!(
        persistence
            .events()
            .get(advance_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        persistence
            .authority_commits()
            .committed_event(&advance_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[path = "realm_read_cases/mod.rs"]
mod realm_read_cases;

mod organization_registration_cases;
