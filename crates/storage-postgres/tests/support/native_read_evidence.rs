//! Archive actual successful reads only after their native assertions pass.
//!
//! This is a test transcript, not a protocol DTO or a source of authority.
//! Signatures are verified at the recorded capture cut; replay is archival.
use super::*;

tokio::task_local! {
    static READ_EVIDENCE: Arc<Mutex<BTreeMap<String, Value>>>;
}

pub(super) fn recording() -> bool {
    READ_EVIDENCE.try_with(|_| ()).is_ok()
}

pub(super) fn pcr_originals(pcr: &PcrGenesisFixture) -> Value {
    pcr.unit.validate().unwrap();
    let committed = pcr
        .unit
        .transactions
        .iter()
        .map(|tx| arkret_wire::CommittedEventFullView {
            event: tx.event.clone(),
            commit: tx.commit.clone(),
        })
        .collect::<Vec<_>>();
    json!({"admission_input":pcr.unit.submission,
        "exact_request_body_base64url":arkret_canonical::base64url_encode(&pcr.unit.exact_request_body),
        "committed_events":committed})
}

fn accepted_original(accepted: &coland_storage::CommittedEventRecord) -> Value {
    json!(arkret_wire::CommittedEventFullView {
        event: accepted.event.clone(),
        commit: accepted.commit.clone()
    })
}

pub(super) async fn peer_read(
    source: &Fixture,
    destination: &Fixture,
    path: &str,
    operation: arkret_wire::ServiceOperationId,
    body: &Value,
) -> Value {
    let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let digest = format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&bytes))
    );
    let url = format!(
        "{}{path}",
        destination
            .state
            .config()
            .public_base_url
            .trim_end_matches('/')
    );
    let target = Url::parse(&url).unwrap();
    let parts = SignedRequestParts {
        method: "POST".into(),
        target_uri: url.clone(),
        authority: target[url::Position::BeforeHost..url::Position::AfterPort].into(),
        path: path.into(),
        headers: vec![
            ("arkret-operation".into(), operation.to_string()),
            ("content-type".into(), "application/json".into()),
            ("content-digest".into(), digest.clone()),
            ("source-service-id".into(), source.state.service_id().into()),
            (
                "destination-service-id".into(),
                destination.state.service_id().into(),
            ),
            (
                "source-trust-domain".into(),
                source.state.config().trust_domain.to_string(),
            ),
            (
                "destination-trust-domain".into(),
                destination.state.config().trust_domain.to_string(),
            ),
        ],
        body_digest: Some(digest),
    };
    let signed = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::ServiceToServiceV1,
        &[
            "content-digest",
            "source-trust-domain",
            "destination-trust-domain",
        ],
        "sig1",
        source
            .state
            .service_verification_method("notary-key")
            .unwrap()
            .as_str(),
        chrono::Utc::now().timestamp(),
        source.state.notary_signing_key().as_ref(),
    )
    .unwrap();
    let client = realm_native_fixture::native_http_client(std::time::Duration::from_secs(30));
    let mut request = client.post(url);
    for (name, value) in parts.headers {
        request = request.header(name, value);
    }
    let response = request
        .header("signature-input", signed.signature_input_header)
        .header("signature", signed.signature_header)
        .body(bytes)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    assert_eq!(status.as_u16(), 200, "{}: {value}", operation.as_str());
    value
}

pub(super) fn capture(
    operation: arkret_wire::ServiceOperationId,
    method: &str,
    path: &str,
    request: Option<Value>,
    response: Value,
    originals: Value,
) {
    let _ = READ_EVIDENCE.try_with(|records| {
        assert!(response.is_object(), "a successful object body is required");
        assert!(!originals.is_null(), "accepted originals must be explicit");
        validate_original_addresses(&originals);
        let record = json!({
            "operation_id":operation,"method":method,"path":path,
            "request_body":request,"response_body":response,
            "verified_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            "accepted_originals":originals,
        });
        let mut records = records.lock().unwrap();
        if !records.contains_key(operation.as_str()) {
            eprintln!("native read captured: {}", operation.as_str());
        }
        records.entry(operation.to_string()).or_insert(record);
    });
}

fn validate_original_addresses(value: &Value) {
    match value {
        Value::Object(fields) => {
            if fields.len() == 2 && fields.contains_key("event") && fields.contains_key("commit") {
                let original: arkret_wire::CommittedEventFullView =
                    serde_json::from_value(value.clone()).unwrap();
                original.commit.validate_content_address().unwrap();
                original
                    .event
                    .verify_event_id_matches_content_with_digest_suite(
                        original.event.realm_id.digest_suite_code().digest_suite(),
                    )
                    .unwrap();
                assert_eq!(original.commit.event_ref, original.event.event_id);
            }
            for child in fields.values() {
                validate_original_addresses(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_original_addresses(child);
            }
        }
        _ => {}
    }
}

pub async fn run(pool: PgPool) {
    let records = Arc::new(Mutex::new(BTreeMap::new()));
    READ_EVIDENCE
        .scope(records.clone(), async {
            let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
            realm_native_fixture::boxed_step(|| realm_native_fixture::run(pool, false)).await;
            realm_native_fixture::boxed_step(|| realm_native_fixture::run(database.pool(), true))
                .await;
            let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
            realm_native_fixture::boxed_step(|| {
                realm_native_fixture::run_bridge(database.pool(), false, false, false, None)
            })
            .await;
        })
        .await;
    let records = records.lock().unwrap();
    let expected = [
        "ak.edge.applet.actor.read.resolve.v1",
        "ak.edge.applet.third_party_users.read.list.v1",
        "ak.open.identity.read.resolution.v1",
        "ak.self.identity.read.resolution_audit.v1",
        "ak.self.actor_profile.read.resolve.v1",
        "ak.self.consent.read.list.v1",
        "ak.self.consent.resource.get.v1",
        "ak.self.media_service_binding.read.resolve.v1",
        "ak.self.mls.read.group_state_material.v1",
        "ak.self.mls.read.roster_authority.v1",
        "ak.peer.mls.read.group_state_material.v1",
        "ak.peer.mls.read.roster_authority.v1",
        "ak.self.realm_actor.read.material.v1",
        "ak.peer.realm_actor.read.material.v1",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        records
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        expected,
        "missing native successes must fail, never export a partial corpus"
    );
    let corpus = json!({"format_version":1,"semantics":"archival_native_read_transcript",
        "authentication_boundary":"DPoP StandardGrant introspection uses the trusted test channel; originals and reads use native PostgreSQL admission and registered routes",
        "operations":records.values().collect::<Vec<_>>()});
    if let Some(path) = std::env::var_os("ARKRET_NATIVE_READ_EVIDENCE_OUTPUT") {
        let path = std::path::PathBuf::from(path);
        std::fs::write(&path, serde_json::to_vec_pretty(&corpus).unwrap()).unwrap();
        eprintln!(
            "native read evidence: {} operations written to {}",
            records.len(),
            path.display()
        );
    }
}

include!("native_account_read_fixture.rs");
include!("native_mls_read_fixture.rs");
