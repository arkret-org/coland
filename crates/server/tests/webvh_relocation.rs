//! Native relocation through the public root operation and durable hosting.

use std::sync::Arc;

use arkret_signatures::webvh::{
    PrincipalInceptionInput, WebvhRelocationInput, prepare_portable_principal_inception,
    prepare_webvh_relocation,
};
use coland_http::config::AppConfig;
use coland_http::service;
use coland_storage::{PersistenceStore, WebvhDocumentRecord, WebvhLogCommitOutcome};
use coland_storage_postgres::PgPersistenceStore;
use coland_storage_postgres::test_database::TestDatabase;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

fn public(seed: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .as_bytes(),
    )
}

fn config(host: &str) -> AppConfig {
    AppConfig {
        public_base_url: format!("https://{host}"),
        embedded_webvh_provider_enabled: true,
        seed_demo_data: false,
        ..coland_test_support::app_config()
    }
}

async fn submit(
    app: &salvo::Service,
    body: &arkret_models_identity::DidOperationSubmitRequestBody,
) -> Value {
    let mut response =
        TestClient::post("https://a.example/_arkret/root/identity/submit-did-operation")
            .add_header(
                "Arkret-Operation",
                "ak.root.identity.command.submit_did_operation.v1",
                true,
            )
            .add_header("Content-Type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(body).unwrap())
            .send(app)
            .await;
    let status = response.status_code;
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{value}");
    value
}

async fn assert_alias(app: &salvo::Service, did: &str, head: &str, entries: &[Value]) {
    let mut response = TestClient::post("https://a.example/_arkret/root/identity/resolve")
        .add_header("Arkret-Operation", "ak.root.identity.read.resolve.v1", true)
        .add_header("Content-Type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(
                &arkret_models_identity::IdentityResolveRequestBody {
                    did: did.parse().unwrap(),
                    requested_evidence_kinds: vec![],
                },
            )
            .unwrap(),
        )
        .send(app)
        .await;
    let status = response.status_code;
    let resolved: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{resolved}");
    assert_eq!(resolved["did_document"]["id"], head);
    assert_eq!(resolved["seq"], entries.len());
    let mut response = TestClient::get("https://a.example/webvh/alice/did.json")
        .send(app)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let document: Value = response.take_json().await.unwrap();
    assert_eq!(document, entries.last().unwrap()["state"]);
    let mut response = TestClient::get("https://a.example/webvh/alice/did.jsonl")
        .send(app)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let bytes = response.take_bytes(None).await.unwrap();
    let expected = entries
        .iter()
        .flat_map(|entry| {
            let mut bytes = arkret_canonical::canonical_json_bytes(entry).unwrap();
            bytes.push(b'\n');
            bytes
        })
        .collect::<Vec<_>>();
    assert_eq!(bytes.as_ref(), expected);
}

fn history_document(did: &str, entries: &[Value]) -> WebvhDocumentRecord {
    use arkret_models_identity::*;
    let at = chrono::Utc::now();
    let first = &entries[0];
    let last = entries.last().unwrap();
    let head = arkret_canonical::canonical_sha256(last).unwrap();
    let normalized: arkret_identity::DidDocument =
        serde_json::from_value(last["state"].clone()).unwrap();
    WebvhDocumentRecord {
        did: did.into(),
        did_document: entries.last().unwrap()["state"].clone(),
        key_log_head: Some(arkret_canonical::canonical_sha256(entries.last().unwrap()).unwrap()),
        seq: entries.len() as u64,
        method_evidence: serde_json::to_value(ResolutionMethodHistoryEvidence::WebvhLog {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: arkret_canonical::canonical_sha256(first).unwrap(),
                from_version_id: first["versionId"].as_str().unwrap().into(),
                to_method_history_head: head.clone(),
                to_version_id: last["versionId"].as_str().unwrap().into(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".into(),
                document_digest: arkret_identity::document_canonical_digest(&normalized).unwrap(),
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: head,
                    witnesses: vec![],
                    witness_proofs_digest: arkret_canonical::canonical_sha256(&Vec::<Value>::new())
                        .unwrap()
                        .parse()
                        .unwrap(),
                }],
            },
            log_entries: entries.to_vec(),
            witness_records: vec![],
        })
        .unwrap(),
        fetched_at: at,
        expires_at: at,
        updated_at: at,
    }
}

#[tokio::test]
async fn root_relocation_serves_current_and_historical_aliases_after_reopen_and_ingestion() {
    let database = Arc::new(TestDatabase::lease().await);
    let source: Arc<dyn PersistenceStore> = Arc::new(PgPersistenceStore::leased(database.clone()));
    let state =
        coland_test_support::app_state_with_persistence(config("a.example"), source.clone()).await;
    let app = service(state);
    let endpoint = "https://a.example".parse().unwrap();
    let at = chrono::Utc::now() - chrono::Duration::minutes(5);
    let inception = prepare_portable_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &endpoint,
        principal_endpoint: &endpoint,
        local_id: "alice",
        also_known_as: &[],
        version_time: at,
        root_seed: &[91; 32],
        next_root_public_key_multibase: &public(&[92; 32]),
        witness_policy: None,
    })
    .unwrap();
    assert_eq!(
        submit(&app, &inception.submit_body).await["status"],
        "accepted"
    );
    let mut entries = vec![inception.log_entry.clone()];
    let scid = inception.did.split(':').nth(2).unwrap();
    let b = format!("did:webvh:{scid}:b.example:webvh:alice");
    let c = format!("did:webvh:{scid}:c.example:webvh:alice");
    let mut current = inception.did.clone();
    for (index, target) in [&b, &c].into_iter().enumerate() {
        let mut document: Value = serde_json::from_str(
            &serde_json::to_string(&entries.last().unwrap()["state"])
                .unwrap()
                .replace(&current, target),
        )
        .unwrap();
        document["alsoKnownAs"] = json!([current]);
        let moved = prepare_webvh_relocation(&WebvhRelocationInput {
            current_did: &current,
            target_did: target,
            previous_entries: &entries,
            version_time: at + chrono::Duration::seconds(index as i64 + 1),
            current_update_seed: &[92 + index as u8; 32],
            next_update_public_key_multibase: &public(&[93 + index as u8; 32]),
            state: &document,
        })
        .unwrap();
        if index == 1 {
            let (connection, driver) =
                tokio_postgres::connect(database.url(), tokio_postgres::NoTls)
                    .await
                    .unwrap();
            let driver = tokio::spawn(driver);
            connection.batch_execute(
                "CREATE FUNCTION refuse_relocation_document() RETURNS trigger LANGUAGE plpgsql AS $$ \
                 BEGIN IF NEW.seq = 3 THEN RAISE EXCEPTION 'injected document failure'; END IF; RETURN NEW; END $$; \
                 CREATE TRIGGER refuse_relocation_document BEFORE INSERT OR UPDATE ON webvh_documents \
                 FOR EACH ROW EXECUTE FUNCTION refuse_relocation_document()"
            ).await.unwrap();
            let response =
                TestClient::post("https://a.example/_arkret/root/identity/submit-did-operation")
                    .add_header(
                        "Arkret-Operation",
                        "ak.root.identity.command.submit_did_operation.v1",
                        true,
                    )
                    .add_header("Content-Type", "application/json", true)
                    .body(arkret_canonical::canonical_json_bytes(&moved.submit_body).unwrap())
                    .send(&app)
                    .await;
            assert_eq!(
                response.status_code,
                Some(StatusCode::INTERNAL_SERVER_ERROR)
            );
            assert_eq!(source.webvh().list_log_events(&b).await.unwrap().len(), 2);
            assert_eq!(
                source
                    .webvh()
                    .get_document(&inception.did)
                    .await
                    .unwrap()
                    .unwrap()
                    .did,
                b
            );
            assert!(source.webvh().get_document(&c).await.unwrap().is_none());
            connection.batch_execute("DROP TRIGGER refuse_relocation_document ON webvh_documents; DROP FUNCTION refuse_relocation_document()").await.unwrap();
            driver.abort();
        }
        assert_eq!(submit(&app, &moved.submit_body).await["status"], "accepted");
        assert_eq!(
            submit(&app, &moved.submit_body).await["status"],
            "duplicate"
        );
        entries.push(moved.log_entry);
        current = target.clone();
    }
    assert_alias(&app, &inception.did, &c, &entries).await;
    drop(app);
    let reopened = service(
        coland_test_support::app_state_with_persistence(config("b.example"), source.clone()).await,
    );
    for alias in [&inception.did, &b, &c] {
        assert_alias(&reopened, alias, &c, &entries).await;
    }
    let events = source.webvh().list_log_events(&c).await.unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.did.as_str())
            .collect::<Vec<_>>(),
        [&inception.did, &b, &c]
    );

    let destination: Arc<dyn PersistenceStore> = Arc::new(PgPersistenceStore::leased(Arc::new(
        TestDatabase::lease().await,
    )));
    let first = history_document(&inception.did, &entries[..1]);
    let first_head = first.key_log_head.clone();
    assert_eq!(
        destination
            .webvh()
            .ingest_verified_history(None, first)
            .await
            .unwrap(),
        WebvhLogCommitOutcome::Accepted
    );
    assert_eq!(
        destination
            .webvh()
            .ingest_verified_history(first_head, history_document(&c, &entries))
            .await
            .unwrap(),
        WebvhLogCommitOutcome::Accepted
    );
    let imported = service(
        coland_test_support::app_state_with_persistence(config("a.example"), destination.clone())
            .await,
    );
    assert_alias(&imported, &inception.did, &c, &entries).await;
    let events = destination.webvh().list_log_events(&c).await.unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.did.as_str())
            .collect::<Vec<_>>(),
        [&inception.did, &b, &c]
    );
    let current_head = events.last().unwrap().event_digest.clone();
    assert_eq!(
        destination
            .webvh()
            .ingest_verified_history(
                Some(current_head),
                history_document(&inception.did, &entries[..1])
            )
            .await
            .unwrap(),
        WebvhLogCommitOutcome::Conflict
    );
    assert_eq!(
        destination
            .webvh()
            .get_document(&inception.did)
            .await
            .unwrap()
            .unwrap()
            .did,
        c
    );
    let unknown = format!("did:webvh:{scid}:unknown.example:webvh:alice");
    assert!(
        destination
            .webvh()
            .get_document(&unknown)
            .await
            .unwrap()
            .is_none()
    );
    let cold: Arc<dyn PersistenceStore> = Arc::new(PgPersistenceStore::leased(Arc::new(
        TestDatabase::lease().await,
    )));
    assert_eq!(
        cold.webvh()
            .ingest_verified_history(None, history_document(&c, &entries))
            .await
            .unwrap(),
        WebvhLogCommitOutcome::Accepted
    );
    let cold_app =
        service(coland_test_support::app_state_with_persistence(config("a.example"), cold).await);
    assert_alias(&cold_app, &inception.did, &c, &entries).await;
    let mut cache_only = history_document(&c, &entries);
    cache_only.did = unknown.clone();
    cache_only.did_document["id"] = json!(unknown);
    cache_only.seq = 1_000;
    destination.webvh().put_document(cache_only).await.unwrap();
    let poisoned_app = service(
        coland_test_support::app_state_with_persistence(
            config("unknown.example"),
            destination.clone(),
        )
        .await,
    );
    for path in ["did.json", "did.jsonl"] {
        let response = TestClient::get(format!("https://unknown.example/webvh/alice/{path}"))
            .send(&poisoned_app)
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::NOT_FOUND),
            "a bare resolution cache row must not acquire hosting authority"
        );
    }
    let mut returned_state: Value = serde_json::from_str(
        &serde_json::to_string(&entries.last().unwrap()["state"])
            .unwrap()
            .replace(&c, &inception.did),
    )
    .unwrap();
    returned_state["alsoKnownAs"] = json!([c]);
    let returned = prepare_webvh_relocation(&WebvhRelocationInput {
        current_did: &c,
        target_did: &inception.did,
        previous_entries: &entries,
        version_time: at + chrono::Duration::seconds(3),
        current_update_seed: &[94; 32],
        next_update_public_key_multibase: &public(&[95; 32]),
        state: &returned_state,
    })
    .unwrap();
    assert_eq!(
        submit(&poisoned_app, &returned.submit_body).await["status"],
        "accepted",
        "an unaccepted cache alias must not choose the native writer's head"
    );
    entries.push(returned.log_entry);
    let returned_app = service(
        coland_test_support::app_state_with_persistence(config("a.example"), destination.clone())
            .await,
    );
    assert_alias(&returned_app, &c, &inception.did, &entries).await;
    let same_url_alias = inception.did.replace(":a.example:", ":A.EXAMPLE:");
    assert_ne!(same_url_alias, inception.did);
    let same_url_did = arkret_wire::Did::new(&same_url_alias).unwrap();
    assert_eq!(
        url::Url::parse(&arkret_identity::DidWebvhResolver::log_url(&same_url_did).unwrap())
            .unwrap(),
        url::Url::parse(
            &arkret_identity::DidWebvhResolver::log_url(&inception.did.parse().unwrap()).unwrap()
        )
        .unwrap()
    );
    let mut same_url_state: Value = serde_json::from_str(
        &serde_json::to_string(&entries.last().unwrap()["state"])
            .unwrap()
            .replace(&inception.did, &same_url_alias),
    )
    .unwrap();
    same_url_state["alsoKnownAs"] = json!([inception.did]);
    let same_url = prepare_webvh_relocation(&WebvhRelocationInput {
        current_did: &inception.did,
        target_did: &same_url_alias,
        previous_entries: &entries,
        version_time: at + chrono::Duration::seconds(4),
        current_update_seed: &[95; 32],
        next_update_public_key_multibase: &public(&[96; 32]),
        state: &same_url_state,
    })
    .unwrap();
    assert_eq!(
        submit(&returned_app, &same_url.submit_body).await["status"],
        "accepted"
    );
    entries.push(same_url.log_entry);
    assert_alias(&returned_app, &c, &same_url_alias, &entries).await;
    // Metadata hosting survives an independently changed business base.
    let split_host_app = service(
        coland_test_support::app_state_with_persistence(config("api.example"), destination.clone())
            .await,
    );
    assert_alias(&split_host_app, &c, &same_url_alias, &entries).await;
    for path in ["did.json", "did.jsonl"] {
        let response = TestClient::get(format!(
            "https://not-an-accepted-host.example/webvh/alice/{path}"
        ))
        .add_header("x-forwarded-host", "a.example", true)
        .send(&split_host_app)
        .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::NOT_FOUND),
            "forwarded host cannot establish a native hosting alias"
        );
    }
}
