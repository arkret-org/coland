//! Real encrypted Agent scope custody shared by PostgreSQL integration fixtures.

use std::future::Future;
use std::pin::Pin;

use coland_storage::AuthorityCommitStore as _;
use coland_storage_postgres::{PgAuthorityCommitStore, PgPersistenceStore};

use super::{device_authorization_history, historical_control_source};

#[inline(never)]
fn fixture_future<'a, T: 'a, F: Future<Output = T> + Send + 'a>(
    make: impl FnOnce() -> F,
) -> Pin<Box<dyn Future<Output = T> + Send + 'a>> {
    Box::pin(make())
}

fn fixture_step<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> Pin<Box<dyn Future<Output = T> + Send>> {
    struct CancelOnDrop(tokio::task::AbortHandle);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    // Allocate before entering another async state machine or spawning it.
    // Otherwise large caller futures are copied through nested poll frames.
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(future);
    fixture_future(|| async move {
        let task = tokio::spawn(future);
        // Cancelling a caller's timeout must also drop the original pending future.
        let _cancel = CancelOnDrop(task.abort_handle());
        task.await.expect("original fixture step task")
    })
}

pub(crate) struct DeliveryScopeVault {
    pub(crate) state: coland_http::state::AppState,
    pub(crate) config: coland_http::config::KeyStoreConfig,
    pub(crate) directory: std::path::PathBuf,
}
impl DeliveryScopeVault {
    pub(crate) fn reopen(&self) -> coland_http::state::AppState {
        self.state
            .clone()
            .with_verifier_private_keystore(std::sync::Arc::from(
                self.config
                    .open(coland_http::config::SERVICE_IDENTITY_KEYSTORE_APP)
                    .unwrap()
                    .unwrap(),
            ))
    }
}
impl Drop for DeliveryScopeVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
// Freeze supplementary native custody metadata before the controller signs.
pub(crate) fn native_pairing_instance(
    key: &arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload,
) -> (arkret_wire::OpaqueLocalId, chrono::DateTime<chrono::Utc>) {
    let pairing = key.approval_evidence.pairing_request_id.as_ref().unwrap();
    let uuid = pairing
        .as_str()
        .strip_prefix("agent_pairing_request:")
        .unwrap();
    // Historical control Events can predate today's supplementary native
    // request. Freeze its live window at the fresh fixture handle allocation.
    let (seconds, nanos) = uuid::Uuid::parse_str(uuid)
        .unwrap()
        .get_timestamp()
        .unwrap()
        .to_unix();
    let allocated_at = arkret_canonical::normalize_timestamp_canonical(
        chrono::DateTime::from_timestamp(seconds as i64, nanos).unwrap(),
    );
    (
        arkret_wire::OpaqueLocalId::new(format!("agent_runtime_approval:{uuid}")).unwrap(),
        allocated_at + chrono::TimeDelta::minutes(5),
    )
}

pub(crate) fn bind_native_pairing_approval(
    payload: &mut serde_json::Value,
    station: &arkret_wire::DidCoreId,
) {
    let mut key: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
        serde_json::from_value(payload.clone()).unwrap();
    let (approval, expiry) = native_pairing_instance(&key);
    let pairing = key.approval_evidence.pairing_request_id.as_ref().unwrap();
    let binding = arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
        &key.agent_id,
        pairing,
        &key.verification_method,
        &key.public_key,
        key.runtime_attestation.as_ref(),
    )
    .unwrap();
    key.approval_evidence.request_canonical_digest = Some(
        arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            &key.accountable_principal_id,
            &key.agent_id,
            pairing,
            &approval,
            expiry,
            station,
            &binding,
        )
        .unwrap(),
    );
    *payload = serde_json::to_value(key).unwrap();
}

pub(crate) async fn retain_delivery_scope(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    principal: &device_authorization_history::DeviceHistoryFixture,
    agent: &arkret_wire::AccountId,
    key_event: &arkret_wire::Event,
    scope: &arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    endpoint: &coland_storage::AgentEndpointGuard,
) -> (
    DeliveryScopeVault,
    coland_storage::VerifiedAgentScopeEvidence,
) {
    retain_delivery_scope_for_runtime(
        pool, station, principal, agent, key_event, scope, endpoint, false,
    )
    .await
}

pub(crate) async fn retain_delivery_scope_for_runtime(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    principal: &device_authorization_history::DeviceHistoryFixture,
    agent: &arkret_wire::AccountId,
    key_event: &arkret_wire::Event,
    scope: &arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    endpoint: &coland_storage::AgentEndpointGuard,
    activate_runtime: bool,
) -> (
    DeliveryScopeVault,
    coland_storage::VerifiedAgentScopeEvidence,
) {
    retain_delivery_scope_with_runtime_seed(
        pool,
        station,
        principal,
        agent,
        key_event,
        scope,
        endpoint,
        activate_runtime,
        &[0x61; 32],
    )
    .await
}

pub(crate) async fn retain_delivery_scope_with_runtime_seed(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    principal: &device_authorization_history::DeviceHistoryFixture,
    agent: &arkret_wire::AccountId,
    key_event: &arkret_wire::Event,
    scope: &arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    endpoint: &coland_storage::AgentEndpointGuard,
    activate_runtime: bool,
    runtime_seed: &[u8; 32],
) -> (
    DeliveryScopeVault,
    coland_storage::VerifiedAgentScopeEvidence,
) {
    use std::sync::Arc;

    use arkret_models_collaboration::agent_scope::{
        AgentKeyPairRequestBody, AgentRequestedScopeDisclosure,
    };
    use coland_storage::{AgentStore as _, IdentityStoreRegistry as _};
    use diesel::sql_types::{Jsonb, Text, Timestamptz};
    use diesel_async::RunQueryDsl as _;
    let directory =
        std::env::temp_dir().join(format!("arkret-delivery-vault-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&directory).unwrap();
    protect_owned_test_path(&directory, 0o700);
    let vault_path = directory.join("private-vault.enc");
    let values = std::collections::BTreeMap::from([
        (
            "COLAND_KEYSTORE_BACKEND".to_owned(),
            "encrypted_file".to_owned(),
        ),
        (
            "COLAND_KEYSTORE_PATH".to_owned(),
            vault_path.to_str().unwrap().to_owned(),
        ),
        (
            "COLAND_KEYSTORE_MASTER_KEY".to_owned(),
            arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        ),
    ]);
    let key_store_config = coland_http::config::KeyStoreConfig::from_values(&values).unwrap();
    let mut config = coland_test_support::app_config();
    config.public_base_url = "https://agent-delivery-cut.example/".to_owned();
    #[derive(diesel::QueryableByName)]
    struct Genesis {
        #[diesel(sql_type = Jsonb)]
        payload: serde_json::Value,
    }
    let mut connection = pool.get().await.unwrap();
    let genesis = diesel::sql_query("SELECT e.envelope->'payload' AS payload FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.realm.create' AND c.realm_id=$1 AND c.stream_position=0")
        .bind::<Text, _>(endpoint.pcr_realm_id.as_str())
        .get_result::<Genesis>(&mut connection).await.unwrap();
    drop(connection);
    let genesis: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(genesis.payload).unwrap();
    config.trust_domain = genesis.object.trust_domain;
    config.key_store = key_store_config.clone();
    let persistence = Arc::new(PgPersistenceStore::new(pool.clone()));
    let identity = station.install_runtime_identity(persistence.as_ref()).await;
    let state = coland_test_support::app_state_with_identity(
        config,
        persistence.clone(),
        identity,
        [83; 32],
    )
    .with_verifier_private_keystore(Arc::from(
        key_store_config
            .open(coland_http::config::SERVICE_IDENTITY_KEYSTORE_APP)
            .unwrap()
            .unwrap(),
    ));
    let key =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            key_event,
        )
        .unwrap();
    let pairing_request_id = key.approval_evidence.pairing_request_id.clone().unwrap();
    let (approval_request_id, pairing_expires_at) = native_pairing_instance(&key);
    let now = chrono::Utc::now();
    let runtime_key = ed25519_dalek::SigningKey::from_bytes(runtime_seed);
    let runtime = arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
        &runtime_key,
        arkret_models_collaboration::agent_operations::AgentPairingBootstrap {
            runtime_identity: None,
            arkret_base_url: "https://agent-delivery-cut.example/".to_owned(),
            service_id: station.core.clone(),
            agent_id: agent.principal_id.clone(),
            pairing_request_id: pairing_request_id.clone(),
            pairing_code: "01234567".to_owned(),
            pairing_expires_at,
        },
        &key.verification_method,
    )
    .build_approval_request()
    .unwrap();
    let runtime_digest =
        arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
            &key.agent_id,
            &pairing_request_id,
            &key.verification_method,
            &key.public_key,
            key.runtime_attestation.as_ref(),
        )
        .unwrap();
    let store = coland_storage_postgres::PgAgentStore { pool: pool.clone() };
    let mut record = store
        .get(agent.principal_id.as_str())
        .await
        .unwrap()
        .unwrap();
    record.controller_account_pk = Some(
        persistence
            .accounts()
            .get(&principal.account)
            .await
            .unwrap()
            .unwrap()
            .pk,
    );
    record.pairing_request_id = Some(pairing_request_id.clone());
    record.pairing_code = Some("01234567".to_owned());
    record.pairing_expires_at = Some(pairing_expires_at);
    record.approval_request_id = Some(approval_request_id.clone());
    if activate_runtime {
        // Populate the original runtime approval material before creating its
        // durable intent. The receipt trigger requires the actual raw key
        // digest; a request body alone is not a verified runtime approval.
        assert!(runtime.body.public_key == key.public_key);
        assert_eq!(runtime.body.verification_method, key.verification_method);
        let verified_at = chrono::Utc::now();
        let validated = arkret_signatures::agent::validate_agent_runtime_public_key(
            &runtime.body.public_key,
            &runtime.body.verification_method,
        )
        .unwrap();
        assert_eq!(
            validated.public_key_digest,
            runtime.runtime_request_public_key_digest
        );
        let proof = &runtime.body.proof_of_possession;
        assert_eq!(proof.audience_id, station.core);
        let signing_bytes = proof
            .validate_shape(
                &agent.principal_id,
                &pairing_request_id,
                &key.verification_method,
                &runtime.body.public_key,
                &runtime_digest,
                "01234567",
                pairing_expires_at,
                verified_at,
            )
            .unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&validated.raw_public_key)
            .unwrap()
            .verify_strict(
                &signing_bytes,
                &ed25519_dalek::Signature::from_slice(
                    &arkret_canonical::base64url_decode(proof.signature.as_str()).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let attestation = runtime
            .body
            .runtime_attestation
            .as_ref()
            .map(|value| serde_json::to_value(value).unwrap());
        record.runtime_public_key_digest = Some(validated.public_key_digest.to_string());
        record.runtime_attestation_digest = Some(
            arkret_signatures::agent::agent_runtime_attestation_digest(attestation.as_ref())
                .unwrap()
                .to_string(),
        );
        record.runtime_proof_verified_at = Some(verified_at);
    }
    record.runtime_key_request = Some(runtime.body);
    record.runtime_key_binding_digest = Some(runtime_digest.to_string());
    store.put(record.clone()).await.unwrap();
    let mut disclosure = AgentRequestedScopeDisclosure {
        schema: arkret_wire::SchemaId::AgentRequestedScopeDisclosureV1,
        request_id: arkret_wire::RequestId::new(format!(
            "ak:request:{}",
            pairing_request_id
                .as_str()
                .strip_prefix("agent_pairing_request:")
                .unwrap()
        ))
        .unwrap(),
        agent_id: agent.principal_id.clone(),
        controller_principal_id: principal.account.principal_id.clone(),
        requested_scope: scope.clone(),
        verifier_id: station.core.clone(),
        audience: arkret_wire::NonEmptyString::new(
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
        )
        .unwrap(),
        challenge: arkret_wire::NonEmptyString::new(pairing_request_id.as_str()).unwrap(),
        issued_at: now - chrono::TimeDelta::seconds(1),
        expires_at: now + chrono::TimeDelta::seconds(5),
        proofs: vec![arkret_wire::PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: principal.device_verification_method.clone(),
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: now,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZDI1NTE5In0..c2ln".to_owned(),
        }],
    };
    disclosure.proofs[0].payload_digest = disclosure.payload_digest().unwrap();
    disclosure.proofs[0].jws = arkret_signatures::proof::sign_ed25519_detached_jws(
        &ed25519_dalek::SigningKey::from_bytes(&principal.founding_device_signing_seed),
        &disclosure
            .canonical_proof_binding_bytes(&disclosure.proofs[0])
            .unwrap(),
    )
    .unwrap();
    let body = AgentKeyPairRequestBody {
        pairing_request_id: pairing_request_id.clone(),
        approval_request_id: approval_request_id.clone(),
        requested_scope_disclosure: disclosure,
        authorize_event: arkret_wire::EventAdmissionSubmission::new(key_event.clone()),
    };
    let custody_state = state.clone();
    let custody_body = body.clone();
    let reference = fixture_step(fixture_future(|| async move {
        Box::pin(custody_state.verify_and_retain_agent_scope_custody(&custody_body)).await
    }))
    .await
    .unwrap();
    let request_digest =
        arkret_canonical::sha256_digest(&arkret_canonical::canonical_json_bytes(&body).unwrap());
    let raw_key_digest = arkret_signatures::agent::agent_runtime_public_key_digest(
        &serde_json::to_value(&key.public_key).unwrap(),
    )
    .unwrap();
    if !activate_runtime {
        // Native imported receipt fixture only. Physical runtime consumers below
        // create awaiting_source_commit through the original intent trigger.
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO agent_pairing_receipts(authorize_event_ref,agent_id,controller_principal_id,pairing_request_id,approval_request_id,runtime_key_binding_digest,request_digest,raw_key_digest,expires_at,activation_state,scope_custody_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10)")
        .bind::<Text,_>(key_event.event_id.as_str()).bind::<Text,_>(agent.principal_id.as_str())
        .bind::<Text,_>(principal.account.principal_id.as_str()).bind::<Text,_>(pairing_request_id.as_str())
        .bind::<Text,_>(approval_request_id.as_str()).bind::<Text,_>(runtime_digest.as_str())
        .bind::<Text,_>(&request_digest).bind::<Text,_>(raw_key_digest.as_str())
        .bind::<Timestamptz,_>(pairing_expires_at)
        .bind::<Jsonb,_>(serde_json::to_value(&reference).unwrap()).execute(&mut conn).await.unwrap();
        drop(conn);
    }
    if activate_runtime {
        // The serving index must be settled by the original activation store,
        // from this exact accepted KeyAuthorize and retained private receipt.
        // Native current authorization alone is not a ready runtime session.
        let accepted = PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&key_event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert!(accepted.event == *key_event);
        assert_eq!(
            accepted.commit.commit_id,
            endpoint.authorization_ref.commit_id
        );
        let public_jwk = serde_json::to_value(&key.public_key).unwrap();
        // This key is read from accepted history, not from the mock issuer.
        let encoded_key = public_jwk["key"].as_str().unwrap();
        assert_eq!(
            encoded_key,
            arkret_canonical::base64url_encode(runtime_key.verifying_key().as_bytes())
        );
        let jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":encoded_key});
        let signer = arkret_models_identity::authenticated_signer_resolution_evidence::build_agent_signer_evidence(
            agent.principal_id.clone(), key.verification_method.clone(),
            serde_json::from_value(jwk).unwrap(), accepted.commit.commit_id.clone(),
            accepted.commit.committed_at,
        ).unwrap();
        assert!(
            store
                .put_pairing_commit_intent_if_compatible(
                    &coland_storage::AgentPairingCommitIntent {
                        agent_id: agent.principal_id.to_string(),
                        approval_request_id: approval_request_id.clone(),
                        runtime_key_binding_digest: runtime_digest.to_string(),
                        pairing_request_id: pairing_request_id.clone(),
                        request_digest: request_digest.clone(),
                        authorize_event_id: key_event.event_id.to_string(),
                        key_authorization_event: key_event.clone(),
                        scope_custody_ref: Some(reference.clone()),
                    }
                )
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .activate_runtime_if_current(&coland_storage::AgentRuntimeActivation {
                    agent_id: agent.principal_id.to_string(),
                    approval_request_id,
                    runtime_key_binding_digest: runtime_digest.to_string(),
                    pairing_request_id,
                    paired_request_digest: request_digest,
                    authorized_event_ref: key_event.event_id.to_string(),
                    authorized_verification_method: key.verification_method.to_string(),
                    authorized_public_key_digest: raw_key_digest.to_string(),
                    frozen_authorize_event: key_event.clone(),
                    scope_custody_ref: Some(reference.clone()),
                    authorize_ref: endpoint.authorization_ref.clone(),
                    status:
                        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
                    authorized_key_event: key_event.clone(),
                    signer_resolution_evidence_ref: Some(signer.signer_evidence_ref().unwrap()),
                    current_signer_evidence: Some(signer),
                    authorized_at: accepted.commit.committed_at,
                })
                .await
                .unwrap()
        );
        let current = store
            .get(agent.principal_id.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.authorized_event_ref.as_deref(),
            Some(key_event.event_id.as_str())
        );
        assert_eq!(
            current.authorized_verification_method.as_deref(),
            Some(key.verification_method.as_str())
        );
        assert!(current.current_signer_evidence.is_some());
        let receipt = store
            .pairing_receipt(key_event.event_id.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            receipt.request_digest,
            current.paired_request_digest.as_ref().unwrap().as_str()
        );
        assert_eq!(receipt.authorize_event_ref, key_event.event_id.as_str());
        assert_eq!(receipt.scope_custody_ref.as_ref(), Some(&reference));
        assert_eq!(
            serde_json::to_value(&receipt.outcome).unwrap()["activation_state"],
            "active"
        );
    } else {
        record.paired_pairing_request_id = Some(pairing_request_id);
        record.paired_request_digest = Some(request_digest);
        store.put(record).await.unwrap();
    }
    let vault = DeliveryScopeVault {
        state,
        config: key_store_config,
        directory,
    };
    let cold = vault.reopen();
    let query_endpoint = endpoint.clone();
    let evidence = fixture_step(fixture_future(|| async move {
        Box::pin(cold.qualified_agent_scope_evidence(&query_endpoint)).await
    }))
    .await
    .unwrap();
    assert_eq!(evidence.custody_ref(), &reference);
    assert_eq!(evidence.command().authorize_event.event, *key_event);
    // A closed presentation window does not erase previously qualified custody.
    let wait = evidence.command().requested_scope_disclosure.expires_at - chrono::Utc::now();
    if wait > chrono::TimeDelta::zero() {
        tokio::time::sleep(wait.to_std().unwrap() + std::time::Duration::from_millis(2)).await;
    }
    assert!(chrono::Utc::now() > evidence.command().requested_scope_disclosure.expires_at);
    let reopened_state = vault.reopen();
    let query_endpoint = endpoint.clone();
    let reopened = fixture_step(fixture_future(|| async move {
        Box::pin(reopened_state.qualified_agent_scope_evidence(&query_endpoint)).await
    }))
    .await
    .unwrap();
    assert_eq!(reopened.custody_ref(), evidence.custody_ref());
    (vault, reopened)
}

pub(crate) fn protect_owned_test_path(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(windows)]
    {
        let _ = mode;
        let identity = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        assert!(identity.status.success(), "actual test user SID lookup");
        let identity = String::from_utf8(identity.stdout).unwrap();
        let sid = identity.split(',').last().unwrap().trim().trim_matches('"');
        assert!(sid.starts_with("S-1-"), "test user SID is malformed");
        let grant = if path.is_dir() {
            format!("*{sid}:(OI)(CI)F")
        } else {
            format!("*{sid}:F")
        };
        let protection = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(grant)
            .output()
            .unwrap();
        assert!(
            protection.status.success(),
            "owned test ACL protection failed"
        );
    }
}
