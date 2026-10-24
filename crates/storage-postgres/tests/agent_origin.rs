//! Actual original admission, immutable source and current-cut regressions.
//! These fixtures require PostgreSQL; no memory/skip fallback exists.
#[path = "../../test-support/src/device_authorization_history.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared device history fixture."
)]
mod device_history_fixture;
use device_history_fixture as device_authorization_history;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared PCR fixture."
)]
mod pcr_genesis_fixture;
use pcr_genesis_fixture as pcr_genesis;
#[path = "../../test-support/src/agent_origin.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses a subset of the shared Origin fixture."
)]
mod origin_fixture;
use arkret_wire::{Did, DidUrl, EventKind, RealmId};
use chrono::{Duration, Utc};
use coland_storage::{
    ActorProfileStore, AgentControlAdmissionWrite, AgentProvisionAdmissionWrite,
    AuthorityCommitStore,
};
use coland_storage_postgres::{PgActorProfileStore, PgAuthorityCommitStore, PgPersistenceStore};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;
use origin_fixture::*;

#[tokio::test]
async fn agent_slug_is_reserved_until_accepted_terminal_lifecycle() {
    let f = OriginFixture::new().await;
    f.admit_provision().await;
    let store = PgActorProfileStore {
        pool: f.pool.clone(),
    };
    let replacement = f.replacement_provision(&f.provision.commit, "origin");
    let write = AgentProvisionAdmissionWrite {
        commit: replacement.clone(),
        queued_at: replacement.commit.committed_at,
    };
    // There is no Agent pairing row or genesis yet. Accepted provision alone
    // keeps its recoverable name; private bootstrap clocks cannot release it.
    let error = store
        .admit_agent_provision(write.clone())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("duplicate_conflict"));
    f.stage(&f.genesis).await;
    f.admit_genesis().await.unwrap();
    assert!(store.admit_agent_provision(write.clone()).await.is_err());
    let key = f.authorize().await;
    let pause = f
        .lifecycle(&key.commit, EventKind::SelfAgentPause, "pause", "active")
        .await;
    assert!(store.admit_agent_provision(write.clone()).await.is_err());
    let resume = f
        .lifecycle(
            &pause.commit,
            EventKind::SelfAgentResume,
            "resume",
            "paused",
        )
        .await;
    assert!(store.admit_agent_provision(write.clone()).await.is_err());
    let terminal = f
        .lifecycle(
            &resume.commit,
            EventKind::SelfAgentDeactivate,
            "deactivate",
            "active",
        )
        .await;
    let accepted = store.admit_agent_provision(write.clone()).await.unwrap();
    assert!(matches!(
        accepted,
        coland_storage::AgentProvisionAdmissionOutcome::Committed(_)
    ));
    assert!(matches!(
        store.admit_agent_provision(write).await.unwrap(),
        coland_storage::AgentProvisionAdmissionOutcome::Duplicate(_)
    ));
    // Replaying the old immutable provision must not retake the replacement's
    // selector binding or make its independent pairing depend on old history.
    assert!(matches!(
        store
            .admit_agent_provision(AgentProvisionAdmissionWrite {
                commit: f.provision.clone(),
                queued_at: f.provision.commit.committed_at,
            })
            .await
            .unwrap(),
        coland_storage::AgentProvisionAdmissionOutcome::Duplicate(_)
    ));

    // A late old runtime authorization must still hit the terminal Agent's
    // gate, not the new selector owner or its future pairing.
    let at = terminal.commit.committed_at + Duration::seconds(1);
    let mut late_payload = agent_key_authorization(
        &f.agent_did,
        &f.controller.history.account.principal_id,
        "late-runtime",
        [0x61; 32],
        Vec::new(),
        at,
    );
    late_payload["audience"] = serde_json::json!([f.station]);
    let event = agent_control_event(
        &f.controller.history,
        &f.agent,
        &f.genesis.event.realm_id,
        &format!("{}#managed-controller", f.agent_did),
        EventKind::AgentKeyAuthorize,
        late_payload,
        at,
    );
    let mut commit = station_successor(&terminal.commit, &event, &f.station_did, 1);
    origin_seal(&mut commit, &f.method, &f.issuer);
    let late = origin_tx(event, commit, &f.station);
    f.stage(&late).await;
    let terminal_error = store
        .admit_agent_control_event(AgentControlAdmissionWrite {
            queued_at: late.commit.committed_at,
            commit: late,
        })
        .await
        .unwrap_err();
    assert!(terminal_error.to_string().contains("active or paused"));

    #[derive(diesel::QueryableByName)]
    struct Selector {
        #[diesel(sql_type=Text)]
        agent: String,
    }
    let mut conn = f.pool.get().await.unwrap();
    let selector = diesel::sql_query("SELECT value->'subject_account_id'->>'principal_id' AS agent FROM agent_selector_claim_current_states WHERE realm_id=$1 AND agent_slug='origin'")
        .bind::<Text,_>(f.provision.event.realm_id.as_str()).get_result::<Selector>(&mut *conn).await.unwrap();
    assert_eq!(
        selector.agent,
        replacement.event.payload["agent_id"].as_str().unwrap()
    );
    drop(conn);
    // The replacement has not reached genesis yet, so it now reserves the
    // same slug even though the previous owner's terminal history remains.
    let third = f.replacement_provision(&replacement.commit, "origin");
    assert!(
        store
            .admit_agent_provision(AgentProvisionAdmissionWrite {
                queued_at: third.commit.committed_at,
                commit: third,
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("duplicate_conflict")
    );
}

#[tokio::test]
async fn concurrent_agent_provisions_cannot_take_one_controller_slug() {
    let f = OriginFixture::new().await;
    let parent = &f.controller.unit.transactions.last().unwrap().commit;
    let a = f.replacement_provision(parent, "same-name");
    let b = f.replacement_provision(parent, "same-name");
    let store = PgActorProfileStore {
        pool: f.pool.clone(),
    };
    let (a, b) = tokio::join!(
        store.admit_agent_provision(AgentProvisionAdmissionWrite {
            queued_at: a.commit.committed_at,
            commit: a
        }),
        store.admit_agent_provision(AgentProvisionAdmissionWrite {
            queued_at: b.commit.committed_at,
            commit: b
        }),
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "exactly one provision may reserve the name"
    );
}

#[tokio::test]
async fn different_controllers_can_reserve_the_same_agent_slug() {
    let f = OriginFixture::new().await;
    f.admit_provision().await;
    let other = pcr_genesis_fixture::PcrGenesisFixture::new_with(
        f.station_did.clone(),
        device_history_fixture::DeviceHistoryFixtureOptions {
            local_id: "another-controller".into(),
            ..Default::default()
        },
    );
    other
        .admit_into(&PgPersistenceStore::new(f.pool.clone()))
        .await
        .unwrap();
    assert_ne!(
        other.history.account.principal_id,
        f.controller.history.account.principal_id
    );
    let agent = arkret_wire::project_did_to_core_id(
        &Did::new("did:web:another-controller-agent.example").unwrap(),
    )
    .unwrap();
    let pcr = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(agent.as_str().as_bytes()),
    ));
    let parent = &other.unit.transactions.last().unwrap().commit;
    let at = parent.committed_at + Duration::seconds(1);
    let event = agent_provision_event(
        &other.history,
        &parent.realm_id,
        &agent,
        &pcr,
        "origin",
        at,
        at,
    );
    let mut commit = station_successor(parent, &event, &f.station_did, 1);
    origin_seal(&mut commit, &f.method, &f.issuer);
    let tx = origin_tx(event, commit, &f.station);
    let outcome = PgActorProfileStore {
        pool: f.pool.clone(),
    }
    .admit_agent_provision(AgentProvisionAdmissionWrite {
        queued_at: tx.commit.committed_at,
        commit: tx,
    })
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        coland_storage::AgentProvisionAdmissionOutcome::Committed(_)
    ));
}

#[tokio::test]
async fn agent_origin_rejected_candidate_never_becomes_accepted_history_and_success_is_atomic() {
    let f = OriginFixture::new().await;
    f.stage(&f.genesis).await;
    assert!(
        f.admit_genesis().await.is_err(),
        "no actual provision declaration"
    );
    assert_eq!(f.count("candidate").await, 1);
    assert_eq!(f.count("source").await, 0);
    assert_eq!(f.count("history").await, 0);
    let store = PgAuthorityCommitStore {
        pool: f.pool.clone(),
    };
    assert!(
        store
            .prepare_agent_origin_state(
                &f.runtime_event(f.genesis.commit.committed_at),
                f.genesis.commit.committed_at
            )
            .await
            .is_err()
    );
    f.admit_provision().await;
    f.admit_genesis().await.unwrap();
    assert_eq!(f.count("candidate").await, 0);
    assert_eq!(f.count("source").await, 1);
    assert_eq!(f.count("history").await, 1);
    f.admit_genesis().await.unwrap();
    assert_eq!(f.count("source").await, 1);
    let key = f.authorize().await;
    let event = f.runtime_event(key.commit.committed_at);
    let state = store
        .prepare_agent_origin_state(&event, key.commit.committed_at)
        .await
        .unwrap();
    state.validate_binding(&f.agent).unwrap();
    assert_eq!(state.pcr_genesis_event, f.genesis.event);
    assert_eq!(state.key_authorization_event, key.event);
    assert_eq!(
        state.commits,
        vec![f.genesis.commit.clone(), key.commit.clone()]
    );
    assert_eq!(f.count("source").await, 2);
    assert_eq!(f.count("history").await, 2);
}

#[tokio::test]
async fn agent_origin_current_pause_rejects_prepared_gate_intent_without_retaining_old_authority() {
    let f = OriginFixture::new().await;
    f.admit_provision().await;
    f.stage(&f.genesis).await;
    f.admit_genesis().await.unwrap();
    let key = f.authorize().await;
    let store = PgAuthorityCommitStore {
        pool: f.pool.clone(),
    };
    let event = f.runtime_event(key.commit.committed_at);
    let state = store
        .prepare_agent_origin_state(&event, key.commit.committed_at)
        .await
        .unwrap();
    let carrier = complete_carrier(&f, state.clone(), key.commit.committed_at);
    arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
        &event,
        &carrier,
        &f.station,
        key.commit.committed_at,
        None,
    )
    .unwrap();
    let original = store
        .agent_origin_controller_gate_request(&event, &state)
        .await
        .unwrap();
    assert_eq!(
        store
            .agent_origin_controller_gate_request(&event, &state)
            .await
            .unwrap(),
        original
    );
    let paused = agent_control_event(
        &f.controller.history,
        &f.agent,
        &f.genesis.event.realm_id,
        &format!("{}#managed-controller", f.agent_did),
        EventKind::SelfAgentPause,
        serde_json::json!({"transition":"pause","previous_status":"active","status_changed_at":arkret_canonical::format_timestamp_canonical(key.commit.committed_at)}),
        key.commit.committed_at,
    );
    let mut commit = station_successor(&key.commit, &paused, &f.station_did, 1);
    origin_seal(&mut commit, &f.method, &f.issuer);
    let tx = origin_tx(paused, commit, &f.station);
    f.stage(&tx).await;
    PgActorProfileStore {
        pool: f.pool.clone(),
    }
    .admit_agent_control_event(AgentControlAdmissionWrite {
        queued_at: tx.commit.committed_at,
        commit: tx,
    })
    .await
    .unwrap();
    assert!(
        store
            .agent_origin_controller_gate_request(&event, &state)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_agent_origin_state(&event, key.commit.committed_at)
            .await
            .is_err()
    );
    assert!(
        store
            .retain_agent_forward_evidence_at_same_cut(&event, &carrier, key.commit.committed_at)
            .await
            .is_err(),
        "independently valid old carrier cannot cross the actual paused cut"
    );
    let mut conn = f.pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct N {
        #[diesel(sql_type=BigInt)]
        value: i64,
    }
    let count = diesel::sql_query("SELECT count(*) AS value FROM agent_origin_forward_evidence")
        .get_result::<N>(&mut *conn)
        .await
        .unwrap()
        .value;
    assert_eq!(
        count, 0,
        "stale prepared state creates no retained forward authority"
    );
}

#[tokio::test]
async fn agent_origin_local_runtime_signature_uses_exact_retained_authorization_and_missing_root_refuses()
 {
    let f = OriginFixture::new().await;
    f.admit_provision().await;
    f.stage(&f.genesis).await;
    f.admit_genesis().await.unwrap();
    let key = f.authorize().await;
    let store = PgAuthorityCommitStore {
        pool: f.pool.clone(),
    };
    let event = f.runtime_event(key.commit.committed_at);
    let state = store
        .prepare_agent_origin_state(&event, key.commit.committed_at)
        .await
        .unwrap();
    let runtime = SigningKey::from_bytes(&[0x61; 32]);
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            runtime.verifying_key().as_bytes(),
        ),
    };
    assert_eq!(
        state.authorization.public_key.key.as_str(),
        arkret_canonical::base64url_encode(runtime.verifying_key().as_bytes())
    );
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        event.producer_proof.as_ref().unwrap(),
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(&event)
            .unwrap(),
        &event.actor_id,
        &public,
        event.event_id.digest_suite_code().digest_suite(),
    )
    .unwrap();
    let mut wrong = event.clone();
    wrong.producer_proof.as_mut().unwrap().verification_method =
        DidUrl::new(format!("{}#other-runtime", f.agent_did)).unwrap();
    assert!(
        store
            .prepare_agent_origin_state(&wrong, key.commit.committed_at)
            .await
            .is_err()
    );
    let mut conn = f.pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM agent_origin_control_sources WHERE commit_id=$1")
        .bind::<Text, _>(f.genesis.commit.commit_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        store
            .prepare_agent_origin_state(&event, key.commit.committed_at)
            .await
            .is_err(),
        "accepted/current rows cannot recreate missing original Directory proof"
    );
    assert_eq!(
        f.count("history").await,
        2,
        "history alone is not a substitute for original producer dependency"
    );
}

#[tokio::test]
async fn agent_origin_bad_staged_signature_rolls_back_original_acceptance_and_never_supplies_history()
 {
    let f = OriginFixture::new().await;
    f.admit_provision().await;
    f.stage(&f.genesis).await;
    let mut conn = f.pool.get().await.unwrap();
    diesel::sql_query("UPDATE agent_origin_control_source_candidates SET source_json=jsonb_set(source_json,'{dependency,account_device_signer_evidence,device_projection_attestation,proof,jws}',to_jsonb('invalid.public.fixture.signature'::text)) WHERE event_id=$1")
        .bind::<Text,_>(f.genesis.event.event_id.as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    assert!(
        f.admit_genesis().await.is_err(),
        "cryptographic refusal inside original acceptance transaction"
    );
    assert_eq!(f.count("candidate").await, 1);
    assert_eq!(f.count("source").await, 0);
    assert_eq!(f.count("history").await, 0);
    #[derive(diesel::QueryableByName)]
    struct Footprint {
        #[diesel(sql_type=BigInt)]
        events: i64,
        #[diesel(sql_type=BigInt)]
        commits: i64,
        #[diesel(sql_type=BigInt)]
        authorities: i64,
        #[diesel(sql_type=BigInt)]
        outbox: i64,
    }
    let mut conn = f.pool.get().await.unwrap();
    let rows=diesel::sql_query("SELECT (SELECT count(*) FROM canonical_events WHERE realm_id=$1) AS events,(SELECT count(*) FROM realm_commits WHERE realm_id=$1) AS commits,(SELECT count(*) FROM realm_authorities WHERE realm_id=$1) AS authorities,(SELECT count(*) FROM event_federation_outbox JOIN canonical_events ON canonical_events.pk=event_federation_outbox.event_pk WHERE canonical_events.realm_id=$1) AS outbox")
        .bind::<Text,_>(f.genesis.event.realm_id.as_str()).get_result::<Footprint>(&mut *conn).await.unwrap();
    assert_eq!(
        (rows.events, rows.commits, rows.authorities, rows.outbox),
        (0, 0, 0, 0)
    );
    drop(conn);
    let store = PgAuthorityCommitStore {
        pool: f.pool.clone(),
    };
    assert!(
        store
            .prepare_agent_origin_state(
                &f.runtime_event(f.genesis.commit.committed_at),
                f.genesis.commit.committed_at
            )
            .await
            .is_err()
    );
}

/// This issuer fixture signs a real typed binding receipt derived from the
/// accepted controller registration anchor. It does not claim deployment of
/// Coauth, stable account-status publication, or authenticated DPoP admission.
fn complete_carrier(
    f: &OriginFixture,
    state: arkret_models_identity::AgentAuthorityState,
    at: chrono::DateTime<Utc>,
) -> arkret_models_identity::AgentProducerEvidence {
    use arkret_models_identity::agent_signer_evidence::{
        AgentDetachedJws, ControllerAccountGateAttestation,
    };
    use arkret_models_identity::{
        AccountBindingReceipt, AgentAuthorityStateAttestation, AgentAuthorityStateEvidence,
        AgentProducerEvidence,
    };
    let principal = &f.controller.history;
    let registration =
        arkret_signatures::webvh::validate_principal_inception_operation(&principal.inception)
            .unwrap();
    let anchor_digest = principal.registration_anchor.canonical_digest().unwrap();
    let accepted_binding = &f.controller.unit.submission.identity_creation_control_proof;
    assert_eq!(
        accepted_binding.principal_id,
        principal.account.principal_id
    );
    assert_eq!(accepted_binding.pcr_realm_id, principal.events[0].realm_id);
    assert_eq!(
        accepted_binding.control_key_digest,
        registration.control_key_digest
    );
    let mut receipt: AccountBindingReceipt = serde_json::from_value(serde_json::json!({
        "binding_state":"bound", "binding_kind":"identity_creation",
        "account_authority_id":f.station, "account_subject":accepted_binding.account_subject,
        "principal_id":principal.account.principal_id, "did":principal.did,
        "did_version_id":registration.did_version_id, "control_key_digest":registration.control_key_digest,
        "identity_creation_lease_id":accepted_binding.identity_creation_lease_id, "lease_fence":accepted_binding.lease_fence,
        "operation_status":"accepted", "registration_anchor_digest":anchor_digest,
        "issued_at":arkret_canonical::format_timestamp_canonical(at),
        "proof":{"kind":"detached_jws","verification_method":f.method,
          "payload_digest":anchor_digest,"created_at":arkret_canonical::format_timestamp_canonical(at),"jws":"pending"}
    })).unwrap();
    receipt.proof.payload_digest = receipt.canonical_payload_digest().unwrap();
    receipt.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &f.issuer,
        &receipt.canonical_proof_binding_bytes().unwrap(),
    )
    .unwrap();
    receipt.validate_shape().unwrap();
    // The gate commits to the complete signed receipt, never a state digest
    // substituted for the receipt digest.
    let receipt_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&receipt).unwrap()).unwrap();
    let basis = serde_json::json!({"kind":"account_binding_default","binding_version":1,
        "binding_receipt_digest":receipt_digest});
    let basis_digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(
            &serde_json::json!({"principal_id":principal.account.principal_id,
            "accepted_id":f.station,"status":"active","basis":basis}),
        )
        .unwrap(),
    )
    .unwrap();
    let mut gate: ControllerAccountGateAttestation = serde_json::from_value(serde_json::json!({
        "schema":ControllerAccountGateAttestation::SCHEMA_ID,
        "principal_id":principal.account.principal_id,"eligibility":"active","status":"active",
        "basis":basis,"basis_digest":basis_digest,"authority_id":f.station,
        "verification_method":f.method,"issued_at":arkret_canonical::format_timestamp_canonical(at),
        "expires_at":arkret_canonical::format_timestamp_canonical(at+Duration::seconds(120)),
        "proof":{"kind":"detached_jws","jws":"pending"}
    }))
    .unwrap();
    arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
        &mut gate, &f.issuer,
    )
    .unwrap();
    let digest = state.digest().unwrap();
    let mut attestation = AgentAuthorityStateAttestation {
        authority_id: f.station.clone(),
        verification_method: f.method.clone(),
        state_digest: digest.clone(),
        issued_at: at,
        expires_at: at + Duration::seconds(120),
        proof: AgentDetachedJws {
            kind: arkret_wire::NonEmptyString::new("detached_jws").unwrap(),
            jws: arkret_wire::NonEmptyString::new("pending").unwrap(),
        },
    };
    attestation.proof.jws = arkret_wire::NonEmptyString::new(
        arkret_signatures::sign_ed25519_detached_jws(
            &f.issuer,
            &attestation.signing_bytes().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let jwk =
        arkret_signatures::jwk::JsonWebKey::ed25519(state.authorization.public_key.key.clone());
    let signer=arkret_models_identity::authenticated_signer_resolution_evidence::build_agent_signer_evidence(
        state.agent_id.clone(),state.authorization.verification_method.clone(),
        serde_json::from_value(serde_json::to_value(jwk).unwrap()).unwrap(),
        state.authorization.accepted_commit_id.clone(),state.authorization.accepted_at).unwrap();
    AgentProducerEvidence {
        authenticated_signer_evidence: signer,
        agent_authority_state_evidence: AgentAuthorityStateEvidence {
            schema: arkret_wire::NonEmptyString::new(
                arkret_wire::SchemaId::AGENT_AUTHORITY_STATE_EVIDENCE_V1,
            )
            .unwrap(),
            state: Some(state),
            state_digest: digest,
            attestation,
        },
        controller_account_gate_attestation: gate,
        authority_resolution: f.history.clone(),
    }
}

#[tokio::test]
async fn agent_origin_complete_retained_carrier_replay_and_bad_gate_have_no_authority_shortcut() {
    let f = OriginFixture::new().await;
    f.admit_provision().await;
    f.stage(&f.genesis).await;
    f.admit_genesis().await.unwrap();
    let key = f.authorize().await;
    let store = PgAuthorityCommitStore {
        pool: f.pool.clone(),
    };
    let at = key.commit.committed_at;
    let event = f.runtime_event(at);
    let state = store.prepare_agent_origin_state(&event, at).await.unwrap();
    let evidence = complete_carrier(&f, state, at);
    arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
        &event, &evidence, &f.station, at, None,
    )
    .unwrap();
    let mut wrong = evidence.clone();
    wrong.controller_account_gate_attestation.proof.jws = arkret_wire::NonEmptyString::new(
        arkret_signatures::sign_ed25519_detached_jws(
            &SigningKey::from_bytes(&[0x42; 32]),
            &wrong
                .controller_account_gate_attestation
                .signing_bytes()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        store
            .retain_agent_forward_evidence_at_same_cut(&event, &wrong, at)
            .await
            .is_err()
    );
    let mut conn = f.pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=BigInt)]
        count: i64,
    }
    let count = diesel::sql_query("SELECT count(*) AS count FROM agent_origin_forward_evidence")
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count;
    assert_eq!(count, 0, "bad gate retains no carrier");
    drop(conn);
    store
        .retain_agent_forward_evidence_at_same_cut(&event, &evidence, at)
        .await
        .unwrap();
    store
        .retain_agent_forward_evidence_at_same_cut(&event, &evidence, at)
        .await
        .unwrap();
    let mut conn = f.pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Stored {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let stored = diesel::sql_query(
        "SELECT evidence_json AS value FROM agent_origin_forward_evidence WHERE event_id=$1",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .get_results::<Stored>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        stored.len(),
        1,
        "exact replay never creates another carrier"
    );
    let reopened: arkret_models_identity::AgentProducerEvidence =
        serde_json::from_value(stored[0].value.clone()).unwrap();
    arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
        &event, &reopened, &f.station, at, None,
    )
    .unwrap();
    assert_eq!(
        arkret_canonical::canonical_sha256(&reopened).unwrap(),
        arkret_canonical::canonical_sha256(&evidence).unwrap()
    );
    drop(conn);
    let mut incomplete = evidence.clone();
    incomplete.agent_authority_state_evidence.state = None;
    assert!(
        store
            .retain_agent_forward_evidence_at_same_cut(&event, &incomplete, at)
            .await
            .is_err()
    );
    assert!(
        store
            .retain_agent_forward_evidence_at_same_cut(
                &event,
                &evidence,
                at + Duration::seconds(121)
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.count("source").await,
        2,
        "forward retention does not mint new accepted control sources"
    );
}

#[tokio::test]
async fn agent_origin_expired_non_authority_candidate_is_restaged_without_erasing_accepted_source()
{
    let f = OriginFixture::new().await;
    f.stage(&f.genesis).await;
    let mut conn = f.pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE agent_origin_control_source_candidates SET staged_at=now()-interval '25 hours'",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    f.stage(&f.genesis).await;
    assert_eq!(f.count("candidate").await, 1);
    assert_eq!(f.count("source").await, 0, "restaging is not acceptance");
    assert_eq!(f.count("history").await, 0);
    f.admit_provision().await;
    f.admit_genesis().await.unwrap();
    assert_eq!(f.count("candidate").await, 0);
    assert_eq!(f.count("source").await, 1);
    assert_eq!(f.count("history").await, 1);
    // Further staged control activity does not expire or edit original source.
    let _key = f.authorize().await;
    assert_eq!(f.count("source").await, 2);
    assert_eq!(f.count("history").await, 2);
}
