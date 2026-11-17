//! Real G native admission and H source transactions. The leased local Service
//! binding and verified status replica inputs are trusted storage-port
//! preconditions. This is not CLI/AA/HTTP/native execution credit.
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(
    dead_code,
    reason = "This integration target uses only the native founding-Device fixture slice."
)]
mod device_authorization_history;
#[path = "support/organization_origin.rs"]
mod organization_origin;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(
    dead_code,
    reason = "The shared native fixture also supports unrelated accepted-Device scenarios."
)]
mod pcr_genesis;
#[path = "support/sql_fault_matrix.rs"]
mod sql_fault_matrix;

use arkret_models_collaboration::account_status::{
    UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::*;
use coland_storage::{
    AccountStatusReplicaAppend, ActorProfileStore as _, ConflictCode, PersistenceStore as _,
    PrincipalResolutionStore as _, SyncStoreRegistry as _,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgActorProfileStore, PgAuthorityCommitStore, PgPersistenceStore, PgPrincipalResolutionStore,
};
use diesel::OptionalExtension as _;
use diesel_async::RunQueryDsl as _;
use organization_origin::OrganizationFixture;

struct Fixture {
    _h: TestDatabase,
    _g: TestDatabase,
    h: PgAuthorityCommitStore,
    g: PgAuthorityCommitStore,
    native: OrganizationFixture,
    hosting: DidCoreId,
}

impl Fixture {
    async fn new() -> Self {
        let h = TestDatabase::lease().await;
        let g = TestDatabase::lease().await;
        let mut native = OrganizationFixture::new(false, true);
        // Real independent Service S is also H for this fixture; G remains
        // the independently generated governor. Only producer input changes.
        let hosting = project_did_to_core_id(&native.producer.did.parse().unwrap()).unwrap();
        let principal = native
            .write
            .request
            .event_submission
            .event
            .actor_id
            .as_account_id()
            .unwrap()
            .principal_id
            .clone();
        native.write.request.event_submission.event.actor_id =
            ActorId::account(AccountId::new(principal, hosting.clone()));
        native.write.source_service_id = hosting.clone();
        native.resign(true);
        h.bind_device_inventory_station(hosting.as_str());
        let governor = project_did_to_core_id(&native.governor.did.parse().unwrap()).unwrap();
        g.bind_device_inventory_station(governor.as_str());
        native.retain_current_histories(&h.pool()).await;
        native.retain_current_histories(&g.pool()).await;
        Self {
            h: PgAuthorityCommitStore { pool: h.pool() },
            g: PgAuthorityCommitStore { pool: g.pool() },
            _h: h,
            _g: g,
            native,
            hosting,
        }
    }

    async fn admit_g(&self) -> AuthoritySubmitResponseBody {
        PgActorProfileStore {
            pool: self.g.pool.clone(),
        }
        .admit_organization_pcr_genesis(self.native.write.clone())
        .await
        .unwrap()
    }

    async fn certificate(
        &self,
    ) -> (
        RealmAuthorityBundle,
        arkret_identity::RealmAuthorityFreshness,
        arkret_identity::RealmAuthorityKeyMap,
    ) {
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let governor = project_did_to_core_id(&self.native.governor.did.parse().unwrap()).unwrap();
        let route = arkret_identity::build_authenticated_webvh_service_resolution(
            governor.clone(),
            "station".into(),
            serde_json::from_value(self.native.governor.log_entry["state"].clone()).unwrap(),
            vec![self.native.governor.log_entry.clone()],
            vec![],
            at,
        )
        .unwrap();
        let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([73u8; 32])).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&self.native.governor.did_key_seed);
        let method = DidUrl::new(&self.native.governor.did_key_id).unwrap();
        let app = coland_services::authority_commit::AuthorityCommitApplication::new(
            coland_services::persistence::PersistenceHandle::new(std::sync::Arc::new(
                PgPersistenceStore::new(self.g.pool.clone()),
            )),
            1024,
        );
        let bundle = app
            .authority_bundle(
                &RealmAuthorityBundleRequestBody {
                    realm_id: self.native.write.transaction.event.realm_id.clone(),
                    nonce: nonce.clone(),
                },
                &governor,
                serde_json::to_value(route).unwrap(),
                method.clone(),
                &key,
                at,
            )
            .await
            .unwrap();
        let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
        for at in [
            bundle.genesis_commit.signature.created_at,
            bundle.current_assertion.signature.created_at,
        ] {
            keys.insert_at(
                &method,
                at,
                arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.verifying_key().to_bytes().to_vec(),
                },
            );
        }
        let freshness = arkret_identity::RealmAuthorityFreshness::new(at, nonce);
        arkret_identity::verify_realm_authority_bundle(&bundle, &freshness, &keys).unwrap();
        (bundle, freshness, keys)
    }

    async fn prepare_h(
        &self,
    ) -> coland_storage::PersistenceResult<
        arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody,
    > {
        self.h
            .prepare_organization_hosting(
                &self.native.write.request,
                &self.hosting,
                &self.native.write.organization_log_entries,
                &self.native.write.organization_witness_records,
                self.native.write.producer_service_resolution.as_ref(),
            )
            .await
    }
}

#[tokio::test]
async fn hosting_source_and_original_install_are_atomic_cold_and_do_not_duplicate_g_approval_consumption()
 {
    let fixture = Fixture::new().await;
    let request = &fixture.native.write.request;
    assert!(
        fixture
            .h
            .organization_hosting_intent(&request.event_submission, &fixture.hosting)
            .await
            .unwrap()
            .is_none()
    );
    let frozen =
        sql_fault_matrix::exhaust_writes(&fixture.h.pool, "H-first-source", || fixture.prepare_h())
            .await;
    assert_eq!(frozen, *request);
    let prepared = sql_fault_matrix::snapshot(&fixture.h.pool).await;
    assert!(prepared["accounts"].as_array().unwrap().is_empty());
    assert!(
        prepared["principal_resolution_current_states"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(prepared["realm_commits"].as_array().unwrap().is_empty());
    assert_eq!(
        prepared["authority_forward_attempts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let outcome = fixture.admit_g().await;
    let installed =
        sql_fault_matrix::exhaust_writes(&fixture.h.pool, "H-original-install", || async {
            let (bundle, freshness, keys) = fixture.certificate().await;
            fixture
                .h
                .complete_organization_hosting(
                    &request.event_submission,
                    &fixture.hosting,
                    &outcome,
                    &bundle,
                    &freshness,
                    &keys,
                )
                .await
        })
        .await;
    assert_eq!(installed, outcome);
    let accepted = sql_fault_matrix::snapshot(&fixture.h.pool).await;
    for table in [
        "accounts",
        "principal_resolution_current_states",
        "realm_commits",
        "agent_producer_signer_keys",
    ] {
        assert_eq!(
            accepted[table].as_array().unwrap().len(),
            1,
            "missing unique accepted H source: {table}"
        );
    }
    for table in [
        "organization_pcr_genesis_sources",
        "event_approval_private_audit",
        "devices",
        "sessions",
        "consent_current_states",
    ] {
        assert!(
            accepted[table].as_array().unwrap().is_empty(),
            "borrowed G/private/Human authority: {table}"
        );
    }
    assert!(accepted["authority_forward_attempts"][0]["peer_request_json"].is_null());
    let cold = PgAuthorityCommitStore {
        pool: fixture.h.pool.clone(),
    };
    let recovered = cold
        .organization_hosting_intent(&request.event_submission, &fixture.hosting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&recovered.unwrap()).unwrap(),
        arkret_canonical::canonical_json_bytes(&outcome).unwrap()
    );
    let holder = request
        .event_submission
        .event
        .actor_id
        .as_account_id()
        .unwrap();
    assert_eq!(
        PgPrincipalResolutionStore {
            pool: fixture.h.pool.clone()
        }
        .by_account_id(holder)
        .await
        .unwrap()
        .unwrap()
        .genesis_event,
        request.event_submission.event
    );
    assert_eq!(sql_fault_matrix::snapshot(&fixture.h.pool).await, accepted);
    // Corrupt G only after genuine native acceptance. H's public source is
    // not a replacement for G's mandatory private source/nonce audit.
    let mut conn = fixture.g.pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM event_approval_private_audit")
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        PgPrincipalResolutionStore {
            pool: fixture.g.pool.clone()
        }
        .by_account_id(holder)
        .await
        .is_err()
    );
    assert!(
        PgActorProfileStore {
            pool: fixture.g.pool.clone(),
        }
        .organization_pcr_genesis_original(request, &fixture.hosting)
        .await
        .is_err()
    );
    assert_eq!(
        cold.organization_hosting_intent(&request.event_submission, &fixture.hosting)
            .await
            .unwrap()
            .unwrap(),
        Some(outcome)
    );
}

#[tokio::test]
async fn stranger_g_certificate_and_second_account_inception_cannot_create_h_hosting() {
    let mut fixture = Fixture::new().await;
    let outcome = fixture.admit_g().await;
    let (bundle, freshness, keys) = fixture.certificate().await;
    let before = sql_fault_matrix::snapshot(&fixture.h.pool).await;
    assert!(
        fixture
            .h
            .complete_organization_hosting(
                &fixture.native.write.request.event_submission,
                &fixture.hosting,
                &outcome,
                &bundle,
                &freshness,
                &keys
            )
            .await
            .is_err()
    );
    assert_eq!(sql_fault_matrix::snapshot(&fixture.h.pool).await, before);
    fixture.prepare_h().await.unwrap();
    let before = sql_fault_matrix::snapshot(&fixture.h.pool).await;
    let original = fixture.native.write.request.clone();
    fixture
        .native
        .write
        .request
        .event_submission
        .event
        .payload
        .get_mut("object")
        .unwrap()["genesis_salt"] = serde_json::json!(arkret_canonical::base64url_encode([98; 32]));
    // An alternate valid Event for this same Account is a new intent, not a
    // retry; retain its root/producer signing through the real fixture helper.
    fixture.native.resign(true);
    arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
        &fixture.native.write.request,
        &fixture.hosting,
        &fixture.native.write.organization_log_entries,
        &fixture.native.write.organization_witness_records,
        fixture.native.write.producer_service_resolution.as_ref(),
        chrono::Utc::now(),
    )
    .unwrap();
    assert!(
        fixture
            .h
            .organization_hosting_intent(
                &fixture.native.write.request.event_submission,
                &fixture.hosting
            )
            .await
            .is_err()
    );
    assert_eq!(sql_fault_matrix::snapshot(&fixture.h.pool).await, before);
    let stranger = project_did_to_core_id(&fixture.native.governor.did.parse().unwrap()).unwrap();
    assert!(
        fixture
            .h
            .organization_hosting_intent(&original.event_submission, &stranger)
            .await
            .is_err()
    );
    assert_eq!(sql_fault_matrix::snapshot(&fixture.h.pool).await, before);
}

#[tokio::test]
async fn accepted_terminal_record_before_h_account_exists_blocks_late_g_install_without_rebuilding_private_state()
 {
    let fixture = Fixture::new().await;
    fixture.prepare_h().await.unwrap();
    let outcome = fixture.admit_g().await;
    let event = &fixture.native.write.request.event_submission.event;
    let holder = event.actor_id.as_account_id().unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let signing = ed25519_dalek::SigningKey::from_bytes(&fixture.native.producer.did_key_seed);
    let method = DidUrl::new(&fixture.native.producer.did_key_id).unwrap();
    let record = arkret_signatures::account_status::sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
            account_authority_id: fixture.hosting.clone(),
            account_id: holder.clone(),
            principal_control_realm_id: event.realm_id.clone(),
            binding_version: 1,
            status_sequence: 1,
            previous_account_status_record_id: None,
            status: AccountStatus::ErasurePending,
            reason_code: None,
            reason: None,
            issued_at: at,
            expires_at: None,
        },
        method.clone(),
        &signing,
    )
    .unwrap();
    let receipt = arkret_signatures::account_status::sign_account_status_receipt(
        UnsignedAccountStatusReceipt {
            receipt_id: format!("ak:receipt:{}", uuid::Uuid::now_v7())
                .parse()
                .unwrap(),
            account_status_record_id: record.account_status_record_id.clone(),
            record_digest: record.payload_digest().unwrap(),
            account_authority_id: record.account_authority_id.clone(),
            account_id: holder.clone(),
            status_sequence: 1,
            receiver_id: fixture.hosting.clone(),
            accepted_at: at,
            verification_method: method,
        },
        &signing,
    )
    .unwrap();
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: signing.verifying_key().to_bytes().to_vec(),
    };
    arkret_signatures::account_status::verify_account_status_record(&record, &public).unwrap();
    arkret_signatures::account_status::verify_account_status_receipt(&receipt, &public).unwrap();
    assert!(matches!(
        PgPersistenceStore::new(fixture.h.pool.clone())
            .account_status_replicas()
            .append(&record, &receipt)
            .await
            .unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
    let before = sql_fault_matrix::snapshot(&fixture.h.pool).await;
    let (bundle, freshness, keys) = fixture.certificate().await;
    let error = fixture
        .h
        .complete_organization_hosting(
            &fixture.native.write.request.event_submission,
            &fixture.hosting,
            &outcome,
            &bundle,
            &freshness,
            &keys,
        )
        .await
        .unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::AccountErased));
    let error = fixture.prepare_h().await.unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::AccountErased));
    assert!(
        PgAuthorityCommitStore {
            pool: fixture.h.pool.clone()
        }
        .organization_hosting_intent(
            &fixture.native.write.request.event_submission,
            &fixture.hosting
        )
        .await
        .is_err()
    );
    assert_eq!(sql_fault_matrix::snapshot(&fixture.h.pool).await, before);
    assert!(before["realm_commits"].as_array().unwrap().is_empty());
    assert!(
        before["principal_resolution_current_states"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

// Real native C PCR and H-issued forward evidence. The PG ports below model
// already authenticated service/AA inputs, not production CLI/network credit.
struct DeviceFixture {
    base: Fixture,
    pcr: pcr_genesis::PcrGenesisFixture,
    service_resolution: arkret_models_identity::AuthenticatedServiceResolution,
}

impl DeviceFixture {
    async fn new() -> Self {
        let mut base = Fixture::new().await;
        let at = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() - chrono::Duration::seconds(2),
        );
        let mut pcr = pcr_genesis::PcrGenesisFixture::new_with(
            base.native.producer.did.parse().unwrap(),
            device_authorization_history::DeviceHistoryFixtureOptions {
                local_id: format!("hosting-c-{}", uuid::Uuid::now_v7()),
                created_at: at,
                founding_not_before: at,
                ..Default::default()
            },
        );
        // Use H's actual native assertion method and held key, rather than
        // borrowing the fixture's default Station authority key/alias.
        let key = ed25519_dalek::SigningKey::from_bytes(&base.native.producer.did_key_seed);
        let method = DidUrl::new(&base.native.producer.did_key_id).unwrap();
        let mut previous = None;
        for (index, tx) in pcr.unit.transactions.iter_mut().enumerate() {
            tx.commit.previous_commit_ref = previous;
            tx.commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(
                    &arkret_canonical::unsigned_value(&tx.commit, &["commit_id", "signature"])
                        .unwrap(),
                )
                .unwrap(),
            ));
            tx.commit.signature = arkret_signatures::detached_object::sign_detached_object(
                &arkret_canonical::unsigned_value(&tx.commit, &["signature"]).unwrap(),
                DetachedSignatureContext::RealmCommit,
                method.clone(),
                tx.commit.committed_at,
                &key,
            )
            .unwrap();
            previous = Some(tx.commit.commit_id.clone());
            pcr.history.commits[index] = tx.commit.clone();
        }
        pcr.unit.validate().unwrap();
        pcr.admit_founding_device(&PgPersistenceStore::new(base.h.pool.clone()))
            .await
            .unwrap();
        let service_resolution = base
            .native
            .write
            .producer_service_resolution
            .take()
            .unwrap();
        base.native.write.request.event_submission.event.created_at =
            pcr.unit.transactions.last().unwrap().commit.committed_at
                + chrono::Duration::milliseconds(1);
        base.native.write.request.event_submission.event.executed_by =
            Some(ActorId::account(pcr.history.account.clone()));
        let mut result = Self {
            base,
            pcr,
            service_resolution,
        };
        result.resign_device(None);
        result
    }

    fn resign_device(&mut self, proof_at: Option<chrono::DateTime<chrono::Utc>>) {
        let mut event = self
            .base
            .native
            .write
            .request
            .event_submission
            .event
            .clone();
        event.producer_proof = None;
        let at = proof_at.unwrap_or(event.created_at);
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(event, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
                self.pcr.history.founding_device_signing_seed,
                self.pcr.history.device_verification_method.as_str(),
            ),
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        self.base.native.write.request.event_submission.event = authored.into_event();
        self.reapprove();
    }

    fn reapprove(&mut self) {
        let original = &mut self.base.native.write.request.event_submission;
        let digest =
            Hash::new(arkret_canonical::canonical_sha256(&original.event).unwrap()).unwrap();
        for vote in original.approval_signatures.as_mut().unwrap() {
            vote.input.approval_target = ApprovalTarget::Event {
                event_id: original.event.event_id.clone(),
            };
            vote.input.request_canonical_digest = digest.clone();
            vote.input.realm_id = original.event.realm_id.clone();
            vote.input.initiating_actor_id = original.event.actor_id.clone();
            vote.input.approved_at =
                arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            vote.input.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
            let seed = if vote
                .proof
                .verification_method
                .as_str()
                .ends_with("#organization-control")
            {
                33
            } else {
                assert!(
                    vote.proof
                        .verification_method
                        .as_str()
                        .ends_with("#governance-second")
                );
                34
            };
            vote.proof.jws = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
                [seed; 32],
                vote.proof.verification_method.as_str(),
            )
            .sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(vote)
                    .unwrap(),
            );
        }
        original
            .approval_signatures
            .as_mut()
            .unwrap()
            .sort_by_key(|vote| arkret_canonical::canonical_json_string(&vote.input).unwrap());
        arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_authority(
            original,
            &self.base.native.write.organization_log_entries,
            &self.base.native.write.organization_witness_records,
            chrono::Utc::now(),
        )
        .unwrap();
    }

    async fn fresh(
        &mut self,
        hosting_owner: bool,
    ) -> arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody {
        let original = &self.base.native.write.request.event_submission;
        let prepared = if hosting_owner {
            self.base
                .h
                .prepare_organization_hosting_device(original, &self.base.hosting)
                .await
                .unwrap()
                .unwrap()
        } else {
            // An independently valid adversarial G certificate may name a
            // different original H business choice. The existing generic C
            // source port proves native current; H's hosting journal must
            // still reject the certificate as a different whole request.
            PgPersistenceStore::new(self.base.h.pool.clone()).account_device_signer_evidence().prepare_forward_request(
                &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(self.base.native.write.request.clone()),
                &project_did_to_core_id(&self.base.native.governor.did.parse().unwrap()).unwrap(),
            ).await.unwrap().unwrap()
        };
        let evidence = arkret_models_identity::ForwardAccountDeviceSignerEvidence {
            device_projection_attestation:
                arkret_signatures::device_projection::sign_forward_device_projection_attestation(
                    prepared.device,
                    DidUrl::new(&self.base.native.producer.did_key_id).unwrap(),
                    &ed25519_dalek::SigningKey::from_bytes(&self.base.native.producer.did_key_seed),
                )
                .unwrap(),
            service_resolution: self.service_resolution.clone(),
        };
        let request = arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody::new(
            original.clone(), None, None, Some(evidence),
        ).unwrap();
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let (_, fact) =
            arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
                &request,
                &self.base.hosting,
                &self.base.native.write.organization_log_entries,
                &self.base.native.write.organization_witness_records,
                None,
                at,
            )
            .unwrap();
        self.base.native.write.request = request.clone();
        self.base.native.write.queued_at = at;
        self.base.native.sign_candidate_fact(Some(fact.into()));
        request
    }

    async fn prepare(&mut self) -> EventAdmissionSubmission {
        let request = self.fresh(true).await;
        self.base
            .h
            .prepare_organization_hosting(
                &request,
                &self.base.hosting,
                &self.base.native.write.organization_log_entries,
                &self.base.native.write.organization_witness_records,
                None,
            )
            .await
            .unwrap();
        request.event_submission
    }
}

#[tokio::test]
async fn finite_device_original_is_the_exact_bundle_projection_and_cold_result() {
    let mut fixture = DeviceFixture::new().await;
    let original = fixture.prepare().await;
    let outcome = fixture.base.admit_g().await;
    assert_eq!(
        PgActorProfileStore {
            pool: fixture.base.g.pool.clone(),
        }
        .organization_pcr_genesis_original(
            &fixture.base.native.write.request,
            &fixture.base.hosting
        )
        .await
        .unwrap(),
        Some(outcome.clone())
    );
    let (bundle, freshness, keys) = fixture.base.certificate().await;
    let accepted = fixture
        .base
        .h
        .recover_organization_hosting(&original, &fixture.base.hosting, &bundle, &freshness, &keys)
        .await
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&accepted).unwrap(),
        arkret_canonical::canonical_json_bytes(&outcome).unwrap()
    );
    let cold = PgAuthorityCommitStore {
        pool: fixture.base.h.pool.clone(),
    };
    assert_eq!(
        cold.organization_hosting_intent(&original, &fixture.base.hosting)
            .await
            .unwrap(),
        Some(Some(outcome))
    );
    let rows = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
    assert!(
        rows["organization_pcr_genesis_sources"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        rows["event_approval_private_audit"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(rows["authority_forward_attempts"][0]["peer_request_json"].is_null());
}

#[tokio::test]
async fn same_id_different_proof_or_exact_approval_vector_never_matches_h_original() {
    for change in ["producer_proof", "new_approval_set"] {
        let mut fixture = DeviceFixture::new().await;
        let original = fixture.prepare().await;
        if change == "producer_proof" {
            let at = original.event.producer_proof.as_ref().unwrap().created_at
                + chrono::Duration::milliseconds(1);
            fixture.resign_device(Some(at));
        } else {
            fixture.reapprove();
        }
        assert_eq!(
            original.event.event_id,
            fixture
                .base
                .native
                .write
                .request
                .event_submission
                .event
                .event_id
        );
        assert_ne!(original, fixture.base.native.write.request.event_submission);
        fixture.fresh(false).await;
        fixture.base.admit_g().await;
        let (bundle, freshness, keys) = fixture.base.certificate().await;
        let before = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
        assert!(
            fixture
                .base
                .h
                .recover_organization_hosting(
                    &original,
                    &fixture.base.hosting,
                    &bundle,
                    &freshness,
                    &keys
                )
                .await
                .is_err(),
            "{change}"
        );
        assert_eq!(
            sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
            before
        );
    }
    let mut fixture = DeviceFixture::new().await;
    let original = fixture.prepare().await;
    fixture.base.admit_g().await;
    let (bundle, freshness, keys) = fixture.base.certificate().await;
    let mut reordered = original.clone();
    reordered.approval_signatures.as_mut().unwrap().reverse();
    assert_ne!(reordered, original);
    let before = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
    assert!(
        fixture
            .base
            .h
            .recover_organization_hosting(
                &reordered,
                &fixture.base.hosting,
                &bundle,
                &freshness,
                &keys
            )
            .await
            .is_err()
    );
    assert_eq!(
        sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
        before
    );
}

#[tokio::test]
async fn wrong_host_extra_siblings_or_duplicate_status_cannot_install_an_original() {
    let mut fixture = DeviceFixture::new().await;
    let original = fixture.prepare().await;
    let outcome = fixture.base.admit_g().await;
    let (bundle, freshness, keys) = fixture.base.certificate().await;
    let before = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
    let wrong_h =
        project_did_to_core_id(&fixture.base.native.governor.did.parse().unwrap()).unwrap();
    assert!(
        fixture
            .base
            .h
            .recover_organization_hosting(&original, &wrong_h, &bundle, &freshness, &keys)
            .await
            .is_err()
    );
    let duplicate = AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Duplicate,
        commit: bundle.genesis_commit.clone(),
    };
    assert!(
        fixture
            .base
            .h
            .complete_organization_hosting(
                &original,
                &fixture.base.hosting,
                &duplicate,
                &bundle,
                &freshness,
                &keys
            )
            .await
            .is_err()
    );
    assert_ne!(duplicate, outcome);
    let mut wrong_g_commit = bundle.genesis_commit.clone();
    let wrong_g_key =
        ed25519_dalek::SigningKey::from_bytes(&fixture.base.native.producer.did_key_seed);
    wrong_g_commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(
            &arkret_canonical::unsigned_value(&wrong_g_commit, &["commit_id", "signature"])
                .unwrap(),
        )
        .unwrap(),
    ));
    wrong_g_commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&wrong_g_commit, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(&fixture.base.native.producer.did_key_id).unwrap(),
        wrong_g_commit.committed_at,
        &wrong_g_key,
    )
    .unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &wrong_g_commit.signature,
        &arkret_canonical::unsigned_value(&wrong_g_commit, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmCommit,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: wrong_g_key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    assert!(
        arkret_identity::organization_pcr_genesis::verify_organization_genesis_signer_fact(
            &CommittedEventFullView {
                event: original.event.clone(),
                commit: wrong_g_commit
            },
            &arkret_models_collaboration::authority_commit::organization_genesis_signer_fact(
                &bundle
            )
            .unwrap()
            .unwrap(),
        )
        .is_err(),
        "a real other Service signature cannot replace the G selected by finite root votes"
    );
    let mut extra = fixture.base.native.write.request.clone();
    extra.content_backup_sources = Some(vec![]);
    assert!(
        coland_http::state::organization_hosting::read_request(
            &serde_json::to_vec(&extra).unwrap()
        )
        .is_err()
    );
    assert!(
        fixture
            .base
            .h
            .prepare_organization_hosting(
                &extra,
                &fixture.base.hosting,
                &fixture.base.native.write.organization_log_entries,
                &fixture.base.native.write.organization_witness_records,
                None
            )
            .await
            .is_err()
    );
    assert_eq!(
        sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
        before
    );
}

use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
use arkret_models_collaboration::governance::erasure::*;
use coland_storage::{
    AccountErasureExecution, AccountErasureExecutionState, PersistenceError, PersistenceResult,
};
use ed25519_dalek::Signer as _;

fn device_erasure_package(
    pending: &AccountErasureExecution,
    signing_key: &ed25519_dalek::SigningKey,
    method: &arkret_wire::DidUrl,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<ErasureReceiptPackage> {
    let receipt_id = arkret_models_collaboration::governance::erasure::account_erasure_receipt_id(
        &pending.triggering_status_record_id,
        pending.storage_boundary,
    );
    let subject = ErasureSubject {
        kind: ErasureSubjectKind::Principal,
        subject_ref: pending.principal_id.to_string(),
    };
    let scope = ErasureScope {
        storage_boundary: pending.storage_boundary,
        realm_id: None,
        target_refs: vec![pending.principal_id.to_string()],
        retention_policy_id: None,
        service_scope: Some("account_status.erasure_execution".into()),
    };
    let trigger = ErasureTrigger::AccountStatusRecord {
        account_status_record_id: pending.triggering_status_record_id.clone(),
    };
    let stub = serde_json::from_value(serde_json::json!({
        "stub_schema":arkret_wire::SchemaId::ERASURE_VERIFICATION_STUB_V1,
        "receipt_id":receipt_id,"trigger":trigger,"subject":subject,"scope":scope,
        "completed_at":arkret_canonical::format_timestamp_canonical(at),
    }))
    .map_err(PersistenceError::database)?;
    let mut receipt = ErasureReceipt {
        receipt_id,
        trigger,
        schema: ErasureReceipt::SCHEMA.into(),
        issuer_id: pending.receiver_id.clone(),
        subject,
        scope,
        outcome: ErasureAttemptOutcome::Completed,
        erased_classes: vec![
            ErasedClass::AccountPrivateState,
            ErasedClass::PushRoutes,
            ErasedClass::DeviceSecrets,
            ErasedClass::ProjectionRows,
        ],
        retained_stub_digest: Hash::new(arkret_canonical::canonical_sha256(&stub).unwrap())
            .unwrap(),
        retained_stub: None,
        legal_hold_ref: None,
        completed_at: at,
        issued_at: Some(at),
        proofs: vec![],
        fanout_status: None,
        peer_receipts: vec![],
    };
    let payload = receipt.canonical_proof_input().unwrap();
    let header = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "alg":"Ed25519","kid":method,
    }))
    .unwrap();
    let protected = arkret_canonical::base64url_encode(&header);
    let signing_input = format!(
        "{protected}.{}",
        arkret_canonical::base64url_encode(&payload)
    );
    let signature = signing_key.sign(signing_input.as_bytes());
    signing_key
        .verifying_key()
        .verify_strict(signing_input.as_bytes(), &signature)
        .unwrap();
    receipt.proofs.push(ErasureReceiptProof {
        verification_method: method.clone(),
        payload_digest: receipt.canonical_payload_digest().unwrap(),
        signature: format!(
            "{protected}..{}",
            arkret_canonical::base64url_encode(signature.to_bytes())
        ),
        extra: std::collections::BTreeMap::from([
            ("scheme".into(), serde_json::json!("ed25519-detached-jws")),
            (
                "signature_input".into(),
                serde_json::json!("rfc7515-detached-jws"),
            ),
        ]),
    });
    let package = ErasureReceiptPackage {
        receipt,
        retained_stub: stub,
    };
    package
        .validate_bindings()
        .map_err(PersistenceError::database)?;
    Ok(package)
}

impl DeviceFixture {
    async fn erase(&self, account: &AccountId, realm: &RealmId) -> AccountErasureExecution {
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let method = DidUrl::new(&self.base.native.producer.did_key_id).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&self.base.native.producer.did_key_seed);
        let record = arkret_signatures::account_status::sign_account_status_record(
            UnsignedAccountStatusRecord {
                schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
                account_authority_id: self.base.hosting.clone(),
                account_id: account.clone(),
                principal_control_realm_id: realm.clone(),
                binding_version: 1,
                status_sequence: 1,
                previous_account_status_record_id: None,
                status: AccountStatus::ErasurePending,
                reason_code: None,
                reason: None,
                issued_at: at,
                expires_at: None,
            },
            method.clone(),
            &key,
        )
        .unwrap();
        let receipt = arkret_signatures::account_status::sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: format!("ak:receipt:{}", uuid::Uuid::now_v7())
                    .parse()
                    .unwrap(),
                account_status_record_id: record.account_status_record_id.clone(),
                record_digest: record.payload_digest().unwrap(),
                account_authority_id: record.account_authority_id.clone(),
                account_id: account.clone(),
                status_sequence: 1,
                receiver_id: self.base.hosting.clone(),
                accepted_at: at,
                verification_method: method.clone(),
            },
            &key,
        )
        .unwrap();
        let document = arkret_identity::authenticated_service_document_at(
            &self.service_resolution,
            &self.base.hosting,
            at,
        )
        .unwrap();
        let public =
            arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, method.as_str())
                .unwrap();
        assert_eq!(public, key.verifying_key());
        let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public.to_bytes().to_vec(),
        };
        arkret_signatures::account_status::verify_account_status_record(&record, &public).unwrap();
        arkret_signatures::account_status::verify_account_status_receipt(&receipt, &public)
            .unwrap();
        let store = PgPersistenceStore::new(self.base.h.pool.clone());
        assert!(matches!(
            store
                .account_status_replicas()
                .append(&record, &receipt)
                .await
                .unwrap(),
            AccountStatusReplicaAppend::Accepted(_)
        ));
        let pending = AccountErasureExecution {
            receiver_id: self.base.hosting.clone(),
            account_authority_id: record.account_authority_id.clone(),
            account_id: account.clone(),
            principal_id: account.principal_id.clone(),
            triggering_status_record_id: record.account_status_record_id,
            storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
            state: AccountErasureExecutionState::Pending,
            package: None,
        };
        let sign = |at| device_erasure_package(&pending, &key, &method, at);
        let completed = store
            .account_status_replicas()
            .complete_erasure(&pending, &sign)
            .await
            .unwrap();
        assert_eq!(completed.state, AccountErasureExecutionState::Completed);
        completed
            .package
            .as_ref()
            .unwrap()
            .validate_bindings()
            .unwrap();
        let never_sign = |_| -> PersistenceResult<ErasureReceiptPackage> {
            panic!("cold original must not sign again")
        };
        let cold_store = PgPersistenceStore::new(self.base.h.pool.clone());
        let cold = cold_store
            .account_status_replicas()
            .complete_erasure(&pending, &never_sign)
            .await
            .unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&completed).unwrap(),
            arkret_canonical::canonical_json_bytes(&cold).unwrap()
        );
        completed
    }
}

#[tokio::test]
async fn c_erasure_clears_private_peer_source_without_releasing_o_unknown_choice() {
    for accepted_at_g in [false, true] {
        let mut fixture = DeviceFixture::new().await;
        let original = fixture.prepare().await;
        let accepted = if accepted_at_g {
            Some(fixture.base.admit_g().await)
        } else {
            None
        };
        fixture
            .erase(
                &fixture.pcr.history.account,
                &fixture.pcr.history.events[0].realm_id,
            )
            .await;
        let after_erasure = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
        let attempt = &after_erasure["authority_forward_attempts"][0];
        assert!(attempt["peer_request_json"].is_null());
        assert!(attempt["terminal_outcome_json"].is_null());
        assert_eq!(attempt["original_submission_json"], serde_json::to_value(arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(original.clone())).unwrap());
        assert_eq!(
            fixture
                .base
                .h
                .organization_hosting_intent(&original, &fixture.base.hosting)
                .await
                .unwrap(),
            Some(None)
        );
        let error = fixture
            .base
            .h
            .prepare_organization_hosting_device(&original, &fixture.base.hosting)
            .await
            .unwrap_err();
        assert_eq!(error.conflict_code(), Some(ConflictCode::AccountErased));
        assert!(
            fixture.base.prepare_h().await.is_err(),
            "old still-signed C source cannot be sent after erasure"
        );
        assert_eq!(
            sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
            after_erasure
        );
        let mut another = original.clone();
        another.event.payload.get_mut("object").unwrap()["genesis_salt"] =
            serde_json::json!(arkret_canonical::base64url_encode([103u8; 32]));
        fixture.base.native.write.request.event_submission = another;
        fixture.resign_device(None);
        let error = fixture
            .base
            .h
            .organization_hosting_intent(
                &fixture.base.native.write.request.event_submission,
                &fixture.base.hosting,
            )
            .await
            .unwrap_err();
        assert_eq!(error.conflict_code(), Some(ConflictCode::DuplicateConflict));
        assert_eq!(
            sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
            after_erasure
        );
        if let Some(accepted) = accepted {
            // The bundle is read at G from the genuine earlier accepted unit;
            // no dynamic C material is fetched or reconstructed at H.
            fixture.base.native.write.request.event_submission = original.clone();
            let (bundle, freshness, keys) = fixture.base.certificate().await;
            let recovered = fixture
                .base
                .h
                .recover_organization_hosting(
                    &original,
                    &fixture.base.hosting,
                    &bundle,
                    &freshness,
                    &keys,
                )
                .await
                .unwrap();
            assert_eq!(
                arkret_canonical::canonical_json_bytes(&recovered).unwrap(),
                arkret_canonical::canonical_json_bytes(&accepted).unwrap()
            );
            let after = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
            assert_eq!(
                after["accounts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["principal_id"]
                        == fixture.pcr.history.account.principal_id.as_str())
                    .unwrap()["display_name"],
                "[user erased]"
            );
            assert!(after["authority_forward_attempts"][0]["peer_request_json"].is_null());
        }
    }
}

#[tokio::test]
async fn o_erasure_after_g_success_prevents_every_late_h_private_install() {
    let mut fixture = DeviceFixture::new().await;
    let original = fixture.prepare().await;
    fixture.base.admit_g().await;
    let holder = original.event.actor_id.as_account_id().unwrap();
    fixture.erase(holder, &original.event.realm_id).await;
    let before = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
    let (bundle, freshness, keys) = fixture.base.certificate().await;
    let error = fixture
        .base
        .h
        .recover_organization_hosting(&original, &fixture.base.hosting, &bundle, &freshness, &keys)
        .await
        .unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::AccountErased));
    assert!(
        fixture
            .base
            .h
            .prepare_organization_hosting_device(&original, &fixture.base.hosting)
            .await
            .is_err()
    );
    assert_eq!(
        sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
        before
    );
    assert!(
        before["principal_resolution_current_states"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["principal_id"] != holder.principal_id.as_str())
    );
}

#[tokio::test]
async fn fresh_device_source_waits_for_c_tuple_before_locking_o_forward_row() {
    use diesel::sql_types::{BigInt, Text};
    #[derive(diesel::QueryableByName)]
    struct Pid {
        #[diesel(sql_type=BigInt)]
        value: i64,
    }
    let mut fixture = DeviceFixture::new().await;
    let original = fixture.prepare().await;
    let before = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
    let mut holder = fixture.base.h.pool.get().await.unwrap();
    diesel::sql_query("BEGIN")
        .execute(&mut holder)
        .await
        .unwrap();
    let pid = diesel::sql_query("SELECT pg_backend_pid()::bigint AS value")
        .get_result::<Pid>(&mut holder)
        .await
        .unwrap()
        .value;
    diesel::sql_query("SELECT pg_advisory_xact_lock(account_private_tuple_key($1,$2))")
        .bind::<Text, _>(fixture.pcr.history.account.principal_id.as_str())
        .bind::<Text, _>(fixture.pcr.history.account.station_id.as_str())
        .execute(&mut holder)
        .await
        .unwrap();
    let pool = fixture.base.h.pool.clone();
    let source_original = original.clone();
    let hosting = fixture.base.hosting.clone();
    let source = tokio::spawn(async move {
        PgAuthorityCommitStore { pool }
            .prepare_organization_hosting_device(&source_original, &hosting)
            .await
    });
    let mut observer = fixture.base.h.pool.get().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked = diesel::sql_query("SELECT a.pid::bigint AS value FROM pg_stat_activity a WHERE a.datname=current_database() AND $1::integer=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE 'SELECT pg_advisory_xact_lock_shared(account_private_tuple_key%' LIMIT 1")
                .bind::<BigInt,_>(pid).get_result::<Pid>(&mut observer).await.optional().unwrap();
            if blocked.is_some() { break; }
            assert!(!source.is_finished(), "source finished before the real tuple blocker");
            tokio::task::yield_now().await;
        }
    }).await.expect("actual source must be waiting on this fixture's C tuple");
    // Had fresh publication taken the forward row before C's gate, this
    // NOWAIT would fail. The exact row was created by prepare(), not SQL.
    diesel::sql_query("SELECT f.event_pk AS value FROM authority_forward_attempts f JOIN canonical_events e ON e.pk=f.event_pk WHERE e.envelope->>'event_id'=$1 FOR UPDATE OF f NOWAIT")
        .bind::<Text,_>(original.event.event_id.as_str()).get_result::<Pid>(&mut observer).await.unwrap();
    assert!(!source.is_finished());
    diesel::sql_query("ROLLBACK")
        .execute(&mut holder)
        .await
        .unwrap();
    assert!(source.await.unwrap().unwrap().is_some());
    assert_eq!(
        sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
        before
    );
}

#[tokio::test]
async fn local_inspection_requires_accepted_this_h_org_and_never_crosses_o_erasure() {
    let mut fixture = DeviceFixture::new().await;
    let original = fixture.prepare().await;
    let account = original.event.actor_id.as_account_id().unwrap();
    let foreign =
        project_did_to_core_id(&fixture.base.native.governor.did.parse().unwrap()).unwrap();
    let before = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
    assert!(
        fixture
            .base
            .h
            .require_accepted_organization_hosting_account(account, &foreign)
            .await
            .is_err()
    );
    let other_account = AccountId::new(account.principal_id.clone(), foreign);
    assert!(
        fixture
            .base
            .h
            .require_accepted_organization_hosting_account(&other_account, &fixture.base.hosting)
            .await
            .is_err()
    );
    assert!(
        fixture
            .base
            .h
            .require_accepted_organization_hosting_account(account, &fixture.base.hosting)
            .await
            .is_err(),
        "pending hosting is not accepted Org inspection authority"
    );
    assert!(
        fixture
            .base
            .h
            .require_accepted_organization_hosting_account(
                &fixture.pcr.history.account,
                &fixture.base.hosting
            )
            .await
            .is_err(),
        "a native Human PCR is not this Org operator scope"
    );
    assert_eq!(
        sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
        before
    );
    fixture.base.admit_g().await;
    let (bundle, freshness, keys) = fixture.base.certificate().await;
    // Even a genuinely admitted foreign G unit cannot authorize H inspection
    // before H has actually installed its own original accepted lineage.
    assert!(
        fixture
            .base
            .h
            .require_accepted_organization_hosting_account(account, &fixture.base.hosting)
            .await
            .is_err()
    );
    assert_eq!(
        sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
        before
    );
    fixture
        .base
        .h
        .recover_organization_hosting(&original, &fixture.base.hosting, &bundle, &freshness, &keys)
        .await
        .unwrap();
    let accepted = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
    assert_eq!(
        fixture
            .base
            .h
            .require_accepted_organization_hosting_account(account, &fixture.base.hosting)
            .await
            .unwrap(),
        original.event.realm_id
    );
    assert_eq!(
        sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
        accepted,
        "qualification itself may not alter accepted source/current/choice"
    );
    fixture.erase(account, &original.event.realm_id).await;
    let erased = sql_fault_matrix::snapshot(&fixture.base.h.pool).await;
    let error = fixture
        .base
        .h
        .require_accepted_organization_hosting_account(account, &fixture.base.hosting)
        .await
        .unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::AccountErased));
    assert_eq!(
        sql_fault_matrix::snapshot(&fixture.base.h.pool).await,
        erased
    );
    assert!(
        erased["authority_forward_attempts"][0]["terminal_outcome_json"].is_object(),
        "accepted public Org lineage remains canonical after private erasure"
    );
}
