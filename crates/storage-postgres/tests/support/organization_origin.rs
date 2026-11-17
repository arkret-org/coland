//! Real signed Organization/Service native inputs; construction alone is not acceptance.
#![allow(dead_code)]

use arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody;
use arkret_models_collaboration::events_payloads::realm::{RealmGenesis, RealmPurpose};
use arkret_signatures::webvh::{
    OrganizationInceptionInput, PrincipalRotationInput, ServiceInceptionInput,
};
use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions};
use arkret_wire::*;
use chrono::{DateTime, Duration, Utc};
use coland_storage::{
    AuthorityCommitTransaction, CurrentRealmAuthority, OrganizationPcrGenesisAdmissionWrite,
};
use ed25519_dalek::SigningKey;
use rand_chacha::rand_core::SeedableRng as _;
use serde_json::json;

fn public(seed: u8) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes(),
    )
}
fn service(seed: u8, at: DateTime<Utc>) -> arkret_signatures::webvh::PreparedInception {
    service_at(seed, at, &format!("https://service-{seed}.example/"))
}
fn service_at(
    seed: u8,
    at: DateTime<Utc>,
    endpoint: &str,
) -> arkret_signatures::webvh::PreparedInception {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([seed; 32]);
    arkret_signatures::webvh::prepare_service_inception(
        &mut rng,
        &ServiceInceptionInput {
            principal_endpoint: &endpoint.parse().unwrap(),
            local_id: "service",
            also_known_as: &[],
            version_created_at: at,
            did_key_fragment: Some("federation-fanout-key"),
        },
    )
    .unwrap()
}

pub struct OrganizationFixture {
    pub write: OrganizationPcrGenesisAdmissionWrite,
    pub organization_did: Did,
    pub control_seeds: Vec<u8>,
    pub producer: arkret_signatures::webvh::PreparedInception,
    pub governor: arkret_signatures::webvh::PreparedInception,
    governor_method: DidUrl,
    governor_seed: [u8; 32],
    organization_next_root_seed: u8,
}

impl OrganizationFixture {
    pub fn new(delegated: bool, quorum: bool) -> Self {
        Self::with_origin(
            delegated,
            quorum,
            "https://organization-provider.example/",
            None,
        )
    }
    pub fn at_origin(delegated: bool, quorum: bool, origin: &str) -> Self {
        Self::with_origin(delegated, quorum, origin, Some(origin))
    }
    fn with_origin(
        delegated: bool,
        quorum: bool,
        organization_origin: &str,
        service_origin: Option<&str>,
    ) -> Self {
        let at =
            arkret_canonical::normalize_timestamp_canonical(Utc::now() - Duration::seconds(10));
        let governor = service(61, at - Duration::seconds(1));
        let producer = service_origin.map_or_else(
            || service(62, at - Duration::seconds(1)),
            |origin| service_at(62, at - Duration::seconds(1), origin),
        );
        let org =
            arkret_signatures::webvh::prepare_organization_inception(&OrganizationInceptionInput {
                provider_endpoint: &organization_origin.parse().unwrap(),
                local_id: &format!("organization-{}", uuid::Uuid::now_v7().simple()),
                version_created_at: at,
                root_seed: &[31; 32],
                next_root_public_key_multibase: &public(32),
                control_public_key: &SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes(),
            })
            .unwrap();
        let organization_did = Did::new(&org.did).unwrap();
        let station = project_did_to_core_id(&Did::new(&governor.did).unwrap()).unwrap();
        let executor = project_did_to_core_id(&Did::new(&producer.did).unwrap()).unwrap();
        let mut entries = vec![org.log_entry.clone()];
        let mut control_seeds = vec![33];
        if delegated || quorum {
            let mut state = org.log_entry["state"].clone();
            let mut governance = json!({});
            if quorum {
                let second = format!("{}#governance-second", org.did);
                state["verificationMethod"].as_array_mut().unwrap().push(json!({
                    "id":second,"type":"Multikey","controller":org.did,"publicKeyMultibase":public(34)}));
                state["capabilityInvocation"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(second));
                governance["threshold"] = json!({"min_signature_count":2,
                    "allowed_kids":[format!("{}#organization-control",org.did),second]});
                control_seeds.push(34);
            }
            if delegated {
                governance["delegations"] = json!([{"service_id":executor,
                    "purposes":["principal_control_realm_bootstrap"],
                    "not_before":arkret_canonical::format_timestamp_canonical(at),
                    "expires_at":arkret_canonical::format_timestamp_canonical(at+Duration::days(1))}]);
            }
            state["arkret_governance"] = governance;
            let successor =
                arkret_signatures::webvh::prepare_organization_rotation(&PrincipalRotationInput {
                    did: &org.did,
                    local_id: &org.local_id,
                    previous_entries: &entries,
                    version_created_at: at + Duration::seconds(1),
                    current_root_seed: &[32; 32],
                    next_root_public_key_multibase: &public(35),
                    state: &state,
                })
                .unwrap();
            entries.push(successor.log_entry);
        }
        let last = entries.last().unwrap();
        let object = RealmGenesis::new(
            RealmPurpose::PrincipalControl,
            GenesisSalt::new(arkret_canonical::base64url_encode([71; 32])).unwrap(),
            TrustDomainId::new("ak:trust_domain:organization-native").unwrap(),
            SecurityClass::HighAssurance,
            station.clone(),
            JoinRule::Closed,
            HistoryAccess::SinceJoin,
            Discoverability::Secret,
            None,
            Some(arkret_models_identity::ResolutionCommitment {
                did: organization_did.clone(),
                method_history_head: arkret_canonical::canonical_sha256(last).unwrap(),
                version_id: last["versionId"].as_str().unwrap().to_owned(),
            }),
        )
        .unwrap();
        let holder = AccountId::new(
            project_did_to_core_id(&organization_did).unwrap(),
            station.clone(),
        );
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.realm.create",
            ScopeRef::RealmGenesis,
            ActorId::account(holder),
            json!({"object":object}),
            at + Duration::seconds(2),
        )
        .unwrap();
        event.executed_by = Some(ActorId::service(executor));
        event.authorization_ref = Some(
            serde_json::from_value(json!(format!("{}#organization-control", org.did))).unwrap(),
        );
        let service_resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            event.actual_signer().signing_principal_id().clone(),
            "station".into(),
            serde_json::from_value(producer.log_entry["state"].clone()).unwrap(),
            vec![producer.log_entry.clone()],
            vec![],
            at + Duration::seconds(3),
        )
        .unwrap();
        let organization_next_root_seed = if entries.len() == 1 { 32 } else { 35 };
        let mut fixture=Self {write:OrganizationPcrGenesisAdmissionWrite {
            transaction:transaction(&event,&governor,at+Duration::seconds(4)),
            request:PeerAuthorityForwardEventRequestBody {
                branch:arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
                event_submission:EventAdmissionSubmission::new(event),mls_group_state_material:None,
                content_backup_sources:None,producer_device_evidence:None,producer_agent_evidence:None,successor_device_evidence:None,
            },source_service_id:station,organization_log_entries:entries,organization_witness_records:vec![],
            producer_service_resolution:Some(service_resolution),queued_at:at+Duration::seconds(4),
        },organization_did,control_seeds,producer,
            governor_method: DidUrl::new(&governor.did_key_id).unwrap(),
            governor_seed: governor.did_key_seed, governor, organization_next_root_seed};
        fixture.resign(!delegated || quorum);
        fixture
    }

    /// Publish a genuine native successor without resigning the already
    /// authored Event or its finite approvals. The caller controls the native
    /// state change and its actual historical instant.
    pub fn append_organization_state(&mut self, state: serde_json::Value, at: DateTime<Utc>) {
        let current_seed = self.organization_next_root_seed;
        let next_seed = if current_seed < 36 {
            36
        } else {
            current_seed + 1
        };
        let local_id = self.organization_did.as_str().rsplit(':').next().unwrap();
        let next =
            arkret_signatures::webvh::prepare_organization_rotation(&PrincipalRotationInput {
                did: self.organization_did.as_str(),
                local_id,
                previous_entries: &self.write.organization_log_entries,
                version_created_at: at,
                current_root_seed: &[current_seed; 32],
                next_root_public_key_multibase: &public(next_seed),
                state: &state,
            })
            .unwrap();
        self.write.organization_log_entries.push(next.log_entry);
        self.organization_next_root_seed = next_seed;
    }

    pub fn organization_state(&self) -> serde_json::Value {
        self.write.organization_log_entries.last().unwrap()["state"].clone()
    }

    pub fn add_governance_method(&self, state: &mut serde_json::Value, seed: u8) -> DidUrl {
        let method = DidUrl::new(format!("{}#governance-second", self.organization_did)).unwrap();
        state["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(json!({
            "id":method,"type":"Multikey","controller":self.organization_did,
            "publicKeyMultibase":public(seed)}));
        state["capabilityInvocation"]
            .as_array_mut()
            .unwrap()
            .push(json!(method));
        method
    }

    pub fn add_approval(&mut self, seed: u8, method: DidUrl, at: DateTime<Utc>) {
        let event = &self.write.request.event_submission.event;
        let signer = Ed25519DetachedJwsSigner::from_seed([seed; 32], method.as_str());
        let mut vote = ApprovalSignature {
            input: ApprovalSignatureInput {
                approval_context: ApprovalContext::RealmGovernance {},
                approval_target: ApprovalTarget::Event {
                    event_id: event.event_id.clone(),
                },
                request_canonical_digest: Hash::new(
                    arkret_canonical::canonical_sha256(event).unwrap(),
                )
                .unwrap(),
                operation: ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1.into(),
                action: CapabilityActionId::RealmCreate,
                realm_id: event.realm_id.clone(),
                initiating_actor_id: event.actor_id.clone(),
                approver_did: self.organization_did.clone(),
                approved_at: at,
                nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            },
            proof: ApprovalSignatureProof {
                kind: ApprovalSignatureProofKind::DetachedJws,
                verification_method: method,
                jws: String::new(),
            },
        };
        vote.proof.jws = signer.sign_detached_jws(
            &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)
                .unwrap(),
        );
        let votes = self
            .write
            .request
            .event_submission
            .approval_signatures
            .get_or_insert_default();
        votes.push(vote);
        votes.sort_by_key(|vote| arkret_canonical::canonical_json_string(&vote.input).unwrap());
    }

    pub fn reauthor_for_control_method(
        &mut self,
        method: &DidUrl,
        seed: u8,
        approved_at: DateTime<Utc>,
    ) {
        let mut event = self.write.request.event_submission.event.clone();
        event.authorization_ref = Some(serde_json::from_value(json!(method)).unwrap());
        event.producer_proof = None;
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(event, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &Ed25519DetachedJwsSigner::from_seed(
                self.producer.did_key_seed,
                &self.producer.did_key_id,
            ),
            SignEventOptions::new().with_created_at(self.write.queued_at - Duration::seconds(2)),
        )
        .unwrap();
        let event = authored.into_event();
        self.write.transaction = signed_transaction(
            &event,
            self.governor_method.clone(),
            self.governor_seed,
            self.write.queued_at,
        );
        self.write.request.event_submission = EventAdmissionSubmission::new(event);
        self.add_approval(seed, method.clone(), approved_at);
        self.bind_public_source_fact();
    }

    pub fn rotate_service_assertion(&mut self) {
        let mut state = self.producer.log_entry["state"].clone();
        for method in state["verificationMethod"].as_array_mut().unwrap() {
            if method["id"] == self.producer.did_key_id {
                method["publicKeyMultibase"] = json!(public(91));
            }
        }
        let prior = vec![self.producer.log_entry.clone()];
        let next = arkret_signatures::webvh::prepare_service_rotation(
            &arkret_signatures::webvh::ServiceRotationInput {
                did: &self.producer.did,
                previous_entries: &prior,
                state: &state,
                current_update_seed: &self.producer.next_update_key_seed,
                next_update_public_key_multibase: &public(92),
                version_created_at: self.write.queued_at - Duration::milliseconds(500),
            },
        )
        .unwrap();
        self.write.producer_service_resolution = Some(
            arkret_identity::build_authenticated_webvh_service_resolution(
                self.write
                    .request
                    .event_submission
                    .event
                    .actual_signer()
                    .signing_principal_id()
                    .clone(),
                "station".into(),
                serde_json::from_value(state).unwrap(),
                vec![self.producer.log_entry.clone(), next.log_entry],
                vec![],
                self.write.queued_at,
            )
            .unwrap(),
        );
    }

    /// Retain actual method-verified originals through the production DID
    /// owner before invoking the native PG port. This is not an accepted Org
    /// fixture or a caller-selected current flag.
    pub async fn retain_current_histories(&self, pool: &coland_storage_postgres::PgPool) {
        use coland_storage::DeliveryPolicyStoreRegistry as _;
        let store = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
        let mut histories = vec![(
            self.write.organization_log_entries.clone(),
            self.write.organization_witness_records.clone(),
        )];
        if let Some(service) = &self.write.producer_service_resolution {
            let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
                log_entries,
                witness_records,
                ..
            } = &service.method_history_evidence
            else {
                panic!("native fixture needs WebVH")
            };
            histories.push((log_entries.clone(), witness_records.clone()));
        }
        for (entries, witnesses) in histories {
            let record = history_document(&entries, &witnesses);
            let old = store
                .webvh()
                .get_document(&record.did)
                .await
                .unwrap()
                .and_then(|old| old.key_log_head);
            assert!(matches!(
                store
                    .webvh()
                    .ingest_verified_history(old, record)
                    .await
                    .unwrap(),
                coland_storage::WebvhLogCommitOutcome::Accepted
                    | coland_storage::WebvhLogCommitOutcome::Duplicate
            ));
        }
    }

    /// Bind the signed Organization request to an independently constructed
    /// real serving Station. The caller supplies that Station's actual key;
    /// no accepted Org state is installed by this authoring helper.
    pub fn rebind_hosting(
        &mut self,
        station: DidCoreId,
        trust_domain: TrustDomainId,
        governor_method: DidUrl,
        governor_seed: [u8; 32],
    ) {
        let event = &mut self.write.request.event_submission.event;
        let principal = event.actor_id.as_account_id().unwrap().principal_id.clone();
        event.actor_id = ActorId::account(AccountId::new(principal, station.clone()));
        event.payload.get_mut("object").unwrap()["governance_station_id"] = json!(station);
        event.payload.get_mut("object").unwrap()["trust_domain"] = json!(trust_domain);
        self.write.source_service_id = station;
        self.governor_method = governor_method;
        self.governor_seed = governor_seed;
        self.resign(true);
    }

    /// Author the complete public projection before signing its original Commit.
    /// This helper grants no authority: negative cases may author an invalid
    /// source, while the production verifier independently rejects that source.
    /// Use the actual held fixture governor after an explicit hosting rebind.
    pub fn governor_signer(&self) -> (DidUrl, [u8; 32]) {
        (self.governor_method.clone(), self.governor_seed)
    }

    pub fn bind_public_source_fact(&mut self) {
        let event = &self.write.request.event_submission.event;
        let document = serde_json::from_value(self.organization_state()).unwrap();
        let fact = arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact {
            event_id: event.event_id.clone(),
            method_history_evidence: arkret_identity::build_webvh_method_history_evidence(
                &document,
                self.write.organization_log_entries.clone(),
                self.write.organization_witness_records.clone(),
            )
            .unwrap(),
            approval_signatures: self
                .write
                .request
                .event_submission
                .approval_signatures
                .clone(),
            producer_resolution: self.write.producer_service_resolution.clone(),
            public_key_base64url: None,
        };
        self.sign_candidate_fact(Some(
            arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::OrganizationGenesis(fact),
        ));
    }

    /// Real G signing for a deliberately wrong candidate source is useful to
    /// distinguish the source gate from malformed signatures/Commit identities.
    pub fn sign_candidate_fact(
        &mut self,
        fact: Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
    ) {
        let mut transaction = signed_transaction(
            &self.write.request.event_submission.event,
            self.governor_method.clone(),
            self.governor_seed,
            self.write.queued_at,
        );
        let commit = &mut transaction.commit;
        commit.producer_signer_fact_digest =
            fact.as_ref().map(|fact| fact.digest()).transpose().unwrap();
        commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(
                &arkret_canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap(),
            )
            .unwrap(),
        ));
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::unsigned_value(commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            self.governor_method.clone(),
            commit.committed_at,
            &SigningKey::from_bytes(&self.governor_seed),
        )
        .unwrap();
        transaction.producer_signer_fact = fact;
        transaction.validate().unwrap();
        self.write.transaction = transaction;
    }

    pub fn resign(&mut self, approve: bool) {
        let mut event = self.write.request.event_submission.event.clone();
        event.producer_proof = None;
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(event, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &Ed25519DetachedJwsSigner::from_seed(
                self.producer.did_key_seed,
                &self.producer.did_key_id,
            ),
            SignEventOptions::new().with_created_at(self.write.queued_at - Duration::seconds(2)),
        )
        .unwrap();
        let event = authored.into_event();
        let approvals = if approve {
            Some(self.control_seeds.iter().map(|seed| {
            let method=DidUrl::new(format!("{}#{}",self.organization_did,
                if *seed==33 {"organization-control"} else {"governance-second"})).unwrap();
            let signer=Ed25519DetachedJwsSigner::from_seed([*seed;32],method.as_str());
            let mut approval=ApprovalSignature {input:ApprovalSignatureInput {
                approval_context:ApprovalContext::RealmGovernance {},approval_target:ApprovalTarget::Event {event_id:event.event_id.clone()},
                request_canonical_digest:Hash::new(arkret_canonical::canonical_sha256(&event).unwrap()).unwrap(),
                operation:ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1.to_owned(),action:CapabilityActionId::RealmCreate,
                realm_id:event.realm_id.clone(),initiating_actor_id:event.actor_id.clone(),approver_did:self.organization_did.clone(),
                approved_at:self.write.queued_at-Duration::seconds(1),nonce:arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            },proof:ApprovalSignatureProof {kind:ApprovalSignatureProofKind::DetachedJws,verification_method:method,jws:String::new()}};
            approval.proof.jws=signer.sign_detached_jws(&arkret_signatures::approval_signature::approval_signature_signing_bytes(&approval).unwrap());
            approval
        }).collect::<Vec<_>>())
        } else {
            None
        };
        let mut submission = EventAdmissionSubmission {
            event: event.clone(),
            approval_signatures: approvals,
        };
        if let Some(votes) = submission.approval_signatures.as_mut() {
            votes.sort_by_key(|vote| arkret_canonical::canonical_json_string(&vote.input).unwrap());
        }
        self.write.request.event_submission = submission;
        self.write.transaction = signed_transaction(
            &event,
            self.governor_method.clone(),
            self.governor_seed,
            self.write.queued_at,
        );
        self.bind_public_source_fact();
        self.write.request.validate().unwrap();
        arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_authority(
            &self.write.request.event_submission,
            &self.write.organization_log_entries,
            &[],
            self.write.queued_at,
        )
        .unwrap();
        arkret_identity::organization_pcr_genesis::verify_organization_pcr_service_producer(
            &event,
            self.write.producer_service_resolution.as_ref().unwrap(),
            self.write.queued_at,
        )
        .unwrap();
    }
}

fn transaction(
    event: &Event,
    governor: &arkret_signatures::webvh::PreparedInception,
    at: DateTime<Utc>,
) -> AuthorityCommitTransaction {
    signed_transaction(
        event,
        DidUrl::new(&governor.did_key_id).unwrap(),
        governor.did_key_seed,
        at,
    )
}

fn signed_transaction(
    event: &Event,
    method: DidUrl,
    seed: [u8; 32],
    at: DateTime<Utc>,
) -> AuthorityCommitTransaction {
    let authority_ref = RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    let key = SigningKey::from_bytes(&seed);
    let mut commit = RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: RealmCommitId::from_digest([0; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        stream_position: 0,
        previous_commit_ref: None,
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: authority_ref.clone(),
        committed_at: at,
        signature: arkret_signatures::detached_object::sign_detached_object(
            &json!({}),
            DetachedSignatureContext::RealmCommit,
            method.clone(),
            at,
            &key,
        )
        .unwrap(),
    };
    let identity = arkret_canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        method,
        at,
        &key,
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
    AuthorityCommitTransaction {
        expected_authority: CurrentRealmAuthority {
            realm_id: event.realm_id.clone(),
            generation: 0,
            service_id: detached_signature_service_id(&commit.signature).unwrap(),
            authority_ref,
            last_handoff_ref: None,
        },
        event: event.clone(),
        commit,
        producer_signer_fact: None,
        content_backup_source: None,
        mls_state: None,
        welcomes: vec![],
        recipient_queue_capacity: 0,
    }
}

pub fn history_document(
    entries: &[serde_json::Value],
    witnesses: &[serde_json::Value],
) -> coland_storage::WebvhDocumentRecord {
    let at = Utc::now();
    let last = entries.last().unwrap();
    let did: Did = last["state"]["id"].as_str().unwrap().parse().unwrap();
    let bytes = entries
        .iter()
        .map(|entry| {
            format!(
                "{}\n",
                arkret_canonical::canonical_json_string(entry).unwrap()
            )
        })
        .collect::<String>();
    arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &did,
        bytes.as_bytes(),
        Some(&serde_json::to_vec(witnesses).unwrap()),
    )
    .unwrap();
    let document = serde_json::from_value(last["state"].clone()).unwrap();
    coland_storage::WebvhDocumentRecord {
        did: did.to_string(),
        did_document: last["state"].clone(),
        key_log_head: Some(arkret_canonical::canonical_sha256(last).unwrap()),
        sequence: entries.len() as u64,
        method_evidence: serde_json::to_value(
            arkret_identity::build_webvh_method_history_evidence(
                &document,
                entries.to_vec(),
                witnesses.to_vec(),
            )
            .unwrap(),
        )
        .unwrap(),
        fetched_at: at,
        expires_at: at + Duration::minutes(15),
        updated_at: at,
    }
}
