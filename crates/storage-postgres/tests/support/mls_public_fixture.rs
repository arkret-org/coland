//! Scenario-local real RFC material for the PostgreSQL MLS boundary tests.
//! Candidate secrets are fixture state only. A later Member Commit is built
//! only after its exact predecessor is read back from the real accepted PG
//! source; candidate creation never manufactures an accepted outcome.

use std::cell::RefCell;
use std::collections::BTreeMap;

use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsPublicGroupTracker};
use arkret_models_collaboration::events_payloads::{
    MlsGenesisCreatorLeafAuthority, MlsGenesisPayload,
};
use arkret_models_crypto::{
    MlsCommitEnvelope, MlsCommitPayload, MlsEndpointIdentity, MlsGovernanceBindingPayload,
    MlsGroupStateRecord, MlsKeyPackageRecord,
};
use arkret_wire::{
    ActorId, BlobRef, CommittedEventFullView, DeviceId, EventId, EventKind, MlsGroupValue,
    MlsWelcomeRecipientEndpoint, RealmId, ScopeRef,
};
use coland_storage::{
    AuthorityCommitStore, EventCommitRequest, MlsConsumedProposalInstallation,
    MlsGroupCurrentStore, MlsInstalledBase, MlsProposalLeafProvenance, MlsPublicBlob,
    MlsStateInstallation,
};
use coland_storage_postgres::{PgAuthorityCommitStore, PgMlsGroupCurrentStore, PgPool};

#[derive(Clone)]
struct Candidate {
    private: MlsGroupStateRecord,
    public: Vec<u8>,
    blobs: Vec<MlsPublicBlob>,
    base: Option<MlsGroupValue>,
    value: Option<MlsGroupValue>,
    proposals: Vec<MlsConsumedProposalInstallation>,
}

pub struct MlsFixture {
    pool: PgPool,
    actor: ActorId,
    device: DeviceId,
    authorization: EventId,
    signing_seed: [u8; 32],
    published: RefCell<BTreeMap<BlobRef, Candidate>>,
    originals: RefCell<BTreeMap<EventId, Candidate>>,
    endpoints: RefCell<BTreeMap<(ActorId, String), (MlsEndpointIdentity, EventId)>>,
}

impl MlsFixture {
    pub fn new(pool: PgPool, head: &coland_storage::AuthorityCommitTransaction) -> Self {
        let fact = head
            .producer_signer_fact
            .as_ref()
            .and_then(|fact| fact.as_account_device())
            .expect("the accepted discussion creator has its real native Device fact");
        assert_eq!(&fact.actor, head.event.actual_signer());
        let signing_seed =
            super::device_authorization_history::DeviceHistoryFixtureOptions::default()
                .founding_device_signing_seed;
        let key = ed25519_dalek::SigningKey::from_bytes(&signing_seed).verifying_key();
        assert_eq!(
            fact.key.public_key_base64url.as_str(),
            arkret_canonical::base64url_encode(key.to_bytes())
        );
        let endpoints = BTreeMap::from([(
            (
                fact.actor.clone(),
                fact.key.public_key_base64url.to_string(),
            ),
            (
                MlsEndpointIdentity::HumanDevice {
                    principal_id: fact.actor.signing_principal_id().clone(),
                    device_id: fact.device_id.clone(),
                },
                fact.key.authorization_ref.event_id.clone(),
            ),
        )]);
        Self {
            pool,
            actor: fact.actor.clone(),
            device: fact.device_id.clone(),
            authorization: fact.key.authorization_ref.event_id.clone(),
            signing_seed,
            published: Default::default(),
            originals: Default::default(),
            endpoints: RefCell::new(endpoints),
        }
    }

    pub fn genesis_payload(
        &self,
        realm: &RealmId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> serde_json::Value {
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let binding = MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
        let identity = ArkretMlsIdentity::new_human_device(
            self.actor.clone(),
            self.device.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
                &self.signing_seed,
            )),
        )
        .unwrap();
        let mut group = identity
            .create_group_with_governance_binding(&scope, &binding)
            .unwrap();
        group
            .install_local_creator_binding(self.actor.clone(), Some(self.authorization.clone()))
            .unwrap();
        let (info, tree) = group.public_group_state_bytes().unwrap();
        let tracker =
            MlsPublicGroupTracker::from_external(&info, &tree, group.group_id().as_str(), 0)
                .unwrap();
        let leaves = tracker.leaves().unwrap();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].actor_id, self.actor);
        let blobs = public_blobs(&info, &tree);
        let payload = MlsGenesisPayload {
            cipher_suite: arkret_wire::NonEmptyString::new(
                tracker.ciphersuite_canonical_id().unwrap(),
            )
            .unwrap(),
            group_info_ref: blobs[0].blob_ref.clone(),
            ratchet_tree_ref: blobs[1].blob_ref.clone(),
            creator_leaf_authority: MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_base64url: leaves[0].signature_key.clone(),
                endpoint: MlsWelcomeRecipientEndpoint::Device {
                    device_id: self.device.clone(),
                },
                authorization_event_ref: self.authorization.clone(),
            },
            governance_binding: binding,
            created_at: at,
        };
        payload.validate().unwrap();
        self.published.borrow_mut().insert(
            blobs[0].blob_ref.clone(),
            Candidate {
                private: group.export_state_record().unwrap(),
                public: tracker.export_state().unwrap(),
                blobs,
                base: None,
                value: None,
                proposals: Vec::new(),
            },
        );
        serde_json::to_value(payload).unwrap()
    }

    pub async fn commit_payload(
        &self,
        realm: &RealmId,
        base: &EventId,
        epoch: u64,
        revision: u64,
    ) -> serde_json::Value {
        let mut group = Box::pin(self.accepted_private_group(base)).await;
        assert_eq!(
            group.scope(),
            &ScopeRef::Realm {
                realm_id: realm.clone()
            }
        );
        assert_eq!(group.epoch(), epoch);
        // Governance may advance key-access revision without changing the
        // accepted MLS base Event. Retain that real authoring cut, while a
        // deliberately stale fork keeps its original historical coordinate.
        if let Some(current) = (PgMlsGroupCurrentStore {
            pool: self.pool.clone(),
        })
        .current(group.scope())
        .await
        .unwrap()
            && &current.value.current_mls_commit_event_ref == base
        {
            self.originals.borrow_mut().get_mut(base).unwrap().value = Some(current.value);
        }
        let binding = MlsGovernanceBindingPayload::realm(
            realm.clone(),
            Some(base.clone()),
            epoch,
            epoch + 1,
            revision,
        )
        .unwrap();
        let commit = group
            .self_update_commit_with_governance_binding(&binding)
            .unwrap();
        let mut tracker = self.tracker(base);
        let proposals = consume(&mut tracker, &commit);
        self.publish_commit(group, tracker, commit, binding, base, proposals)
    }

    pub async fn accepted_private_group(&self, event: &EventId) -> ArkretMlsGroup {
        let candidate = self
            .originals
            .borrow()
            .get(event)
            .expect("the exact private predecessor was produced by this scenario")
            .clone();
        let original = PgAuthorityCommitStore {
            pool: self.pool.clone(),
        }
        .committed_event(event)
        .await
        .unwrap()
        .expect("only an actually accepted PG predecessor can advance the private fixture");
        assert_eq!(&original.event.event_id, event);
        let mut group = ArkretMlsGroup::restore_from_state_record(&candidate.private).unwrap();
        if original.event.kind == EventKind::MlsCommit {
            let value = candidate
                .base
                .as_ref()
                .expect("Member Commit retains its accepted base");
            group
                .install_accepted_commit(
                    &CommittedEventFullView {
                        event: original.event,
                        commit: original.commit,
                    },
                    value,
                )
                .unwrap();
        } else {
            assert_eq!(original.event.kind, EventKind::MlsGenesis);
        }
        assert_eq!(group.epoch(), candidate.value.as_ref().unwrap().epoch);
        self.install_leaf_bindings(event, &mut group);
        let (info, tree) = group.public_group_state_bytes().unwrap();
        self.tracker(event)
            .verify_publication(&info, &tree)
            .unwrap();
        group
    }

    /// Bind only the exact scenario roster which the caller read back as accepted.
    pub fn install_leaf_bindings(&self, event: &EventId, group: &mut ArkretMlsGroup) {
        let endpoints = self.endpoints.borrow();
        let bindings = self
            .tracker(event)
            .leaves()
            .unwrap()
            .into_iter()
            .map(|leaf| {
                let (endpoint, authorization) = endpoints
                    .get(&(leaf.actor_id.clone(), leaf.signature_key.to_string()))
                    .expect("every new member has an explicit fixture endpoint/source binding");
                arkret_mls::MlsVerifiedLeafBinding {
                    leaf_index: leaf.leaf_index,
                    actor_id: leaf.actor_id,
                    endpoint: endpoint.clone(),
                    signature_key: leaf.signature_key,
                    device_authorize_event_id: Some(authorization.clone()),
                }
            })
            .collect();
        group.install_verified_leaf_bindings(bindings).unwrap();
    }

    pub fn register_package(
        &self,
        package: &MlsKeyPackageRecord,
        proposals: &[MlsConsumedProposalInstallation],
        authorization: &EventId,
    ) {
        let leaf = proposals
            .iter()
            .filter(|p| p.proposal_type == 1)
            .map(|p| arkret_mls::verify_add_proposal_leaf(&p.proposal_wire).unwrap())
            .find(|leaf| {
                leaf.actor_id == package.actor_id
                    && leaf.key_package_bytes
                        == arkret_canonical::base64url_decode(&package.keypackage).unwrap()
            })
            .expect("the exact claimed KeyPackage occurs in this real Add");
        self.endpoints.borrow_mut().insert(
            (leaf.actor_id, leaf.leaf_signature_key.to_string()),
            (package.endpoint.clone(), authorization.clone()),
        );
    }

    pub fn seal_welcome(
        &self,
        delivery: &mut arkret_wire::MlsWelcomeDelivery,
        draft: &arkret_mls::MlsWelcomeDraft,
    ) {
        assert_eq!(delivery.keypackage_claim_ref, draft.keypackage_claim_ref);
        delivery.ciphertext_base64url = draft.ciphertext_base64url.clone();
        let unsigned =
            arkret_canonical::canonical::unsigned_value(delivery, &["producer_proof"]).unwrap();
        delivery.producer_proof = arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            delivery.producer_proof.verification_method.clone(),
            delivery.producer_proof.created_at,
            &ed25519_dalek::SigningKey::from_bytes(&self.signing_seed),
        )
        .unwrap();
    }

    pub fn tracker(&self, event: &EventId) -> MlsPublicGroupTracker {
        let original = self.originals.borrow();
        let candidate = original
            .get(event)
            .expect("the exact public predecessor belongs to this scenario");
        let value = candidate.value.as_ref().unwrap();
        MlsPublicGroupTracker::restore(
            &candidate.public,
            value
                .effective_scope
                .canonical_mls_group_id()
                .unwrap()
                .as_str(),
            value.epoch,
        )
        .unwrap()
    }

    pub fn publish_commit(
        &self,
        group: ArkretMlsGroup,
        tracker: MlsPublicGroupTracker,
        commit: MlsCommitEnvelope,
        binding: MlsGovernanceBindingPayload,
        base: &EventId,
        proposals: Vec<MlsConsumedProposalInstallation>,
    ) -> serde_json::Value {
        let base_value = self
            .originals
            .borrow()
            .get(base)
            .unwrap()
            .value
            .clone()
            .unwrap();
        let (info, tree) = group
            .pending_public_group_state_bytes(&commit, &binding)
            .unwrap();
        tracker.verify_publication(&info, &tree).unwrap();
        let blobs = public_blobs(&info, &tree);
        let payload = MlsCommitPayload::new(
            base.clone(),
            binding.key_access_revision(),
            &commit,
            binding,
            blobs[0].blob_ref.clone(),
            blobs[1].blob_ref.clone(),
        )
        .unwrap();
        self.published.borrow_mut().insert(
            blobs[0].blob_ref.clone(),
            Candidate {
                private: group.export_state_record().unwrap(),
                public: tracker.export_state().unwrap(),
                blobs,
                base: Some(base_value),
                value: None,
                proposals,
            },
        );
        serde_json::to_value(payload).unwrap()
    }

    pub fn with_installation(
        &self,
        mut request: EventCommitRequest,
        base: Option<(&EventId, u64)>,
        epoch: u64,
    ) -> EventCommitRequest {
        let event = &request.authority_commit.event;
        let value = serde_json::to_value(&event.payload).unwrap();
        let reference: BlobRef = serde_json::from_value(value["group_info_ref"].clone()).unwrap();
        let mut candidate = self
            .published
            .borrow()
            .get(&reference)
            .expect("publication has real fixture bytes")
            .clone();
        assert_eq!(
            candidate
                .base
                .as_ref()
                .map(|base| (&base.current_mls_commit_event_ref, base.epoch)),
            base
        );
        let tracker = MlsPublicGroupTracker::restore(
            &candidate.public,
            event.scope_ref.canonical_mls_group_id().unwrap().as_str(),
            epoch,
        )
        .unwrap();
        let binding = tracker.governance_binding().unwrap();
        let next = MlsGroupValue {
            effective_scope: event.scope_ref.clone(),
            genesis_event_ref: candidate.base.as_ref().map_or_else(
                || event.event_id.clone(),
                |base| base.genesis_event_ref.clone(),
            ),
            cipher_suite: arkret_wire::NonEmptyString::new(
                tracker.ciphersuite_canonical_id().unwrap(),
            )
            .unwrap(),
            current_mls_commit_event_ref: event.event_id.clone(),
            epoch,
            current_key_access_revision: binding.key_access_revision(),
            covered_key_access_revision: binding.key_access_revision(),
            public_tree_ref: candidate.blobs[1].blob_ref.clone(),
        };
        candidate.value = Some(next);
        request.realm_fanout_source =
            Some(arkret_wire::EventAdmissionSubmission::new(event.clone()));
        request.authority_commit.mls_state = Some(MlsStateInstallation {
            effective_scope: event.scope_ref.clone(),
            base: base.map(|(reference, epoch)| MlsInstalledBase {
                current_mls_commit_event_ref: reference.clone(),
                epoch,
            }),
            epoch,
            public_state: candidate.public.clone(),
            member_principals: tracker
                .leaves()
                .unwrap()
                .into_iter()
                .map(|leaf| leaf.actor_id)
                .collect(),
            consumed_proposals: candidate.proposals.clone(),
            public_blobs: candidate.blobs.clone(),
        });
        self.originals
            .borrow_mut()
            .insert(event.event_id.clone(), candidate);
        request
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition(
        &self,
        previous: &coland_storage::AuthorityCommitTransaction,
        group: ArkretMlsGroup,
        tracker: MlsPublicGroupTracker,
        commit: MlsCommitEnvelope,
        binding: MlsGovernanceBindingPayload,
        base: &EventId,
        proposals: Vec<MlsConsumedProposalInstallation>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> EventCommitRequest {
        let epoch = group.epoch();
        let payload = self.publish_commit(group, tracker, commit, binding, base, proposals);
        let next = super::ordinary_realm::next_request(
            previous,
            EventKind::MlsCommit,
            previous.event.actor_id.signing_principal_id(),
            payload,
            at,
        );
        self.with_installation(next, Some((base, epoch)), epoch + 1)
    }
}

fn public_blobs(info: &[u8], tree: &[u8]) -> Vec<MlsPublicBlob> {
    [info, tree]
        .into_iter()
        .map(|bytes| {
            let digest = arkret_canonical::sha256_digest(bytes);
            let sha256 = digest.as_str().strip_prefix("sha256:").unwrap().to_owned();
            MlsPublicBlob {
                blob_ref: format!("ak:blob:{digest}").parse().unwrap(),
                sha256: sha256.clone(),
                size_bytes: i64::try_from(bytes.len()).unwrap(),
                storage_backend: "local".into(),
                storage_key: format!("sha256/{sha256}"),
            }
        })
        .collect()
}

pub fn consume(
    tracker: &mut MlsPublicGroupTracker,
    commit: &MlsCommitEnvelope,
) -> Vec<MlsConsumedProposalInstallation> {
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = tracker
        .process_public_handshake(&arkret_canonical::base64url_decode(&commit.commit).unwrap())
        .unwrap()
    else {
        panic!("a real Member transition is a Commit")
    };
    let leaf = |leaf: arkret_mls::MlsPublicEndpointLeaf| MlsProposalLeafProvenance {
        leaf_index: leaf.leaf_index,
        actor_id: leaf.actor_id,
        signature_key: leaf.signature_key,
    };
    consumed_proposals
        .into_iter()
        .map(|proposal| MlsConsumedProposalInstallation {
            ordinal: proposal.ordinal,
            proposal_ref: proposal.proposal_ref,
            proposal_type: proposal.proposal_type,
            proposal_wire: proposal.proposal_wire,
            sender_leaf: leaf(proposal.sender_leaf),
            target_before: proposal.target_before.map(leaf),
            target_after: proposal.target_after.map(leaf),
        })
        .collect()
}
