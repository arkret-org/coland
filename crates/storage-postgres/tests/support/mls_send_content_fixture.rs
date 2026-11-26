//! Genuine accepted-epoch roots, native Human PUT and bound message AEAD.
//! The exporter is restored from the scenario's accepted private group. This
//! PG fixture consumes actual queued Welcomes but does not claim HTTP PUT.

use std::collections::BTreeMap;

use arkret_crypto::content_history::{
    ContentRootBackupAuthor, ContentRootBackupDraft, content_key_commitment, content_root_ref,
    derive_content_key, fresh_content_key_salt, open_content, seal_content,
};
use arkret_event_draft::EventPayloadExt as _;
use arkret_models_crypto::*;
use arkret_wire::{ActorId, Did, EventKind};
use coland_storage::{
    AuthorityCommitStore as _, IdentityStoreRegistry as _, KeyBackupStore as _,
    MlsGroupCurrentStore as _,
};
use coland_storage_postgres::{PgAuthorityCommitStore, PgKeyBackupStore, PgMlsGroupCurrentStore};
use ed25519_dalek::Signer as _;

use super::*;

pub struct Author {
    selector: DeviceRevocationGateSelector,
    did: Did,
    seed: [u8; 32],
}

pub struct Enrolled {
    pub head: Box<EventCommitRequest>,
    target_stale: MlsGroupStateRecord,
    target_current: MlsGroupStateRecord,
    sibling_current: MlsGroupStateRecord,
}

pub async fn enroll(
    pool: &PgPool,
    mls: &MlsFixture,
    mut previous: Box<EventCommitRequest>,
    endpoints: [(&DeviceRevocationGateSelector, [u8; 32]); 2],
) -> Box<Enrolled> {
    let groups = PgMlsGroupCurrentStore { pool: pool.clone() };
    let commits = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut target_stale = None;
    let mut target_current = None;
    let mut sibling_current = None;
    for (index, (recipient, seed)) in endpoints.into_iter().enumerate() {
        let current = groups
            .current(&previous.authority_commit.event.scope_ref)
            .await
            .unwrap()
            .unwrap();
        let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
            recipient_actor(recipient),
            arkret_wire::DeviceId::new(&recipient.device_id).unwrap(),
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&seed),
            ),
        )
        .unwrap();
        let next = Box::new(
            Box::pin(mls_local_add_fixture::add_for_identity(
                pool,
                mls,
                &previous,
                recipient,
                &identity,
                &claim_id(),
                current.value.current_key_access_revision,
                None,
            ))
            .await
            .0,
        );
        Box::pin(uow.commit_event((*next).clone())).await.unwrap();
        let accepted = commits
            .committed_event(&next.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.event, next.authority_commit.event);
        assert_eq!(accepted.commit, next.authority_commit.commit);
        let queue = PgDeviceMessageStore { pool: pool.clone() };
        let deliveries = queue
            .list_recipient_deliveries(
                &RecipientQueueSelector::HumanDevice {
                    recipient: recipient.principal_id.to_string(),
                    device_id: recipient.device_id.clone(),
                },
                0,
                10,
            )
            .await
            .unwrap();
        let delivery = deliveries
            .into_iter()
            .filter_map(|row| match row.delivery {
                arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
                    mls_welcome,
                } if mls_welcome.commit_event_ref == accepted.event.event_id => Some(mls_welcome),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(delivery.len(), 1);
        let delivery = &delivery[0];
        assert_eq!(*delivery, next.authority_commit.welcomes[0].delivery);
        let producer =
            Box::pin(mls.accepted_private_group(&previous.authority_commit.event.event_id)).await;
        let key = producer.local_content_endpoint().unwrap();
        assert_eq!(key.actor_id, accepted.event.actor_id);
        arkret_signatures::detached_object::verify_detached_object_signature(
            &delivery.producer_proof,
            &arkret_canonical::unsigned_value(delivery, &["producer_proof"]).unwrap(),
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: arkret_canonical::base64url_decode(&key.signature_key_base64url).unwrap(),
            },
        )
        .unwrap();
        let full = arkret_wire::CommittedEventFullView {
            event: accepted.event,
            commit: accepted.commit,
        };
        let mut joined = arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
            identity, delivery, &full,
        )
        .unwrap();
        mls.install_leaf_bindings(&full.event.event_id, &mut joined);
        assert_eq!(
            joined.local_content_endpoint().unwrap().actor_id,
            recipient_actor(recipient)
        );
        if index == 0 {
            // Export before the later Add. Restore uses a new provider/store;
            // it cannot share the live OpenMLS storage of the current group.
            target_stale = Some(joined.export_state_record().unwrap());
        } else {
            sibling_current = Some(joined.export_state_record().unwrap());
            let mut target = arkret_mls::ArkretMlsGroup::restore_from_state_record(
                target_stale.as_ref().unwrap(),
            )
            .unwrap();
            target
                .install_accepted_commit(&full, &current.value)
                .unwrap();
            mls.install_leaf_bindings(&full.event.event_id, &mut target);
            target_current = Some(target.export_state_record().unwrap());
        }
        previous = next;
    }
    Box::new(Enrolled {
        head: previous,
        target_stale: target_stale.unwrap(),
        target_current: target_current.unwrap(),
        sibling_current: sibling_current.unwrap(),
    })
}

impl Author {
    pub fn new(selector: &DeviceRevocationGateSelector, did: &Did, seed: [u8; 32]) -> Self {
        Self {
            selector: selector.clone(),
            did: did.clone(),
            seed,
        }
    }
}

struct Epoch {
    private: MlsGroupStateRecord,
    context: ContentRootContext,
    root: ContentRootSecret,
}

pub struct PublishedContent {
    current: Epoch,
    stale: Epoch,
    packages: BTreeMap<String, KeyBackup>,
    published_at: chrono::DateTime<chrono::Utc>,
    local_states: BTreeMap<(ActorId, String, u64), MlsGroupStateRecord>,
    originals: BTreeMap<arkret_wire::BackupId, serde_json::Value>,
    pub founder: Author,
}

async fn retained_packet(pool: &PgPool, id: &arkret_wire::BackupId) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Packet {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        payload: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('body',b.payload,'actor',i.actor_id,'digest',i.envelope_digest,'index',i.content_index,'admission',i.writer_admission,'deleted_at',i.deleted_at) AS payload FROM key_backups b JOIN key_backup_identities i USING(id) WHERE b.id=$1")
        .bind::<diesel::sql_types::Uuid,_>(uuid::Uuid::parse_str(id.as_str().strip_prefix("ak:backup:").unwrap()).unwrap())
        .get_result::<Packet>(&mut *conn).await.unwrap().payload
}

/// Reconstruct only the two known fixture origins and compare their genuine
/// initial signed originals before calling the shared native policy owner.
fn policy_principal(
    station_did: &Did,
    label: &str,
    signing_seed: [u8; 32],
    originals: (&[arkret_wire::Event], &[arkret_wire::RealmCommit]),
) -> coland_test_support::pcr_genesis::PcrGenesisFixture {
    let (events, commits) = originals;
    let expected_account = events[0].actor_id.as_account_id().unwrap();
    let authorization: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&events[1].payload).unwrap()).unwrap();
    let principal = coland_test_support::pcr_genesis::PcrGenesisFixture::new_with(
        station_did.clone(),
        coland_test_support::device_authorization_history::DeviceHistoryFixtureOptions {
            local_id: label.into(),
            founding_device_id: authorization.device_id,
            founding_device_signing_seed: signing_seed,
            ..Default::default()
        },
    );
    assert_eq!(&principal.history.account, expected_account);
    for index in 0..2 {
        assert_eq!(principal.history.events[index], events[index]);
        assert_eq!(principal.history.commits[index], commits[index]);
    }
    principal
}

async fn epoch(
    pool: &PgPool,
    mls: &MlsFixture,
    reference: &arkret_wire::EventId,
    current: &arkret_wire::MlsGroupValue,
) -> Epoch {
    let group = Box::pin(mls.accepted_private_group(reference)).await;
    let declaration = (PgAuthorityCommitStore { pool: pool.clone() })
        .committed_event(&current.effective_scope.realm_id().event_id())
        .await
        .unwrap()
        .unwrap();
    let strategy = declaration
        .event
        .as_realm_create()
        .unwrap()
        .object
        .initial_encryption_backup_strategy;
    let context = ContentRootContext {
        effective_scope: group.scope().clone(),
        genesis_event_ref: current.genesis_event_ref.clone(),
        epoch: group.epoch(),
        group_state_ref: reference.clone(),
        cipher_suite: group.group_ciphersuite_canonical_id().unwrap().into(),
        encryption_backup_strategy: strategy,
        backup_strategy_ref: declaration.event.event_id,
    };
    context.validate().unwrap();
    let root = group.export_content_root(&context).unwrap();
    Epoch {
        private: group.export_state_record().unwrap(),
        context,
        root,
    }
}

pub async fn prepare(
    pool: &PgPool,
    mls: &MlsFixture,
    enrolled: &Enrolled,
    source: &mut pcr_genesis::PcrGenesisFixture,
) -> Box<PublishedContent> {
    let last_add = &enrolled.head;
    let commits = PgAuthorityCommitStore { pool: pool.clone() };
    let value = (PgMlsGroupCurrentStore { pool: pool.clone() })
        .current(&last_add.authority_commit.event.scope_ref)
        .await
        .unwrap()
        .unwrap()
        .value;
    let payload: MlsCommitPayload = serde_json::from_value(
        serde_json::to_value(&last_add.authority_commit.event.payload).unwrap(),
    )
    .unwrap();
    let stale_ref = payload.base_group_state_ref();
    let current = Box::pin(epoch(
        pool,
        mls,
        &last_add.authority_commit.event.event_id,
        &value,
    ))
    .await;
    let stale = Box::pin(epoch(pool, mls, stale_ref, &value)).await;
    assert!(stale.context.epoch < current.context.epoch);
    assert_eq!(current.context.epoch, value.epoch);
    let mut local_states = BTreeMap::new();
    for record in [
        &enrolled.target_stale,
        &enrolled.target_current,
        &enrolled.sibling_current,
        &stale.private,
        &current.private,
    ] {
        let group = arkret_mls::ArkretMlsGroup::restore_from_state_record(record).unwrap();
        let endpoint = group.local_content_endpoint().unwrap();
        let arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } = endpoint.endpoint
        else {
            panic!("this case uses actual Human Device endpoints")
        };
        let epoch = if group.epoch() == current.context.epoch {
            &current
        } else {
            &stale
        };
        assert_eq!(group.epoch(), epoch.context.epoch);
        assert_eq!(
            group.export_content_root(&epoch.context).unwrap(),
            epoch.root
        );
        local_states.insert(
            (endpoint.actor_id, device_id.to_string(), group.epoch()),
            record.clone(),
        );
    }
    let founder_local = ordinary_realm::human_profile::fixture_for_did(
        source.history.station_did.clone(),
        "ordinary-founder",
    );
    let founder_group =
        arkret_mls::ArkretMlsGroup::restore_from_state_record(&current.private).unwrap();
    let endpoint = founder_group.local_content_endpoint().unwrap();
    assert_eq!(
        endpoint.actor_id,
        ActorId::account(founder_local.history.account.clone())
    );
    assert_eq!(
        endpoint.authorization_event_ref,
        founder_local.history.events[1].event_id
    );
    let founder = Author::new(
        &DeviceRevocationGateSelector {
            principal_id: founder_local.history.account.principal_id.clone(),
            station_id: founder_local.history.account.station_id.clone(),
            device_id: founder_local.history.founding_device_id.to_string(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: founder_local.history.events[1].event_id.clone(),
                commit_id: founder_local.history.commits[1].commit_id.clone(),
                stream_ref: founder_local.history.commits[1].stream_ref.clone(),
                stream_position: founder_local.history.commits[1].stream_position,
            },
        },
        &founder_local.history.did,
        founder_local.history.founding_device_signing_seed,
    );
    let resolution = historical_roster_attestor_resolution();
    let station_key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
    let station_method = resolution
        .normalized_did_document
        .verification_methods
        .keys()
        .map(|id| arkret_wire::DidUrl::new(id).unwrap())
        .find(|method| {
            arkret_identity::validate_verification_method_relationship(
                &resolution.normalized_did_document,
                method,
                &resolution.normalized_did_document.id,
                arkret_identity::DidVerificationRelationship::AssertionMethod,
            )
            .is_ok()
                && arkret_identity::public_key_material_from_document(
                    &resolution.normalized_did_document,
                    method,
                )
                .unwrap()
                .ed25519_bytes()
                .unwrap()
                    == station_key.verifying_key().to_bytes()
        })
        .unwrap();
    let mut packages = BTreeMap::new();
    let mut originals = BTreeMap::new();
    let mut published_at = last_add.authority_commit.commit.committed_at;
    // The two local fixture modules deliberately have distinct Rust types.
    // Reconstruct their one shared fixture type only from original SDK values.
    let source_principal = policy_principal(
        &source.history.station_did,
        "alice",
        source.history.founding_device_signing_seed,
        (&source.history.events, &source.history.commits),
    );
    let founder_principal = policy_principal(
        &founder_local.history.station_did,
        "ordinary-founder",
        founder_local.history.founding_device_signing_seed,
        (
            &founder_local.history.events,
            &founder_local.history.commits,
        ),
    );
    for principal in [&source_principal, &founder_principal] {
        // Native acceptance is established by immutable original bytes,
        // before creating the ordinary minimal local private projection.
        for index in 0..2 {
            let accepted = commits
                .committed_event(&principal.history.events[index].event_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(accepted.event, principal.history.events[index]);
            assert_eq!(accepted.commit, principal.history.commits[index]);
        }
        coland_storage_postgres::PgPersistenceStore::new(pool.clone())
            .accounts()
            .put(&coland_storage::AccountRecord {
                pk: coland_storage::AccountPk(0),
                principal_id: principal.history.account.principal_id.clone(),
                station_id: principal.history.account.station_id.clone(),
                localpart: String::new(),
                display_name: None,
                biography: None,
                avatar_blob_ref: None,
                created_at: principal.history.events[0].created_at,
            })
            .await
            .unwrap();
        let (head, custody) = Box::pin(
            coland_test_support::agent_origin::admit_controller_history_custody(
                pool,
                principal,
                &station_method,
                &station_key,
            ),
        )
        .await;
        let original = commits
            .committed_event(&head.event_ref)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original.commit, head);
        assert_eq!(
            original.event.actor_id,
            ActorId::account(principal.history.account.clone())
        );
        let created_at = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now().max(head.committed_at),
        );
        let recovery =
            arkret_crypto::identity_root::derive_identity_recovery_key_material(&[149; 32], 0)
                .unwrap();
        let key =
            ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed);
        let authorization: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
            serde_json::from_value(
                serde_json::to_value(&principal.history.events[1].payload).unwrap(),
            )
            .unwrap();
        let roots = [&stale, &current]
            .into_iter()
            .map(|epoch| ContentRootBackupEntry {
                item_kind: ContentRootItemKind::ContentEpochRoot,
                secret_id: format!("epoch_root_{}", epoch.context.epoch),
                root_context: epoch.context.clone(),
                root_ref: content_root_ref(&epoch.root, &epoch.context).unwrap(),
                root_base64url: epoch.root.clone(),
            })
            .collect();
        let package = ContentRootBackupDraft {
            backup_id: arkret_wire::BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            actor_id: ActorId::account(principal.history.account.clone()),
            created_at,
            expires_at: None,
            author: ContentRootBackupAuthor::Device {
                binding: arkret_crypto::backup::KeyBackupAuthorizationBinding {
                    device_id: principal.history.founding_device_id.clone(),
                    verification_method: principal.history.device_verification_method.clone(),
                    signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                    device_authorize_event_id: principal.history.events[1].event_id.clone(),
                },
                source: KeyBackupSourceCommitRef {
                    realm_commit_id: head.commit_id,
                    device_generation_ref: authorization.authorized_generation_ref,
                },
            },
            recipient_key_ref: custody.recipient_key_ref.to_string(),
            recovery_policy_ref: custody.recovery_policy_ref,
            domain_separation: KeyBackupDomainSeparation {
                subdomain: "key_backup".into(),
                aead_aad_extensions: Default::default(),
            },
            series_id: arkret_wire::BackupSeriesId::new(format!(
                "ak:backup_series:{}",
                uuid::Uuid::now_v7()
            ))
            .unwrap(),
            series_sequence: 0,
            supersedes: None,
            custody: None,
        }
        .seal(roots, &recovery.backup_hpke_public_key, |bytes| {
            Ok(key.sign(bytes).to_bytes().to_vec())
        })
        .unwrap();
        package.validate().unwrap();
        package.validate_ciphertext_digest().unwrap();
        let store = PgKeyBackupStore { pool: pool.clone() };
        store
            .put(
                package.backup_id.to_string(),
                serde_json::to_value(&package).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .get(package.backup_id.as_str())
                .await
                .unwrap()
                .unwrap(),
            serde_json::to_value(&package).unwrap()
        );
        let original = retained_packet(pool, &package.backup_id).await;
        assert_eq!(original["body"], serde_json::to_value(&package).unwrap());
        assert_eq!(
            original["index"],
            serde_json::to_value(&package.contents).unwrap()
        );
        assert_eq!(
            original["digest"],
            arkret_canonical::canonical_sha256(&package).unwrap()
        );
        assert_eq!(original["actor"], package.actor_id.canonical_key().unwrap());
        assert!(original["admission"].is_object());
        assert!(original["deleted_at"].is_null());
        originals.insert(package.backup_id.clone(), original);
        published_at = published_at.max(package.created_at);
        packages.insert(package.actor_id.canonical_key().unwrap(), package);
    }
    // Preserve the actual newly accepted PCR head for the later real revoke.
    let source_head = commits
        .held_stream_head_commit(&source.history.commits[0].stream_ref)
        .await
        .unwrap()
        .unwrap();
    if source.history.commits.last().unwrap().commit_id != source_head.commit_id {
        let original = commits
            .committed_event(&source_head.event_ref)
            .await
            .unwrap()
            .unwrap();
        source.history.events.push(original.event);
        source.history.commits.push(original.commit);
    }
    assert_eq!(
        (PgMlsGroupCurrentStore { pool: pool.clone() })
            .current(&value.effective_scope)
            .await
            .unwrap()
            .unwrap()
            .value,
        value
    );
    Box::new(PublishedContent {
        current,
        stale,
        packages,
        published_at,
        local_states,
        originals,
        founder,
    })
}

impl PublishedContent {
    pub async fn assert_originals(&self, pool: &PgPool) {
        for (id, original) in &self.originals {
            assert_eq!(
                retained_packet(pool, id).await,
                *original,
                "revocation or sends must not rewrite or republish an original root packet"
            );
        }
    }
    fn encrypted_request(
        &self,
        previous: &coland_storage::AuthorityCommitTransaction,
        author: &Author,
        strand: &arkret_wire::StrandId,
        stale: bool,
        body: &str,
    ) -> Box<EventCommitRequest> {
        let epoch = if stale { &self.stale } else { &self.current };
        let actor = recipient_actor(&author.selector);
        let private = self
            .local_states
            .get(&(
                actor.clone(),
                author.selector.device_id.clone(),
                epoch.context.epoch,
            ))
            .unwrap();
        let group = arkret_mls::ArkretMlsGroup::restore_from_state_record(private).unwrap();
        let created_at = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now()
                .max(previous.commit.committed_at)
                .max(self.published_at)
                + chrono::TimeDelta::milliseconds(1),
        );
        let method =
            arkret_wire::DidUrl::new(format!("{}#{}", author.did, author.selector.device_id))
                .unwrap();
        let raw = device_authorization_history::sign_event(
            ordinary_realm::event_for_actor(
                EventKind::MessageCreate,
                epoch.context.effective_scope.clone(),
                actor.clone(),
                ordinary_realm::message_payload(strand, body),
                created_at,
            ),
            method.clone(),
            author.seed,
        );
        let endpoint = group.local_content_endpoint().unwrap();
        assert_eq!(endpoint, group.original_content_endpoint(&raw).unwrap());
        assert_eq!(endpoint.actor_id, actor);
        assert_eq!(
            endpoint.authorization_event_ref,
            author.selector.authorization_ref.event_id
        );
        assert_eq!(
            endpoint.signature_key_base64url,
            arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&author.seed)
                    .verifying_key()
                    .to_bytes()
            )
        );
        let package = self.packages.get(&actor.canonical_key().unwrap()).unwrap();
        assert_eq!(package.actor_id, actor);
        let content = ContentContext {
            root_context: epoch.context.clone(),
            root_ref: content_root_ref(&epoch.root, &epoch.context).unwrap(),
            purpose: ContentPurpose::EventBody,
            encryption_scheme: arkret_wire::EncryptedPayloadScheme::EpochContentAead,
            encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
            producer: endpoint,
            content_key_salt: fresh_content_key_salt().unwrap(),
        };
        let protection = ContentProtection {
            root_refs: vec![content.root_ref.clone()],
            blob_refs: vec![],
            backup_refs: vec![package.backup_id.clone()],
        };
        let key = derive_content_key(&epoch.root, &content).unwrap();
        let commitment = content_key_commitment(&content, &key).unwrap();
        let header = EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/vnd.arkret.message+json",
            content.encryption_scheme.clone(),
            epoch.context.effective_scope.clone(),
            raw.kind.as_str(),
            epoch.context.epoch,
            epoch.context.group_state_ref.clone(),
            arkret_canonical::canonical_json_string(&actor).unwrap(),
            EventContentRoutingContext::None,
            EventContentMaterial {
                content_context: content.clone(),
                outer_event: EventContentMaterial::outer_event_for(&raw).unwrap(),
                protection: protection.clone(),
                key_commitment: commitment.clone(),
            },
        )
        .unwrap();
        let plaintext = arkret_canonical::canonical_json_bytes(
            &serde_json::json!({"kind":"ak.content.text","body":body,"format":"plain"}),
        )
        .unwrap();
        let ciphertext = seal_content(&epoch.root, &header, &plaintext).unwrap();
        assert_eq!(
            open_content(&epoch.root, &header, &ciphertext).unwrap(),
            plaintext
        );
        let envelope = EncryptedEnvelope {
            version: "1.0".into(),
            content_type: header.content_type,
            encryption_scheme: content.encryption_scheme,
            encryption_context: EncryptedEnvelopeEncryptionContext::EpochContent {
                epoch: epoch.context.epoch,
                group_state_ref: epoch.context.group_state_ref.clone(),
                content_key_salt: content.content_key_salt,
                root_ref: content.root_ref,
                key_commitment: commitment,
                protection,
                routing_context: None,
            },
            ciphertext,
        };
        let mut event = raw;
        event.payload.remove("content");
        event.payload.insert(
            "encrypted_content".into(),
            serde_json::to_value(envelope).unwrap(),
        );
        let event = device_authorization_history::sign_event(event, method, author.seed);
        let mut request = ordinary_realm::request_for_event(previous, event, created_at);
        request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
            author.selector.clone(),
        ));
        request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
            request.authority_commit.event.clone(),
        ));
        Box::new(request)
    }

    pub async fn message(
        &self,
        pool: &PgPool,
        previous: &coland_storage::AuthorityCommitTransaction,
        author: &Author,
        strand: &arkret_wire::StrandId,
        stale: bool,
        body: &str,
    ) -> Box<EventCommitRequest> {
        let request = self.encrypted_request(previous, author, strand, stale, body);
        Box::new(Box::pin(ordinary_realm::source_request(pool, *request)).await)
    }
}
