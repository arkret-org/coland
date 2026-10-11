//! Native Sidecar cut preserves exact controller identity and parent authority.

#[path = "support/historical_control_source.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared control source fixture."
)]
mod historical_control_source;

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
#[path = "support/sidecar_agent.rs"]
mod sidecar_agent;
#[path = "support/sidecar_exchange_controls.rs"]
mod sidecar_exchange_controls;
#[path = "support/sidecar_readiness.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared readiness fixture."
)]
mod sidecar_readiness;

use std::future::Future;
use std::pin::Pin;

use arkret_wire::{AccountId, EventKind, SidecarId};
use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use coland_storage_postgres::sidecar_authority_cut::read;
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPersistenceStore,
};

/// Prepare the complete candidate from the accepted PCR, then bind its final
/// coordinates and source digest into the actual Station signature.
async fn source_candidate(
    pool: &coland_storage_postgres::PgPool,
    request: &mut coland_storage::EventCommitRequest,
) {
    let tx = &mut request.authority_commit;
    tx.producer_signer_fact = PgAuthorityCommitStore { pool: pool.clone() }
        .prepare_human_signer_fact(&tx.event, tx.commit.committed_at)
        .await
        .unwrap()
        .map(Into::into);
    assert!(tx.producer_signer_fact.is_some());
    tx.commit.producer_signer_fact_digest = tx
        .producer_signer_fact
        .as_ref()
        .map(|fact| fact.digest().unwrap());
    let identity =
        arkret_canonical::canonical::unsigned_value(&tx.commit, &["commit_id", "signature"])
            .unwrap();
    tx.commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    tx.commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(&tx.commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        tx.commit.signature.verification_method.clone(),
        tx.commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(
            &device_authorization_history::STATION_AUTHORITY_SEED,
        ),
    )
    .unwrap();
    tx.commit.verify_commit_id_matches_content().unwrap();
}

async fn accepted_controller(
    pool: &coland_storage_postgres::PgPool,
    station_did: arkret_wire::Did,
) -> pcr_genesis::PcrGenesisFixture {
    use coland_storage::IdentityStoreRegistry;
    use diesel_async::RunQueryDsl;
    let principal = pcr_genesis::PcrGenesisFixture::new(station_did);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<diesel::sql_types::Text, _>(principal.history.account.station_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let persistence = PgPersistenceStore::new(pool.clone());
    persistence
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: principal.history.account.principal_id.clone(),
            station_id: principal.history.account.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    principal.admit_founding_device(&persistence).await.unwrap();
    ordinary_realm::human_profile::register_fixture_signer(
        &principal.history.account,
        principal.history.device_verification_method.clone(),
        principal.history.founding_device_signing_seed,
    );
    historical_control_source::register_device(
        &principal.history.account,
        &principal.history.founding_device_id,
        &principal.history.events[1].event_id,
    );
    principal
}

/// Exercise the real PG read ports with an RFC public group and accepted
/// handshake Events while the desired Agent has no consumed Welcome.
async fn pending_agent_handshake_reads(
    pool: &coland_storage_postgres::PgPool,
    principal: &std::sync::Arc<pcr_genesis::PcrGenesisFixture>,
    head: &coland_storage::AuthorityCommitTransaction,
    sidecar: &SidecarId,
    sidecar_genesis: &arkret_wire::EventId,
    agent: &AccountId,
) -> (
    coland_storage::AuthorityCommitTransaction,
    arkret_mls::ArkretMlsGroup,
    arkret_mls::MlsPublicGroupTracker,
) {
    let pool = pool.clone();
    let principal = principal.clone();
    let head = head.clone();
    let sidecar = sidecar.clone();
    let sidecar_genesis = sidecar_genesis.clone();
    let agent = agent.clone();
    // Await the independent fixture task so its poll frame is not nested in its caller.
    tokio::spawn(async move {
        let pool = &pool;
        let principal = &*principal;
        let head = &head;
        let sidecar = &sidecar;
        let sidecar_genesis = &sidecar_genesis;
        let agent = &agent;
        use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload};
        use arkret_wire::{ActorId, CommitStreamRef, CommittedEventView, ScopeRef};
        use coland_storage::{
            AccountStreamScan, MlsMemberGroupStateMaterialRead, MlsStateInstallation,
        };

        let controller = &principal.history.account;
        let realm = &head.event.realm_id;
        let at = head.commit.committed_at;
        let actor = ActorId::account(controller.clone());
        let scope = ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        };
        let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
        let (group, tracker, genesis, commit, context, info, tree) = Box::pin(async {
            let cut = read(pool, realm, sidecar, controller)
                .await
                .unwrap()
                .unwrap();
            let binding = |base, previous, next| {
                MlsGovernanceBindingPayload::sidecar(
                    realm.clone(),
                    sidecar.clone(),
                    base,
                    previous,
                    next,
                    0,
                    cut.participant_authority_digest.clone(),
                    cut.authority_stream_head.clone(),
                )
                .unwrap()
            };
            let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
                actor.clone(),
                principal.history.founding_device_id.clone(),
                arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
                    ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed),
                ),
            )
            .unwrap();
            let mut group = identity
                .create_group_with_governance_binding(&scope, &binding(None, 0, 0))
                .unwrap();
            let (info, tree) = group.public_group_state_bytes().unwrap();
            let mut tracker = arkret_mls::MlsPublicGroupTracker::from_external(
                &info,
                &tree,
                group.group_id().as_str(),
                0,
            )
            .unwrap();
            let blob = |bytes: &[u8]| {
                arkret_wire::BlobRef::new(format!(
                    "ak:blob:{}",
                    arkret_canonical::sha256_digest(bytes),
                ))
                .unwrap()
            };
            let authorization = principal
                .history
                .events
                .iter()
                .find(|event| event.kind == EventKind::DeviceAuthorize)
                .unwrap();
            let genesis_payload = serde_json::json!({
                "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                "group_info_ref": blob(&info), "ratchet_tree_ref": blob(&tree),
                "creator_leaf_authority": {
                    "leaf_signature_key_b64u": arkret_canonical::base64url_encode(
                        ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed)
                            .verifying_key().as_bytes(),
                    ),
                    "endpoint": {"kind":"device", "device_id": principal.history.founding_device_id},
                    "authorization_event_ref": authorization.event_id,
                },
                "governance_binding": binding(None, 0, 0),
                "created_at": arkret_canonical::format_timestamp_canonical(at),
            });
            let make_request = |kind, payload, previous: &coland_storage::AuthorityCommitTransaction| {
                let mut event =
                    ordinary_realm::event_for_actor(kind, scope.clone(), actor.clone(), payload, at);
                if event.kind == EventKind::SidecarContextAttach {
                    event.semantic_refs = vec![arkret_wire::SemanticRef::new(
                        sidecar_genesis.to_string(),
                        "after",
                    )];
                }
                let event = device_authorization_history::sign_event(
                    event,
                    principal.history.device_verification_method.clone(),
                    principal.history.founding_device_signing_seed,
                );
                let mut request = ordinary_realm::request_for_event(previous, event, at);
                request.authority_commit.commit.stream_ref = stream.clone();
                if previous.commit.stream_ref == stream {
                    request.authority_commit.commit.stream_position = previous.commit.stream_position + 1;
                    request.authority_commit.commit.previous_commit_ref =
                        Some(previous.commit.commit_id.clone());
                } else {
                    request.authority_commit.commit.stream_position = 0;
                    request.authority_commit.commit.previous_commit_ref = None;
                }
                request
            };
            let state = |base, epoch, public_state| MlsStateInstallation {
                effective_scope: scope.clone(),
                base,
                epoch,
                public_state,
                member_principals: [actor.clone()].into_iter().collect(),
                consumed_proposals: Vec::new(),
                public_blobs: Vec::new(),
            };
            let public_blob = |bytes: &[u8]| {
                let sha256 = arkret_canonical::sha256_digest(bytes)
                    .strip_prefix("sha256:")
                    .unwrap()
                    .to_owned();
                coland_storage::MlsPublicBlob {
                    blob_ref: blob(bytes),
                    size_bytes: i64::try_from(bytes.len()).unwrap(),
                    storage_backend: "local".to_owned(),
                    storage_key: format!("sha256/{sha256}"),
                    sha256,
                }
            };
            let uow = PgEventCommitUnitOfWork::new(pool.clone());
            let mut genesis = make_request(EventKind::MlsGenesis, genesis_payload, head);
            genesis.authority_commit.mls_state = Some(state(None, 0, tracker.export_state().unwrap()));
            genesis
                .authority_commit
                .mls_state
                .as_mut()
                .unwrap()
                .public_blobs = vec![public_blob(&info), public_blob(&tree)];
            source_candidate(pool, &mut genesis).await;
            let genesis = ordinary_realm::source_request(&pool, genesis).await;
            uow.commit_event(genesis.clone()).await.unwrap();
            let envelope = group
                .self_update_commit_with_governance_binding(&binding(
                    Some(genesis.authority_commit.event.event_id.clone()),
                    0,
                    1,
                ))
                .unwrap();
            let wire = arkret_canonical::base64url_decode(&envelope.commit).unwrap();
            tracker.process_public_handshake(&wire).unwrap();
            let payload = MlsCommitPayload::new(
                genesis.authority_commit.event.event_id.clone(),
                0,
                &envelope,
                binding(Some(genesis.authority_commit.event.event_id.clone()), 0, 1),
            )
            .unwrap();
            let mut commit = make_request(
                EventKind::MlsCommit,
                serde_json::to_value(payload).unwrap(),
                &genesis.authority_commit,
            );
            commit.authority_commit.mls_state = Some(state(
                Some(coland_storage::MlsInstalledBase {
                    current_mls_commit_event_ref: genesis.authority_commit.event.event_id.clone(),
                    epoch: 0,
                }),
                1,
                tracker.export_state().unwrap(),
            ));
            commit
                .authority_commit
                .mls_state
                .as_mut()
                .unwrap()
                .public_blobs = vec![public_blob(&tracker.ratchet_tree_bytes().unwrap())];
            let groups = coland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() };
            let base = coland_storage::MlsGroupCurrentStore::current(&groups, &scope)
                .await
                .unwrap()
                .unwrap()
                .value;
            source_candidate(pool, &mut commit).await;
            let commit = ordinary_realm::source_request(&pool, commit).await;
            uow.commit_event(commit.clone()).await.unwrap();
            group
                .install_accepted_commit(
                    &arkret_wire::CommittedEventFullView {
                        event: commit.authority_commit.event.clone(),
                        commit: commit.authority_commit.commit.clone(),
                    },
                    &base,
                )
                .unwrap();
            let strand = ordinary_realm::next_request(
                head,
                EventKind::StrandCreate,
                &controller.principal_id,
                serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
                    "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                    "metadata":{"title":"Pending Sidecar source"},"state":"active","created_by":actor,
                    "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
                at,
            );
            let strand = ordinary_realm::source_request(&pool, strand).await;
            uow.commit_event(strand.clone()).await.unwrap();
            let mut context = make_request(
                EventKind::SidecarContextAttach,
                serde_json::json!({
                    "sidecar_id":sidecar,
                    "source_context_ref":{"kind":"strand","strand_id":arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id)},
                    "version":1,
                }),
                &commit.authority_commit,
            );
            source_candidate(pool, &mut context).await;
            let context = ordinary_realm::source_request(&pool, context).await;
            uow.commit_event(context.clone()).await.unwrap();
            (group, tracker, genesis, commit, context, info, tree)
        })
        .await;
        Box::pin(async {
            let blob = |bytes: &[u8]| {
                arkret_wire::BlobRef::new(format!(
                    "ak:blob:{}",
                    arkret_canonical::sha256_digest(bytes),
                ))
                .unwrap()
            };
            let store = PgAuthorityCommitStore { pool: pool.clone() };
            let request = arkret_wire::StreamScanRequest {
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                direction: arkret_wire::StreamScanDirection::After(None),
                limit: 10,
            };
            let AccountStreamScan::Page(page) = store
                .scan_stream_for_account(&request, agent, &controller.station_id)
                .await
                .unwrap()
            else {
                panic!("desired Agent must be able to verify its restricted handshakes before consume")
            };
            assert_eq!(page.committed_events.len(), 3);
            assert!(
                matches!(&page.committed_events[0], CommittedEventView::Full(row) if row.event == genesis.authority_commit.event)
            );
            assert!(
                matches!(&page.committed_events[1], CommittedEventView::Full(row) if row.event == commit.authority_commit.event)
            );
            assert!(
                matches!(&page.committed_events[2], CommittedEventView::Withheld(row) if row.commit == context.authority_commit.commit)
            );
            // The exact Event read used by historical signer resolution must apply
            // the same pending-recipient handshake disclosure as the native scan.
            for original in [&genesis.authority_commit, &commit.authority_commit] {
                assert!(matches!(
                    store.committed_event_for_member(
                        &original.event.event_id, &ActorId::account(agent.clone()), &controller.station_id,
                    ).await.unwrap(),
                    coland_storage::MemberCommittedEventRead::Read(view)
                        if matches!(*view, CommittedEventView::Full(ref row)
                            if row.event == original.event && row.commit == original.commit)
                ));
            }
            assert!(matches!(
                store
                    .committed_event_for_member(
                        &context.authority_commit.event.event_id,
                        &ActorId::account(agent.clone()),
                        &controller.station_id,
                    )
                    .await
                    .unwrap(),
                coland_storage::MemberCommittedEventRead::Read(view)
                    if matches!(*view, CommittedEventView::Withheld(_))
            ));
            let material =
                arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody {
                    realm_id: realm.clone(),
                    effective_scope: scope,
                    mls_group_id: group.group_id().clone(),
                    epoch: Default::default(),
                    group_state_event_id: genesis.authority_commit.event.event_id.clone(),
                    caller_actor_id: Some(ActorId::account(agent.clone())),
                    target_commit_event_ref: Some(commit.authority_commit.event.event_id.clone()),
                    target_epoch: Some(1),
                    group_info_ref: blob(&info),
                    ratchet_tree_ref: blob(&tree),
                    max_response_bytes: None,
                };
            assert!(
                matches!(store.mls_member_group_state_material_read(&material, &controller.station_id, None).await.unwrap(),
                MlsMemberGroupStateMaterialRead::Authorized {genesis:Some(row)} if row.event == genesis.authority_commit.event)
            );
            let snapshot = store
                .realm_state_snapshot_material_for_account(realm, agent)
                .await
                .unwrap()
                .unwrap();
            assert!(
                snapshot
                    .visible_stream_heads
                    .iter()
                    .any(|head| head.stream_ref == stream)
            );
            let public_rows: Vec<_> = snapshot.current_state_entries.iter().filter(|row| matches!(row,
                arkret_wire::TypedCurrentRow::Value {source_stream_ref,..} if source_stream_ref == &stream)).collect();
            assert_eq!(public_rows.len(), 1);
            assert!(
                matches!(public_rows[0], arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup {scope_ref}, value, ..
            } if scope_ref == &material.effective_scope
                && value["genesis_event_ref"] == serde_json::to_value(&genesis.authority_commit.event.event_id).unwrap()
                && value["epoch"] == 1)
            );
            assert!(
                !snapshot
                    .current_state_entries
                    .iter()
                    .any(|row| matches!(row,
                arkret_wire::TypedCurrentRow::Value {selector:
                    arkret_wire::CurrentSelector::Sidecar {sidecar_id}
                    | arkret_wire::CurrentSelector::SidecarContext {sidecar_id,..}, ..}
                    if sidecar_id == sidecar))
            );
            let foreign = AccountId::new(
                agent.principal_id.clone(),
                arkret_wire::DidCoreId::new("ak:did_core:web:wrong-sidecar-station.example").unwrap(),
            );
            assert!(matches!(
                store
                    .scan_stream_for_account(&request, &foreign, &controller.station_id)
                    .await
                    .unwrap(),
                AccountStreamScan::NotAuthorized
            ));
            assert!(matches!(
                store
                    .committed_event_for_member(
                        &genesis.authority_commit.event.event_id,
                        &ActorId::account(foreign),
                        &controller.station_id,
                    )
                    .await
                    .unwrap(),
                coland_storage::MemberCommittedEventRead::NotVisible
            ));
        })
        .await;
        (context.authority_commit, group, tracker)
    })
    .await
    .expect("pending handshake fixture task")
}

#[tokio::test]
async fn sidecar_cut_requires_exact_controller_and_current_parent_join() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station = historical_control_source::HistoricalControlStation::new(
        "sidecar-native-control",
        [83; 32],
    );
    let station_did = historical_station.did.clone();
    let principal = accepted_controller(&pool, station_did.clone()).await;
    let controller = principal.history.account.clone();
    let realm = ordinary_realm::bootstrap_unit_for_account(
        "sidecar-participant-cut",
        &controller,
        &station_did,
    );
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let last = realm.transactions.last().unwrap();
    let create = ordinary_realm::next_request(
        last,
        EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        last.commit.committed_at,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let create = ordinary_realm::source_request(&pool, create).await;
    uow.commit_event(create.clone()).await.unwrap();
    let realm_id = &create.authority_commit.event.realm_id;
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let cut = read(&pool, realm_id, &sidecar, &controller)
        .await
        .unwrap()
        .unwrap();
    assert!(cut.desired_agent_ids.is_empty());
    assert_eq!(cut.authority_stream_head.len(), 2);
    assert!(
        cut.authority_stream_head
            .contains(&create.authority_commit.event.event_id)
    );
    assert_eq!(cut.visible_stream_heads.len(), 1);
    assert_eq!(
        cut.visible_stream_heads[0].commit_id,
        create.authority_commit.commit.commit_id
    );
    assert_eq!(
        cut.participant_authority_digest,
        arkret_models_collaboration::agent_sidecar::sidecar_participant_authority_digest(
            &sidecar,
            realm_id,
            &controller,
            &[]
        )
        .unwrap()
    );
    let snapshot = store
        .realm_state_snapshot_material_for_account(realm_id, &controller)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(
        |row| matches!(row, arkret_wire::TypedCurrentRow::Value {
        selector: arkret_wire::CurrentSelector::Sidecar { sidecar_id }, ..
    } if sidecar_id == &sidecar)
    ));
    let another_station = AccountId::new(
        controller.principal_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:foreign-controller.example").unwrap(),
    );
    assert!(
        read(&pool, realm_id, &sidecar, &another_station)
            .await
            .unwrap()
            .is_none()
    );
    let unknown = SidecarId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [113; 32],
    ));
    assert!(
        read(&pool, realm_id, &unknown, &controller)
            .await
            .unwrap()
            .is_none()
    );
    let leave = ordinary_realm::next_request(
        &create.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"realm_id":realm_id,"member_id":arkret_wire::ActorId::account(controller.clone()),
            "membership":"leave","reason":"Sidecar authority current matrix"}),
        create.authority_commit.commit.committed_at,
    );
    let leave = ordinary_realm::source_request(&pool, leave).await;
    uow.commit_event(leave).await.unwrap();
    assert!(
        read(&pool, realm_id, &sidecar, &controller)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn desired_agents_require_owned_active_key_and_exact_realm_membership() {
    use coland_storage::AgentControlAdmissionWrite;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station = historical_control_source::HistoricalControlStation::new(
        "sidecar-native-control",
        [83; 32],
    );
    let station_did = historical_station.did.clone();
    let principal = accepted_controller(&pool, station_did.clone()).await;
    let controller = &principal.history.account;
    let realm = ordinary_realm::bootstrap_unit_for_account(
        "sidecar-agent-matrix",
        controller,
        &station_did,
    );
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let create = ordinary_realm::next_request(
        parent,
        EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        parent.commit.committed_at,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let create = ordinary_realm::source_request(&pool, create).await;
    uow.commit_event(create.clone()).await.unwrap();
    let realm_id = &create.authority_commit.event.realm_id;
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let (agent, genesis, provision_ref) = provision_owned_agent(&pool, &principal).await;
    let no_key = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(no_key.desired_agent_ids.is_empty());
    assert!(no_key.authority_stream_head.contains(&provision_ref));
    let original_genesis: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.event.payload).unwrap()).unwrap();
    let agent_did = original_genesis.object.initial_resolution.unwrap().did;
    let delegation = format!("{agent_did}#managed-controller");
    let key_event = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        &agent,
        &genesis.event.realm_id,
        &delegation,
        sidecar_agent::agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            genesis.commit.committed_at,
        ),
        genesis.commit.committed_at,
    );
    let key_commit = sidecar_agent::station_successor(&genesis.commit, &key_event, &station_did, 1);
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    historical_control_source::admit_control(
        &profiles,
        &pool,
        AgentControlAdmissionWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: genesis.expected_authority.clone(),
                event: key_event.clone(),
                commit: key_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: key_commit.committed_at,
        },
    )
    .await
    .unwrap();
    let not_joined = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(not_joined.desired_agent_ids.is_empty());
    assert!(
        not_joined
            .authority_stream_head
            .contains(&key_event.event_id)
    );
    let join = ordinary_realm::next_request(
        &create.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id": arkret_wire::ActorId::account(agent.clone()), "membership":"join",
            "agent_controller_binding": {"controller_account_id":controller,
                "controller_membership_generation_ref":parent.event.event_id}}),
        key_commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    let joined = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.desired_agent_ids, vec![agent.principal_id.clone()]);
    assert!(
        joined
            .authority_stream_head
            .contains(&join.authority_commit.event.event_id)
    );
    assert_ne!(
        joined.participant_authority_digest,
        not_joined.participant_authority_digest
    );
    let member_reader = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(matches!(
        member_reader
            .committed_event_for_member(
                &join.authority_commit.event.event_id,
                &arkret_wire::ActorId::account(agent.clone()),
                &controller.station_id,
            )
            .await
            .unwrap(),
        coland_storage::MemberCommittedEventRead::Read(view)
            if matches!(*view, arkret_wire::CommittedEventView::Full(_))
    ));
    let controller_leave = ordinary_realm::next_request(
        &join.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(controller.clone()),"membership":"leave"}),
        join.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let controller_leave = ordinary_realm::source_request(&pool, controller_leave).await;
    uow.commit_event(controller_leave.clone()).await.unwrap();
    let read_error = member_reader
        .committed_event_for_member(
            &join.authority_commit.event.event_id,
            &arkret_wire::ActorId::account(agent.clone()),
            &controller.station_id,
        )
        .await
        .unwrap_err();
    assert!(
        read_error
            .to_string()
            .contains("controller binding is unavailable"),
        "{read_error}"
    );
    assert!(
        read(&pool, realm_id, &sidecar, controller)
            .await
            .unwrap()
            .is_none()
    );
    let controller_rejoin = ordinary_realm::next_request(
        &controller_leave.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(controller.clone()),"membership":"join"}),
        controller_leave.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let controller_rejoin = ordinary_realm::source_request(&pool, controller_rejoin).await;
    uow.commit_event(controller_rejoin.clone()).await.unwrap();
    let read_error = member_reader
        .committed_event_for_member(
            &join.authority_commit.event.event_id,
            &arkret_wire::ActorId::account(agent.clone()),
            &controller.station_id,
        )
        .await
        .unwrap_err();
    assert!(
        read_error
            .to_string()
            .contains("controller binding is unavailable"),
        "{read_error}"
    );
    let stale_generation = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(stale_generation.desired_agent_ids.is_empty());
    assert!(
        stale_generation
            .authority_stream_head
            .contains(&controller_rejoin.authority_commit.event.event_id)
    );
    assert!(
        stale_generation
            .authority_stream_head
            .contains(&join.authority_commit.event.event_id)
    );
    let leave = ordinary_realm::next_request_for_actor(
        &controller_rejoin.authority_commit,
        EventKind::MemberState,
        arkret_wire::ActorId::account(agent.clone()),
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"leave"}),
        controller_rejoin.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    // The v1 ingress has no Agent cleanup carrier. An invalidated Agent
    // self-leave cannot rewrite canonical membership or revive its generation.
    let error = uow.commit_event(leave.clone()).await.unwrap_err();
    assert!(error.to_string().contains("unsupported_feature"));
    let left = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(left.desired_agent_ids.is_empty());
    assert!(
        !left
            .authority_stream_head
            .contains(&leave.authority_commit.event.event_id)
    );
    assert_eq!(
        left.authority_stream_head,
        stale_generation.authority_stream_head
    );
    assert_eq!(
        left.participant_authority_digest,
        stale_generation.participant_authority_digest
    );
    let fresh_join = ordinary_realm::next_request(
        &controller_rejoin.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,
                "controller_membership_generation_ref":controller_rejoin.authority_commit.event.event_id}}),
        controller_rejoin.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    // A new controller generation cannot turn the existing Agent join into
    // another join without an accepted canonical leave transition.
    let error = uow.commit_event(fresh_join.clone()).await.unwrap_err();
    assert!(error.to_string().contains("invalid_membership_transition"));
    let fresh = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(fresh.desired_agent_ids.is_empty());
    assert!(
        !fresh
            .authority_stream_head
            .contains(&fresh_join.authority_commit.event.event_id)
    );
    assert_eq!(
        fresh.authority_stream_head,
        stale_generation.authority_stream_head
    );
    assert_eq!(
        fresh.participant_authority_digest,
        stale_generation.participant_authority_digest
    );
}

#[tokio::test]
async fn pending_sidecar_handshake_reads_keep_content_private_and_reject_stale_authority() {
    boxed_pending_sidecar_handshake().await;
}

// Construct the large scenario outside the harness Future's poll frame.
fn boxed_pending_sidecar_handshake() -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(pending_sidecar_handshake_scenario())
}

async fn pending_sidecar_handshake_scenario() {
    use coland_storage::AgentControlAdmissionWrite;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station = historical_control_source::HistoricalControlStation::new(
        "sidecar-native-control",
        [83; 32],
    );
    let station_did = historical_station.did.clone();
    let principal = std::sync::Arc::new(accepted_controller(&pool, station_did.clone()).await);
    let controller = &principal.history.account;
    let realm = ordinary_realm::bootstrap_unit_for_account(
        "sidecar-agent-matrix",
        controller,
        &station_did,
    );
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let create = ordinary_realm::next_request(
        parent,
        EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        parent.commit.committed_at,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let create = ordinary_realm::source_request(&pool, create).await;
    uow.commit_event(create.clone()).await.unwrap();
    let realm_id = &create.authority_commit.event.realm_id;
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let (agent, genesis, provision_ref) = provision_owned_agent(&pool, &principal).await;
    let no_key = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(no_key.desired_agent_ids.is_empty());
    assert!(no_key.authority_stream_head.contains(&provision_ref));
    let original_genesis: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.event.payload).unwrap()).unwrap();
    let agent_did = original_genesis.object.initial_resolution.unwrap().did;
    let delegation = format!("{agent_did}#managed-controller");
    let key_event = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        &agent,
        &genesis.event.realm_id,
        &delegation,
        sidecar_agent::agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            genesis.commit.committed_at,
        ),
        genesis.commit.committed_at,
    );
    let key_commit = sidecar_agent::station_successor(&genesis.commit, &key_event, &station_did, 1);
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    historical_control_source::admit_control(
        &profiles,
        &pool,
        AgentControlAdmissionWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: genesis.expected_authority.clone(),
                event: key_event.clone(),
                commit: key_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: key_commit.committed_at,
        },
    )
    .await
    .unwrap();
    let not_joined = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(not_joined.desired_agent_ids.is_empty());
    assert!(
        not_joined
            .authority_stream_head
            .contains(&key_event.event_id)
    );
    let join = ordinary_realm::next_request(
        &create.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id": arkret_wire::ActorId::account(agent.clone()), "membership":"join",
            "agent_controller_binding": {"controller_account_id":controller,
                "controller_membership_generation_ref":parent.event.event_id}}),
        key_commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    Box::pin(pending_agent_handshake_reads(
        &pool,
        &principal,
        &join.authority_commit,
        &sidecar,
        &create.authority_commit.event.event_id,
        &agent,
    ))
    .await;
    let renewed_at = key_commit.committed_at + chrono::TimeDelta::seconds(2);
    let mut renewed_authorization =
        sidecar_agent::agent_key_authorization(&agent_did, &controller.principal_id, renewed_at);
    renewed_authorization["supersedes"] = serde_json::json!([{
        "key_id":key_event.payload["key_id"],
        "authorized_event_ref":key_event.event_id,
    }]);
    let renewal = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        &agent,
        &genesis.event.realm_id,
        &delegation,
        renewed_authorization,
        renewed_at,
    );
    let renewal_commit = sidecar_agent::station_successor(&key_commit, &renewal, &station_did, 2);
    historical_control_source::admit_control(
        &profiles,
        &pool,
        AgentControlAdmissionWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: genesis.expected_authority.clone(),
                event: renewal,
                commit: renewal_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: renewal_commit.committed_at,
        },
    )
    .await
    .unwrap();
    let current_cut = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        current_cut.desired_agent_ids,
        vec![agent.principal_id.clone()]
    );
    let stale = arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: sidecar,
        },
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 10,
    };
    assert!(matches!(
        store
            .scan_stream_for_account(&stale, &agent, &controller.station_id)
            .await
            .unwrap(),
        coland_storage::AccountStreamScan::NotAuthorized
    ));
    let snapshot = store
        .realm_state_snapshot_material_for_account(realm_id, &agent)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == stale.stream_ref)
    );
    assert!(
        !snapshot
            .current_state_entries
            .iter()
            .any(|row| matches!(row,
        arkret_wire::TypedCurrentRow::Value {source_stream_ref,..}
        if source_stream_ref == &stale.stream_ref))
    );
}

/// Real accepted Sidecar Add, original Welcome and signed durable receipt.
/// The PG consume port takes serving-layer verified receipts as its input.
#[tokio::test]
async fn consumed_sidecar_agent_requires_exact_controller_owner_and_consume_digest() {
    boxed_consumed_sidecar_agent().await;
}

// Construct the large scenario outside the harness Future's poll frame.
fn boxed_consumed_sidecar_agent() -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(consumed_sidecar_agent_scenario())
}

async fn consumed_sidecar_agent_scenario() {
    use coland_storage::AgentControlAdmissionWrite;
    let (database, resolution, principal, create, agent_did, agent, genesis,
        key_event, key_commit, join, delegation, station_did) = Box::pin(async {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let historical_station = historical_control_source::HistoricalControlStation::new(
            "sidecar-consumed-control",
            [83; 32],
        );
        let resolution = historical_station.history.clone();
        let station_did = historical_station.did.clone();
        let principal = std::sync::Arc::new(accepted_controller(&pool, station_did.clone()).await);
        let controller = &principal.history.account;
        let realm = ordinary_realm::bootstrap_unit_for_account(
            "sidecar-agent-matrix",
            controller,
            &station_did,
        );
        let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        store
            .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
            .await
            .unwrap();
        let parent = realm.transactions.last().unwrap();
        let create = ordinary_realm::next_request(
            parent,
            EventKind::SidecarCreate,
            &controller.principal_id,
            serde_json::json!({}),
            parent.commit.committed_at,
        );
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let create = ordinary_realm::source_request(&pool, create).await;
        uow.commit_event(create.clone()).await.unwrap();
        let realm_id = &create.authority_commit.event.realm_id;
        let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
        let agent_did = arkret_wire::Did::new(format!(
            "did:webvh:{}:sidecar-agent.example",
            arkret_canonical::multibase::sha256_multihash_base58btc(uuid::Uuid::now_v7().as_bytes())
        ))
        .unwrap();
        let (agent, genesis, provision_ref) =
            provision_owned_agent_with_did(&pool, &principal, agent_did.clone()).await;
        let no_key = read(&pool, realm_id, &sidecar, controller)
            .await
            .unwrap()
            .unwrap();
        assert!(no_key.desired_agent_ids.is_empty());
        assert!(no_key.authority_stream_head.contains(&provision_ref));
        let delegation = format!("{agent_did}#managed-controller");
        let key_event = sidecar_agent::agent_control_event(
            &principal.history.device_verification_method,
            principal.history.founding_device_signing_seed,
            controller,
            &agent,
            &genesis.event.realm_id,
            &delegation,
            sidecar_agent::agent_key_authorization(
                &agent_did,
                &controller.principal_id,
                genesis.commit.committed_at,
            ),
            genesis.commit.committed_at,
        );
        let key_commit = sidecar_agent::station_successor(&genesis.commit, &key_event, &station_did, 1);
        let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
        historical_control_source::admit_control(
            &profiles,
            &pool,
            AgentControlAdmissionWrite {
                commit: coland_storage::AuthorityCommitTransaction {
                    expected_authority: genesis.expected_authority.clone(),
                    event: key_event.clone(),
                    commit: key_commit.clone(),
                    producer_signer_fact: None,
                    mls_state: None,
                    welcomes: Vec::new(),
                    recipient_queue_capacity: 0,
                },
                queued_at: key_commit.committed_at,
            },
        )
        .await
        .unwrap();
        let not_joined = read(&pool, realm_id, &sidecar, controller)
            .await
            .unwrap()
            .unwrap();
        assert!(not_joined.desired_agent_ids.is_empty());
        assert!(
            not_joined
                .authority_stream_head
                .contains(&key_event.event_id)
        );
        let join = ordinary_realm::next_request(
            &create.authority_commit,
            EventKind::MemberState,
            &controller.principal_id,
            serde_json::json!({"member_id": arkret_wire::ActorId::account(agent.clone()), "membership":"join",
                "agent_controller_binding": {"controller_account_id":controller,
                    "controller_membership_generation_ref":parent.event.event_id}}),
            key_commit.committed_at + chrono::TimeDelta::milliseconds(1),
        );
        let join = ordinary_realm::source_request(&pool, join).await;
        uow.commit_event(join.clone()).await.unwrap();
        (database, resolution, principal, create, agent_did, agent, genesis,
            key_event, key_commit, join, delegation, station_did)
    })
        .await;

    let pool = database.pool();
    let controller = &principal.history.account;
    let realm_id = &create.authority_commit.event.realm_id;
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let (head, mut group, mut tracker) = Box::pin(pending_agent_handshake_reads(
        &pool,
        &principal,
        &join.authority_commit,
        &sidecar,
        &create.authority_commit.event.event_id,
        &agent,
    ))
    .await;
    let (request, mut group, mut recipient_group) = Box::pin(async {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        use arkret_models_crypto::{
            KeyOperationSignature, KeyPackageConsumeReceipt, MlsGovernanceBindingPayload,
            RecipientMlsDurableReceipt, RecipientMlsDurableSigner,
        };
        use arkret_wire::{ActorId, ScopeRef};
        use diesel::sql_types::{BigInt, Jsonb, Text};
        use diesel_async::RunQueryDsl;
        use coland_storage::{MlsGroupCurrentStore, MlsKeyPackageStore};
        let scope = ScopeRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: sidecar.clone(),
        };
        let cut = read(&pool, realm_id, &sidecar, controller)
            .await
            .unwrap()
            .unwrap();
        let actor = ActorId::account(agent.clone());
        let method = arkret_wire::DidUrl::new(format!("{agent_did}#runtime-1")).unwrap();
        let identity = arkret_mls::ArkretMlsIdentity::new_agent(
            actor.clone(),
            method.clone(),
            key_event.event_id.clone(),
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]),
            ),
        )
        .unwrap();
        let mut package = identity.key_package_record().unwrap();
        let now =
            chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
        #[derive(diesel::QueryableByName)]
        struct LocalAccount {
            #[diesel(sql_type=BigInt)]
            pk: i64,
        }
        let mut conn = pool.get().await.unwrap();
        let owner = diesel::sql_query("INSERT INTO accounts(principal_id,station_id) VALUES($1,$2) ON CONFLICT(principal_id,station_id) DO UPDATE SET principal_id=EXCLUDED.principal_id RETURNING pk")
            .bind::<Text,_>(controller.principal_id.as_str()).bind::<Text,_>(controller.station_id.as_str())
            .get_result::<LocalAccount>(&mut conn).await.unwrap().pk;
        drop(conn);
        // Materialize the serving layer's local endpoint index from the same
        // accepted Agent PCR and runtime authorization used by the cut above.
        let mut record = coland_storage::AgentPrincipalRecord::new(
            agent.principal_id.to_string(),
            controller.principal_id.to_string(),
            genesis.event.realm_id.to_string(),
            arkret_wire::DidUrl::new(delegation.clone()).unwrap(),
            arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
            genesis.commit.committed_at,
        );
        record.controller_account_pk = Some(coland_storage::AccountPk(owner));
        record.authorized_event_ref = Some(key_event.event_id.to_string());
        record.authorized_verification_method = Some(method.to_string());
        record.authorized_key_event = Some(key_event.clone());
        let evidence = arkret_models_identity::authenticated_signer_resolution_evidence::build_agent_signer_evidence(
            agent.principal_id.clone(), method.clone(),
            serde_json::from_value(serde_json::json!({
                "kty":"OKP", "crv":"Ed25519", "x":arkret_canonical::base64url_encode(
                    ed25519_dalek::SigningKey::from_bytes(&[0x61;32]).verifying_key().as_bytes())
            })).unwrap(), key_commit.commit_id.clone(), key_commit.committed_at,
        ).unwrap();
        record.signer_resolution_evidence_ref = Some(evidence.signer_evidence_ref().unwrap());
        record.current_signer_evidence = Some(evidence);
        record.authorized_public_key_digest =
            Some(arkret_canonical::canonical_sha256(&key_event.payload["public_key"]).unwrap());

        coland_storage::AgentStore::put(
            &coland_storage_postgres::PgAgentStore { pool: pool.clone() },
            record,
        )
        .await
        .unwrap();
        let packages = coland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() };
        packages
            .put(&coland_storage::MlsKeyPackageRow {
                id: package.keypackage_id.clone(),
                keypackage_ref: package.keypackage_ref.to_string(),
                keypackage_digest: package.keypackage_ref.to_string(),
                owner_account_pk: coland_storage::AccountPk(owner),
                actor_id: agent.principal_id.to_string(),
                device_id: None,
                endpoint_verification_method: Some(method.to_string()),
                key_package_bytes: arkret_canonical::base64url_decode(&package.keypackage).unwrap(),
                capabilities: package.capabilities.clone(),
                capabilities_digest: arkret_canonical::canonical_sha256(&package.capabilities).unwrap(),
                last_resort: false,
                last_resort_realm_id: None,
                lifetime_not_before: now.timestamp() - 1,
                lifetime_not_after: now.timestamp() + 3600,
                claimed_by_mls_group_id: None,
                device_authorize_event_id: None,
                agent_key_authorize_event_id: Some(key_event.event_id.to_string()),
                claimed_at: None,
                claim_expires_at_unix_ms: None,
                consumed_at: None,
                created_at: now.timestamp(),
            })
            .await
            .unwrap();
        let claim_id = arkret_wire::KeypackageClaimId::new(format!(
            "ak:keypackage_claim:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap();
        let request_id =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([39; 32])).unwrap();
        let claim_outcome = sidecar_readiness::claim_outcome(
            &station_did,
            &package,
            &claim_id,
            &request_id,
            controller,
            &agent,
            &method,
            &key_event.event_id,
            &scope,
            now,
        );
        let ledger = coland_storage::PeerKeyPackageClaimLedgerRecord {
            source_id: controller.station_id.to_string(),
            claim_request_id: request_id.to_string(),
            request_digest: format!("sha256:{}", "6".repeat(64)),
            key_package_use: "single_use".into(),
            keypackage_id: Some(package.keypackage_id.clone()),
            outcome: Some(serde_json::to_value(&claim_outcome).unwrap()),
            terminal_receipt: None,
            consume_receipt: None,
            claim_expires_at_unix_ms: Some(now.timestamp_millis() + 3_000_000),
            expires_at: now.timestamp() + 86400,
            state: "claimed".into(),
            updated_at: now.timestamp(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
        assert!(matches!(
            packages
                .try_claim_peer(coland_storage::PeerKeyPackageClaimAttempt {
                    keypackage_id: &package.keypackage_id,
                    mls_group_id: group_id.as_str(),
                    device_authorize_event_id: None,
                    agent_key_authorize_event_id: Some(key_event.event_id.as_str()),
                    device_revocation_gate: None,
                    claimed_at_unix_ms: now.timestamp_millis(),
                    claim_expires_at_unix_ms: now.timestamp_millis() + 3_000_000,
                    ledger: &ledger,
                })
                .await
                .unwrap(),
            coland_storage::PeerKeyPackageClaimAttemptResult::Claimed(_)
        ));
        package.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
        package.claim_id = Some(claim_id.to_string());
        let groups = coland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() };
        let base = groups.current(&scope).await.unwrap().unwrap().value;
        let binding = MlsGovernanceBindingPayload::sidecar(
            realm_id.clone(),
            sidecar.clone(),
            Some(base.current_mls_commit_event_ref.clone()),
            base.epoch,
            base.epoch + 1,
            0,
            cut.participant_authority_digest.clone(),
            cut.authority_stream_head.clone(),
        )
        .unwrap();
        let add = group
            .add_member_with_governance_binding(&package, &binding)
            .unwrap();
        let transition = tracker
            .process_public_handshake(&arkret_canonical::base64url_decode(&add.commit.commit).unwrap())
            .unwrap();
        let arkret_mls::MlsPublicHandshakeTransition::Commit {
            consumed_proposals, ..
        } = transition
        else {
            panic!("real Add required")
        };
        let event = device_authorization_history::sign_event(
            ordinary_realm::event_for_actor(
                EventKind::MlsCommit,
                scope.clone(),
                ActorId::account(controller.clone()),
                serde_json::to_value(
                    arkret_models_crypto::MlsCommitPayload::new(
                        base.current_mls_commit_event_ref.clone(),
                        base.current_key_access_revision,
                        &add.commit,
                        binding,
                    )
                    .unwrap(),
                )
                .unwrap(),
                head.commit.committed_at,
            ),
            principal.history.device_verification_method.clone(),
            principal.history.founding_device_signing_seed,
        );
        let mut request = ordinary_realm::request_for_event(&head, event, head.commit.committed_at);
        request.authority_commit.commit.stream_ref = head.commit.stream_ref.clone();
        request.authority_commit.commit.stream_position = head.commit.stream_position + 1;
        request.authority_commit.commit.previous_commit_ref = Some(head.commit.commit_id.clone());
        let tree = tracker.ratchet_tree_bytes().unwrap();
        let sha256 = arkret_canonical::sha256_digest(&tree)
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned();
        let leaf = |l: arkret_mls::MlsPublicEndpointLeaf| coland_storage::MlsProposalLeafProvenance {
            leaf_index: l.leaf_index,
            actor_id: l.actor_id,
            signature_key: l.signature_key,
        };
        request.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
            effective_scope: scope.clone(),
            base: Some(coland_storage::MlsInstalledBase {
                current_mls_commit_event_ref: base.current_mls_commit_event_ref.clone(),
                epoch: base.epoch,
            }),
            epoch: base.epoch + 1,
            public_state: tracker.export_state().unwrap(),
            member_principals: tracker
                .leaves()
                .unwrap()
                .into_iter()
                .map(|l| l.actor_id)
                .collect(),
            consumed_proposals: consumed_proposals
                .into_iter()
                .map(|p| coland_storage::MlsConsumedProposalInstallation {
                    ordinal: p.ordinal,
                    proposal_ref: p.proposal_ref,
                    proposal_type: p.proposal_type,
                    proposal_wire: p.proposal_wire,
                    sender_leaf: leaf(p.sender_leaf),
                    target_before: p.target_before.map(leaf),
                    target_after: p.target_after.map(leaf),
                })
                .collect(),
            public_blobs: vec![coland_storage::MlsPublicBlob {
                blob_ref: arkret_wire::BlobRef::new(format!("ak:blob:sha256:{sha256}")).unwrap(),
                size_bytes: tree.len() as i64,
                storage_backend: "local".into(),
                storage_key: format!("sha256/{sha256}"),
                sha256,
            }],
        });
        let placeholder = arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: principal.history.device_verification_method.clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: now,
            sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
        };
        let mut delivery = arkret_wire::MlsWelcomeDelivery {
            welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
                "ak:mls_welcome_delivery:{}",
                uuid::Uuid::now_v7()
            ))
            .unwrap(),
            realm_id: realm_id.clone(),
            effective_scope: scope.clone(),
            commit_event_ref: request.authority_commit.event.event_id.clone(),
            recipient_actor_id: actor,
            recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: method.clone(),
            },
            keypackage_claim_ref: claim_id.clone(),
            ciphertext_b64: add.welcome.ciphertext_b64,
            producer_proof: placeholder,
        };
        let mut unsigned = serde_json::to_value(&delivery).unwrap();
        unsigned.as_object_mut().unwrap().remove("producer_proof");
        delivery.producer_proof = arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            principal.history.device_verification_method.clone(),
            now,
            &ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed),
        )
        .unwrap();
        request.authority_commit.welcomes = vec![coland_storage::VerifiedMlsWelcome {
            delivery: delivery.clone(),
            claim: Some(coland_storage::MlsWelcomeClaimLedgerKey {
                source_id: ledger.source_id.clone(),
                claim_request_id: ledger.claim_request_id.clone(),
                request_digest: ledger.request_digest.clone(),
            }),
            roster_witness: Some(sidecar_readiness::add_witness(
                claim_outcome,
                &delivery,
                &base,
                request.authority_commit.commit.stream_position,
                tracker
                    .leaves()
                    .unwrap()
                    .into_iter()
                    .find(|l| l.actor_id == arkret_wire::ActorId::account(agent.clone()))
                    .unwrap()
                    .signature_key,
                resolution,
            )),
        }];
        request.authority_commit.recipient_queue_capacity = 8;
        source_candidate(&pool, &mut request).await;
        let request = ordinary_realm::source_request(&pool, request).await;
        uow.commit_event(request.clone()).await.unwrap();
        let accepted = arkret_wire::CommittedEventFullView {
            event: request.authority_commit.event.clone(),
            commit: request.authority_commit.commit.clone(),
        };
        // Preserve the complete already-accepted MLS submission separately from
        // canonical installation. This storage regression uses the actual accepted
        // Add and its real Welcome; it does not assert peer HTTP authorization.
        {
            use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
            let origin_database = TestDatabase::lease().await;
            let origin_pool = origin_database.pool();
            let origin = PgAuthorityCommitStore {
                pool: origin_pool.clone(),
            };
            let submission = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
                commit_event: accepted.event.clone(),
                welcomes: vec![delivery.clone()],
                idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
            });
            submission.validate().unwrap();
            origin
                .queue_event(&accepted.event, accepted.commit.committed_at)
                .await
                .unwrap();
            origin
                .retain_forwarded_submission(&accepted.event, &submission, accepted.commit.committed_at)
                .await
                .unwrap();
            origin
                .retain_forwarded_acceptance(
                    &accepted.event,
                    &accepted.commit,
                    accepted.commit.committed_at,
                )
                .await
                .unwrap();
            drop(origin);
            let reopened = PgAuthorityCommitStore {
                pool: origin_pool.clone(),
            };
            let retained = reopened
                .queued_event(&accepted.event.event_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(retained.status, coland_storage::QueuedEventStatus::Queued);
            assert!(retained.committed.is_none());
            let attempt = retained.forward_attempt.unwrap();
            assert_eq!(attempt.original_submission, Some(submission.clone()));
            assert_eq!(attempt.accepted_commit, Some(accepted.commit.clone()));
            assert_eq!(
                attempt.status,
                coland_storage::ForwardAttemptStatus::Forwarding
            );
            for alter_welcome in [true, false] {
                let mut changed = submission.clone();
                let SelfAuthoritySubmitRequest::MlsCommit(ref mut value) = changed else {
                    unreachable!()
                };
                if alter_welcome {
                    // Validly shaped but different complete Welcome bytes must not
                    // replace the frozen request, even when its Event is identical.
                    value.welcomes[0].ciphertext_b64 = arkret_wire::Base64UrlString::new("AQ").unwrap();
                    let mut unsigned = serde_json::to_value(&value.welcomes[0]).unwrap();
                    unsigned.as_object_mut().unwrap().remove("producer_proof");
                    value.welcomes[0].producer_proof =
                        arkret_signatures::detached_object::sign_detached_object(
                            &unsigned,
                            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
                            principal.history.device_verification_method.clone(),
                            value.welcomes[0].producer_proof.created_at,
                            &ed25519_dalek::SigningKey::from_bytes(
                                &principal.history.founding_device_signing_seed,
                            ),
                        )
                        .unwrap();
                } else {
                    value.idempotency_key = arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap();
                }
                changed.validate().unwrap();
                let error = reopened
                    .retain_forwarded_submission(
                        &accepted.event,
                        &changed,
                        accepted.commit.committed_at,
                    )
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.conflict_code(),
                    Some(coland_storage::ConflictCode::DuplicateConflict)
                );
                assert_eq!(
                    reopened
                        .queued_event(&accepted.event.event_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .forward_attempt,
                    Some(attempt.clone())
                );
            }
            assert!(
                reopened
                    .committed_event(&accepted.event.event_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            #[derive(diesel::QueryableByName)]
            struct ForwardOnlyFootprint {
                #[diesel(sql_type = diesel::sql_types::BigInt)]
                installed: i64,
            }
            let mut conn = origin_pool.get().await.unwrap();
            use diesel_async::RunQueryDsl;
            let footprint = diesel::sql_query("SELECT (SELECT count(*) FROM realm_commits) + (SELECT count(*) FROM realm_authorities) + (SELECT count(*) FROM replica_stream_anchors) + (SELECT count(*) FROM replica_authorization_cuts) + (SELECT count(*) FROM replica_authorization_rows) + (SELECT count(*) FROM current_result_heads) + (SELECT count(*) FROM realm_state_snapshots) + (SELECT count(*) FROM member_state_current_results) + (SELECT count(*) FROM agent_producer_signer_keys) + (SELECT count(*) FROM federation_outbox) AS installed")
                .get_result::<ForwardOnlyFootprint>(&mut *conn).await.unwrap();
            assert_eq!(footprint.installed, 0);
        }
        group.install_accepted_commit(&accepted, &base).unwrap();
        let mut recipient_group = arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
            identity, &delivery, &accepted,
        )
        .unwrap();
        let device_authorization = principal
            .history
            .events
            .iter()
            .find(|e| e.kind == EventKind::DeviceAuthorize)
            .unwrap();
        let bindings = tracker
            .leaves()
            .unwrap()
            .into_iter()
            .map(|l| {
                let is_controller = l.actor_id == ActorId::account(controller.clone());
                arkret_mls::MlsVerifiedLeafBinding {
                    leaf_index: l.leaf_index,
                    actor_id: l.actor_id,
                    signature_key: l.signature_key,
                    endpoint: if is_controller {
                        arkret_models_crypto::MlsEndpointIdentity::human_device(
                            controller.principal_id.clone(),
                            principal.history.founding_device_id.clone(),
                        )
                    } else {
                        arkret_models_crypto::MlsEndpointIdentity::agent_runtime(
                            agent.principal_id.clone(),
                            method.clone(),
                            key_event.event_id.clone(),
                        )
                        .unwrap()
                    },
                    device_authorize_event_id: is_controller
                        .then(|| device_authorization.event_id.clone()),
                }
            })
            .collect();
        recipient_group
            .install_verified_leaf_bindings(bindings)
            .unwrap();
        assert_eq!(
            recipient_group.export_state_record().unwrap().epoch,
            base.epoch + 1
        );
        let status = || {
            store.sidecar_access_cut(
                realm_id,
                &sidecar,
                controller,
                &principal.history.founding_device_id,
            )
        };
        assert!(
            status().await.unwrap().unwrap().1.is_empty(),
            "Add without durable consume stays pending"
        );
        let durable = recipient_group
            .identity()
            .sign_recipient_mls_durable_receipt(RecipientMlsDurableReceipt {
                domain: arkret_wire::NonEmptyString::new(
                    arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1,
                )
                .unwrap(),
                claim_request_id: request_id,
                key_package_ref: arkret_wire::NonEmptyString::new(package.keypackage_ref.to_string())
                    .unwrap(),
                recipient: RecipientMlsDurableSigner::Agent {
                    recipient_agent_id: agent.principal_id.clone(),
                    recipient_agent_verification_method: method.clone(),
                    agent_key_authorize_event_id: key_event.event_id.clone(),
                },
                recipient_id: controller.station_id.clone(),
                realm_id: realm_id.clone(),
                mls_group_id: group_id.clone(),
                mls_epoch: base.epoch + 1,
                welcome_ref: delivery.welcome_id.clone(),
                welcome_digest: delivery.durable_receipt_digest().unwrap(),
                durable_at: now,
                signature: KeyOperationSignature {
                    kid: arkret_wire::NonEmptyString::new(method.to_string()).unwrap(),
                    signature_algorithm: None,
                    sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
                },
            })
            .unwrap();
        let consume = recipient_group
            .identity()
            .signed_key_packages_consume_request(claim_id.clone(), durable.clone())
            .unwrap();
        let mut receipt = KeyPackageConsumeReceipt {
            domain: arkret_wire::NonEmptyString::new(
                arkret_wire::DomainSeparationId::KEYPACKAGE_CONSUME_RECEIPT_V1,
            )
            .unwrap(),
            request_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(&consume.unsigned()).unwrap(),
            )
            .unwrap(),
            claim_id,
            recipient_durable_receipt: durable,
            consumed_at: now,
            signature: KeyOperationSignature {
                kid: arkret_wire::NonEmptyString::new(format!("{station_did}#authority")).unwrap(),
                signature_algorithm: None,
                sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
            },
        };
        use ed25519_dalek::Signer;
        receipt.signature.sig = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&[83; 32])
                .sign(&receipt.canonical_signing_bytes().unwrap())
                .to_bytes(),
        ))
        .unwrap();
        assert_ne!(receipt.request_digest.as_str(), ledger.request_digest);
        let receipt_json = serde_json::to_value(&receipt).unwrap();
        packages
            .consume_claim(
                &package.keypackage_id,
                group_id.as_str(),
                now.timestamp_millis(),
                Some(&receipt_json),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            status().await.unwrap().unwrap().1,
            vec![agent.principal_id.clone()]
        );
        let mut conn = pool.get().await.unwrap();
        for (label, mutation) in [
            (
                "owner Station",
                "station_id='ak:did_core:web:wrong-sidecar-owner.example'",
            ),
            (
                "owner principal",
                "principal_id='ak:did_core:web:wrong-sidecar-owner.example'",
            ),
        ] {
            diesel::sql_query(format!("UPDATE accounts SET {mutation} WHERE pk=$1"))
                .bind::<BigInt, _>(owner)
                .execute(&mut conn)
                .await
                .unwrap();
            drop(conn);
            assert!(status().await.unwrap().unwrap().1.is_empty(), "{label}");
            conn = pool.get().await.unwrap();
            diesel::sql_query("UPDATE accounts SET principal_id=$2,station_id=$3 WHERE pk=$1")
                .bind::<BigInt, _>(owner)
                .bind::<Text, _>(controller.principal_id.as_str())
                .bind::<Text, _>(controller.station_id.as_str())
                .execute(&mut conn)
                .await
                .unwrap();
        }
        let mut wrong_digest = receipt_json.clone();
        wrong_digest["request_digest"] = serde_json::json!(ledger.request_digest);
        diesel::sql_query("UPDATE peer_keypackage_claims SET consume_receipt=$1 WHERE source_id=$2 AND claim_request_id=$3")
            .bind::<Jsonb,_>(wrong_digest).bind::<Text,_>(&ledger.source_id).bind::<Text,_>(&ledger.claim_request_id).execute(&mut conn).await.unwrap();
        drop(conn);
        assert!(
            status().await.unwrap().unwrap().1.is_empty(),
            "claim digest cannot stand in for consume digest"
        );
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("UPDATE peer_keypackage_claims SET consume_receipt=$1 WHERE source_id=$2 AND claim_request_id=$3")
            .bind::<Jsonb,_>(receipt_json).bind::<Text,_>(&ledger.source_id).bind::<Text,_>(&ledger.claim_request_id).execute(&mut conn).await.unwrap();
        drop(conn);
        assert_eq!(
            status().await.unwrap().unwrap().1,
            vec![agent.principal_id.clone()]
        );
        sidecar_exchange_controls::assert_current(
            &pool,
            &principal,
            &sidecar,
            &request.authority_commit,
            &mut group,
            &agent.principal_id,
        )
        .await;
        (request, group, recipient_group)
    })
        .await;
    Box::pin(
        sidecar_post_tree_rejects_stale_endpoint_and_paused_self_update(
            &pool,
            &principal,
            &agent,
            &agent_did,
            &genesis,
            &key_event,
            &key_commit,
            &request.authority_commit,
            &sidecar,
            &mut group,
            &mut recipient_group,
        ),
    )
    .await;
}

#[tokio::test]
async fn sidecar_snapshot_lists_and_scans_keep_private_stream_coordinates() {
    use arkret_wire::{ActorId, CommitStreamRef, StreamScanDirection, StreamScanRequest};
    use coland_storage::{AccountRealmStreamList, AccountStreamScan};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station = historical_control_source::HistoricalControlStation::new(
        "sidecar-native-control",
        [83; 32],
    );
    let station = historical_station.core.clone();
    let did = historical_station.did.clone();
    let principal = accepted_controller(&pool, did.clone()).await;
    let controller = &principal.history.account;
    let unit =
        ordinary_realm::bootstrap_unit_for_account("sidecar-stream-disclosure", controller, &did);
    let unit = ordinary_realm::source_bootstrap(&pool, unit).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = unit.transactions.last().unwrap();
    let realm = parent.event.realm_id.clone();
    let actor = ActorId::account(controller.clone());
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = ordinary_realm::next_request(
        parent,
        EventKind::StrandCreate,
        &controller.principal_id,
        serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Sidecar source"},
            "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(parent.commit.committed_at)}}),
        parent.commit.committed_at,
    );
    let strand = ordinary_realm::source_request(&pool, strand).await;
    uow.commit_event(strand.clone()).await.unwrap();
    let source = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let create = ordinary_realm::next_request(
        &strand.authority_commit,
        EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        parent.commit.committed_at,
    );
    let create = ordinary_realm::source_request(&pool, create).await;
    uow.commit_event(create.clone()).await.unwrap();
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let stream = CommitStreamRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let mut attach_event = ordinary_realm::event_for_actor(
        EventKind::SidecarContextAttach,
        arkret_wire::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        },
        actor.clone(),
        serde_json::json!({"sidecar_id":sidecar,"source_context_ref":{"kind":"strand","strand_id":source},"version":1}),
        parent.commit.committed_at,
    );
    attach_event.semantic_refs = vec![arkret_wire::SemanticRef::new(
        create.authority_commit.event.event_id.to_string(),
        "after",
    )];
    ordinary_realm::reseal(&mut attach_event);
    let mut attach = ordinary_realm::request_for_event(
        &create.authority_commit,
        attach_event,
        parent.commit.committed_at,
    );
    attach.authority_commit.commit.stream_ref = stream.clone();
    attach.authority_commit.commit.stream_position = 0;
    attach.authority_commit.commit.previous_commit_ref = None;
    let attach = ordinary_realm::source_request(&pool, attach).await;
    uow.commit_event(attach.clone()).await.unwrap();
    let foreign = AccountId::new(
        controller.principal_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:sidecar-foreign.example").unwrap(),
    );
    let mut join = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::MemberState,
        ActorId::account(foreign.clone()),
        serde_json::json!({"member_id":ActorId::account(foreign.clone()),"membership":"join"}),
        parent.commit.committed_at,
    );
    join.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        join.authority_commit.event.clone(),
    ));
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    let snapshot = store
        .realm_state_snapshot_material_for_account(&realm, controller)
        .await
        .unwrap()
        .unwrap();
    let foreign_snapshot = store
        .realm_state_snapshot_material_for_account(&realm, &foreign)
        .await
        .unwrap()
        .unwrap();
    assert!(
        snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == stream
                && head.stream_position == 0
                && head.commit_id == attach.authority_commit.commit.commit_id)
    );
    assert!(
        snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| floor.stream_ref == stream && floor.oldest_position == 0)
    );
    assert!(snapshot.current_state_entries.iter().any(|row| matches!(row, arkret_wire::TypedCurrentRow::Value {selector:arkret_wire::CurrentSelector::SidecarContext {sidecar_id,..},source_stream_ref,revision,..} if sidecar_id == &sidecar && source_stream_ref == &stream && revision.stream_position == 0)));
    assert!(
        !foreign_snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == stream)
    );
    assert!(
        !foreign_snapshot
            .current_state_entries
            .iter()
            .any(|row| matches!(
                row,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::Sidecar { .. }
                        | arkret_wire::CurrentSelector::SidecarContext { .. },
                    ..
                }
            ))
    );
    let AccountRealmStreamList::Listed(streams) = store
        .list_realm_streams_for_account(&realm, controller, &station)
        .await
        .unwrap()
    else {
        panic!("controller streams must be proved")
    };
    assert!(
        streams
            .iter()
            .any(|row| row.stream_ref == stream && row.next_position == 1)
    );
    for direction in [
        StreamScanDirection::After(None),
        StreamScanDirection::Before(None),
    ] {
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction,
            limit: 1,
        };
        let AccountStreamScan::Page(page) = store
            .scan_stream_for_account(&request, controller, &station)
            .await
            .unwrap()
        else {
            panic!("controller scan must be served")
        };
        page.validate_for_request(&request).unwrap();
        assert_eq!(page.committed_events.len(), 1);
        assert_eq!(
            page.committed_events[0].commit(),
            &attach.authority_commit.commit
        );
        assert!(matches!(
            store
                .scan_stream_for_account(&request, &foreign, &station)
                .await
                .unwrap(),
            AccountStreamScan::NotAuthorized
        ));
        let coland_storage::PeerStreamScan::Page(peer) = store
            .scan_stream_for_peer(&request, &station, &station)
            .await
            .unwrap()
        else {
            panic!("controller Station's peer scan must be served")
        };
        peer.validate_for_request(&request).unwrap();
        assert_eq!(
            peer.committed_events[0].commit(),
            &attach.authority_commit.commit
        );
        assert!(matches!(
            store
                .scan_stream_for_peer(&request, &foreign.station_id, &station)
                .await
                .unwrap(),
            coland_storage::PeerStreamScan::NotAuthorized
        ));
    }
}

async fn provision_owned_agent(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
) -> (
    arkret_wire::AccountId,
    coland_storage::AuthorityCommitTransaction,
    arkret_wire::EventId,
) {
    let agent_did = historical_control_source::managed_agent_did(
        &principal.history.account.principal_id,
        "sidecar-agent",
        principal.unit.transactions[1].commit.committed_at,
    );
    provision_owned_agent_with_did(pool, principal, agent_did).await
}

async fn provision_owned_agent_with_did(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent_did: arkret_wire::Did,
) -> (
    arkret_wire::AccountId,
    coland_storage::AuthorityCommitTransaction,
    arkret_wire::EventId,
) {
    use arkret_wire::{ActorId, RealmId};
    use coland_storage::{
        ActorProfileStore, AgentPcrGenesisAdmissionWrite, AgentProvisionAdmissionWrite,
        AuthorityCommitTransaction, CurrentRealmAuthority,
    };
    let controller = principal.history.account.clone();
    let station = controller.station_id.clone();
    let station_did = principal.history.station_did.clone();
    let controller_realm = principal.unit.transactions[0].event.realm_id.clone();
    let controller_head = principal.unit.transactions[1].commit.clone();
    let controller_authority = principal.unit.transactions[1].expected_authority.clone();
    let controller_method = principal.history.device_verification_method.clone();
    let controller_seed = principal.history.founding_device_signing_seed;
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let agent = AccountId::new(agent_id.clone(), station.clone());
    let delegation = format!("{agent_did}#managed-controller");
    let genesis = device_authorization_history::sign_event(
        arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
            payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                agent_id: agent_id.clone(),
                governance_station_id: station.clone(),
                initial_resolution: arkret_models_identity::ResolutionCommitment {
                    did: agent_did.clone(),
                    method_history_head: format!("sha256:{}", "c".repeat(64)),
                    version_id: "1-agent".to_owned(),
                },
                genesis_salt: arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                )
                .unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new(
                    "ak:trust_domain:pcr-contract.example".to_owned(),
                )
                .unwrap(),
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
            },
            executed_by: ActorId::account(controller.clone()),
            authorization_ref: arkret_wire::AuthorizationRef::new(delegation.clone()).unwrap(),
            created_at: controller_head.committed_at,
        })
        .unwrap()
        .into_event(),
        controller_method.clone(),
        controller_seed,
    );
    let agent_pcr = RealmId::from_event_id(&genesis.event_id);
    let provision = sidecar_agent::agent_provision_event(
        &controller,
        &controller_realm,
        &controller_method,
        controller_seed,
        &agent_id,
        &agent_pcr,
        &delegation,
        controller_head.committed_at,
    );
    let provision_commit =
        sidecar_agent::station_successor(&controller_head, &provision, &station_did, 1);
    let transaction =
        |authority: CurrentRealmAuthority,
         event: arkret_wire::Event,
         commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority,
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
    profiles
        .admit_agent_provision(AgentProvisionAdmissionWrite {
            commit: transaction(
                controller_authority,
                provision.clone(),
                provision_commit.clone(),
            ),
            queued_at: provision_commit.committed_at,
        })
        .await
        .unwrap();
    let genesis_commit = sidecar_agent::station_genesis_commit(
        &controller_head,
        &genesis,
        &station_did,
        provision_commit.committed_at + chrono::TimeDelta::seconds(1),
    );
    historical_control_source::admit_genesis(
        &profiles,
        &pool,
        AgentPcrGenesisAdmissionWrite {
            commit: transaction(
                CurrentRealmAuthority {
                    realm_id: agent_pcr.clone(),
                    generation: 0,
                    service_id: station.clone(),
                    authority_ref: genesis_commit.authority_ref.clone(),
                    last_handoff_ref: None,
                },
                genesis.clone(),
                genesis_commit.clone(),
            ),
            queued_at: genesis_commit.committed_at,
        },
    )
    .await
    .unwrap();

    (
        agent,
        transaction(
            CurrentRealmAuthority {
                realm_id: agent_pcr,
                generation: 0,
                service_id: station,
                authority_ref: genesis_commit.authority_ref.clone(),
                last_handoff_ref: None,
            },
            genesis,
            genesis_commit,
        ),
        provision.event_id,
    )
}

/// Storage admission only: accepted controller/Agent units are real; RFC
/// verification and publication signatures are covered by HTTP/MLS suites.
#[tokio::test]
async fn ordinary_member_can_join_own_agent_without_permission_to_add_humans() {
    use diesel::sql_types::{Bool, Text};
    use diesel_async::RunQueryDsl;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = historical_control_source::HistoricalControlStation::new(
        "sidecar-native-control",
        [83; 32],
    );
    let principal = accepted_controller(&pool, station.did.clone()).await;
    let controller = &principal.history.account;
    let founder = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        station.did.clone(),
        "agent-self-add-founder",
    )
    .await;
    let realm = ordinary_realm::bootstrap_unit_with_history_for_account(
        "ordinary-member-agent-self-add",
        "public",
        "since_join",
        &founder,
        &station.did,
    );
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let member_join = ordinary_realm::next_request_for_actor(
        parent,
        EventKind::MemberState,
        arkret_wire::ActorId::account(controller.clone()),
        serde_json::json!({"member_id":arkret_wire::ActorId::account(controller.clone()),"membership":"join"}),
        parent.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let member_join = ordinary_realm::source_request(&pool, member_join).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(member_join.clone()).await.unwrap();
    let outsider = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        station.did.clone(),
        "agent-self-add-human-target",
    )
    .await;
    let human_add = ordinary_realm::next_request_for_actor(
        &member_join.authority_commit,
        EventKind::MemberState,
        arkret_wire::ActorId::account(controller.clone()),
        serde_json::json!({"member_id":arkret_wire::ActorId::account(outsider.clone()),"membership":"join"}),
        member_join.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let human_add = ordinary_realm::source_request(&pool, human_add).await;
    let error = uow.commit_event(human_add).await.unwrap_err();
    assert!(
        error.to_string().contains("only the target itself"),
        "{error}"
    );
    let (agent, genesis, _) = provision_owned_agent(&pool, &principal).await;
    let agent_join = ordinary_realm::next_request_for_actor(
        &member_join.authority_commit,
        EventKind::MemberState,
        arkret_wire::ActorId::account(controller.clone()),
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,
            "controller_membership_generation_ref":member_join.authority_commit.event.event_id}}),
        genesis
            .commit
            .committed_at
            .max(member_join.authority_commit.commit.committed_at)
            + chrono::TimeDelta::milliseconds(1),
    );
    let agent_join = ordinary_realm::source_request(&pool, agent_join).await;
    uow.commit_event(agent_join).await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct ResultRow {
        #[diesel(sql_type = Bool)]
        correct: bool,
    }
    let mut conn = pool.get().await.unwrap();
    let result = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2 AND membership='join') \
         AND NOT EXISTS(SELECT 1 FROM member_state_current_results WHERE realm_id=$1 AND member_id=$3) \
         AND NOT EXISTS(SELECT 1 FROM capability_grant_current_results WHERE realm_id=$1) AS correct",
    )
    .bind::<Text, _>(parent.event.realm_id.as_str())
    .bind::<Text, _>(arkret_wire::ActorId::account(agent).to_string())
    .bind::<Text, _>(arkret_wire::ActorId::account(outsider).to_string())
    .get_result::<ResultRow>(&mut *conn)
    .await
    .unwrap();
    assert!(result.correct);
}

/// Storage admission only: accepted controller/Agent units are real; RFC
/// verification and publication signatures are covered by HTTP/MLS suites.
#[tokio::test]
async fn administrator_can_remove_agent_without_controller_join_binding() {
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = historical_control_source::HistoricalControlStation::new(
        "sidecar-native-control",
        [83; 32],
    );
    let principal = accepted_controller(&pool, station.did.clone()).await;
    let controller = &principal.history.account;
    let realm = ordinary_realm::bootstrap_unit_for_account(
        "administrator-agent-removal",
        controller,
        &station.did,
    );
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let (agent, genesis, _) = provision_owned_agent(&pool, &principal).await;
    let join = ordinary_realm::next_request(
        parent,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),
            "membership":"join","agent_controller_binding":{
                "controller_account_id":controller,
                "controller_membership_generation_ref":parent.event.event_id}}),
        genesis.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(join.clone()).await.unwrap();
    let outsider = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        station.did.clone(),
        "agent-removal-outsider",
    )
    .await;
    let outsider_join = ordinary_realm::next_request_for_actor(
        &join.authority_commit,
        EventKind::MemberState,
        arkret_wire::ActorId::account(outsider.clone()),
        serde_json::json!({"member_id":arkret_wire::ActorId::account(outsider.clone()),"membership":"join"}),
        join.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let outsider_join = ordinary_realm::source_request(&pool, outsider_join).await;
    uow.commit_event(outsider_join.clone()).await.unwrap();
    let unauthorized_leave = ordinary_realm::next_request_for_actor(
        &outsider_join.authority_commit,
        EventKind::MemberState,
        arkret_wire::ActorId::account(outsider),
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"leave"}),
        outsider_join.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let unauthorized_leave = ordinary_realm::source_request(&pool, unauthorized_leave).await;
    let error = uow.commit_event(unauthorized_leave).await.unwrap_err();
    assert!(error.to_string().contains("capability_denied"));
    let leave = ordinary_realm::next_request(
        &outsider_join.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"leave"}),
        outsider_join.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let leave = ordinary_realm::source_request(&pool, leave).await;
    uow.commit_event(leave).await.unwrap();

    #[derive(diesel::QueryableByName)]
    struct MembershipRow {
        #[diesel(sql_type = Text)]
        membership: String,
    }
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT membership FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(parent.event.realm_id.as_str())
    .bind::<Text, _>(arkret_wire::ActorId::account(agent).to_string())
    .get_result::<MembershipRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(row.membership, "leave");
}

#[tokio::test]
async fn encrypted_agent_join_rechecks_claimability_and_writes_nothing_on_refusal() {
    use coland_storage::{AgentControlAdmissionWrite, MlsKeyPackageStore};
    use diesel::sql_types::{BigInt, Text};
    use diesel_async::RunQueryDsl;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station = historical_control_source::HistoricalControlStation::new(
        "sidecar-native-control",
        [83; 32],
    );
    let station_did = historical_station.did.clone();
    let principal = accepted_controller(&pool, station_did.clone()).await;
    let controller = &principal.history.account;
    let realm = ordinary_realm::bootstrap_unit_with_history_for_account(
        "agent-mls-join",
        "invite",
        "since_join",
        controller,
        &station_did,
    );
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let realm_id = &parent.event.realm_id;
    let (agent, genesis, _) = provision_owned_agent(&pool, &principal).await;
    let original_genesis: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.event.payload).unwrap()).unwrap();
    let agent_did = original_genesis.object.initial_resolution.unwrap().did;
    let delegation = format!("{agent_did}#managed-controller");
    let key_event = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        &agent,
        &genesis.event.realm_id,
        &delegation,
        sidecar_agent::agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            genesis.commit.committed_at,
        ),
        genesis.commit.committed_at,
    );
    let key_commit = sidecar_agent::station_successor(&genesis.commit, &key_event, &station_did, 1);
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    historical_control_source::admit_control(
        &profiles,
        &pool,
        AgentControlAdmissionWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: genesis.expected_authority.clone(),
                event: key_event.clone(),
                commit: key_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: key_commit.committed_at,
        },
    )
    .await
    .unwrap();

    let at = key_commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let mut group = ordinary_realm::next_request(
        parent,
        EventKind::MlsGenesis,
        &controller.principal_id,
        serde_json::json!({
            "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref":format!("ak:blob:sha256:{}", "3".repeat(64)),
            "ratchet_tree_ref":format!("ak:blob:sha256:{}", "4".repeat(64)),
            "creator_leaf_authority":{
                "leaf_signature_key_b64u":arkret_canonical::base64url_encode(
                    ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed).verifying_key().as_bytes()),
                "endpoint":{"kind":"device","device_id":principal.history.founding_device_id},
                "authorization_event_ref":principal.unit.transactions[1].event.event_id
            },
            "governance_binding":arkret_models_crypto::MlsGovernanceBindingPayload::realm(realm_id.clone(),None,0,0,0).unwrap(),
            "created_at":arkret_canonical::format_timestamp_canonical(at)
        }),
        at,
    );
    // The storage boundary consumes an already verified installation, just
    // as the founding-unit storage matrix does. No RFC verification is claimed.
    group.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
        effective_scope: group.authority_commit.event.scope_ref.clone(),
        base: None,
        epoch: 0,
        public_state: b"storage-verified-public-state".to_vec(),
        member_principals: std::collections::BTreeSet::from([arkret_wire::ActorId::account(
            controller.clone(),
        )]),
        consumed_proposals: Vec::new(),
        public_blobs: Vec::new(),
    });
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let group = ordinary_realm::source_request(&pool, group).await;
    uow.commit_event(group.clone()).await.unwrap();
    let join = ordinary_realm::next_request(
        &group.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({
            "realm_id":realm_id,"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,
                "controller_membership_generation_ref":parent.event.event_id}
        }),
        at,
    );
    #[derive(diesel::QueryableByName, Debug, PartialEq)]
    struct Footprint {
        #[diesel(sql_type=BigInt)]
        events: i64,
        #[diesel(sql_type=BigInt)]
        commits: i64,
        #[diesel(sql_type=BigInt)]
        members: i64,
        #[diesel(sql_type=BigInt)]
        revision: i64,
        #[diesel(sql_type=BigInt)]
        covered: i64,
        #[diesel(sql_type=BigInt)]
        epoch: i64,
    }
    async fn footprint(
        pool: &coland_storage_postgres::PgPool,
        realm: &arkret_wire::RealmId,
    ) -> Footprint {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("SELECT (SELECT COUNT(*) FROM canonical_events) AS events, \
            (SELECT COUNT(*) FROM realm_commits) AS commits, \
            (SELECT COUNT(*) FROM member_state_current_results) AS members, \
            (SELECT (value->>'current_key_access_revision')::bigint FROM mls_group_current_results WHERE realm_id=$1) AS revision, \
            (SELECT (value->>'covered_key_access_revision')::bigint FROM mls_group_current_results WHERE realm_id=$1) AS covered, \
            (SELECT (value->>'epoch')::bigint FROM mls_group_current_results WHERE realm_id=$1) AS epoch")
            .bind::<Text,_>(realm.as_str()).get_result(&mut *conn).await.unwrap()
    }
    let before = footprint(&pool, realm_id).await;
    assert!(
        uow.commit_event(join.clone())
            .await
            .unwrap_err()
            .to_string()
            .contains("claimable membership KeyPackage")
    );
    assert_eq!(footprint(&pool, realm_id).await, before);
    #[derive(diesel::QueryableByName)]
    struct Account {
        #[diesel(sql_type=BigInt)]
        pk: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let wrong_owner=diesel::sql_query("INSERT INTO accounts(principal_id,station_id) VALUES($1,$2) \
        ON CONFLICT(principal_id,station_id) DO UPDATE SET principal_id=EXCLUDED.principal_id RETURNING pk")
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(agent.station_id.as_str())
        .get_result::<Account>(&mut *conn).await.unwrap().pk;
    let owner =
        diesel::sql_query("INSERT INTO accounts(principal_id,station_id) VALUES($1,$2) ON CONFLICT(principal_id,station_id) DO UPDATE SET principal_id=EXCLUDED.principal_id RETURNING pk")
            .bind::<Text, _>(controller.principal_id.as_str())
            .bind::<Text, _>(controller.station_id.as_str())
            .get_result::<Account>(&mut *conn)
            .await
            .unwrap()
            .pk;
    drop(conn);
    let packages = coland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() };
    let package = coland_storage::MlsKeyPackageRow {
        id: "agent-membership-package".into(),
        keypackage_ref: format!("sha256:{}", "7".repeat(64)),
        keypackage_digest: format!("sha256:{}", "7".repeat(64)),
        owner_account_pk: coland_storage::AccountPk(owner),
        actor_id: agent.principal_id.to_string(),
        device_id: None,
        endpoint_verification_method: Some(format!("{agent_did}#runtime-1")),
        key_package_bytes: b"verified-published-keypackage".to_vec(),
        capabilities: vec!["ak.content.v1".into(), "mimi.content.v1".into()],
        capabilities_digest: format!("sha256:{}", "8".repeat(64)),
        last_resort: false,
        last_resort_realm_id: None,
        lifetime_not_before: at.timestamp() - 1,
        lifetime_not_after: at.timestamp() + 3600,
        claimed_by_mls_group_id: None,
        device_authorize_event_id: None,
        agent_key_authorize_event_id: Some(key_event.event_id.to_string()),
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at: at.timestamp(),
    };
    packages.put(&package).await.unwrap();
    let mut mutations = vec![
        "lifetime_not_after=0",
        "claimed_by_mls_group_id='already-claimed',claimed_at=1,claim_expires_at_unix_ms=2",
        "capabilities='[]'::jsonb",
        "actor_id='ak:did_core:web:foreign-agent.example'",
        "agent_key_authorize_event_id=(SELECT id FROM canonical_events WHERE kind='ak.realm.create' ORDER BY pk LIMIT 1)",
        "endpoint_verification_method='did:web:wrong-agent.example#runtime-1'",
    ].into_iter().map(str::to_owned).collect::<Vec<_>>();
    mutations.push(format!("owner_account_pk={wrong_owner}"));
    for mutation in mutations {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(format!(
            "UPDATE mls_key_packages SET {mutation} WHERE id=$1"
        ))
        .bind::<Text, _>(&package.id)
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);
        let before = footprint(&pool, realm_id).await;
        assert!(
            uow.commit_event(join.clone()).await.is_err(),
            "mutation {mutation}"
        );
        assert_eq!(
            footprint(&pool, realm_id).await,
            before,
            "mutation {mutation}"
        );
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("DELETE FROM mls_key_packages WHERE id=$1")
            .bind::<Text, _>(&package.id)
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        packages.put(&package).await.unwrap();
    }
    let mut stale_payload = serde_json::to_value(&join.authority_commit.event.payload).unwrap();
    // A valid current KeyPackage does not revive an old controller generation.
    stale_payload["agent_controller_binding"]["controller_membership_generation_ref"] =
        serde_json::to_value(key_event.event_id.clone()).unwrap();
    let stale = ordinary_realm::next_request(
        &group.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        stale_payload,
        at,
    );
    let before = footprint(&pool, realm_id).await;
    assert!(uow.commit_event(stale).await.is_err());
    assert_eq!(footprint(&pool, realm_id).await, before);
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    let after = footprint(&pool, realm_id).await;
    assert_eq!(after.events, before.events + 1);
    assert_eq!(after.commits, before.commits + 1);
    assert_eq!(after.members, before.members + 1);
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.covered, before.covered);
    assert_eq!(after.epoch, before.epoch);
}

type AgentModeScenario = (
    TestDatabase,
    pcr_genesis::PcrGenesisFixture,
    AccountId,
    coland_storage::AuthorityCommitTransaction,
    arkret_wire::CurrentRevision,
    coland_storage::DeviceRevocationGateSelector,
);

fn agent_mode_request(
    previous: &coland_storage::AuthorityCommitTransaction,
    mode: &str,
    expected: Option<arkret_wire::CurrentRevision>,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent: &AccountId,
    guard: &coland_storage::DeviceRevocationGateSelector,
) -> coland_storage::EventCommitRequest {
    let controller = &principal.history.account;
    let payload = arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        agent_account_id: agent.clone(),
        controller_account_id: controller.clone(),
        interaction_mode: if mode == "public" {
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public
        } else {
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Private
        },
        expected_revision: expected,
    };
    let mut request = ordinary_realm::next_request(
        previous,
        EventKind::AgentInteractionSet,
        &controller.principal_id,
        serde_json::to_value(payload).unwrap(),
        previous.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    request.authority_commit.event = device_authorization_history::sign_event(
        request.authority_commit.event,
        principal.history.device_verification_method.clone(),
        principal.history.founding_device_signing_seed,
    );
    request = ordinary_realm::request_for_event(
        previous,
        request.authority_commit.event,
        previous.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        guard.clone(),
    ));
    request
}

#[tokio::test]
async fn agent_mode_controller_cas_preserves_derived_sidecar_roster() {
    let (database, principal, agent, initial, revision, guard) =
        boxed_agent_mode_controller_cas().await;
    let pool = database.pool();
    let make_mode = |previous: &coland_storage::AuthorityCommitTransaction,
                     mode: &str,
                     expected: Option<arkret_wire::CurrentRevision>| {
        agent_mode_request(previous, mode, expected, &principal, &agent, &guard)
    };
    Box::pin(agent_publish_policy_scenario(
        &pool,
        &principal.history.account,
        &agent,
        &initial,
        revision,
        &make_mode,
    ))
    .await;
}

// Construct the large scenario outside the harness Future's poll frame.
fn boxed_agent_mode_controller_cas() -> Pin<Box<dyn Future<Output = AgentModeScenario> + Send>> {
    Box::pin(agent_mode_controller_cas_scenario())
}

async fn agent_mode_footprint(
    pool: &coland_storage_postgres::PgPool,
    realm: &arkret_wire::RealmId,
) -> serde_json::Value {
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT jsonb_build_object( \
         'events', (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1), \
         'commits', (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1), \
         'facts', (SELECT COUNT(*) FROM agent_producer_signer_keys f JOIN realm_commits c ON c.commit_id=f.commit_id WHERE c.realm_id=$1), \
         'outbox', (SELECT COUNT(*) FROM event_federation_outbox o JOIN canonical_events e ON e.pk=o.event_pk WHERE e.realm_id=$1), \
         'authority', (SELECT to_jsonb(a) FROM realm_authorities a WHERE realm_id=$1), \
         'interaction', (SELECT COALESCE(jsonb_agg(to_jsonb(i) ORDER BY to_jsonb(i)::text),'[]'::jsonb) FROM agent_interaction_current_results i WHERE realm_id=$1), \
         'sidecar', (SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]'::jsonb) FROM sidecar_current_results s WHERE realm_id=$1), \
         'message_revision', (SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM message_revision_current_results r WHERE realm_id=$1), \
         'mls', (SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]'::jsonb) FROM mls_group_current_results m WHERE realm_id=$1) \
         ) AS value",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<Row>(&mut *conn)
    .await
    .unwrap()
    .value
}
async fn agent_mode_controller_cas_scenario() -> AgentModeScenario {
    use coland_storage::AgentControlAdmissionWrite;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station = historical_control_source::HistoricalControlStation::new(
        "sidecar-native-control",
        [83; 32],
    );
    let station_did = historical_station.did.clone();
    let principal = accepted_controller(&pool, station_did.clone()).await;
    let controller = &principal.history.account;
    let realm =
        ordinary_realm::bootstrap_unit_for_account("agent-mode-cas", controller, &station_did);
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let create = ordinary_realm::next_request(
        parent,
        EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        parent.commit.committed_at,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let create = ordinary_realm::source_request(&pool, create).await;
    uow.commit_event(create.clone()).await.unwrap();
    let realm_id = &create.authority_commit.event.realm_id;
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let endpoint = "https://sidecar-agent.example/".parse().unwrap();
    let local_id = format!("mode-agent-{}", uuid::Uuid::now_v7().simple());
    let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &ed25519_dalek::SigningKey::from_bytes(&[0x72; 32])
            .verifying_key()
            .to_bytes(),
    );
    let inception = arkret_signatures::webvh::prepare_agent_inception(
        &arkret_signatures::webvh::AgentInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &local_id,
            controller_principal_id: &controller.principal_id,
            version_time: principal.unit.transactions[1].commit.committed_at,
            root_seed: &[0x71; 32],
            next_root_public_key_multibase: &next_key,
        },
    )
    .unwrap();
    let agent_did = arkret_wire::Did::new(inception.did).unwrap();
    let (agent, genesis, provision_ref) =
        provision_owned_agent_with_did(&pool, &principal, agent_did.clone()).await;
    let no_key = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(no_key.desired_agent_ids.is_empty());
    assert!(no_key.authority_stream_head.contains(&provision_ref));
    let delegation = format!("{agent_did}#managed-controller");
    let key_event = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        &agent,
        &genesis.event.realm_id,
        &delegation,
        sidecar_agent::agent_key_authorization(
            &agent_did,
            &controller.principal_id,
            genesis.commit.committed_at,
        ),
        genesis.commit.committed_at,
    );
    let key_commit = sidecar_agent::station_successor(&genesis.commit, &key_event, &station_did, 1);
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    historical_control_source::admit_control(
        &profiles,
        &pool,
        AgentControlAdmissionWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: genesis.expected_authority.clone(),
                event: key_event.clone(),
                commit: key_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: key_commit.committed_at,
        },
    )
    .await
    .unwrap();
    let not_joined = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(not_joined.desired_agent_ids.is_empty());
    assert!(
        not_joined
            .authority_stream_head
            .contains(&key_event.event_id)
    );
    let join = ordinary_realm::next_request(
        &create.authority_commit,
        EventKind::MemberState,
        &controller.principal_id,
        serde_json::json!({"member_id": arkret_wire::ActorId::account(agent.clone()), "membership":"join",
            "agent_controller_binding": {"controller_account_id":controller,
                "controller_membership_generation_ref":parent.event.event_id}}),
        key_commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let join = ordinary_realm::source_request(&pool, join).await;
    uow.commit_event(join.clone()).await.unwrap();
    let joined = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.desired_agent_ids, vec![agent.principal_id.clone()]);
    assert!(
        joined
            .authority_stream_head
            .contains(&join.authority_commit.event.event_id)
    );
    assert_ne!(
        joined.participant_authority_digest,
        not_joined.participant_authority_digest
    );

    let guard = principal
        .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
        .await
        .unwrap();
    let make_mode = |previous: &coland_storage::AuthorityCommitTransaction,
                     mode: &str,
                     expected: Option<arkret_wire::CurrentRevision>| {
        agent_mode_request(previous, mode, expected, &principal, &agent, &guard)
    };
    let mut public = make_mode(&join.authority_commit, "public", None);
    source_candidate(&pool, &mut public).await;
    let mut unguarded = public.clone();
    unguarded.self_producer_guard = None;
    assert!(
        uow.commit_event(unguarded)
            .await
            .unwrap_err()
            .to_string()
            .contains("capability_denied")
    );
    let public = ordinary_realm::source_request(&pool, public).await;
    uow.commit_event(public.clone()).await.unwrap();
    let selector = arkret_wire::CurrentSelector::AgentInteraction {
        agent_account_id: agent.clone(),
    };
    let row = store
        .current_agent_result(realm_id, &selector)
        .await
        .unwrap()
        .unwrap();
    let arkret_wire::TypedCurrentRow::Value {
        revision, value, ..
    } = row;
    assert_eq!(value["interaction_mode"], "public");
    let public_cut = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.desired_agent_ids, public_cut.desired_agent_ids);
    assert_eq!(
        joined.participant_authority_digest,
        public_cut.participant_authority_digest
    );
    let mut stale = make_mode(&public.authority_commit, "private", None);
    source_candidate(&pool, &mut stale).await;
    assert!(
        uow.commit_event(stale)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    let mut private = make_mode(&public.authority_commit, "private", Some(revision));
    source_candidate(&pool, &mut private).await;
    let private = ordinary_realm::source_request(&pool, private).await;
    uow.commit_event(private.clone()).await.unwrap();
    let arkret_wire::TypedCurrentRow::Value { value, .. } = store
        .current_agent_result(realm_id, &selector)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(value["interaction_mode"], "private");
    let private_cut = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.desired_agent_ids, private_cut.desired_agent_ids);
    assert_eq!(
        joined.participant_authority_digest,
        private_cut.participant_authority_digest
    );
    // This serving index copies only the accepted native provisioning identity.
    // The actual ownership/status cut is independently read by require_current.
    use coland_storage::{AgentParticipationStore, AgentStore};
    let original_provision = store
        .committed_event(&provision_ref)
        .await
        .unwrap()
        .unwrap();
    let original_payload =
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
            &original_provision.event,
        )
        .unwrap();
    assert_eq!(original_payload.agent_id, agent.principal_id);
    assert_eq!(
        original_payload.controller_principal_id,
        controller.principal_id
    );
    assert_eq!(
        original_payload.principal_control_realm_id,
        genesis.event.realm_id
    );
    assert_eq!(
        original_payload.controller_authorization_ref.as_str(),
        delegation
    );
    coland_storage_postgres::PgAgentStore { pool: pool.clone() }
        .put(coland_storage::AgentPrincipalRecord::new(
            original_payload.agent_id.to_string(),
            original_payload.controller_principal_id.to_string(),
            original_payload.principal_control_realm_id.to_string(),
            original_payload.controller_authorization_ref,
            arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
            original_provision.commit.committed_at,
        ))
        .await
        .unwrap();
    assert!(
        coland_storage_postgres::PgAgentParticipationStore { pool: pool.clone() }
            .compare_and_swap_selection(
                serde_json::json!({
                    "agent_id": agent.principal_id,
                    "scope_kind": "realm", "scope_key": format!("realm:{realm_id}"),
                    "realm_id": realm_id, "scope": {"kind":"realm", "realm_id":realm_id},
                    "version": 1, "reply_message": true,
                    "reaction_add": false, "reaction_remove": false,
                    "accept_third_party_mention": false, "act_on_behalf": false,
                }),
                0
            )
            .await
            .unwrap()
    );
    let private_write = ordinary_realm::next_request(
        &private.authority_commit,
        EventKind::MessageCreate,
        &agent.principal_id,
        serde_json::json!({}),
        private.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let agent_event = device_authorization_history::sign_event(
        private_write.authority_commit.event,
        arkret_wire::DidUrl::new(format!("{agent_did}#runtime-1")).unwrap(),
        [0x61; 32],
    );
    let mut private_write = ordinary_realm::request_for_event(
        &private.authority_commit,
        agent_event,
        private.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    assert!(
        private_write
            .authority_commit
            .producer_signer_fact
            .is_none()
    );
    private_write.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::Agent {
        pcr_realm_id: genesis.event.realm_id.clone(),
        agent_id: agent.principal_id.clone(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: key_event.event_id.clone(),
            commit_id: key_commit.commit_id.clone(),
            stream_ref: key_commit.stream_ref.clone(),
            stream_position: key_commit.stream_position,
        },
        verification_method: arkret_wire::DidUrl::new(format!("{agent_did}#runtime-1")).unwrap(),
    });
    private_write.agent_deployment_ceiling =
        arkret_models_collaboration::governance::agent_participation::ParticipationBits {
            reply_message: true,
            ..arkret_models_collaboration::governance::agent_participation::ParticipationBits::NONE
        };
    assert_eq!(
        key_event.payload["public_key"]["key"],
        serde_json::json!(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&[0x61; 32])
                .verifying_key()
                .as_bytes()
        ))
    );
    let commit = &mut private_write.authority_commit.commit;
    let identity =
        arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        commit.signature.verification_method.clone(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(
            &device_authorization_history::STATION_AUTHORITY_SEED,
        ),
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();

    let private_write_before = agent_mode_footprint(&pool, realm_id).await;
    assert!(
        uow.commit_event(private_write)
            .await
            .unwrap_err()
            .to_string()
            .contains("shared Agent authority is unavailable")
    );
    assert_eq!(
        agent_mode_footprint(&pool, realm_id).await,
        private_write_before
    );
    let arkret_wire::TypedCurrentRow::Value {
        revision: private_revision,
        ..
    } = store
        .current_agent_result(realm_id, &selector)
        .await
        .unwrap()
        .unwrap();
    let mut same_value = make_mode(
        &private.authority_commit,
        "private",
        Some(private_revision.clone()),
    );
    source_candidate(&pool, &mut same_value).await;
    let same_value = ordinary_realm::source_request(&pool, same_value).await;
    uow.commit_event(same_value.clone()).await.unwrap();
    let arkret_wire::TypedCurrentRow::Value {
        revision: advanced, ..
    } = store
        .current_agent_result(realm_id, &selector)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        advanced.stream_position,
        private_revision.stream_position + 1
    );
    assert_eq!(
        advanced.commit_id,
        same_value.authority_commit.commit.commit_id
    );
    let snapshot = store
        .realm_state_snapshot_material_for_account(realm_id, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|row| matches!(row, arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::AgentInteraction { agent_account_id }, value, .. } if agent_account_id == &agent && value["interaction_mode"] == "private")));

    (
        database,
        principal,
        agent,
        same_value.authority_commit,
        advanced,
        guard,
    )
}

async fn agent_publish_policy_scenario<F>(
    pool: &coland_storage_postgres::PgPool,
    controller: &AccountId,
    agent: &AccountId,
    initial: &coland_storage::AuthorityCommitTransaction,
    mut mode_revision: arkret_wire::CurrentRevision,
    make_mode: &F,
) where
    F: Fn(
            &coland_storage::AuthorityCommitTransaction,
            &str,
            Option<arkret_wire::CurrentRevision>,
        ) -> coland_storage::EventCommitRequest
        + Sync,
{
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm_id = &initial.event.realm_id;
    let selector = arkret_wire::CurrentSelector::AgentInteraction {
        agent_account_id: agent.clone(),
    };
    // Management writes remain guarded. Import complete accepted policy history
    // to exercise the real mode UOW consumer without claiming HTTP enablement.
    async fn import_publish_policy(
        pool: &coland_storage_postgres::PgPool,
        previous: &coland_storage::AuthorityCommitTransaction,
        controller: &AccountId,
        expected: Option<arkret_wire::CurrentRevision>,
        effect: &str,
    ) -> coland_storage::AuthorityCommitTransaction {
        use diesel::sql_types::{BigInt, Binary, Jsonb, Nullable, Text, Timestamptz};
        use diesel_async::{AsyncConnection, RunQueryDsl};
        let mut payload: arkret_models_collaboration::governance::operation_wire::PolicySetStatePayload =
            serde_json::from_value(serde_json::json!({
                "policy_id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
                "expected_revision":expected,
                "value":{
                    "schema":"ak.schema.policy.v1",
                    "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
                    "realm_id":previous.event.realm_id, "policy_kind":"agent",
                    "rules":[{"rule_id":"publish", "kind":"agent", "effect":effect,
                        "agent_target":{"kind":"controller","controller_account_id":controller},
                        "agent_operations":["publish"]}],
                    "default_effect":"allow", "created_by":arkret_wire::ActorId::account(controller.clone()),
                    "created_at":previous.commit.committed_at
                }
            })).unwrap();
        if effect == "require_review" {
            let arkret_models_collaboration::governance::operation_wire::PolicySetValue::Governance(
                document,
            ) = &mut payload.value
            else {
                unreachable!()
            };
            document.rules[0].review_requirement = Some(arkret_models_collaboration::governance::operation_wire::ManagementReviewRequirement {
                approver_actor_ids: vec![arkret_wire::ActorId::account(controller.clone())],
                threshold: 1,
                max_age_seconds: 60,
            });
        }
        payload.validate().unwrap();
        let request = ordinary_realm::next_request(
            previous,
            EventKind::PolicySet,
            &controller.principal_id,
            serde_json::to_value(&payload).unwrap(),
            previous.commit.committed_at + chrono::TimeDelta::milliseconds(1),
        );
        let request = ordinary_realm::source_request(pool, request).await;
        let tx = request.authority_commit;
        let event = &tx.event;
        let commit = &tx.commit;
        let mut conn = pool.get().await.unwrap();
        (&mut *conn).transaction::<(), diesel::result::Error, _>(async move |conn| {
            diesel::sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,'committed',$9)")
                .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).bind::<Binary,_>(event.event_id.digest_bytes().to_vec())
                .bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(event.realm_id.as_str())
                .bind::<Jsonb,_>(serde_json::json!(event.scope_ref)).bind::<Text,_>(event.kind.as_str())
                .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(event).unwrap()).bind::<Jsonb,_>(serde_json::json!(event))
                .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await?;
            diesel::sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9")
                .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(commit.realm_id.as_str())
                .bind::<Text,_>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap())
                .bind::<Jsonb,_>(serde_json::json!(commit.stream_ref)).bind::<BigInt,_>(commit.stream_position as i64)
                .bind::<Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
                .bind::<Jsonb,_>(serde_json::json!(commit)).bind::<Timestamptz,_>(commit.committed_at)
                .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).execute(&mut *conn).await?;
            diesel::sql_query("INSERT INTO policy_current_results(realm_id,policy_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(policy_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.policy_id.as_str())
                .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(commit.stream_position as i64)
                .bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(serde_json::json!(payload.value))
                .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await?;
            Ok(())
        }).await.unwrap();
        tx
    }
    let mut previous = initial.clone();
    let mut policy_revision = None;
    for effect in ["deny", "require_review", "allow"] {
        previous =
            import_publish_policy(&pool, &previous, controller, policy_revision, effect).await;
        policy_revision = Some(arkret_wire::CurrentRevision {
            commit_id: previous.commit.commit_id.clone(),
            stream_position: previous.commit.stream_position,
        });
        let mut opening = make_mode(&previous, "public", Some(mode_revision.clone()));
        source_candidate(&pool, &mut opening).await;
        let before = agent_mode_footprint(&pool, realm_id).await;
        if effect != "allow" {
            let error = uow.commit_event(opening).await.unwrap_err();
            let expected = if effect == "deny" {
                "forbids publishing"
            } else {
                "unresolved quarantine or review evidence"
            };
            assert!(error.to_string().contains(expected), "{error}");
            assert_eq!(agent_mode_footprint(&pool, realm_id).await, before);
        } else {
            let opening = ordinary_realm::source_request(&pool, opening).await;
            uow.commit_event(opening.clone()).await.unwrap();
            previous = opening.authority_commit.clone();
            mode_revision = arkret_wire::CurrentRevision {
                commit_id: previous.commit.commit_id.clone(),
                stream_position: previous.commit.stream_position,
            };
            previous =
                import_publish_policy(&pool, &previous, controller, policy_revision.take(), "deny")
                    .await;
            let before_replay = agent_mode_footprint(&pool, realm_id).await;
            uow.commit_event(opening).await.unwrap();
            assert_eq!(agent_mode_footprint(&pool, realm_id).await, before_replay);
            let mut unchanged = make_mode(&previous, "public", Some(mode_revision));
            source_candidate(&pool, &mut unchanged).await;
            let unchanged = ordinary_realm::source_request(&pool, unchanged).await;
            uow.commit_event(unchanged.clone()).await.unwrap();
            previous = unchanged.authority_commit;
            mode_revision = arkret_wire::CurrentRevision {
                commit_id: previous.commit.commit_id.clone(),
                stream_position: previous.commit.stream_position,
            };
        }
        // With a deny/review policy present, private remains an unreviewed
        // controller choice; switching off never needs publish permission.
        let mut private = make_mode(&previous, "private", Some(mode_revision));
        source_candidate(&pool, &mut private).await;
        let private = ordinary_realm::source_request(&pool, private).await;
        uow.commit_event(private.clone()).await.unwrap();
        previous = private.authority_commit;
        mode_revision = arkret_wire::CurrentRevision {
            commit_id: previous.commit.commit_id.clone(),
            stream_position: previous.commit.stream_position,
        };
        let arkret_wire::TypedCurrentRow::Value { value, .. } = store
            .current_agent_result(realm_id, &selector)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value["interaction_mode"], "private");
    }
    // A corrupt projection must not turn the last accepted private intent into
    // an already-public exception to the publish gate.
    {
        use diesel::sql_types::{Jsonb, Text};
        use diesel_async::RunQueryDsl;
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("UPDATE agent_interaction_current_results SET value=jsonb_set(value,'{interaction_mode}','\"public\"'::jsonb) WHERE realm_id=$1 AND agent_account_id=$2")
            .bind::<Text,_>(realm_id.as_str()).bind::<Jsonb,_>(serde_json::json!(agent)).execute(&mut *conn).await.unwrap();
    }
    let mut opening = make_mode(&previous, "public", Some(mode_revision));
    source_candidate(&pool, &mut opening).await;
    let before = agent_mode_footprint(&pool, realm_id).await;
    let error = uow.commit_event(opening).await.unwrap_err();
    assert!(
        error.to_string().contains("revision_unavailable"),
        "{error}"
    );
    assert_eq!(agent_mode_footprint(&pool, realm_id).await, before);
}

/// Real RFC transitions, accepted ownership/key/membership and real PostgreSQL
/// UOW gates. No fabricated post-tree fact is used as the crypto proof.
#[allow(clippy::too_many_arguments)]
async fn sidecar_post_tree_rejects_stale_endpoint_and_paused_self_update(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent: &AccountId,
    agent_did: &arkret_wire::Did,
    agent_genesis: &coland_storage::AuthorityCommitTransaction,
    key_event: &arkret_wire::Event,
    key_commit: &arkret_wire::RealmCommit,
    template: &coland_storage::AuthorityCommitTransaction,
    sidecar: &SidecarId,
    group: &mut arkret_mls::ArkretMlsGroup,
    paused_group: &mut arkret_mls::ArkretMlsGroup,
) {
    use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload};
    use arkret_wire::{ActorId, ScopeRef};
    use coland_storage::{AgentControlAdmissionWrite, MlsGroupCurrentStore};
    use diesel::sql_types::BigInt;
    use diesel_async::RunQueryDsl;
    let controller = &principal.history.account;
    let realm = &template.event.realm_id;
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    group
        .install_verified_leaf_bindings(paused_group.verified_leaf_bindings().unwrap())
        .unwrap();
    let stream = arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap();
    let head_commit = store
        .held_stream_head_commit(&stream)
        .await
        .unwrap()
        .unwrap();
    let head_event = store
        .committed_event(&head_commit.event_ref)
        .await
        .unwrap()
        .unwrap()
        .event;
    let mut head = template.clone();
    head.event = head_event;
    head.commit = head_commit;
    let baseline = store
        .sidecar_access_cut(
            realm,
            sidecar,
            controller,
            &principal.history.founding_device_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(baseline.3);
    assert_eq!(baseline.1, vec![agent.principal_id.clone()]);
    let now = key_commit.committed_at + chrono::TimeDelta::seconds(10);
    let mut authorization =
        sidecar_agent::agent_key_authorization(agent_did, &controller.principal_id, now);
    authorization["supersedes"] = serde_json::json!([{"key_id":key_event.payload["key_id"],"authorized_event_ref":key_event.event_id}]);
    let renewal = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        agent,
        &agent_genesis.event.realm_id,
        &format!("{agent_did}#managed-controller"),
        authorization,
        now,
    );
    let renewal_commit =
        sidecar_agent::station_successor(key_commit, &renewal, &principal.history.station_did, 10);
    historical_control_source::admit_control(
        &profiles,
        &pool,
        AgentControlAdmissionWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: agent_genesis.expected_authority.clone(),
                event: renewal.clone(),
                commit: renewal_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: renewal_commit.committed_at,
        },
    )
    .await
    .unwrap();
    let renewed_cut = read(pool, realm, sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        renewed_cut.desired_agent_ids,
        vec![agent.principal_id.clone()]
    );
    let status = store
        .sidecar_access_cut(
            realm,
            sidecar,
            controller,
            &principal.history.founding_device_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        !status.3,
        "an old authorization dot cannot authorize a retained endpoint"
    );
    #[derive(diesel::QueryableByName, Debug, PartialEq)]
    struct Counts {
        #[diesel(sql_type=BigInt)]
        events: i64,
        #[diesel(sql_type=BigInt)]
        commits: i64,
        #[diesel(sql_type = BigInt)]
        outbox: i64,
    }
    async fn counts(pool: &coland_storage_postgres::PgPool) -> Counts {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("SELECT (SELECT count(*) FROM canonical_events) AS events,(SELECT count(*) FROM realm_commits) AS commits,(SELECT count(*) FROM event_federation_outbox) AS outbox")
            .get_result(&mut conn).await.unwrap()
    }
    let make = |binding: MlsGovernanceBindingPayload,
                envelope: &arkret_models_crypto::MlsCommitEnvelope,
                tracker: &arkret_mls::MlsPublicGroupTracker,
                proposals: Vec<arkret_mls::MlsVerifiedConsumedProposal>| {
        let base = binding.base_group_state_ref().unwrap().clone();
        let payload = MlsCommitPayload::new(
            base.clone(),
            binding.key_access_revision(),
            envelope,
            binding,
        )
        .unwrap();
        let event = device_authorization_history::sign_event(
            ordinary_realm::event_for_actor(
                EventKind::MlsCommit,
                scope.clone(),
                ActorId::account(controller.clone()),
                serde_json::to_value(payload).unwrap(),
                head.commit.committed_at,
            ),
            principal.history.device_verification_method.clone(),
            principal.history.founding_device_signing_seed,
        );
        let mut request = ordinary_realm::request_for_event(&head, event, head.commit.committed_at);
        request.authority_commit.commit.stream_ref = stream.clone();
        request.authority_commit.commit.stream_position = head.commit.stream_position + 1;
        request.authority_commit.commit.previous_commit_ref = Some(head.commit.commit_id.clone());
        let leaf =
            |l: arkret_mls::MlsPublicEndpointLeaf| coland_storage::MlsProposalLeafProvenance {
                leaf_index: l.leaf_index,
                actor_id: l.actor_id,
                signature_key: l.signature_key,
            };
        let tree = tracker.ratchet_tree_bytes().unwrap();
        let digest = arkret_canonical::sha256_digest(&tree);
        let sha256 = digest.strip_prefix("sha256:").unwrap().to_owned();
        request.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
            effective_scope: scope.clone(),
            base: Some(coland_storage::MlsInstalledBase {
                current_mls_commit_event_ref: base,
                epoch: envelope.epoch - 1,
            }),
            epoch: envelope.epoch,
            public_state: tracker.export_state().unwrap(),
            member_principals: tracker
                .leaves()
                .unwrap()
                .into_iter()
                .map(|l| l.actor_id)
                .collect(),
            consumed_proposals: proposals
                .into_iter()
                .map(|p| coland_storage::MlsConsumedProposalInstallation {
                    ordinal: p.ordinal,
                    proposal_ref: p.proposal_ref,
                    proposal_type: p.proposal_type,
                    proposal_wire: p.proposal_wire,
                    sender_leaf: leaf(p.sender_leaf),
                    target_before: p.target_before.map(leaf),
                    target_after: p.target_after.map(leaf),
                })
                .collect(),
            public_blobs: vec![coland_storage::MlsPublicBlob {
                blob_ref: arkret_wire::BlobRef::new(format!("ak:blob:{digest}")).unwrap(),
                sha256: sha256.clone(),
                size_bytes: tree.len() as i64,
                storage_backend: "local".into(),
                storage_key: format!("sha256/{sha256}"),
            }],
        });
        request
    };
    let before = groups.current(&scope).await.unwrap().unwrap();
    let binding =
        |cut: &arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityCut| {
            MlsGovernanceBindingPayload::sidecar(
                realm.clone(),
                sidecar.clone(),
                Some(before.value.current_mls_commit_event_ref.clone()),
                before.value.epoch,
                before.value.epoch + 1,
                before.value.current_key_access_revision,
                cut.participant_authority_digest.clone(),
                cut.authority_stream_head.clone(),
            )
            .unwrap()
        };
    let previous_bindings = group.verified_leaf_bindings().unwrap();
    let frozen = group.export_state_record().unwrap();
    // A true SelfUpdate signed against the renewed current cut still carries
    // the original Add endpoint, whose authorization dot was superseded.
    let mut stale = arkret_mls::ArkretMlsGroup::restore_from_state_record(&frozen).unwrap();
    let envelope = stale
        .self_update_commit_with_governance_binding(&binding(&renewed_cut))
        .unwrap();
    let mut tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &before.public_state,
        group.group_id().as_str(),
        before.value.epoch,
    )
    .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = tracker
        .process_public_handshake(&arkret_canonical::base64url_decode(&envelope.commit).unwrap())
        .unwrap()
    else {
        panic!("real SelfUpdate required")
    };
    let request = make(
        binding(&renewed_cut),
        &envelope,
        &tracker,
        consumed_proposals,
    );
    let request = ordinary_realm::source_request(pool, request).await;
    let footprint = counts(pool).await;
    let error = uow.commit_event(request).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("the Sidecar post-transition tree retains an unauthorized endpoint"),
        "superseded endpoint SelfUpdate must reach the new tree gate: {error}"
    );
    assert_eq!(counts(pool).await, footprint);
    let unchanged = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(unchanged.value, before.value);
    assert_eq!(unchanged.public_state, before.public_state);
    let mut pause = ordinary_realm::event_for_actor(
        EventKind::SelfAgentPause,
        ScopeRef::Realm {
            realm_id: agent_genesis.event.realm_id.clone(),
        },
        ActorId::account(agent.clone()),
        serde_json::json!({"transition":"pause","previous_status":"active","status_changed_at":arkret_canonical::format_timestamp_canonical(now)}),
        now,
    );
    pause.executed_by = key_event.executed_by.clone();
    pause.authorization_ref = key_event.authorization_ref.clone();
    let pause = device_authorization_history::sign_event(
        pause,
        principal.history.device_verification_method.clone(),
        principal.history.founding_device_signing_seed,
    );
    let pause_commit = sidecar_agent::station_successor(
        &renewal_commit,
        &pause,
        &principal.history.station_did,
        1,
    );
    historical_control_source::admit_control(
        &profiles,
        &pool,
        AgentControlAdmissionWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: agent_genesis.expected_authority.clone(),
                event: pause,
                commit: pause_commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: pause_commit.committed_at,
        },
    )
    .await
    .unwrap();
    let paused_cut = read(pool, realm, sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(paused_cut.desired_agent_ids.is_empty());
    let mut malicious = arkret_mls::ArkretMlsGroup::restore_from_state_record(&frozen).unwrap();
    let envelope = malicious
        .self_update_commit_with_governance_binding(&binding(&paused_cut))
        .unwrap();
    let mut tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &before.public_state,
        group.group_id().as_str(),
        before.value.epoch,
    )
    .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = tracker
        .process_public_handshake(&arkret_canonical::base64url_decode(&envelope.commit).unwrap())
        .unwrap()
    else {
        panic!("real SelfUpdate required")
    };
    assert!(
        tracker
            .leaves()
            .unwrap()
            .iter()
            .any(|leaf| leaf.actor_id == ActorId::account(agent.clone()))
    );
    let request = make(
        binding(&paused_cut),
        &envelope,
        &tracker,
        consumed_proposals,
    );
    let request = ordinary_realm::source_request(pool, request).await;
    let footprint = counts(pool).await;
    let error = uow.commit_event(request).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("the Sidecar post-transition tree retains an unauthorized endpoint"),
        "paused extra-leaf SelfUpdate must reach the new tree gate: {error}"
    );
    assert_eq!(counts(pool).await, footprint);
    let unchanged = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(unchanged.value, before.value);
    assert_eq!(unchanged.public_state, before.public_state);
    let remove = group
        .remove_members_by_actor_with_governance_binding(
            &[ActorId::account(agent.clone())],
            &binding(&paused_cut),
        )
        .unwrap();
    let mut tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &before.public_state,
        group.group_id().as_str(),
        before.value.epoch,
    )
    .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = tracker
        .process_public_handshake(
            &arkret_canonical::base64url_decode(&remove.commit.commit).unwrap(),
        )
        .unwrap()
    else {
        panic!("real Remove required")
    };
    assert!(consumed_proposals.iter().any(|p| p.proposal_type == 3));
    assert_eq!(
        tracker
            .leaves()
            .unwrap()
            .into_iter()
            .map(|l| l.actor_id)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([ActorId::account(controller.clone())])
    );
    let request = make(
        binding(&paused_cut),
        &remove.commit,
        &tracker,
        consumed_proposals,
    );
    let request = ordinary_realm::source_request(&pool, request).await;
    uow.commit_event(request.clone()).await.unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: request.authority_commit.event,
        commit: request.authority_commit.commit,
    };
    group
        .install_accepted_commit(&accepted, &before.value)
        .unwrap();
    let remaining = tracker.leaves().unwrap();
    group
        .install_verified_leaf_bindings(
            previous_bindings
                .into_iter()
                .filter(|binding| {
                    remaining.iter().any(|leaf| {
                        leaf.leaf_index == binding.leaf_index
                            && leaf.actor_id == binding.actor_id
                            && leaf.signature_key == binding.signature_key
                    })
                })
                .collect(),
        )
        .unwrap();
    let current = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(current.value.epoch, before.value.epoch + 1);
    assert_eq!(
        current.value.current_mls_commit_event_ref,
        accepted.event.event_id
    );
    let status = store
        .sidecar_access_cut(
            realm,
            sidecar,
            controller,
            &principal.history.founding_device_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(status.3);
    assert!(status.1.is_empty());
    let header = arkret_models_crypto::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "text/plain",
        arkret_wire::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        EventKind::MessageCreate.as_str(),
        group.epoch(),
        current.value.current_mls_commit_event_ref,
        group.local_content_sender_domain().unwrap(),
        arkret_models_crypto::EventContentRoutingContext::None,
    )
    .unwrap();
    let encrypted = group.encrypt_payload(header, b"after removal").unwrap();
    assert!(
        paused_group.decrypt_payload(&encrypted).is_err(),
        "removed endpoint cannot decrypt the accepted post-Remove epoch"
    );
}
