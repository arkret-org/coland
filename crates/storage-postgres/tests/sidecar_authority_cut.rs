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

async fn fixture_step<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) -> T {
    struct CancelOnDrop(tokio::task::AbortHandle);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let task = tokio::spawn(future);
    // Cancelling a caller's timeout must also drop the original pending future.
    let _cancel = CancelOnDrop(task.abort_handle());
    task.await.expect("original fixture step task")
}

// Run large production futures in independent ordinary tasks, preserving the
// original inputs, results, transaction guards and default runtime stack.
fn fixture_commit_step(
    pool: &coland_storage_postgres::PgPool,
    request: coland_storage::EventCommitRequest,
) -> Pin<
    Box<
        dyn Future<Output = coland_storage::PersistenceResult<coland_storage::EventCommitOutcome>>
            + Send,
    >,
> {
    let pool = pool.clone();
    Box::pin(async move {
        fixture_step(async move {
            PgEventCommitUnitOfWork::new(pool)
                .commit_event(request)
                .await
        })
        .await
    })
}

fn fixture_commit_batch_step(
    pool: &coland_storage_postgres::PgPool,
    request: coland_storage::EventBatchCommitRequest,
) -> Pin<
    Box<
        dyn Future<Output = coland_storage::PersistenceResult<coland_storage::EventCommitOutcome>>
            + Send,
    >,
> {
    let pool = pool.clone();
    Box::pin(async move {
        fixture_step(async move {
            PgEventCommitUnitOfWork::new(pool)
                .commit_event_batch(request)
                .await
        })
        .await
    })
}

fn fixture_bootstrap_step(
    pool: &coland_storage_postgres::PgPool,
    unit: &coland_storage::OrdinaryRealmBootstrapCommitUnit,
    queued_at: chrono::DateTime<chrono::Utc>,
) -> Pin<
    Box<
        dyn Future<
                Output = coland_storage::PersistenceResult<
                    coland_storage::OrdinaryRealmBootstrapCommitOutcome,
                >,
            > + Send,
    >,
> {
    let pool = pool.clone();
    let unit = unit.clone();
    Box::pin(async move {
        fixture_step(async move {
            PgAuthorityCommitStore { pool }
                .admit_ordinary_realm_bootstrap_unit(&unit, queued_at)
                .await
        })
        .await
    })
}

fn fixture_delivery_step(
    pool: &coland_storage_postgres::PgPool,
    account: &AccountId,
    station: &arkret_wire::DidCoreId,
    input: &coland_storage::AccountContentDeliveryInput,
) -> Pin<
    Box<
        dyn Future<
                Output = coland_storage::PersistenceResult<
                    Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>,
                >,
            > + Send,
    >,
> {
    let pool = pool.clone();
    let account = account.clone();
    let station = station.clone();
    let input = input.clone();
    Box::pin(async move {
        fixture_step(async move {
            PgAuthorityCommitStore { pool }
                .acquire_committed_content_delivery(&account, &station, &input)
                .await
        })
        .await
    })
}

// These exact current reads also poll the original native delivery authority
// chain. Use the same cancellation-safe ordinary-task boundary as delivery/UOW.
fn fixture_realm_export_step(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
    actor: &arkret_wire::ActorId,
    station: &arkret_wire::DidCoreId,
) -> Pin<
    Box<
        dyn Future<
                Output = coland_storage::PersistenceResult<
                    Option<(
                        arkret_models_collaboration::governance::realm_governance::RealmExport,
                        Vec<arkret_wire::CommittedEventView>,
                    )>,
                >,
            > + Send,
    >,
> {
    let pool = pool.clone();
    let realm_id = realm_id.clone();
    let actor = actor.clone();
    let station = station.clone();
    Box::pin(async move {
        fixture_step(async move {
            PgAuthorityCommitStore { pool }
                .realm_export_for_actor(&realm_id, &actor, &station)
                .await
        })
        .await
    })
}

fn fixture_strand_watch_current_step(
    pool: &coland_storage_postgres::PgPool,
    request: &arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody,
    account: &AccountId,
    issuer: &arkret_wire::DidCoreId,
) -> Pin<
    Box<
        dyn Future<
                Output = coland_storage::PersistenceResult<
                    coland_storage::SelfExactCurrentRead<
                        arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome,
                    >,
                >,
            > + Send,
    >,
>{
    let pool = pool.clone();
    let request = request.clone();
    let account = account.clone();
    let issuer = issuer.clone();
    Box::pin(async move {
        fixture_step(async move {
            PgAuthorityCommitStore { pool }
                .strand_watch_current_for_account(&request, &account, &issuer)
                .await
        })
        .await
    })
}

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
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) ON CONFLICT(singleton) DO NOTHING")
        .bind::<diesel::sql_types::Text, _>(principal.history.account.station_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    #[derive(diesel::QueryableByName)]
    struct FixtureStation {
        #[diesel(sql_type=diesel::sql_types::Text)]
        station_id: String,
    }
    let selected: FixtureStation =
        diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton=TRUE")
            .get_result(&mut conn)
            .await
            .unwrap();
    assert_eq!(
        selected.station_id,
        principal.history.account.station_id.as_str()
    );
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
            let coland_storage::AccountRealmStreamList::Listed(streams) = store
                .list_realm_streams_for_account(realm, agent, &controller.station_id)
                .await
                .unwrap()
            else {
                panic!("desired Agent must discover its restricted handshake stream")
            };
            let discovered = streams.iter().find(|row| row.stream_ref == stream).unwrap();
            assert_eq!(discovered.readable_floor, page.readable_floor);
            assert_eq!(discovered.head_commit_ref, context.authority_commit.commit.commit_id);
            assert_eq!(discovered.next_position, 3);
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
    let grant_reader =
        coland_storage_postgres::PgCapabilityGrantCurrentResultStore { pool: pool.clone() };
    let authorization = coland_storage::CapabilityGrantCurrentResultStore::actor_authorization(
        &grant_reader,
        realm_id,
        &arkret_wire::ActorId::account(agent.clone()),
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        authorization
            .agent_ceiling
            .as_ref()
            .unwrap()
            .controller
            .actor
            .as_account_id(),
        Some(controller)
    );
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
    assert!(
        coland_storage::CapabilityGrantCurrentResultStore::actor_authorization(
            &grant_reader,
            realm_id,
            &arkret_wire::ActorId::account(agent.clone()),
            chrono::Utc::now(),
        )
        .await
        .is_err()
    );
    // Snapshot and discovery cannot retain membership-derived access after
    // the exact controller incarnation terminates, including after reopening.
    let reopened_reader = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(
        reopened_reader
            .realm_state_snapshot_material_for_account(realm_id, &agent)
            .await
            .is_err()
    );
    assert!(
        reopened_reader
            .list_realm_streams_for_account(realm_id, &agent, &controller.station_id)
            .await
            .is_err()
    );
    assert!(
        reopened_reader
            .accepted_realm_reader(realm_id, &arkret_wire::ActorId::account(agent.clone()))
            .await
            .is_err()
    );
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
    assert!(
        coland_storage::CapabilityGrantCurrentResultStore::actor_authorization(
            &grant_reader,
            realm_id,
            &arkret_wire::ActorId::account(agent.clone()),
            chrono::Utc::now(),
        )
        .await
        .is_err()
    );
    assert!(
        reopened_reader
            .realm_state_snapshot_material_for_account(realm_id, &agent)
            .await
            .is_err()
    );
    assert!(
        reopened_reader
            .list_realm_streams_for_account(realm_id, &agent, &controller.station_id)
            .await
            .is_err()
    );
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
    let coland_storage::AccountRealmStreamList::Listed(streams) = store
        .list_realm_streams_for_account(realm_id, &agent, &controller.station_id)
        .await
        .unwrap()
    else {
        panic!("the Realm membership remains current")
    };
    assert!(!streams.iter().any(|row| row.stream_ref == stale.stream_ref));
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
    Box::pin(consumed_sidecar_agent_scenario(None))
}

#[derive(Clone, Copy)]
enum OwnedWelcomeCase {
    CurrentCutAndBytes,
    HeldOwnerWithdrawal,
    AcceptedKeyRevoke,
    DeviceMessagesOwnerLeave,
    DeviceMessagesPolicyDeny,
    DeviceMessagesContinuationOwnerLeave,
    DeviceMessagesContinuationPolicyDeny,
}

async fn owned_welcome_footprint(
    pool: &coland_storage_postgres::PgPool,
    realm: &arkret_wire::RealmId,
    pcr: &arkret_wire::RealmId,
) -> String {
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let ordinary = agent_mode_footprint(pool, realm).await;
    let control = agent_mode_footprint(pool, pcr).await;
    let mut connection = pool.get().await.unwrap();
    let deliveries = diesel::sql_query(
        "SELECT jsonb_build_object( \
         'welcomes',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY welcome_id),'[]'::jsonb) FROM mls_welcome_deliveries w WHERE realm_id=$1), \
         'quota_counters',(SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]'::jsonb) FROM capability_quota_counters q), \
         'quota_buckets',(SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]'::jsonb) FROM capability_quota_buckets q), \
         'quota_consumptions',(SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]'::jsonb) FROM capability_quota_consumptions q), \
         'notifications',(SELECT COALESCE(jsonb_agg(to_jsonb(n) ORDER BY to_jsonb(n)::text),'[]'::jsonb) FROM notifications n), \
         'relay',(SELECT COALESCE(jsonb_agg(to_jsonb(n) ORDER BY to_jsonb(n)::text),'[]'::jsonb) FROM event_notification_relay n) \
         ) AS value",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<Row>(&mut *connection)
    .await
    .unwrap()
    .value;
    // Assert digests rather than rendering private Welcome bytes on failure.
    arkret_canonical::canonical_sha256(&serde_json::json!([ordinary, control, deliveries])).unwrap()
}

async fn owned_welcome_held_delivery_scenario(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent: &AccountId,
    genesis: &coland_storage::AuthorityCommitTransaction,
    key_event: &arkret_wire::Event,
    key_commit: &arkret_wire::RealmCommit,
    realm_parent: &coland_storage::AuthorityCommitTransaction,
    welcome: &arkret_wire::MlsWelcomeDelivery,
    endpoint: coland_storage::AgentEndpointGuard,
    evidence: coland_storage::VerifiedAgentScopeEvidence,
    scope: &arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    case: OwnedWelcomeCase,
) {
    use coland_storage::AccountContentDeliveryInput;
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    let controller = &principal.history.account;
    let realm = &welcome.realm_id;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    // The real handshake also advances the governing Realm independently of
    // its Sidecar MLS stream. Read that stream's actual accepted parent.
    let realm_stream = arkret_wire::CommitStreamRef::from_scope(
        &arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
    )
    .unwrap();
    let realm_head = store
        .held_stream_head_commit(&realm_stream)
        .await
        .unwrap()
        .unwrap();
    let realm_head_event = store
        .committed_event(&realm_head.event_ref)
        .await
        .unwrap()
        .unwrap()
        .event;
    let mut current_parent = realm_parent.clone();
    current_parent.event = realm_head_event;
    current_parent.commit = realm_head;
    current_parent.mls_state = None;
    current_parent.welcomes.clear();
    let realm_parent = &current_parent;
    let details = serde_json::json!({
        "controller_principal_id":controller.principal_id,
        "agent_key_authorization_ref":key_event.event_id,
        "realm_ids":[realm],"strand_ids":[],
        "resources":{"realm_ids":[realm],"strand_ids":[]},
        "constraints":{"allowed_tracks":[],"allowed_data_labels":[],"allowed_endpoints":[]},
        "capability_grant_refs":[],"policy_refs":[]
    })
    .as_object()
    .unwrap()
    .clone();
    let input = AccountContentDeliveryInput {
        realms: vec![realm.clone()],
        future_materials: vec![welcome.clone()],
        credential_expires_at: Some(chrono::Utc::now() + chrono::TimeDelta::minutes(10)),
        agent_session_scope: Some((scope.actions.clone(), details)),
        agent_endpoint: Some(endpoint),
        qualified_agent_scope_evidence: Some(evidence),
        ..Default::default()
    };
    assert!(input.committed_events.is_empty());
    let before = owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await;
    let guard = fixture_delivery_step(pool, agent, &agent.station_id, &input)
        .await
        .expect("the exact accepted Add permits its pending recipient's Welcome")
        .expect("an owned future material must retain its current cut");
    assert!(guard.permits_handoff());
    guard.finish().await.unwrap();
    assert_eq!(
        owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await,
        before
    );

    if matches!(case, OwnedWelcomeCase::HeldOwnerWithdrawal) {
        let leave = ordinary_realm::next_request_for_actor(
            realm_parent,
            EventKind::MemberState,
            arkret_wire::ActorId::account(controller.clone()),
            serde_json::json!({"member_id":arkret_wire::ActorId::account(controller.clone()),"membership":"leave"}),
            realm_parent.commit.committed_at + chrono::TimeDelta::milliseconds(1),
        );
        let leave = Box::pin(ordinary_realm::source_request(pool, leave)).await;
        let guard = fixture_delivery_step(pool, agent, &agent.station_id, &input)
            .await
            .unwrap()
            .unwrap();
        let leave_pool = pool.clone();
        let mut leaving = tokio::spawn(async move {
            Box::pin(PgEventCommitUnitOfWork::new(leave_pool).commit_event(leave)).await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), &mut leaving)
                .await
                .is_err(),
            "owner withdrawal must wait until the Welcome physical handoff finishes"
        );
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        leaving.await.unwrap().unwrap();
        let terminal = owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await;
        assert!(
            fixture_delivery_step(pool, agent, &agent.station_id, &input)
                .await
                .is_err(),
            "an undelivered Welcome cannot inherit its controller's old membership"
        );
        assert_eq!(
            owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await,
            terminal
        );
        return;
    }
    if matches!(case, OwnedWelcomeCase::AcceptedKeyRevoke) {
        let at =
            chrono::Utc::now().max(key_commit.committed_at + chrono::TimeDelta::milliseconds(1));
        let payload = arkret_models_collaboration::events_payloads::agent::AgentKeyRevokePayload {
            agent_id: agent.principal_id.clone(),
            key_id: arkret_wire::NonEmptyString::new(
                key_event.payload["verification_method"].as_str().unwrap(),
            )
            .unwrap(),
            revoked_by: controller.principal_id.clone(),
            revoked_at: at,
            reason: None,
        };
        let mut revoke = ordinary_realm::event_for_actor(
            EventKind::AgentKeyRevoke,
            arkret_wire::ScopeRef::Realm {
                realm_id: genesis.event.realm_id.clone(),
            },
            arkret_wire::ActorId::account(agent.clone()),
            serde_json::to_value(payload).unwrap(),
            at,
        );
        revoke.executed_by = key_event.executed_by.clone();
        revoke.authorization_ref = key_event.authorization_ref.clone();
        let revoke = device_authorization_history::sign_event(
            revoke,
            principal.history.device_verification_method.clone(),
            principal.history.founding_device_signing_seed,
        );
        let commit = sidecar_agent::station_successor(
            key_commit,
            &revoke,
            &principal.history.station_did,
            (at - key_commit.committed_at)
                .num_seconds()
                .saturating_add(1)
                .max(1),
        );
        Box::pin(historical_control_source::admit_control(
            &coland_storage_postgres::PgActorProfileStore { pool: pool.clone() },
            pool,
            coland_storage::AgentControlAdmissionWrite {
                commit: coland_storage::AuthorityCommitTransaction {
                    expected_authority: genesis.expected_authority.clone(),
                    event: revoke,
                    commit: commit.clone(),
                    producer_signer_fact: None,
                    mls_state: None,
                    welcomes: Vec::new(),
                    recipient_queue_capacity: 0,
                },
                queued_at: commit.committed_at,
            },
        ))
        .await
        .unwrap();
        let terminal = owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await;
        assert!(
            fixture_delivery_step(pool, agent, &agent.station_id, &input)
                .await
                .is_err(),
            "accepted key revocation forbids the old endpoint's future Welcome"
        );
        assert_eq!(
            owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await,
            terminal
        );
        return;
    }

    let mut missing = input.clone();
    missing.qualified_agent_scope_evidence = None;
    let mut recipient = input.clone();
    recipient.future_materials[0].recipient_actor_id =
        arkret_wire::ActorId::account(controller.clone());
    let mut changed = input.clone();
    changed.future_materials[0].ciphertext_b64 = arkret_wire::Base64UrlString::new("AQ").unwrap();
    let mut unsigned = serde_json::to_value(&changed.future_materials[0]).unwrap();
    unsigned.as_object_mut().unwrap().remove("producer_proof");
    changed.future_materials[0].producer_proof =
        arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            principal.history.device_verification_method.clone(),
            welcome.producer_proof.created_at,
            &ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed),
        )
        .unwrap();
    let mut service_only = input.clone();
    service_only
        .agent_session_scope
        .as_mut()
        .unwrap()
        .0
        .retain(|action| action != arkret_wire::CapabilityActionId::EventRead.as_str());
    let mut expired = input.clone();
    expired.credential_expires_at = Some(chrono::Utc::now() - chrono::TimeDelta::seconds(1));
    let mut foreign = input.clone();
    let foreign_realm = &principal.unit.transactions[0].event.realm_id;
    let map = &mut foreign.agent_session_scope.as_mut().unwrap().1;
    map.insert("realm_ids".into(), serde_json::json!([foreign_realm]));
    map.insert(
        "resources".into(),
        serde_json::json!({"realm_ids":[foreign_realm],"strand_ids":[]}),
    );
    for (label, rejected) in [
        ("missing verified custody", missing),
        ("wrong recipient", recipient),
        (
            "same Welcome id with validly signed different bytes",
            changed,
        ),
        ("queue operation without the content ceiling", service_only),
        ("expired original credential", expired),
        ("another Realm's issuer scope", foreign),
    ] {
        assert!(
            fixture_delivery_step(pool, agent, &agent.station_id, &rejected)
                .await
                .is_err(),
            "{label}"
        );
        assert_eq!(
            owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await,
            before,
            "{label}"
        );
    }

    // Fault injection changes only the exact source being queried. Restoration
    // is followed by a real positive to exclude blanket rejection of Welcomes.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE mls_welcome_deliveries SET state='delivered',delivered_at=now() WHERE welcome_id=$1")
        .bind::<Text,_>(welcome.welcome_id.as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    let terminal = owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await;
    let error = fixture_delivery_step(pool, agent, &agent.station_id, &input)
        .await
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("future material queue source changed")
    );
    assert_eq!(
        owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await,
        terminal
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE mls_welcome_deliveries SET state='queued',delivered_at=NULL WHERE welcome_id=$1",
    )
    .bind::<Text, _>(welcome.welcome_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let restored = fixture_delivery_step(pool, agent, &agent.station_id, &input)
        .await
        .unwrap()
        .unwrap();
    assert!(restored.permits_handoff());
    restored.finish().await.unwrap();
    assert_eq!(
        owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await,
        before
    );

    let mut previous = realm_parent.clone();
    let mut revision = None;
    for operation in ["read", "deliver"] {
        previous = Box::pin(import_agent_management_policy(
            pool, &previous, controller, revision, "deny", operation,
        ))
        .await;
        revision = Some(arkret_wire::CurrentRevision {
            commit_id: previous.commit.commit_id.clone(),
            stream_position: previous.commit.stream_position,
        });
        let denied = owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await;
        let error = fixture_delivery_step(pool, agent, &agent.station_id, &input)
            .await
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("Agent management refuses content disclosure"),
            "the exact {operation} ceiling must reject at its registered management gate: {error}"
        );
        assert_eq!(
            owned_welcome_footprint(pool, realm, &genesis.event.realm_id).await,
            denied
        );
    }
}

#[tokio::test]
async fn owned_agent_welcome_delivery_requires_current_cut_and_exact_queued_bytes() {
    boxed_owned_welcome(OwnedWelcomeCase::CurrentCutAndBytes).await;
}

#[tokio::test]
async fn owned_agent_welcome_delivery_holds_owner_cut_until_physical_handoff() {
    boxed_owned_welcome(OwnedWelcomeCase::HeldOwnerWithdrawal).await;
}

#[tokio::test]
async fn owned_agent_welcome_delivery_rejects_accepted_runtime_key_revocation() {
    boxed_owned_welcome(OwnedWelcomeCase::AcceptedKeyRevoke).await;
}

fn boxed_owned_welcome(case: OwnedWelcomeCase) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(consumed_sidecar_agent_scenario(Some(case)))
}

async fn consumed_sidecar_agent_scenario(future_case: Option<OwnedWelcomeCase>) {
    use coland_storage::AgentControlAdmissionWrite;
    let (database, resolution, principal, create, agent_did, agent, genesis,
        key_event, key_commit, join, delegation, station_did, historical_station, content_scope) = Box::pin(async {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let notary_public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[83; 32]).verifying_key().as_bytes(),
        );
        let historical_station = if future_case.is_some() {
            historical_control_source::HistoricalControlStation::new_with_assertion_keys(
                "sidecar-owned-welcome", [83; 32], &[("notary-key", &notary_public)],
            )
        } else {
            historical_control_source::HistoricalControlStation::new(
                "sidecar-consumed-control", [83; 32],
            )
        };
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
        let create = ordinary_realm::source_request(&pool, create).await;
        fixture_commit_step(&pool, create.clone()).await.unwrap();
        let realm_id = &create.authority_commit.event.realm_id;
        let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
        let content_scope = Some({
            let mut scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope =
                serde_json::from_value(serde_json::json!({
                    "actions":[arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
                        arkret_wire::CapabilityActionId::EventRead],
                    "resources":[{"kind":"operation","operation":arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1},
                        {"kind":"realm","realm_id":realm_id}]
                })).unwrap();
            scope.actions = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(&scope.actions).unwrap();
            scope
        });
        let agent_did = historical_control_source::managed_agent_did(
            &controller.principal_id,"owned-sidecar-agent",
            principal.unit.transactions[1].commit.committed_at,
        );
        let (agent, genesis, provision_ref) = provision_owned_agent_with_did_and_scope(
            &pool, &principal, agent_did.clone(), content_scope.as_ref(),
        ).await;
        let no_key = read(&pool, realm_id, &sidecar, controller)
            .await
            .unwrap()
            .unwrap();
        assert!(no_key.desired_agent_ids.is_empty());
        assert!(no_key.authority_stream_head.contains(&provision_ref));
        let delegation = format!("{agent_did}#managed-controller");
        let mut authorization = sidecar_agent::agent_key_authorization(
            &agent_did, &controller.principal_id, genesis.commit.committed_at,
        );
        if let Some(scope) = &content_scope {
            authorization["agent_key_scope"] = serde_json::to_value(scope).unwrap();
            authorization["audience"] = serde_json::json!([historical_station.core]);
        }
        let key_event = sidecar_agent::agent_control_event(
            &principal.history.device_verification_method,
            principal.history.founding_device_signing_seed,
            controller, &agent, &genesis.event.realm_id, &delegation,
            authorization, genesis.commit.committed_at,
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
        fixture_commit_step(&pool, join.clone()).await.unwrap();
        (database, resolution, principal, create, agent_did, agent, genesis,
            key_event, key_commit, join, delegation, station_did, historical_station, content_scope)
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
    let completed = Box::pin(async {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
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
        let mut record = if content_scope.is_some() {
            coland_storage::AgentStore::get(
                &coland_storage_postgres::PgAgentStore { pool: pool.clone() }, agent.principal_id.as_str(),
            ).await.unwrap().unwrap()
        } else {
            coland_storage::AgentPrincipalRecord::new(
            agent.principal_id.to_string(),
            controller.principal_id.to_string(),
            genesis.event.realm_id.to_string(),
            arkret_wire::DidUrl::new(delegation.clone()).unwrap(),
            arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
            genesis.commit.committed_at,
        )
        };
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
        fixture_commit_step(&pool, request.clone()).await.unwrap();
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
            .collect::<Vec<_>>();
        // Both actual private groups inherit the exact accepted Add/claim
        // endpoint bindings; the public tree alone is not an authority map.
        group
            .install_verified_leaf_bindings(bindings.clone())
            .unwrap();
        recipient_group
            .install_verified_leaf_bindings(bindings)
            .unwrap();
        assert_eq!(
            recipient_group.export_state_record().unwrap().epoch,
            base.epoch + 1
        );
        if let Some(case) = future_case {
            let endpoint = coland_storage::AgentEndpointGuard {
                pcr_realm_id: genesis.event.realm_id.clone(), agent_id: agent.principal_id.clone(),
                authorization_ref: arkret_wire::CommittedEventRef {
                    event_id: key_event.event_id.clone(), commit_id: key_commit.commit_id.clone(),
                    stream_ref: key_commit.stream_ref.clone(), stream_position: key_commit.stream_position,
                },
                verification_method: method.clone(),
            };
            let scope = content_scope.as_ref().unwrap();
            let (vault, evidence) = Box::pin(retain_delivery_scope_for_runtime(
                &pool, &historical_station, &principal, &agent, &key_event, scope, &endpoint, true,
            )).await;
            if matches!(case, OwnedWelcomeCase::DeviceMessagesContinuationOwnerLeave | OwnedWelcomeCase::DeviceMessagesContinuationPolicyDeny | OwnedWelcomeCase::DeviceMessagesOwnerLeave | OwnedWelcomeCase::DeviceMessagesPolicyDeny) {
                let input = Box::new(OwnedConsumerDeviceFlow {
                    pool: pool.clone(), station: historical_station.clone(),
                    principal: principal.clone(), agent: agent.clone(), endpoint,
                    vault, delivery: delivery.clone(), realm: realm_id.clone(),
                    controller_group: group, public_tracker: tracker,
                    realm_template: join.authority_commit.clone(),
                    key_event: key_event.clone(), key_commit: key_commit.clone(),
                    continuation: matches!(case, OwnedWelcomeCase::DeviceMessagesContinuationOwnerLeave | OwnedWelcomeCase::DeviceMessagesContinuationPolicyDeny),
                    policy_deny: matches!(case, OwnedWelcomeCase::DeviceMessagesContinuationPolicyDeny | OwnedWelcomeCase::DeviceMessagesPolicyDeny),
                });
                // Keep the complete accepted fixture, but do not poll recipient
                // HTTP/MLS work beneath the large original Welcome scenario.
                fixture_step(Box::pin(owned_consumer_device_flow(input))).await;
                return None;
            }
            let future_pool = pool.clone();
            let future_principal = principal.clone();
            let future_agent = agent.clone();
            let future_genesis = genesis.clone();
            let future_key_event = key_event.clone();
            let future_key_commit = key_commit.clone();
            let future_parent = join.authority_commit.clone();
            let future_delivery = delivery.clone();
            let future_scope = scope.clone();
            // Poll the delivery cut on its own ordinary Tokio task rather
            // than nesting it beneath the large real MLS preparation frame.
            tokio::spawn(async move {
                Box::pin(owned_welcome_held_delivery_scenario(
                    &future_pool, &future_principal, &future_agent, &future_genesis,
                    &future_key_event, &future_key_commit, &future_parent,
                    &future_delivery, endpoint, evidence, &future_scope, case,
                )).await;
            }).await.unwrap();
            // The real recipient joined these exact producer-signed Welcome
            // bytes above. No consume/ACK is synthesized by this delivery test.
            return None;
        }
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
        Some((request, group, recipient_group))
    })
        .await;
    let Some((request, mut group, mut recipient_group)) = completed else {
        return;
    };
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
    provision_owned_agent_with_did_and_scope(pool, principal, agent_did, None).await
}

async fn provision_owned_agent_with_did_and_scope(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent_did: arkret_wire::Did,
    requested_scope: Option<&arkret_models_collaboration::events_payloads::agent::AgentKeyScope>,
) -> (
    arkret_wire::AccountId,
    coland_storage::AuthorityCommitTransaction,
    arkret_wire::EventId,
) {
    provision_owned_agent_binding_phase(
        pool,
        principal,
        agent_did,
        requested_scope,
        true,
        None,
        &[102; 32],
    )
    .await
}

async fn provision_owned_agent_binding_phase(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent_did: arkret_wire::Did,
    requested_scope: Option<&arkret_models_collaboration::events_payloads::agent::AgentKeyScope>,
    publish_binding: bool,
    prepared_inception: Option<&arkret_signatures::webvh::PreparedPrincipalInception>,
    current_root_seed: &[u8; 32],
) -> (
    arkret_wire::AccountId,
    coland_storage::AuthorityCommitTransaction,
    arkret_wire::EventId,
) {
    provision_owned_agent_binding_phase_at_head(
        pool,
        principal,
        agent_did,
        requested_scope,
        publish_binding,
        prepared_inception,
        current_root_seed,
        None,
    )
    .await
}

async fn provision_owned_agent_binding_phase_at_head(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent_did: arkret_wire::Did,
    requested_scope: Option<&arkret_models_collaboration::events_payloads::agent::AgentKeyScope>,
    publish_binding: bool,
    prepared_inception: Option<&arkret_signatures::webvh::PreparedPrincipalInception>,
    current_root_seed: &[u8; 32],
    accepted_controller_head: Option<&arkret_wire::RealmCommit>,
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
    // Ordinary fixtures publish real inception + entry1 too. A genesis-only
    // active row is retained only in the explicit incomplete-bootstrap test.
    let default_scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope = serde_json::from_value(serde_json::json!({
        "actions":["ak.self.events.command.submit.v1","ak.self.committed_event.read.scan.v1","ak.self.committed_event.stream.subscribe.v1"],
        "resources":[
            {"kind":"operation","operation":"ak.self.events.command.submit.v1"},
            {"kind":"operation","operation":"ak.self.committed_event.read.scan.v1"},
            {"kind":"operation","operation":"ak.self.committed_event.stream.subscribe.v1"}
        ]
    })).unwrap();
    let requested_scope = Some(requested_scope.unwrap_or(&default_scope));
    let controller = principal.history.account.clone();
    let station = controller.station_id.clone();
    let station_did = principal.history.station_did.clone();
    let controller_realm = principal.unit.transactions[0].event.realm_id.clone();
    let controller_head = accepted_controller_head
        .unwrap_or(&principal.unit.transactions[1].commit)
        .clone();
    let controller_authority = principal.unit.transactions[1].expected_authority.clone();
    let controller_method = principal.history.device_verification_method.clone();
    let controller_seed = principal.history.founding_device_signing_seed;
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let agent = AccountId::new(agent_id.clone(), station.clone());
    let delegation = format!("{agent_did}#managed-controller");
    let scoped_inception = requested_scope.map(|_| {
        if let Some(prepared) = prepared_inception {
            assert_eq!(prepared.did, agent_did.as_str());
            return prepared.clone();
        }
        let local_id = agent_did.as_str().rsplit(':').next().unwrap();
        let endpoint = "https://agent-fixture.example/".parse().unwrap();
        let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[102; 32])
                .verifying_key()
                .as_bytes(),
        );
        let inception = arkret_signatures::webvh::prepare_agent_inception(
            &arkret_signatures::webvh::AgentInceptionInput {
                principal_endpoint: &endpoint,
                local_id,
                controller_principal_id: &controller.principal_id,
                version_time: controller_head.committed_at,
                root_seed: &[101; 32],
                next_root_public_key_multibase: &next,
            },
        )
        .unwrap();
        assert_eq!(inception.did, agent_did.as_str());
        inception
    });
    let initial_resolution = scoped_inception.as_ref().map_or_else(
        || arkret_models_identity::ResolutionCommitment {
            did: agent_did.clone(),
            method_history_head: format!("sha256:{}", "c".repeat(64)),
            version_id: "1-agent".to_owned(),
        },
        |inception| arkret_models_identity::ResolutionCommitment {
            did: agent_did.clone(),
            method_history_head: arkret_canonical::canonical_sha256(&inception.log_entry).unwrap(),
            version_id: inception.version_id.clone(),
        },
    );
    let genesis = device_authorization_history::sign_event(
        arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
            payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                agent_id: agent_id.clone(),
                governance_station_id: station.clone(),
                initial_resolution: initial_resolution.clone(),
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
    let provision = if let Some(scope) = requested_scope {
        let mut provision = provision;
        provision.payload.insert(
            "requested_scope_digest".into(),
            serde_json::json!(
                arkret_models_collaboration::agent_scope::agent_requested_scope_digest(
                    &agent_id,
                    &controller.principal_id,
                    scope,
                )
                .unwrap()
            ),
        );
        device_authorization_history::sign_event(
            provision,
            controller_method.clone(),
            controller_seed,
        )
    } else {
        provision
    };
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

    if let Some(scope) = requested_scope {
        use coland_storage::DeliveryPolicyStoreRegistry as _;
        let inception = scoped_inception.unwrap();
        let digest = arkret_models_collaboration::agent_scope::agent_requested_scope_digest(
            &agent_id,
            &controller.principal_id,
            scope,
        )
        .unwrap();
        let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[103; 32])
                .verifying_key()
                .as_bytes(),
        );
        let update = arkret_signatures::webvh::prepare_agent_binding_update(
            &arkret_signatures::webvh::AgentBindingUpdateInput {
                did: agent_did.as_str(),
                local_id: &inception.local_id,
                previous_entries: std::slice::from_ref(&inception.log_entry),
                version_time: genesis_commit.committed_at,
                current_root_seed,
                next_root_public_key_multibase: &next,
                controller_principal_id: &controller.principal_id,
                principal_control_realm_id: &agent_pcr,
                requested_scope_digest: &digest,
            },
        )
        .unwrap();
        let entries = if publish_binding {
            vec![inception.log_entry, update.log_entry]
        } else {
            vec![inception.log_entry]
        };
        arkret_identity::verify_did_webvh_v1_chain(&agent_did, &entries).unwrap();
        let persistence = PgPersistenceStore::new(pool.clone());
        for (index, entry) in entries.iter().enumerate() {
            persistence
                .webvh()
                .append_log_event(coland_storage::WebvhLogRecord {
                    event_digest: arkret_canonical::canonical_sha256(entry).unwrap(),
                    did: agent_did.to_string(),
                    seq: index as u64 + 1,
                    created_at: entry["versionTime"].as_str().unwrap().parse().unwrap(),
                    operation: entry.clone(),
                })
                .await
                .unwrap();
        }
        let now = chrono::Utc::now();
        persistence
            .webvh()
            .put_document(coland_storage::WebvhDocumentRecord {
                did: agent_did.to_string(),
                did_document: entries.last().unwrap()["state"].clone(),
                key_log_head: Some(
                    arkret_canonical::canonical_sha256(entries.last().unwrap()).unwrap(),
                ),
                seq: entries.len() as u64,
                method_evidence: serde_json::Value::Null,
                fetched_at: now,
                expires_at: now + chrono::TimeDelta::minutes(15),
                updated_at: now,
            })
            .await
            .unwrap();
        let mut record = coland_storage::AgentPrincipalRecord::new(
            agent_id.to_string(),
            controller.principal_id.to_string(),
            agent_pcr.to_string(),
            arkret_wire::DidUrl::new(delegation).unwrap(),
            arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
            genesis_commit.committed_at,
        );
        record.requested_scope = Some(serde_json::to_value(scope).unwrap());
        record.provision_event_refs = Some(serde_json::json!({
            "provision_event_id": provision.event_id,
            "initial_resolution": initial_resolution,
        }));
        coland_storage::AgentStore::put(
            &coland_storage_postgres::PgAgentStore { pool: pool.clone() },
            record,
        )
        .await
        .unwrap();
    }
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
    boxed_ordinary_member_owned_agent_join().await;
}

// Keep the expanded real-transaction scenario outside the harness poll frame.
fn boxed_ordinary_member_owned_agent_join() -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(ordinary_member_owned_agent_join_scenario())
}

async fn ordinary_member_owned_agent_join_scenario() {
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
    uow.commit_event(agent_join.clone()).await.unwrap();

    // Exercise admitted Policy writes, not imported management projections.
    // The all-target join rule is the default for new Agents only; an explicit
    // higher-priority controller exception must not relax another operation.
    let realm_id = &agent_join.authority_commit.event.realm_id;
    let policy_id = "ak:policy:0198ff00-0000-7000-8000-000000000001";
    let make_policy = |previous: &coland_storage::AuthorityCommitTransaction,
                       revision: Option<arkret_wire::CurrentRevision>,
                       exception: bool| {
        let mut rules = vec![serde_json::json!({
            "rule_id":"new_agents", "kind":"agent", "effect":"deny",
            "agent_target":{"kind":"all"}, "agent_operations":["join"]
        })];
        if exception {
            rules.push(serde_json::json!({
                "rule_id":"controller_exception", "kind":"agent", "priority":10,
                "effect":"allow", "agent_target":{"kind":"controller", "controller_account_id":controller},
                "agent_operations":["join"]
            }));
        }
        ordinary_realm::next_request_for_actor(
            previous,
            EventKind::PolicySet,
            arkret_wire::ActorId::account(founder.clone()),
            serde_json::json!({"policy_id":policy_id, "expected_revision":revision,
                "value":{"schema":"ak.schema.policy.v1", "id":policy_id, "realm_id":realm_id,
                    "policy_kind":"agent", "rules":rules, "default_effect":"allow",
                    "created_by":arkret_wire::ActorId::account(founder.clone()),
                    "created_at":previous.commit.committed_at}}),
            previous.commit.committed_at + chrono::TimeDelta::milliseconds(1),
        )
    };
    let ban = ordinary_realm::source_request(
        &pool,
        make_policy(&agent_join.authority_commit, None, false),
    )
    .await;
    let before_ban = agent_mode_footprint(&pool, realm_id).await;
    uow.commit_event(ban.clone()).await.unwrap();
    let revision = arkret_wire::CurrentRevision {
        commit_id: ban.authority_commit.commit.commit_id.clone(),
        stream_position: ban.authority_commit.commit.stream_position,
    };
    // Accepted retries retain their exact outcome rather than repeating CAS.
    let before_retry = agent_mode_footprint(&pool, realm_id).await;
    assert_eq!(before_retry["membership"], before_ban["membership"]);
    uow.commit_event(ban.clone()).await.unwrap();
    assert_eq!(agent_mode_footprint(&pool, realm_id).await, before_retry);
    uow.commit_event(agent_join.clone()).await.unwrap();
    assert_eq!(agent_mode_footprint(&pool, realm_id).await, before_retry);
    let removal = ordinary_realm::next_request_for_actor(
        &ban.authority_commit,
        EventKind::MemberState,
        arkret_wire::ActorId::account(founder.clone()),
        serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"leave"}),
        ban.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let removal = ordinary_realm::source_request(&pool, removal).await;
    uow.commit_event(removal.clone()).await.unwrap();
    let make_rejoin = |previous: &coland_storage::AuthorityCommitTransaction| {
        ordinary_realm::next_request_for_actor(
            previous,
            EventKind::MemberState,
            arkret_wire::ActorId::account(controller.clone()),
            serde_json::json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join",
                "agent_controller_binding":{"controller_account_id":controller,
                "controller_membership_generation_ref":member_join.authority_commit.event.event_id}}),
            previous.commit.committed_at + chrono::TimeDelta::milliseconds(1),
        )
    };
    let rejected =
        ordinary_realm::source_request(&pool, make_rejoin(&removal.authority_commit)).await;
    let before_rejection = agent_mode_footprint(&pool, realm_id).await;
    let error = uow.commit_event(rejected).await.unwrap_err();
    assert!(error.to_string().contains("forbids joining"), "{error}");
    assert_eq!(
        agent_mode_footprint(&pool, realm_id).await,
        before_rejection
    );
    let stale =
        ordinary_realm::source_request(&pool, make_policy(&removal.authority_commit, None, true))
            .await;
    assert!(uow.commit_event(stale).await.is_err());
    assert_eq!(
        agent_mode_footprint(&pool, realm_id).await,
        before_rejection
    );
    let exception = ordinary_realm::source_request(
        &pool,
        make_policy(&removal.authority_commit, Some(revision), true),
    )
    .await;
    uow.commit_event(exception.clone()).await.unwrap();
    let rejoin =
        ordinary_realm::source_request(&pool, make_rejoin(&exception.authority_commit)).await;
    uow.commit_event(rejoin).await.unwrap();
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
         'membership', (SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]'::jsonb) FROM member_state_current_results m WHERE realm_id=$1), \
         'policy', (SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY to_jsonb(p)::text),'[]'::jsonb) FROM policy_current_results p WHERE realm_id=$1), \
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
    let agent_did = arkret_wire::Did::new(inception.did.clone()).unwrap();
    let (agent, genesis, provision_ref) = provision_owned_agent_binding_phase(
        &pool,
        &principal,
        agent_did.clone(),
        None,
        true,
        Some(&inception),
        &[0x72; 32],
    )
    .await;
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
    // Publish Policy configurations enter through the production UOW. The
    // following mode writes still require their own exact approvals.
    let mut previous = initial.clone();
    let mut policy_revision = None;
    for effect in ["deny", "require_review", "allow"] {
        previous = import_agent_management_policy(
            &pool,
            &previous,
            controller,
            policy_revision,
            effect,
            "publish",
        )
        .await;
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
            previous = import_agent_management_policy(
                &pool,
                &previous,
                controller,
                policy_revision.take(),
                "deny",
                "publish",
            )
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

/// The lease covers real current dependencies until publication finishes.
/// This storage test does not substitute for HTTP service/key scope checks.
#[tokio::test]
async fn owned_agent_delivery_holds_current_cut_until_finish_and_cancel() {
    tokio::spawn(Box::pin(owned_agent_delivery_cut_scenario(
        DeliveryExpiryCase::NoExpiry,
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn owned_agent_delivery_rechecks_key_expiry_after_waiting_for_producer_lock() {
    tokio::spawn(Box::pin(owned_agent_delivery_cut_scenario(
        DeliveryExpiryCase::LockWait,
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn owned_agent_delivery_rechecks_key_expiry_at_physical_handoff() {
    tokio::spawn(Box::pin(owned_agent_delivery_cut_scenario(
        DeliveryExpiryCase::HeldLease,
    )))
    .await
    .unwrap();
}

#[derive(Clone, Copy)]
enum DeliveryExpiryCase {
    NoExpiry,
    LockWait,
    HeldLease,
}

// This native delivery fixture imports the exact receipt after real accepted
// key history. The public custody owner still verifies the disclosure's real
// current Device proof and the signed native DID binding before it can be used.
struct DeliveryScopeVault {
    state: coland_http::state::AppState,
    config: coland_http::config::KeyStoreConfig,
    directory: std::path::PathBuf,
}
impl DeliveryScopeVault {
    fn reopen(&self) -> coland_http::state::AppState {
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
async fn retain_delivery_scope(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    principal: &pcr_genesis::PcrGenesisFixture,
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

async fn retain_delivery_scope_for_runtime(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent: &arkret_wire::AccountId,
    key_event: &arkret_wire::Event,
    scope: &arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    endpoint: &coland_storage::AgentEndpointGuard,
    activate_runtime: bool,
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
    config.trust_domain =
        arkret_wire::TrustDomainId::new("ak:trust_domain:pcr-contract.example").unwrap();
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
    let approval_request_id =
        arkret_wire::OpaqueLocalId::new(format!("agent_runtime_approval:{}", uuid::Uuid::now_v7()))
            .unwrap();
    let now = chrono::Utc::now();
    let runtime_key = ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]);
    let runtime = arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
        &runtime_key,
        arkret_models_collaboration::agent_operations::AgentPairingBootstrap {
            runtime_identity: None,
            arkret_base_url: "https://agent-delivery-cut.example/".to_owned(),
            service_id: station.core.clone(),
            agent_id: agent.principal_id.clone(),
            pairing_request_id: pairing_request_id.clone(),
            pairing_code: "01234567".to_owned(),
            pairing_expires_at: now + chrono::TimeDelta::minutes(5),
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
            .get(&principal.history.account)
            .await
            .unwrap()
            .unwrap()
            .pk,
    );
    record.pairing_request_id = Some(pairing_request_id.clone());
    record.pairing_code = Some("01234567".to_owned());
    record.pairing_expires_at = Some(now + chrono::TimeDelta::minutes(5));
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
                now + chrono::TimeDelta::minutes(5),
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
        controller_principal_id: principal.history.account.principal_id.clone(),
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
            verification_method: principal.history.device_verification_method.clone(),
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
        &ed25519_dalek::SigningKey::from_bytes(&principal.history.founding_device_signing_seed),
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
    let reference = state
        .verify_and_retain_agent_scope_custody(&body)
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
        .bind::<Text,_>(principal.history.account.principal_id.as_str()).bind::<Text,_>(pairing_request_id.as_str())
        .bind::<Text,_>(approval_request_id.as_str()).bind::<Text,_>(runtime_digest.as_str())
        .bind::<Text,_>(&request_digest).bind::<Text,_>(raw_key_digest.as_str())
        .bind::<Timestamptz,_>(now + chrono::TimeDelta::minutes(5))
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
    let evidence = cold.qualified_agent_scope_evidence(endpoint).await.unwrap();
    assert_eq!(evidence.custody_ref(), &reference);
    assert_eq!(evidence.command().authorize_event.event, *key_event);
    // A closed presentation window does not erase previously qualified custody.
    let wait = evidence.command().requested_scope_disclosure.expires_at - chrono::Utc::now();
    if wait > chrono::TimeDelta::zero() {
        tokio::time::sleep(wait.to_std().unwrap() + std::time::Duration::from_millis(2)).await;
    }
    assert!(chrono::Utc::now() > evidence.command().requested_scope_disclosure.expires_at);
    let reopened = vault
        .reopen()
        .qualified_agent_scope_evidence(endpoint)
        .await
        .unwrap();
    assert_eq!(reopened.custody_ref(), evidence.custody_ref());
    (vault, reopened)
}

async fn owned_agent_delivery_cut_scenario(expiry_case: DeliveryExpiryCase) {
    use arkret_wire::{ActorId, CommittedEventFullView, CommittedEventView};
    use coland_storage::{AccountContentDeliveryInput, AgentControlAdmissionWrite};
    use diesel_async::RunQueryDsl;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let notary_public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        ed25519_dalek::SigningKey::from_bytes(&[83; 32])
            .verifying_key()
            .as_bytes(),
    );
    let station = historical_control_source::HistoricalControlStation::new_with_assertion_keys(
        "agent-delivery-cut",
        [83; 32],
        &[("notary-key", &notary_public)],
    );
    let principal = accepted_controller(&pool, station.did.clone()).await;
    let controller = &principal.history.account;
    let founder = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        station.did.clone(),
        "delivery-founder",
    )
    .await;
    let realm = ordinary_realm::bootstrap_unit_with_history_for_account(
        "agent-delivery-cut",
        "public",
        "since_join",
        &founder,
        &station.did,
    );
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    fixture_bootstrap_step(&pool, &realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let controller_join = ordinary_realm::next_request_for_actor(
        parent,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        serde_json::json!({"member_id":ActorId::account(controller.clone()),"membership":"join"}),
        parent.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let controller_join = ordinary_realm::source_request(&pool, controller_join).await;
    fixture_commit_step(&pool, controller_join.clone())
        .await
        .unwrap();
    let mut content_scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope =
        serde_json::from_value(serde_json::json!({
            "actions":[arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                arkret_wire::ServiceOperationId::SELF_REALM_READ_EXPORT_V1,
                arkret_wire::CapabilityActionId::EventRead,
                arkret_wire::CapabilityActionId::ObjectRead,
                arkret_wire::CapabilityActionId::StrandRead],
            "resources":[{"kind":"operation","operation":arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1},
                {"kind":"operation","operation":arkret_wire::ServiceOperationId::SELF_REALM_READ_EXPORT_V1},
                {"kind":"realm","realm_id":parent.event.realm_id}]
        })).unwrap();
    content_scope.actions =
        arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(&content_scope.actions)
            .unwrap();
    let agent_did = historical_control_source::managed_agent_did(
        &controller.principal_id,
        "delivery-scoped-agent",
        principal.unit.transactions[1].commit.committed_at,
    );
    let (agent, genesis, _) = provision_owned_agent_with_did_and_scope(
        &pool,
        &principal,
        agent_did,
        Some(&content_scope),
    )
    .await;
    let payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.event.payload).unwrap()).unwrap();
    let agent_did = payload.object.initial_resolution.unwrap().did;
    let expiry = chrono::Utc::now() + chrono::TimeDelta::seconds(10);
    let mut authorization = sidecar_agent::agent_key_authorization(
        &agent_did,
        &controller.principal_id,
        genesis.commit.committed_at,
    );
    authorization["agent_key_scope"] = serde_json::to_value(&content_scope).unwrap();
    authorization["audience"] = serde_json::json!([station.core]);
    if !matches!(expiry_case, DeliveryExpiryCase::NoExpiry) {
        authorization["expires_at"] =
            serde_json::json!(arkret_canonical::format_timestamp_canonical(expiry));
    }
    let key_event = sidecar_agent::agent_control_event(
        &principal.history.device_verification_method,
        principal.history.founding_device_signing_seed,
        controller,
        &agent,
        &genesis.event.realm_id,
        &format!("{agent_did}#managed-controller"),
        authorization,
        genesis.commit.committed_at,
    );
    let key_commit = sidecar_agent::station_successor(&genesis.commit, &key_event, &station.did, 1);
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
    let agent_join = ordinary_realm::next_request_for_actor(
        &controller_join.authority_commit,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        serde_json::json!({"member_id":ActorId::account(agent.clone()),"membership":"join",
        "agent_controller_binding":{"controller_account_id":controller,"controller_membership_generation_ref":controller_join.authority_commit.event.event_id}}),
        key_commit
            .committed_at
            .max(controller_join.authority_commit.commit.committed_at)
            + chrono::TimeDelta::milliseconds(1),
    );
    let agent_join = ordinary_realm::source_request(&pool, agent_join).await;
    fixture_commit_step(&pool, agent_join.clone())
        .await
        .unwrap();
    let full = CommittedEventView::Full(CommittedEventFullView {
        event: agent_join.authority_commit.event.clone(),
        commit: agent_join.authority_commit.commit.clone(),
    });
    let mut input = AccountContentDeliveryInput::committed(std::slice::from_ref(&full));
    input.agent_endpoint = Some(coland_storage::AgentEndpointGuard {
        pcr_realm_id: genesis.event.realm_id.clone(),
        agent_id: agent.principal_id.clone(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: key_event.event_id.clone(),
            commit_id: key_commit.commit_id.clone(),
            stream_ref: key_commit.stream_ref.clone(),
            stream_position: key_commit.stream_position,
        },
        verification_method: arkret_wire::DidUrl::new(
            key_event.payload["verification_method"].as_str().unwrap(),
        )
        .unwrap(),
    });
    let (_vault, evidence) = retain_delivery_scope(
        &pool,
        &station,
        &principal,
        &agent,
        &key_event,
        &content_scope,
        input.agent_endpoint.as_ref().unwrap(),
    )
    .await;
    let missing = fixture_delivery_step(&pool, &agent, &agent.station_id, &input).await;
    assert!(
        missing.is_err(),
        "a private Agent row and matching digest cannot authorize delivery"
    );
    input.qualified_agent_scope_evidence = Some(evidence.clone());
    let mut wrong_custody = input.clone();
    let mut different_ref = evidence.custody_ref().clone();
    different_ref.content_digest =
        arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
    wrong_custody.qualified_agent_scope_evidence = Some(
        coland_storage::VerifiedAgentScopeEvidence::from_verified_custody(
            different_ref,
            evidence.command().clone(),
            evidence.accepted_binding().clone(),
            evidence.runtime_key_binding_digest().to_owned(),
            evidence.request_digest().to_owned(),
            evidence.accepted_authorization_ref().clone(),
        ),
    );
    assert!(
        fixture_delivery_step(&pool, &agent, &agent.station_id, &wrong_custody)
            .await
            .is_err(),
        "a substituted custody reference cannot inherit the durable receipt"
    );
    let mut delivery_parent = agent_join.authority_commit.clone();
    if matches!(expiry_case, DeliveryExpiryCase::NoExpiry) {
        let created_at = delivery_parent.commit.committed_at + chrono::TimeDelta::milliseconds(1);
        let strand = ordinary_realm::next_request_for_actor(
            &delivery_parent,
            EventKind::StrandCreate,
            ActorId::account(founder.clone()),
            serde_json::json!({"object":{"schema":"ak.schema.strand.v1",
                "realm_id":delivery_parent.event.realm_id,
                "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":"Delivery watch target"},"state":"active",
                "created_by":ActorId::account(founder.clone()),
                "created_at":arkret_canonical::format_timestamp_canonical(created_at)}}),
            created_at,
        );
        let mut strand = ordinary_realm::source_request(&pool, strand).await;
        let operation_id = format!("ak:operation:{}", uuid::Uuid::now_v7());
        assert_eq!(strand.projections.len(), 1);
        assert_eq!(
            strand.projections[0].event_id,
            strand.authority_commit.event.event_id.as_str()
        );
        strand.projections[0].operation_id = Some(operation_id.clone());
        fixture_commit_step(&pool, strand.clone()).await.unwrap();
        delivery_parent = strand.authority_commit;
        let request =
            arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody {
                realm_id: delivery_parent.event.realm_id.clone(),
                strand_id: arkret_wire::StrandId::from_event_id(&delivery_parent.event.event_id),
                watcher_actor_id: ActorId::account(agent.clone()),
            };
        let coland_storage::SelfExactCurrentRead::Answer(outcome) =
            fixture_strand_watch_current_step(&pool, &request, &agent, &agent.station_id)
                .await
                .unwrap()
        else {
            panic!("native watch absence must be proved");
        };
        assert!(matches!(outcome,
            arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome::NeverWritten { .. }));
        input.watch_reads.push((request.clone(), outcome.clone()));
        let mut wrong_watcher = input.clone();
        wrong_watcher.watch_reads[0].0.watcher_actor_id = ActorId::account(controller.clone());
        let before = agent_mode_footprint(&pool, &request.realm_id).await;
        assert!(
            fixture_delivery_step(&pool, &agent, &agent.station_id, &wrong_watcher)
                .await
                .is_err(),
            "owner watch identity cannot replace the actual Agent"
        );
        assert_eq!(agent_mode_footprint(&pool, &request.realm_id).await, before);
        let (export, export_sources) = fixture_realm_export_step(
            &pool,
            &request.realm_id,
            &ActorId::account(agent.clone()),
            &agent.station_id,
        )
        .await
        .unwrap()
        .expect("a qualified current Agent can read its canonical Realm export");
        assert!(export.events.iter().any(|row| {
            row.get("event_id").and_then(serde_json::Value::as_str)
                == Some(delivery_parent.event.event_id.as_str())
        }));
        assert_eq!(export.operations.len(), 1);
        assert_eq!(export.operations[0]["operation_id"], operation_id);
        assert_eq!(export.operations[0]["operation_type"], "create");
        assert_eq!(export_sources.len(), export.events.len());
        let mut export_connection = pool.get().await.unwrap();
        diesel::sql_query("UPDATE projection_events p SET payload=$2 FROM realm_commits c WHERE c.event_pk=p.event_pk AND c.commit_json->>'event_ref'=$1")
            .bind::<diesel::sql_types::Text,_>(delivery_parent.event.event_id.as_str())
            .bind::<diesel::sql_types::Jsonb,_>(serde_json::json!({"forged":true}))
            .execute(&mut export_connection).await.unwrap();
        assert!(
            fixture_realm_export_step(
                &pool,
                &request.realm_id,
                &ActorId::account(agent.clone()),
                &agent.station_id,
            )
            .await
            .is_err(),
            "a substituted projection payload is not an accepted Event source"
        );
        diesel::sql_query("UPDATE projection_events p SET payload=$2 FROM realm_commits c WHERE c.event_pk=p.event_pk AND c.commit_json->>'event_ref'=$1")
            .bind::<diesel::sql_types::Text,_>(delivery_parent.event.event_id.as_str())
            .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(&delivery_parent.event.payload).unwrap())
            .execute(&mut export_connection).await.unwrap();
        drop(export_connection);
        let mut export_input = input.clone();
        export_input.realm_exports.push(export.clone());
        export_input.committed_events.extend(export_sources);
        let guard = fixture_delivery_step(&pool, &agent, &agent.station_id, &export_input)
            .await
            .unwrap()
            .unwrap();
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        let mut substituted = export_input.clone();
        let row = substituted.realm_exports[0]
            .events
            .iter_mut()
            .find(|row| {
                row.get("event_id").and_then(serde_json::Value::as_str)
                    == Some(delivery_parent.event.event_id.as_str())
            })
            .unwrap();
        row.insert("payload".into(), serde_json::json!({"forged":true}));
        assert!(
            fixture_delivery_step(&pool, &agent, &agent.station_id, &substituted)
                .await
                .is_err(),
            "a canonical Event ID cannot authorize substituted export content"
        );
        let mut omitted = export_input.clone();
        omitted.realm_exports[0].events.clear();
        omitted.realm_exports[0].operations.clear();
        omitted.committed_events.clear();
        assert!(
            fixture_delivery_step(&pool, &agent, &agent.station_id, &omitted)
                .await
                .is_err(),
            "an empty export cannot bypass complete current output validation"
        );
        assert_eq!(agent_mode_footprint(&pool, &request.realm_id).await, before);
        input = export_input;
    }
    let realm_id = &agent_join.authority_commit.event.realm_id;
    let before = agent_mode_footprint(&pool, realm_id).await;
    if matches!(expiry_case, DeliveryExpiryCase::NoExpiry) {
        let scope_details = serde_json::json!({
            "controller_principal_id":controller.principal_id,
            "agent_key_authorization_ref":key_event.event_id,
            "realm_ids":[realm_id],"strand_ids":[],
            "resources":{"realm_ids":[realm_id],"strand_ids":[]},
            "constraints":{"allowed_tracks":[],"allowed_data_labels":[],"allowed_endpoints":[]},
            "capability_grant_refs":[],"policy_refs":[]
        })
        .as_object()
        .unwrap()
        .clone();
        input.credential_expires_at = Some(chrono::Utc::now() + chrono::TimeDelta::minutes(10));
        assert!(
            fixture_delivery_step(&pool, &agent, &agent.station_id, &input)
                .await
                .is_err(),
            "credential delivery requires the issuer's complete scope"
        );
        input.agent_session_scope = Some((content_scope.actions.clone(), scope_details));
        let mut operation_only = input.clone();
        operation_only
            .agent_session_scope
            .as_mut()
            .unwrap()
            .0
            .retain(|action| action != arkret_wire::CapabilityActionId::EventRead.as_str());
        assert!(
            fixture_delivery_step(&pool, &agent, &agent.station_id, &operation_only)
                .await
                .is_err(),
            "the export operation scope cannot replace EventRead for exported content"
        );
        assert_eq!(agent_mode_footprint(&pool, realm_id).await, before);
        let mut other_realm = input.clone();
        let details = &mut other_realm.agent_session_scope.as_mut().unwrap().1;
        details.insert(
            "realm_ids".into(),
            serde_json::json!([principal.unit.transactions[0].event.realm_id]),
        );
        details.insert(
            "resources".into(),
            serde_json::json!({
                "realm_ids":[principal.unit.transactions[0].event.realm_id],"strand_ids":[]
            }),
        );
        assert!(
            fixture_delivery_step(&pool, &agent, &agent.station_id, &other_realm)
                .await
                .is_err(),
            "another Realm's valid session cannot disclose this Realm"
        );
        assert_eq!(agent_mode_footprint(&pool, realm_id).await, before);
    }
    if !matches!(expiry_case, DeliveryExpiryCase::NoExpiry) {
        let guard = fixture_delivery_step(&pool, &agent, &agent.station_id, &input)
            .await
            .unwrap()
            .unwrap();
        assert!(
            guard.permits_handoff(),
            "the same accepted key is initially current"
        );
        if matches!(expiry_case, DeliveryExpiryCase::HeldLease) {
            while chrono::Utc::now() <= expiry {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(
                !guard.permits_handoff(),
                "a held lock cannot keep an expired key alive"
            );
            guard.finish().await.unwrap();
        } else {
            guard.finish().await.unwrap();
            let mut blocker = pool.get().await.unwrap();
            diesel::sql_query("BEGIN")
                .execute(&mut *blocker)
                .await
                .unwrap();
            diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<diesel::sql_types::Text, _>(format!(
                    "agent-producer-current:{}:{}",
                    genesis.event.realm_id, agent.principal_id
                ))
                .execute(&mut *blocker)
                .await
                .unwrap();
            let waiting_store = PgAuthorityCommitStore { pool: pool.clone() };
            let waiting_agent = agent.clone();
            let mut waiting = tokio::spawn(async move {
                waiting_store
                    .acquire_committed_content_delivery(
                        &waiting_agent,
                        &waiting_agent.station_id,
                        &input,
                    )
                    .await
            });
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(200), &mut waiting)
                    .await
                    .is_err()
            );
            while chrono::Utc::now() <= expiry {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            diesel::sql_query("ROLLBACK")
                .execute(&mut *blocker)
                .await
                .unwrap();
            assert!(
                waiting.await.unwrap().is_err(),
                "pre-wait time cannot authorize the expired key"
            );
        }
        assert_eq!(agent_mode_footprint(&pool, realm_id).await, before);
        return;
    }
    let cancelled = fixture_delivery_step(&pool, &agent, &agent.station_id, &input)
        .await
        .unwrap()
        .unwrap();
    drop(cancelled);
    let guard = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture_delivery_step(&pool, &agent, &agent.station_id, &input),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    guard.finish().await.unwrap();
    assert_eq!(agent_mode_footprint(&pool, realm_id).await, before);
    let leave = ordinary_realm::next_request_for_actor(
        &delivery_parent,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        serde_json::json!({"member_id":ActorId::account(controller.clone()),"membership":"leave"}),
        delivery_parent.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let leave = ordinary_realm::source_request(&pool, leave).await;
    let guard = fixture_delivery_step(&pool, &agent, &agent.station_id, &input)
        .await
        .unwrap()
        .unwrap();
    let leave_pool = pool.clone();
    let mut leaving = tokio::spawn(async move {
        PgEventCommitUnitOfWork::new(leave_pool)
            .commit_event(leave)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut leaving)
            .await
            .is_err(),
        "withdrawal must wait for the active delivery cut"
    );
    guard.finish().await.unwrap();
    leaving.await.unwrap().unwrap();
    let terminal = agent_mode_footprint(&pool, realm_id).await;
    let error = fixture_delivery_step(&pool, &agent, &agent.station_id, &input)
        .await
        .err()
        .expect("queued bytes cannot survive owner leaving");
    assert!(
        error.to_string().contains("capability_denied")
            || error.to_string().contains("revision_unavailable"),
        "{error}"
    );
    assert_eq!(agent_mode_footprint(&pool, realm_id).await, terminal);
}

// Complete accepted policy-history import used by native consumer tests;
// it does not claim the management configuration HTTP admission is enabled.
async fn import_agent_management_policy(
    pool: &coland_storage_postgres::PgPool,
    previous: &coland_storage::AuthorityCommitTransaction,
    controller: &AccountId,
    expected: Option<arkret_wire::CurrentRevision>,
    effect: &str,
    operation: &str,
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
                    "agent_operations":[operation]}],
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
        document.rules[0].review_requirement = Some(
            arkret_models_collaboration::governance::operation_wire::ManagementReviewRequirement {
                approver_actor_ids: vec![arkret_wire::ActorId::account(controller.clone())],
                threshold: 1,
                max_age_seconds: 60,
            },
        );
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
    if operation == "publish" {
        let transaction = request.authority_commit.clone();
        PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(request)
            .await
            .unwrap();
        return transaction;
    }
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

#[tokio::test]
async fn owned_agent_join_requires_complete_binding_after_active_genesis() {
    Box::pin(owned_agent_incomplete_binding_scenario()).await;
}
async fn owned_agent_incomplete_binding_scenario() {
    use coland_storage::DeliveryPolicyStoreRegistry as _;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = historical_control_source::HistoricalControlStation::new(
        "review-bootstrap-station",
        [83; 32],
    );
    let principal = accepted_controller(&pool, station.did.clone()).await;
    let controller = &principal.history.account;
    let realm = ordinary_realm::bootstrap_unit_with_history_for_account(
        "review-bootstrap-open",
        "public",
        "since_join",
        controller,
        &station.did,
    );
    let realm = ordinary_realm::source_bootstrap(&pool, realm).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&realm, realm.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = realm.transactions.last().unwrap();
    let agent_did = historical_control_source::managed_agent_did(
        &controller.principal_id,
        "review-unbound-agent",
        principal.unit.transactions[1].commit.committed_at,
    );
    let (agent, genesis, provision_id) = provision_owned_agent_binding_phase(
        &pool,
        &principal,
        agent_did.clone(),
        None,
        false,
        None,
        &[102; 32],
    )
    .await;
    // Use the actual owner's joined-generation source rather than the head.
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Joined {
        #[diesel(sql_type=Jsonb)]
        event: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let joined=diesel::sql_query("SELECT e.envelope AS event FROM member_state_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join'")
        .bind::<Text,_>(parent.event.realm_id.as_str()).bind::<Text,_>(arkret_wire::ActorId::account(controller.clone()).to_string()).get_result::<Joined>(&mut *conn).await.unwrap();
    drop(conn);
    let candidate = ordinary_realm::next_request_for_actor(
        parent,
        EventKind::MemberState,
        arkret_wire::ActorId::account(controller.clone()),
        serde_json::json!({
            "member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,"controller_membership_generation_ref":joined.event["event_id"]}
        }),
        genesis.commit.committed_at.max(parent.commit.committed_at)
            + chrono::TimeDelta::milliseconds(1),
    );
    let candidate = ordinary_realm::source_request(&pool, candidate).await;
    let before = agent_mode_footprint(&pool, &parent.event.realm_id).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let error = uow.commit_event(candidate.clone()).await.unwrap_err();
    assert!(
        error.to_string().contains("Agent accepted PCR inception")
            || error.to_string().contains("Agent complete DID binding"),
        "the actual genesis-only native chain must refuse join"
    );
    assert!(agent_mode_footprint(&pool, &parent.event.realm_id).await == before);
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let original = persistence
        .webvh()
        .get_document(agent_did.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.seq, 1);
    let logs = persistence
        .webvh()
        .list_log_events(agent_did.as_str())
        .await
        .unwrap();
    let provision = store.committed_event(&provision_id).await.unwrap().unwrap();
    let provision =
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
            &provision.event,
        )
        .unwrap();
    let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        ed25519_dalek::SigningKey::from_bytes(&[103; 32])
            .verifying_key()
            .as_bytes(),
    );
    let update = arkret_signatures::webvh::prepare_agent_binding_update(
        &arkret_signatures::webvh::AgentBindingUpdateInput {
            did: agent_did.as_str(),
            local_id: agent_did.as_str().rsplit(':').next().unwrap(),
            previous_entries: &logs.iter().map(|l| l.operation.clone()).collect::<Vec<_>>(),
            version_time: genesis.commit.committed_at,
            current_root_seed: &[102; 32],
            next_root_public_key_multibase: &next,
            controller_principal_id: &controller.principal_id,
            principal_control_realm_id: &genesis.event.realm_id,
            requested_scope_digest: &provision.requested_scope_digest,
        },
    )
    .unwrap();
    let digest = arkret_canonical::canonical_sha256(&update.log_entry).unwrap();
    let now = chrono::Utc::now();
    let mut document = original.clone();
    document.did_document = update.log_entry["state"].clone();
    document.seq = 2;
    document.key_log_head = Some(digest.clone());
    document.updated_at = now;
    let outcome = persistence
        .webvh()
        .commit_log_operation(
            original.key_log_head,
            document,
            coland_storage::WebvhLogRecord {
                did: agent_did.to_string(),
                event_digest: digest,
                seq: 2,
                created_at: genesis.commit.committed_at,
                operation: update.log_entry,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, coland_storage::WebvhLogCommitOutcome::Accepted);
    uow.commit_event(candidate.clone()).await.unwrap();
    assert!(
        store
            .committed_event(&candidate.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_some()
    );
}

/// Exact original native approval, selected from the accepted principal's
/// verified history. This storage test imports no fabricated reviewer authority.
fn management_native_vote(
    principal: &pcr_genesis::PcrGenesisFixture,
    request: &arkret_models_integration::management_review::ManagementReviewRequestBody,
    approved_at: chrono::DateTime<chrono::Utc>,
    nonce: &str,
) -> coland_storage::ApprovalHistoricalMethod {
    use arkret_wire::{
        ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
        ApprovalSignatureProofKind, ApprovalTarget, CapabilityActionId, Hash,
    };
    let arkret_models_identity::principal_registration_anchor::PrincipalRegistrationAnchor::WebvhRegistration { log_entries, .. } = &principal.history.registration_anchor;
    let entries = log_entries
        .iter()
        .map(|entry| serde_json::to_value(entry).unwrap())
        .collect::<Vec<_>>();
    let history =
        arkret_identity::verify_did_webvh_v1_chain(&principal.history.did, &entries).unwrap();
    let selected = coland_services::identity::select_did_webvh_state_at(
        &principal.history.did,
        &history,
        approved_at,
    )
    .unwrap();
    let method_multibase = selected.update_keys.first().unwrap();
    let method =
        arkret_wire::DidUrl::new(format!("did:key:{method_multibase}#{method_multibase}")).unwrap();
    // The accepted fixture's root is known, but must match its verified selection.
    let seed = [[70; 32], [71; 32]]
        .into_iter()
        .find(|seed| {
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                ed25519_dalek::SigningKey::from_bytes(seed)
                    .verifying_key()
                    .as_bytes(),
            ) == *method_multibase
        })
        .unwrap();
    let control =
        arkret_identity::principal_control::native_identity_control_key_from_verified_selection(
            &selected.did,
            &principal.history.account.principal_id,
            &selected.update_keys,
            &method,
            arkret_identity::principal_control::DirectIdentityControlPurpose::ApprovalSignature,
        )
        .unwrap();
    let arkret_models_integration::management_review::ManagementReviewTarget::Event { event } =
        &request.target
    else {
        panic!("Event fixture")
    };
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::Management {
                request_id: request.request_id.clone(),
                management_operation: request.management_operation,
                effective_scope: request.effective_scope.clone(),
            },
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(arkret_canonical::canonical_sha256(event).unwrap())
                .unwrap(),
            operation: "ak.self.events.command.submit.v1".into(),
            action: if request.management_operation == arkret_wire::ManagementOperation::Join {
                CapabilityActionId::AgentJoin
            } else {
                CapabilityActionId::AgentPublish
            },
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actor_id.clone(),
            approver_did: principal.history.did.clone(),
            approved_at,
            nonce: nonce.into(),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: method.clone(),
            jws: String::new(),
        },
    };
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(seed, method.as_str());
    signature.proof.jws = signer.sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&signature)
            .unwrap(),
    );
    coland_storage::ApprovalHistoricalMethod {
        public_key: *control.public_key(),
        signature,
        native_control: Some(control),
        control_history: Some(
            serde_json::json!({"did":selected.did,"version_id":selected.version_id,
            "log_head_digest":selected.log_head_digest,"update_keys":selected.update_keys,
            "verified_at":arkret_canonical::format_timestamp_canonical(approved_at)}),
        ),
    }
}

#[tokio::test]
async fn management_review_approved_intent_consumes_atomically_and_exact_replays() {
    // Keep the complete accepted-source fixture outside the test harness frame.
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false, false, None,
    )))
    .await
    .unwrap();
}

async fn management_review_consumed_vote_count(
    pool: &coland_storage_postgres::PgPool,
    realm: &arkret_wire::RealmId,
) -> i64 {
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COUNT(*) AS count FROM event_approval_private_audit WHERE realm_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(realm.as_str())
    .get_result::<Count>(&mut conn)
    .await
    .unwrap()
    .count
}

/// Native fixture import of original signed AA records and receiver receipts.
/// HTTP cases subsequently perform the actual authenticated resolve; this
/// helper alone does not claim a normal Coauth lifecycle or remote freshness.
async fn management_current_for_accounts(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    accounts: &[AccountId],
) -> coland_storage::ManagementReviewCurrent {
    use coland_storage::SyncStoreRegistry as _;
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Pcr {
        #[diesel(sql_type=diesel::sql_types::Text)]
        realm: String,
    }
    let persistence = PgPersistenceStore::new(pool.clone());
    let mut observations = Vec::new();
    for account in accounts
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
    {
        let mut conn = pool.get().await.unwrap();
        let pcr: Pcr = diesel::sql_query("SELECT pcr_realm_id AS realm FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2")
            .bind::<diesel::sql_types::Text,_>(account.principal_id.as_str())
            .bind::<diesel::sql_types::Text,_>(account.station_id.as_str())
            .get_result(&mut conn).await.unwrap();
        drop(conn);
        let existing = persistence
            .account_status_replicas()
            .current(account.station_id.as_str(), &account)
            .await
            .unwrap();
        let record = if let Some(record) = existing {
            record
        } else {
            let record = management_signed_status(
                station,
                &account,
                &pcr.realm.parse().unwrap(),
                None,
                arkret_models_collaboration::objects::account_status::AccountStatus::Active,
            );
            management_append_status(&persistence, station, &record).await;
            record
        };
        observations.push(
            coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve(record),
        );
    }
    coland_storage::ManagementReviewCurrent {
        station_id: station.core.clone(),
        observations,
    }
}

/// Reobserve only records already appended by the actual authenticated resolve.
/// This helper never imports or fabricates an Account Authority head.
async fn management_current_from_receiver(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    accounts: &[AccountId],
) -> coland_storage::ManagementReviewCurrent {
    use coland_storage::SyncStoreRegistry as _;
    let persistence = PgPersistenceStore::new(pool.clone());
    let mut observations = Vec::new();
    for account in accounts
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
    {
        let record = persistence
            .account_status_replicas()
            .current(account.station_id.as_str(), &account)
            .await
            .unwrap()
            .expect("the authenticated AA resolve appended the exact receiver head");
        observations.push(
            coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve(record),
        );
    }
    coland_storage::ManagementReviewCurrent {
        station_id: station.core.clone(),
        observations,
    }
}

fn management_signed_status(
    station: &historical_control_source::HistoricalControlStation,
    account: &AccountId,
    pcr: &arkret_wire::RealmId,
    previous: Option<&arkret_models_collaboration::account_status::AccountStatusRecord>,
    status: arkret_models_collaboration::objects::account_status::AccountStatus,
) -> arkret_models_collaboration::account_status::AccountStatusRecord {
    use arkret_models_collaboration::account_status::UnsignedAccountStatusRecord;
    assert_eq!(account.station_id, station.core);
    let method = arkret_wire::DidUrl::new(format!("{}#authority", station.did)).unwrap();
    let record = arkret_signatures::account_status::sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
            account_authority_id: station.core.clone(),
            account_id: account.clone(),
            principal_control_realm_id: pcr.clone(),
            binding_version: 1,
            status_seq: previous.map_or(1, |record| record.status_seq + 1),
            previous_account_status_record_id: previous
                .map(|record| record.account_status_record_id.clone()),
            status,
            reason_code: None,
            reason: None,
            issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            expires_at: None,
        },
        method,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    let document = arkret_identity::authenticated_service_document_at(
        &station.history,
        &station.core,
        record.issued_at,
    )
    .unwrap();
    let key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &document,
        record.proof.verification_method.as_str(),
    )
    .unwrap();
    arkret_signatures::account_status::verify_account_status_record(
        &record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_bytes().to_vec(),
        },
    )
    .unwrap();
    record
}

async fn management_append_status(
    persistence: &PgPersistenceStore,
    station: &historical_control_source::HistoricalControlStation,
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
) {
    use coland_storage::SyncStoreRegistry as _;
    let method = arkret_wire::DidUrl::new(format!("{}#authority", station.did)).unwrap();
    let receipt = arkret_signatures::account_status::sign_account_status_receipt(
        arkret_models_collaboration::account_status::UnsignedAccountStatusReceipt {
            receipt_id: format!("ak:receipt:{}", uuid::Uuid::now_v7())
                .parse()
                .unwrap(),
            account_status_record_id: record.account_status_record_id.clone(),
            record_digest: record.payload_digest().unwrap(),
            account_authority_id: station.core.clone(),
            account_id: record.account_id.clone(),
            status_seq: record.status_seq,
            receiver_id: station.core.clone(),
            accepted_at: chrono::Utc::now(),
            verification_method: method,
        },
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    receipt.validate_for_record(record).unwrap();
    arkret_signatures::account_status::verify_account_status_receipt(
        &receipt,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: ed25519_dalek::SigningKey::from_bytes(&[83; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
    )
    .unwrap();
    assert!(matches!(
        persistence
            .account_status_replicas()
            .append(record, &receipt)
            .await
            .unwrap(),
        coland_storage::AccountStatusReplicaAppend::Accepted(_)
            | coland_storage::AccountStatusReplicaAppend::Duplicate(_)
    ));
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ManagementAaCase {
    MissingObservation,
    EmptyAuthorityHead,
    StaleObservation,
    WrongFullAccount,
    WrongReceivingStation,
    CallerTerminal,
    ControllerTerminal,
    RetainedVoteTerminal,
    UnusedForeignAdministrator,
    WriterHeldCut,
    RealExpiry,
    ConsumedReplay,
}

async fn management_review_atomic_join_scenario(
    use_http: bool,
    withdraw_approver: bool,
    aa_case: Option<ManagementAaCase>,
) {
    use arkret_models_integration::management_review::*;
    use arkret_wire::{ActorId, ManagementOperation, ScopeRef};
    use coland_storage::{
        AgentStore, DeliveryPolicyStoreRegistry as _, DeviceRevocationGateSelector,
        EventApprovalCommit, EventBatchCommitRequest, SelfProducerCommitGuard,
    };
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station =
        historical_control_source::HistoricalControlStation::new("review-atomic-station", [83; 32]);
    let requester = Box::pin(accepted_controller(&pool, station.did.clone())).await;
    let approver = Box::pin(accepted_controller(&pool, station.did.clone())).await;
    let controller = &requester.history.account;
    let administrator = ActorId::account(approver.history.account.clone());
    assert_ne!(
        controller.principal_id,
        approver.history.account.principal_id
    );
    let bootstrap = ordinary_realm::bootstrap_unit_with_history_for_account(
        "management-review-atomic",
        "public",
        "since_join",
        &approver.history.account,
        &station.did,
    );
    let bootstrap = Box::pin(ordinary_realm::source_bootstrap(&pool, bootstrap)).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    fixture_bootstrap_step(
        &pool,
        &bootstrap,
        bootstrap.transactions[0].commit.committed_at,
    )
    .await
    .unwrap();
    let parent = bootstrap.transactions.last().unwrap();
    let join=Box::pin(ordinary_realm::source_request(&pool,ordinary_realm::next_request_for_actor(
        parent,EventKind::MemberState,ActorId::account(controller.clone()),
        serde_json::json!({"member_id":ActorId::account(controller.clone()),"membership":"join"}),
        parent.commit.committed_at+chrono::TimeDelta::milliseconds(1),
    ))).await;
    fixture_commit_step(&pool, join.clone()).await.unwrap();
    let (agent, genesis, _) = Box::pin(provision_owned_agent(&pool, &requester)).await;
    let mut current = if aa_case == Some(ManagementAaCase::EmptyAuthorityHead) {
        Box::pin(management_unstored_current_for_accounts(
            &pool,
            &station,
            &[controller.clone(), approver.history.account.clone()],
        ))
        .await
    } else {
        Box::pin(management_current_for_accounts(
            &pool,
            &station,
            &[controller.clone(), approver.history.account.clone()],
        ))
        .await
    };
    let http = if use_http {
        Some(
            Box::pin(management_review_http_fixture(
                &pool, &station, &requester, &approver, &current,
            ))
            .await,
        )
    } else {
        None
    };
    let realm = &join.authority_commit.event.realm_id;
    let policy_id = "ak:policy:0198ff00-0000-7000-8000-000000000101";
    let mut designated_administrators = vec![administrator.clone()];
    if aa_case == Some(ManagementAaCase::UnusedForeignAdministrator) {
        let foreign_station = historical_control_source::HistoricalControlStation::new(
            "review-unused-foreign-administrator",
            [84; 32],
        );
        // Same principal, different full Account. This policy alternative must
        // not cause a resolve of an unused foreign AA or SQL-first selection.
        designated_administrators.push(ActorId::account(AccountId::new(
            approver.history.account.principal_id.clone(),
            foreign_station.core,
        )));
    }
    let max_age_seconds = if aa_case == Some(ManagementAaCase::RealExpiry) {
        3
    } else {
        3600
    };
    let policy=Box::pin(ordinary_realm::source_request(&pool,ordinary_realm::next_request_for_actor(
        &join.authority_commit,EventKind::PolicySet,administrator.clone(),
        serde_json::json!({"policy_id":policy_id,"expected_revision":null,
            "value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":realm,
                "policy_kind":"agent","default_effect":"allow",
                "created_by":administrator,"created_at":join.authority_commit.commit.committed_at,
                "rules":[{"rule_id":"review_original_controller_join","kind":"agent","effect":"require_review",
                    "agent_target":{"kind":"all"},"agent_operations":["join","publish"],
                    "review_requirement":{"approver_actor_ids":designated_administrators,"threshold":1,"max_age_seconds":max_age_seconds}}]}}),
        genesis.commit.committed_at.max(join.authority_commit.commit.committed_at)+chrono::TimeDelta::milliseconds(1),
    ))).await;
    fixture_commit_step(&pool, policy.clone()).await.unwrap();
    let mut candidate = Box::pin(ordinary_realm::source_request(
        &pool,
        ordinary_realm::next_request_for_actor(
            &policy.authority_commit,
            EventKind::MemberState,
            ActorId::account(controller.clone()),
            serde_json::json!({"member_id":ActorId::account(agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,
                "controller_membership_generation_ref":join.authority_commit.event.event_id}}),
            policy.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
        ),
    ))
    .await;
    let authorized = &requester.unit.transactions[1].commit;
    let producer = SelfProducerCommitGuard::HumanDevice(DeviceRevocationGateSelector {
        principal_id: controller.principal_id.clone(),
        station_id: controller.station_id.clone(),
        device_id: requester.history.founding_device_id.to_string(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: authorized.event_ref.clone(),
            commit_id: authorized.commit_id.clone(),
            stream_ref: authorized.stream_ref.clone(),
            stream_position: authorized.stream_position,
        },
    });
    candidate.self_producer_guard = Some(producer.clone());
    let body = ManagementReviewRequestBody {
        request_id: "management-review-atomic-original".into(),
        effective_scope: ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        management_operation: ManagementOperation::Join,
        requester_actor_id: ActorId::account(controller.clone()),
        target: ManagementReviewTarget::Event {
            event: Box::new(candidate.authority_commit.event.clone()),
        },
    };
    let reviews = coland_storage_postgres::PgAgentStore { pool: pool.clone() };
    let before = agent_mode_footprint(&pool, realm).await;
    if let Some(case) = aa_case {
        if matches!(
            case,
            ManagementAaCase::MissingObservation
                | ManagementAaCase::StaleObservation
                | ManagementAaCase::WrongFullAccount
                | ManagementAaCase::WrongReceivingStation
                | ManagementAaCase::CallerTerminal
        ) {
            let mut attempted = current.clone();
            match case {
                ManagementAaCase::MissingObservation => attempted.observations.clear(),
                ManagementAaCase::WrongFullAccount => attempted
                    .observations
                    .retain(|obs| obs.record().account_id != *controller),
                ManagementAaCase::WrongReceivingStation => {
                    attempted.station_id = historical_control_source::HistoricalControlStation::new(
                        "review-wrong-receiver",
                        [84; 32],
                    )
                    .core
                }
                ManagementAaCase::StaleObservation | ManagementAaCase::CallerTerminal => {
                    let status = if case == ManagementAaCase::CallerTerminal {
                        arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated
                    } else {
                        arkret_models_collaboration::objects::account_status::AccountStatus::Active
                    };
                    let fresh = Box::pin(management_advance_current(
                        &pool, &station, &current, controller, status,
                    ))
                    .await;
                    if case == ManagementAaCase::CallerTerminal {
                        attempted = fresh;
                    }
                }
                _ => unreachable!(),
            }
            let error = Box::pin(reviews.management_review_request(
                &body.requester_actor_id,
                &body,
                &producer,
                &attempted,
                chrono::Utc::now(),
            ))
            .await
            .unwrap_err();
            if case == ManagementAaCase::CallerTerminal {
                assert!(error.to_string().contains("capability_denied"));
            } else {
                assert!(error.to_string().contains("revision_unavailable"));
            }
            assert_eq!(agent_mode_footprint(&pool, realm).await, before);
            assert_eq!(management_review_ledger_count(&pool).await, 0);
            assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 0);
            return;
        }
        if case == ManagementAaCase::EmptyAuthorityHead {
            let http = http.as_ref().unwrap();
            http.aa_records.lock().unwrap().clear();
            let problem = Box::pin(management_review_http_refusal(
                http,
                false,
                "requests",
                "ak.self.management_review.command.request.v1",
                &body,
            ))
            .await;
            assert_eq!(problem.0, salvo::http::StatusCode::SERVICE_UNAVAILABLE);
            assert!(problem.1.contains("temporarily_unavailable"));
            assert_eq!(management_review_ledger_count(&pool).await, 0);
            assert_eq!(agent_mode_footprint(&pool, realm).await, before);
            // The actual authenticated AA now returns its original signed seq1.
            // No receiver row is manufactured: production refresh appends it.
            for observation in &current.observations {
                http.aa_records.lock().unwrap().insert(
                    observation.record().account_id.clone(),
                    vec![observation.record().clone()],
                );
            }
        }
    }
    let pending = if let Some(http) = &http {
        Box::pin(management_review_http_post(
            http,
            false,
            "requests",
            "ak.self.management_review.command.request.v1",
            &body,
        ))
        .await
    } else {
        reviews
            .management_review_request(
                &body.requester_actor_id,
                &body,
                &producer,
                &current,
                chrono::Utc::now(),
            )
            .await
            .unwrap()
    };
    assert_eq!(pending.status, ManagementReviewStatus::Pending);
    if let Some(http) = &http {
        let result = Box::pin(management_review_http_post(
            http,
            false,
            "requests",
            "ak.self.management_review.command.request.v1",
            &body,
        ))
        .await;
        assert!(serde_json::to_value(&result).unwrap() == serde_json::to_value(&pending).unwrap());
        let result = Box::pin(management_review_http_post(
            http,
            false,
            "status",
            "ak.self.management_review.read.status.v1",
            &ManagementReviewLookupRequestBody {
                request_id: body.request_id.clone(),
            },
        ))
        .await;
        assert!(serde_json::to_value(&result).unwrap() == serde_json::to_value(&pending).unwrap());
    }
    if aa_case == Some(ManagementAaCase::EmptyAuthorityHead) {
        let http = http.as_ref().unwrap();
        // Resolve the real administrator through the same authenticated status
        // operation, then use the exact receiver records for native follow-ups.
        // The pre-transport signed objects are not receiver observations.
        let result = Box::pin(management_review_http_post(
            http,
            true,
            "status",
            "ak.self.management_review.read.status.v1",
            &ManagementReviewLookupRequestBody {
                request_id: body.request_id.clone(),
            },
        ))
        .await;
        assert!(serde_json::to_value(&result).unwrap() == serde_json::to_value(&pending).unwrap());
        current = Box::pin(management_current_from_receiver(
            &pool,
            &station,
            &[controller.clone(), approver.history.account.clone()],
        ))
        .await;
    }
    assert_eq!(agent_mode_footprint(&pool, realm).await, before);
    let retry = reviews
        .management_review_request(
            &body.requester_actor_id,
            &body,
            &producer,
            &current,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(retry).unwrap(),
        serde_json::to_value(&pending).unwrap()
    );
    let mut duplicate = body.clone();
    duplicate.request_id = "management-review-atomic-other-id".into();
    let error = reviews
        .management_review_request(
            &body.requester_actor_id,
            &duplicate,
            &producer,
            &current,
            chrono::Utc::now(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("duplicate_conflict"));
    let error = fixture_commit_step(&pool, candidate.clone())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("approval_required"));
    assert_eq!(agent_mode_footprint(&pool, realm).await, before);
    let lookup = ManagementReviewLookupRequestBody {
        request_id: body.request_id.clone(),
    };
    // A real requester signature cannot become a designated administrator vote.
    let self_vote = management_native_vote(
        &requester,
        &body,
        chrono::Utc::now(),
        "review-self-vote-128-bit-nonce",
    );
    let error = reviews
        .management_review_decide(
            &body.requester_actor_id,
            &ManagementReviewDecisionRequestBody {
                request_id: body.request_id.clone(),
                expected_status: ManagementReviewStatus::Pending,
                decision: ManagementReviewDecision::Approve,
                approval_signatures: vec![self_vote.signature.clone()],
            },
            &[self_vote],
            &current,
            chrono::Utc::now(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("capability_denied"));
    assert_eq!(agent_mode_footprint(&pool, realm).await, before);
    let vote = management_native_vote(
        &approver,
        &body,
        chrono::Utc::now(),
        "review-admin-original-128-bit-nonce",
    );
    let mut wrong = vote.clone();
    wrong.signature.proof.jws.push('x');
    let decision =
        |method: &coland_storage::ApprovalHistoricalMethod| ManagementReviewDecisionRequestBody {
            request_id: body.request_id.clone(),
            expected_status: ManagementReviewStatus::Pending,
            decision: ManagementReviewDecision::Approve,
            approval_signatures: vec![method.signature.clone()],
        };
    let error = reviews
        .management_review_decide(
            &administrator,
            &decision(&wrong),
            &[wrong.clone()],
            &current,
            chrono::Utc::now(),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("signature_invalid"),
        "invalid approval signature rejection boundary: {}",
        if error.to_string().contains("revision_unavailable") {
            "revision_unavailable"
        } else if error.to_string().contains("capability_denied") {
            "capability_denied"
        } else {
            "other_registered_or_internal_boundary"
        }
    );
    assert_eq!(
        reviews
            .management_review_status(
                &body.requester_actor_id,
                &lookup,
                &current,
                chrono::Utc::now()
            )
            .await
            .unwrap()
            .status,
        ManagementReviewStatus::Pending
    );
    let approved = if let Some(http) = &http {
        Box::pin(management_review_http_post(
            http,
            true,
            "decisions",
            "ak.self.management_review.command.decide.v1",
            &decision(&vote),
        ))
        .await
    } else {
        reviews
            .management_review_decide(
                &administrator,
                &decision(&vote),
                &[vote.clone()],
                &current,
                chrono::Utc::now(),
            )
            .await
            .unwrap()
    };
    assert_eq!(approved.status, ManagementReviewStatus::Approved);
    assert_eq!(agent_mode_footprint(&pool, realm).await, before);
    if let Some(case) = aa_case {
        if matches!(
            case,
            ManagementAaCase::ControllerTerminal
                | ManagementAaCase::RetainedVoteTerminal
                | ManagementAaCase::RealExpiry
                | ManagementAaCase::WriterHeldCut
        ) {
            if case == ManagementAaCase::WriterHeldCut {
                Box::pin(management_review_writer_held_cut(
                    &pool,
                    &station,
                    &reviews,
                    &administrator,
                    &lookup,
                    &current,
                    &approver.history.account,
                ))
                .await;
                let fresh = Box::pin(management_current_for_accounts(
                    &pool,
                    &station,
                    &[controller.clone(), approver.history.account.clone()],
                ))
                .await;
                assert_eq!(
                    Box::pin(reviews.management_review_status(
                        &body.requester_actor_id,
                        &lookup,
                        &fresh,
                        chrono::Utc::now()
                    ))
                    .await
                    .unwrap()
                    .status,
                    ManagementReviewStatus::Superseded
                );
                assert_eq!(agent_mode_footprint(&pool, realm).await, before);
                assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 0);
                return;
            }
            let status_caller = if case == ManagementAaCase::ControllerTerminal {
                &administrator
            } else {
                &body.requester_actor_id
            };
            let expected = if case == ManagementAaCase::RealExpiry {
                while chrono::Utc::now() < approved.expires_at {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                ManagementReviewStatus::Expired
            } else {
                let changed = if case == ManagementAaCase::ControllerTerminal {
                    controller
                } else {
                    &approver.history.account
                };
                current = Box::pin(management_advance_current(&pool, &station, &current, changed,
                    arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated)).await;
                ManagementReviewStatus::Superseded
            };
            assert_eq!(
                Box::pin(reviews.management_review_status(
                    status_caller,
                    &lookup,
                    &current,
                    chrono::Utc::now()
                ))
                .await
                .unwrap()
                .status,
                expected
            );
            let mut attempt = Box::pin(ordinary_realm::source_request(
                &pool,
                ordinary_realm::request_for_event(
                    &policy.authority_commit,
                    candidate.authority_commit.event.clone(),
                    chrono::Utc::now(),
                ),
            ))
            .await;
            attempt.self_producer_guard = Some(producer.clone());
            let batch = EventBatchCommitRequest {
                event_approvals: Some(EventApprovalCommit {
                    management_current: Some(current.clone()),
                    event_id: attempt.authority_commit.event.event_id.clone(),
                    event_digest: arkret_canonical::canonical_sha256(
                        &attempt.authority_commit.event,
                    )
                    .unwrap(),
                    committed_at: attempt.authority_commit.commit.committed_at,
                    methods: vec![vote.clone()],
                }),
                events: vec![attempt],
                franking_replay_nonce: None,
                realm_organization_proof: None,
                invite_claim_proof: None,
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            };
            assert!(fixture_commit_batch_step(&pool, batch).await.is_err());
            assert_eq!(agent_mode_footprint(&pool, realm).await, before);
            assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 0);
            return;
        }
    }
    if withdraw_approver {
        let arkret_models_identity::principal_registration_anchor::PrincipalRegistrationAnchor::WebvhRegistration { log_entries, .. } = &approver.history.registration_anchor;
        let mut entries = log_entries
            .iter()
            .map(|entry| serde_json::to_value(entry).unwrap())
            .collect::<Vec<_>>();
        // Native versionTime is second-granularity; rotate only after the
        // original signed approval instant, rather than backdating this update.
        let rotation_at = chrono::DateTime::from_timestamp(
            vote.signature
                .input
                .approved_at
                .timestamp()
                .checked_add(1)
                .unwrap(),
            0,
        )
        .unwrap();
        while chrono::Utc::now() < rotation_at {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let rotation = arkret_signatures::webvh::prepare_principal_rotation(
            &arkret_signatures::webvh::PrincipalRotationInput {
                did: approver.history.did.as_str(),
                local_id: approver.history.did.as_str().rsplit(':').next().unwrap(),
                previous_entries: &entries,
                version_time: rotation_at,
                current_root_seed: &[71; 32],
                next_root_public_key_multibase:
                    &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                        ed25519_dalek::SigningKey::from_bytes(&[72; 32])
                            .verifying_key()
                            .as_bytes(),
                    ),
                state: &entries.last().unwrap()["state"],
            },
        )
        .unwrap();
        entries.push(rotation.log_entry.clone());
        let history =
            arkret_identity::verify_did_webvh_v1_chain(&approver.history.did, &entries).unwrap();
        let selected = coland_services::identity::select_did_webvh_state_at(
            &approver.history.did,
            &history,
            vote.signature.input.approved_at,
        )
        .unwrap();
        let historical=arkret_identity::principal_control::native_identity_control_key_from_verified_selection(
            &selected.did,&approver.history.account.principal_id,&selected.update_keys,
            &vote.signature.proof.verification_method,
            arkret_identity::principal_control::DirectIdentityControlPurpose::ApprovalSignature).unwrap();
        assert!(historical.public_key() == &vote.public_key);
        assert!(
            !history
                .active_update_keys
                .contains(&selected.update_keys[0])
        );
        let persistence = PgPersistenceStore::new(pool.clone());
        persistence
            .webvh()
            .append_log_event(coland_storage::WebvhLogRecord {
                did: approver.history.did.to_string(),
                seq: 2,
                event_digest: arkret_canonical::canonical_sha256(&rotation.log_entry).unwrap(),
                operation: rotation.log_entry,
                created_at: rotation_at,
            })
            .await
            .unwrap();
        assert_eq!(
            reviews
                .management_review_status(
                    &body.requester_actor_id,
                    &lookup,
                    &current,
                    chrono::Utc::now()
                )
                .await
                .unwrap()
                .status,
            ManagementReviewStatus::Approved
        );
        // Current membership/admin loss is independent from historic key validity.
        let leave = Box::pin(ordinary_realm::source_request(
            &pool,
            ordinary_realm::next_request_for_actor(
                &policy.authority_commit,
                EventKind::MemberState,
                administrator.clone(),
                serde_json::json!({"member_id":administrator,"membership":"leave"}),
                chrono::Utc::now(),
            ),
        ))
        .await;
        fixture_commit_step(&pool, leave.clone()).await.unwrap();
        let after_leave = agent_mode_footprint(&pool, realm).await;
        assert_eq!(
            reviews
                .management_review_status(
                    &body.requester_actor_id,
                    &lookup,
                    &current,
                    chrono::Utc::now()
                )
                .await
                .unwrap()
                .status,
            ManagementReviewStatus::Superseded
        );
        let mut attempt = Box::pin(ordinary_realm::source_request(
            &pool,
            ordinary_realm::request_for_event(
                &leave.authority_commit,
                candidate.authority_commit.event.clone(),
                chrono::Utc::now(),
            ),
        ))
        .await;
        attempt.self_producer_guard = Some(producer);
        let prepared = coland_storage::EventApprovalCommit {
            management_current: Some(current.clone()),
            event_id: attempt.authority_commit.event.event_id.clone(),
            event_digest: arkret_canonical::canonical_sha256(&attempt.authority_commit.event)
                .unwrap(),
            committed_at: attempt.authority_commit.commit.committed_at,
            methods: vec![vote],
        };
        let batch = EventBatchCommitRequest {
            events: vec![attempt],
            event_approvals: Some(prepared),
            franking_replay_nonce: None,
            realm_organization_proof: None,
            invite_claim_proof: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        };
        assert!(
            fixture_commit_batch_step(&pool, batch)
                .await
                .unwrap_err()
                .to_string()
                .contains("approval_required")
        );
        assert_eq!(agent_mode_footprint(&pool, realm).await, after_leave);
        assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 0);
        return;
    }
    // Commit time follows the decision; the approved Event is byte-for-byte
    // identical, and current producer/source authority is freshly selected.
    let original_event = candidate.authority_commit.event.clone();
    let mut execution = Box::pin(ordinary_realm::source_request(
        &pool,
        ordinary_realm::request_for_event(
            &policy.authority_commit,
            original_event.clone(),
            chrono::Utc::now(),
        ),
    ))
    .await;
    execution.self_producer_guard = Some(producer.clone());
    let batch = EventBatchCommitRequest {
        events: vec![execution.clone()],
        event_approvals: Some(EventApprovalCommit {
            management_current: Some(current.clone()),
            event_id: original_event.event_id.clone(),
            event_digest: arkret_canonical::canonical_sha256(&original_event).unwrap(),
            committed_at: execution.authority_commit.commit.committed_at,
            methods: vec![vote.clone()],
        }),
        franking_replay_nonce: None,
        realm_organization_proof: None,
        invite_claim_proof: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };
    assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 0);
    // A legitimately signed but non-next Commit cannot consume approval, nor
    // manufacture a business effect. The original accepted Event is unchanged.
    let mut out_of_order = batch.clone();
    let transaction = &mut out_of_order.events[0].authority_commit;
    transaction.commit.stream_position += 1;
    ordinary_realm::seal_final_commit(&mut transaction.commit);
    let refused = fixture_commit_batch_step(&pool, out_of_order).await;
    assert!(refused.is_err());
    assert_eq!(agent_mode_footprint(&pool, realm).await, before);
    assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 0);
    assert_eq!(
        reviews
            .management_review_status(
                &body.requester_actor_id,
                &lookup,
                &current,
                chrono::Utc::now()
            )
            .await
            .unwrap()
            .status,
        ManagementReviewStatus::Approved
    );
    fixture_commit_batch_step(&pool, batch.clone())
        .await
        .unwrap();
    assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 1);
    assert_eq!(
        reviews
            .management_review_status(
                &body.requester_actor_id,
                &lookup,
                &current,
                chrono::Utc::now()
            )
            .await
            .unwrap()
            .status,
        ManagementReviewStatus::Consumed
    );
    assert!(
        store
            .committed_event(&original_event.event_id)
            .await
            .unwrap()
            .is_some()
    );
    let accepted = agent_mode_footprint(&pool, realm).await;
    assert_ne!(accepted, before);
    if aa_case == Some(ManagementAaCase::ConsumedReplay) {
        let terminal = Box::pin(management_advance_current(
            &pool,
            &station,
            &current,
            controller,
            arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated,
        ))
        .await;
        // Both exact durable receipts bypass new current qualification. This
        // never permits a new request, changed candidate or reused approval.
        assert_eq!(
            Box::pin(reviews.management_review_request(
                &body.requester_actor_id,
                &body,
                &producer,
                &terminal,
                chrono::Utc::now()
            ))
            .await
            .unwrap()
            .status,
            ManagementReviewStatus::Consumed
        );
        let mut empty = batch.clone();
        empty.event_approvals.as_mut().unwrap().management_current = None;
        fixture_commit_batch_step(&pool, empty).await.unwrap();
        assert_eq!(agent_mode_footprint(&pool, realm).await, accepted);
        assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 1);
        return;
    }
    fixture_commit_batch_step(&pool, batch).await.unwrap();
    assert_eq!(agent_mode_footprint(&pool, realm).await, accepted);
    assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 1);
    if let Some(http) = &http {
        let consumed = Box::pin(management_review_http_post(
            http,
            false,
            "status",
            "ak.self.management_review.read.status.v1",
            &lookup,
        ))
        .await;
        assert_eq!(consumed.status, ManagementReviewStatus::Consumed);
        let replay = Box::pin(management_review_http_post(
            http,
            false,
            "requests",
            "ak.self.management_review.command.request.v1",
            &body,
        ))
        .await;
        assert!(serde_json::to_value(&replay).unwrap() == serde_json::to_value(&consumed).unwrap());
        assert_eq!(agent_mode_footprint(&pool, realm).await, accepted);
    }
    let consumed_retry = reviews
        .management_review_request(
            &body.requester_actor_id,
            &body,
            &producer,
            &current,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(consumed_retry.status, ManagementReviewStatus::Consumed);

    // Publish is a separate, original controller intent. A cancelled review
    // never becomes a mode write, and its terminal id cannot be revived.
    assert_eq!(accepted["interaction"], serde_json::json!([]));
    let mut publish=Box::pin(ordinary_realm::source_request(&pool,ordinary_realm::next_request_for_actor(
        &execution.authority_commit,EventKind::AgentInteractionSet,body.requester_actor_id.clone(),
        serde_json::to_value(arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
            agent_account_id:agent.clone(),controller_account_id:controller.clone(),
            interaction_mode:arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
            expected_revision:None,
        }).unwrap(),chrono::Utc::now(),
    ))).await;
    publish.self_producer_guard = Some(producer.clone());
    let mut public_body = ManagementReviewRequestBody {
        request_id: "management-review-publish-cancelled".into(),
        effective_scope: body.effective_scope.clone(),
        management_operation: ManagementOperation::Publish,
        requester_actor_id: body.requester_actor_id.clone(),
        target: ManagementReviewTarget::Event {
            event: Box::new(publish.authority_commit.event.clone()),
        },
    };
    let pending = reviews
        .management_review_request(
            &body.requester_actor_id,
            &public_body,
            &producer,
            &current,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(pending.status, ManagementReviewStatus::Pending);
    let cancellation = ManagementReviewDecisionRequestBody {
        request_id: public_body.request_id.clone(),
        expected_status: ManagementReviewStatus::Pending,
        decision: ManagementReviewDecision::Cancel,
        approval_signatures: Vec::new(),
    };
    let cancelled = reviews
        .management_review_decide(
            &body.requester_actor_id,
            &cancellation,
            &[],
            &current,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(cancelled.status, ManagementReviewStatus::Cancelled);
    assert_eq!(
        reviews
            .management_review_request(
                &body.requester_actor_id,
                &public_body,
                &producer,
                &current,
                chrono::Utc::now()
            )
            .await
            .unwrap()
            .status,
        ManagementReviewStatus::Cancelled
    );
    let cancelled_vote = management_native_vote(
        &approver,
        &public_body,
        chrono::Utc::now(),
        "review-cancelled-publish-128-bit-nonce",
    );
    let error = reviews
        .management_review_decide(
            &administrator,
            &ManagementReviewDecisionRequestBody {
                request_id: public_body.request_id.clone(),
                expected_status: ManagementReviewStatus::Pending,
                decision: ManagementReviewDecision::Approve,
                approval_signatures: vec![cancelled_vote.signature.clone()],
            },
            &[cancelled_vote],
            &current,
            chrono::Utc::now(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("failed_precondition"));
    assert_eq!(agent_mode_footprint(&pool, realm).await, accepted);
    assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 1);
    public_body.request_id = "management-review-publish-original".into();
    assert_eq!(
        reviews
            .management_review_request(
                &body.requester_actor_id,
                &public_body,
                &producer,
                &current,
                chrono::Utc::now()
            )
            .await
            .unwrap()
            .status,
        ManagementReviewStatus::Pending
    );
    let public_vote = management_native_vote(
        &approver,
        &public_body,
        chrono::Utc::now(),
        "review-public-original-128-bit-nonce",
    );
    assert_eq!(
        reviews
            .management_review_decide(
                &administrator,
                &ManagementReviewDecisionRequestBody {
                    request_id: public_body.request_id.clone(),
                    expected_status: ManagementReviewStatus::Pending,
                    decision: ManagementReviewDecision::Approve,
                    approval_signatures: vec![public_vote.signature.clone()],
                },
                &[public_vote.clone()],
                &current,
                chrono::Utc::now()
            )
            .await
            .unwrap()
            .status,
        ManagementReviewStatus::Approved
    );
    assert_eq!(agent_mode_footprint(&pool, realm).await, accepted);
    let mut execution_public = Box::pin(ordinary_realm::source_request(
        &pool,
        ordinary_realm::request_for_event(
            &execution.authority_commit,
            publish.authority_commit.event.clone(),
            chrono::Utc::now(),
        ),
    ))
    .await;
    execution_public.self_producer_guard = Some(producer);
    let public_batch = EventBatchCommitRequest {
        event_approvals: Some(EventApprovalCommit {
            management_current: Some(current.clone()),
            event_id: execution_public.authority_commit.event.event_id.clone(),
            event_digest: arkret_canonical::canonical_sha256(
                &execution_public.authority_commit.event,
            )
            .unwrap(),
            committed_at: execution_public.authority_commit.commit.committed_at,
            methods: vec![public_vote],
        }),
        events: vec![execution_public],
        franking_replay_nonce: None,
        realm_organization_proof: None,
        invite_claim_proof: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };
    fixture_commit_batch_step(&pool, public_batch.clone())
        .await
        .unwrap();
    assert_eq!(
        reviews
            .management_review_status(
                &body.requester_actor_id,
                &ManagementReviewLookupRequestBody {
                    request_id: public_body.request_id.clone(),
                },
                &current,
                chrono::Utc::now()
            )
            .await
            .unwrap()
            .status,
        ManagementReviewStatus::Consumed
    );
    let public_accepted = agent_mode_footprint(&pool, realm).await;
    assert_eq!(
        public_accepted["interaction"][0]["value"]["interaction_mode"],
        "public"
    );
    assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 2);
    fixture_commit_batch_step(&pool, public_batch)
        .await
        .unwrap();
    assert_eq!(agent_mode_footprint(&pool, realm).await, public_accepted);
    assert_eq!(management_review_consumed_vote_count(&pool, realm).await, 2);
}

/// The native HTTP fixture uses accepted PCR/device history plus an exact-token
/// mock issuer over the original introspection transport and real DPoP. The
/// production resource-server gates run; this is not normal Coauth issuance.
struct ManagementReviewHttpFixture {
    service: salvo::Service,
    public_base_url: String,
    requester_token: String,
    approver_token: String,
    requester_key: ed25519_dalek::SigningKey,
    approver_key: ed25519_dalek::SigningKey,
    introspection_task: tokio::task::JoinHandle<()>,
    aa_records: std::sync::Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<
                AccountId,
                Vec<arkret_models_collaboration::account_status::AccountStatusRecord>,
            >,
        >,
    >,
}
impl Drop for ManagementReviewHttpFixture {
    fn drop(&mut self) {
        self.introspection_task.abort();
    }
}
async fn management_review_http_fixture(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    requester: &pcr_genesis::PcrGenesisFixture,
    approver: &pcr_genesis::PcrGenesisFixture,
    current: &coland_storage::ManagementReviewCurrent,
) -> ManagementReviewHttpFixture {
    use arkret_models_collaboration::session_grants::*;
    use arkret_models_identity::session_credential::*;
    use sha2::{Digest, Sha256};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let channel = uuid::Uuid::now_v7().to_string();
    let persistence = std::sync::Arc::new(PgPersistenceStore::new(pool.clone()));
    let identity = station.install_runtime_identity(persistence.as_ref()).await;
    let mut config = coland_test_support::app_config();
    config.development_mode = true;
    config.session_grant_introspection_url = Some(format!(
        "{origin}/_coauth/internal/session-grants/introspect"
    ));
    config.account_authority_url = Some(origin.clone());
    config.account_authority_trust_domain = Some(config.trust_domain.clone());
    config.register_test_internal_authority_channel(channel.clone());
    let aa_records = std::sync::Arc::new(std::sync::Mutex::new(
        current
            .observations
            .iter()
            .map(|observation| {
                (
                    observation.record().account_id.clone(),
                    vec![observation.record().clone()],
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>(),
    ));
    let server_aa_records = aa_records.clone();
    let aa_address = listener.local_addr().unwrap().to_string();
    let allowed_accounts = std::collections::BTreeSet::from([
        requester.history.account.clone(),
        approver.history.account.clone(),
    ]);
    let state =
        coland_test_support::app_state_with_identity(config, persistence, identity, [83; 32]);
    let keys = [
        ed25519_dalek::SigningKey::from_bytes(&[88; 32]),
        ed25519_dalek::SigningKey::from_bytes(&[89; 32]),
    ];
    let tokens = [
        uuid::Uuid::now_v7().to_string(),
        uuid::Uuid::now_v7().to_string(),
    ];
    let mut outcomes = std::collections::BTreeMap::new();
    for ((principal, key), token) in [requester, approver].into_iter().zip(&keys).zip(&tokens) {
        let jwk = arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&key.verifying_key());
        let jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&jwk).unwrap();
        let grant = SessionGrantValidationMetadata {
            id: arkret_identifiers::SessionGrantId::from_issuance_digest(Sha256::digest(token.as_bytes()).into()),
            issuer_id: "ak:did_core:web:coauth.example".parse().unwrap(),
            account_id: principal.history.account.clone(),
            device_id: Some(principal.history.founding_device_id.clone()),
            audience_id: state.service_core_id(),
            scopes: vec!["ak.self.management_review.command.request.v1".into(),
                "ak.self.management_review.read.status.v1".into(),
                "ak.self.management_review.command.decide.v1".into()],
            expires_at: chrono::Utc::now()+chrono::TimeDelta::hours(1), revoked_at: None,
            revocation_ref: format!("ak:session:{}",uuid::Uuid::now_v7()),
            session_public_key: CanonicalSessionPublicJwk::new(serde_json::to_string(&serde_json::json!({
                "crv":"Ed25519","kty":"OKP","x":arkret_canonical::base64url_encode(key.verifying_key().to_bytes())
            })).unwrap()).unwrap(),
            cnf_jkt: jkt, credential_class: SessionGrantCredentialClass::Standard,
            holder_binding: SessionGrantHolderBinding::HumanDevice { device_binding: principal.history.founding_device_id.to_string() },
            device_binding: Some(SessionGrantDeviceBinding {
                device_id: principal.history.founding_device_id.clone(),
                authorization_event_id: principal.history.events[1].event_id.clone(), model_generation_ref: 1,
            }), scope_details: None,
        };
        grant.validate().unwrap();
        let outcome = SessionGrantValidationOutcome {
            active: true,
            status:
                arkret_models_identity::admin_grant::SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(grant),
        };
        outcome.validate().unwrap();
        outcomes.insert(token.clone(), outcome);
    }
    let audience = state.service_core_id();
    let public_base_url = state
        .config()
        .public_base_url
        .trim_end_matches('/')
        .to_owned();
    let introspection_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let (header_end, length) = loop {
                let mut chunk = [0u8; 2048];
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
                assert!(request.len() < 16384);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&request[..end]);
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while request.len() < header_end + length {
                let mut chunk = [0u8; 2048];
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
                assert!(request.len() < 16384);
            }
            let headers = String::from_utf8_lossy(&request[..header_end]);
            if headers.lines().next() == Some("POST /_arkret/peer/account-status/resolve HTTP/1.1")
            {
                use arkret_models_collaboration::account_lifecycle::{
                    AccountStatusResolveOutcome, AccountStatusResolveRequestBody,
                };
                let body = &request[header_end..header_end + length];
                let resolved: AccountStatusResolveRequestBody =
                    serde_json::from_slice(body).unwrap();
                resolved.validate().unwrap();
                assert!(
                    allowed_accounts.contains(&resolved.account_id),
                    "unused administrator must not be resolved"
                );
                assert_eq!(resolved.account_authority_id, audience);
                assert_eq!(resolved.limit, 128);
                let header_pairs = headers
                    .lines()
                    .skip(1)
                    .filter_map(|line| line.split_once(':'))
                    .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
                    .collect::<Vec<_>>();
                let policy = arkret_signatures::http_signature::SignatureVerificationPolicy::for_scenario(
                    arkret_signatures::http_signature::HttpSignatureScenario::ServiceToServiceV1,
                    &["content-digest","source-trust-domain","destination-trust-domain"]).unwrap();
                arkret_signatures::http_signature::verify_signed_canonical_json_message(
                    "POST",
                    &format!("http://{aa_address}/_arkret/peer/account-status/resolve"),
                    &aa_address,
                    "/_arkret/peer/account-status/resolve",
                    header_pairs
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str())),
                    false,
                    body,
                    &ed25519_dalek::SigningKey::from_bytes(&[83; 32]).verifying_key(),
                    &policy,
                    chrono::Utc::now().timestamp(),
                )
                .unwrap();
                let records = server_aa_records
                    .lock()
                    .unwrap()
                    .get(&resolved.account_id)
                    .into_iter()
                    .flatten()
                    .filter(|record| record.status_seq >= resolved.from_status_seq)
                    .take(usize::from(resolved.limit))
                    .cloned()
                    .collect();
                let answer = AccountStatusResolveOutcome {
                    account_authority_id: resolved.account_authority_id.clone(),
                    account_id: resolved.account_id.clone(),
                    records,
                    next_status_seq: None,
                    has_more: false,
                };
                answer.validate_for_request(&resolved).unwrap();
                let bytes = arkret_canonical::canonical_json_bytes(&answer).unwrap();
                let header = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                continue;
            }
            assert!(headers.lines().any(|line| {
                line.eq_ignore_ascii_case(&format!("authorization: Bearer {channel}"))
            }));
            let SessionGrantValidationInput::ByJwt(input) =
                serde_json::from_slice::<SessionGrantValidationInput>(
                    &request[header_end..header_end + length],
                )
                .unwrap()
            else {
                panic!("exact-token introspection required")
            };
            assert!(input.audience_id.as_ref() == Some(&audience));
            let outcome = outcomes.get(&input.grant_jwt).expect("exact issuer token");
            let bytes = arkret_canonical::canonical_json_bytes(outcome).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                bytes.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        }
    });
    ManagementReviewHttpFixture {
        service: coland_http::service(state),
        public_base_url,
        requester_token: tokens[0].clone(),
        approver_token: tokens[1].clone(),
        requester_key: keys[0].clone(),
        approver_key: keys[1].clone(),
        introspection_task,
        aa_records,
    }
}

async fn management_review_http_response<T: serde::Serialize>(
    fixture: &ManagementReviewHttpFixture,
    approver: bool,
    suffix: &str,
    operation: &str,
    body: &T,
) -> salvo::Response {
    use salvo::test::TestClient;
    let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let token = if approver {
        &fixture.approver_token
    } else {
        &fixture.requester_token
    };
    let path = format!("/_arkret/self/management-reviews/{suffix}");
    let key = if approver {
        &fixture.approver_key
    } else {
        &fixture.requester_key
    };
    let dpop = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new(
            "POST",
            format!("{}{path}", fixture.public_base_url),
        )
        .access_token(token.clone()),
        key,
    )
    .unwrap();
    TestClient::post(format!("http://server{path}"))
        .add_header("Authorization", format!("DPoP {token}"), true)
        .add_header("DPoP", dpop.header_value, true)
        .add_header("Arkret-Operation", operation, true)
        .add_header("Content-Type", "application/json", true)
        .body(bytes)
        .send(&fixture.service)
        .await
}

async fn management_review_http_refusal<T: serde::Serialize>(
    fixture: &ManagementReviewHttpFixture,
    approver: bool,
    suffix: &str,
    operation: &str,
    body: &T,
) -> (salvo::http::StatusCode, String) {
    use salvo::test::ResponseExt;
    let mut response = Box::pin(management_review_http_response(
        fixture, approver, suffix, operation, body,
    ))
    .await;
    let code = response.status_code.unwrap();
    let problem = response.take_json::<arkret_wire::Problem>().await.unwrap();
    // Only the registered type is returned to the assertion, never raw detail.
    (code, problem.problem_type)
}

async fn management_review_http_post<T: serde::Serialize>(
    fixture: &ManagementReviewHttpFixture,
    approver: bool,
    suffix: &str,
    operation: &str,
    body: &T,
) -> arkret_models_integration::management_review::ManagementReviewOutcome {
    use salvo::test::ResponseExt;
    let mut response = Box::pin(management_review_http_response(
        fixture, approver, suffix, operation, body,
    ))
    .await;
    assert_eq!(response.status_code, Some(salvo::http::StatusCode::OK));
    assert_eq!(
        response.headers().get("arkret-operation").unwrap(),
        operation
    );
    assert!(
        response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let result = response
        .take_json::<arkret_models_integration::management_review::ManagementReviewOutcome>()
        .await
        .unwrap();
    assert!(!result.request_id.is_empty());
    result
}
#[tokio::test]
async fn management_review_standard_http_operations_retain_signed_candidate() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        true, false, None,
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_historical_rotation_is_preserved_but_admin_loss_is_terminal() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false, true, None,
    )))
    .await
    .unwrap();
}

async fn management_review_ledger_count(pool: &coland_storage_postgres::PgPool) -> i64 {
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM management_review_requests")
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

/// Prepare signed issuer records without importing a receiver head. This is
/// used only to exercise the actual HTTP resolve and receiver append boundary.
async fn management_unstored_current_for_accounts(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    accounts: &[AccountId],
) -> coland_storage::ManagementReviewCurrent {
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Pcr {
        #[diesel(sql_type=diesel::sql_types::Text)]
        realm: String,
    }
    let mut observations = Vec::new();
    for account in accounts
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
    {
        let mut conn = pool.get().await.unwrap();
        let pcr: Pcr = diesel::sql_query("SELECT pcr_realm_id AS realm FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2")
            .bind::<diesel::sql_types::Text,_>(account.principal_id.as_str())
            .bind::<diesel::sql_types::Text,_>(account.station_id.as_str())
            .get_result(&mut conn).await.unwrap();
        let record = management_signed_status(
            station,
            &account,
            &pcr.realm.parse().unwrap(),
            None,
            arkret_models_collaboration::objects::account_status::AccountStatus::Active,
        );
        observations.push(
            coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve(record),
        );
    }
    coland_storage::ManagementReviewCurrent {
        station_id: station.core.clone(),
        observations,
    }
}

async fn management_advance_current(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    previous: &coland_storage::ManagementReviewCurrent,
    account: &AccountId,
    status: arkret_models_collaboration::objects::account_status::AccountStatus,
) -> coland_storage::ManagementReviewCurrent {
    let mut fresh = previous.clone();
    let observation = fresh
        .observations
        .iter_mut()
        .find(|obs| &obs.record().account_id == account)
        .unwrap();
    let record = management_signed_status(
        station,
        account,
        &observation.record().principal_control_realm_id,
        Some(observation.record()),
        status,
    );
    let persistence = PgPersistenceStore::new(pool.clone());
    Box::pin(management_append_status(&persistence, station, &record)).await;
    *observation =
        coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve(record);
    fresh
}

/// Lock only the original private review row to pause the production reader
/// after its PCR/AA qualification. The successor uses the real replica append
/// port and must wait until that review transaction releases its AA cut.
async fn management_review_writer_held_cut(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    _reviews: &coland_storage_postgres::PgAgentStore,
    caller: &arkret_wire::ActorId,
    lookup: &arkret_models_integration::management_review::ManagementReviewLookupRequestBody,
    current: &coland_storage::ManagementReviewCurrent,
    changed: &AccountId,
) {
    use coland_storage::AgentStore;
    use diesel::OptionalExtension;
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Number {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        number: i64,
    }
    let mut held = pool.get().await.unwrap();
    diesel::sql_query("BEGIN").execute(&mut held).await.unwrap();
    let pid = diesel::sql_query("SELECT pg_backend_pid()::bigint AS number")
        .get_result::<Number>(&mut held)
        .await
        .unwrap()
        .number;
    diesel::sql_query(
        "SELECT request_id FROM management_review_requests WHERE request_id=$1 FOR UPDATE",
    )
    .bind::<diesel::sql_types::Text, _>(&lookup.request_id)
    .execute(&mut held)
    .await
    .unwrap();
    let review_pool = pool.clone();
    let review_caller = caller.clone();
    let review_lookup = lookup.clone();
    let observed = current.clone();
    let reader = tokio::spawn(async move {
        Box::pin(
            coland_storage_postgres::PgAgentStore { pool: review_pool }.management_review_status(
                &review_caller,
                &review_lookup,
                &observed,
                chrono::Utc::now(),
            ),
        )
        .await
    });
    // This is a causal readiness fence, not a sleep assumed to mean "held".
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let reader_pid = loop {
        let mut conn = pool.get().await.unwrap();
        let waiting = diesel::sql_query("SELECT pid::bigint AS number FROM pg_stat_activity WHERE $1::bigint::integer=ANY(pg_blocking_pids(pid)) AND query LIKE '%management_review_requests%' AND query LIKE '%FOR UPDATE%'")
            .bind::<diesel::sql_types::BigInt,_>(pid).get_result::<Number>(&mut conn).await.optional().unwrap();
        if let Some(waiting) = waiting {
            break waiting.number;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "review did not reach its locked private row"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    let writer_pool = pool.clone();
    let writer_station = station.clone();
    let writer_current = current.clone();
    let writer_account = changed.clone();
    let (started, ready) = tokio::sync::oneshot::channel();
    let mut writer = tokio::spawn(async move {
        started.send(()).unwrap();
        Box::pin(management_advance_current(
            &writer_pool,
            &writer_station,
            &writer_current,
            &writer_account,
            arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated,
        ))
        .await
    });
    ready.await.unwrap();
    let writer_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut conn = pool.get().await.unwrap();
        let waiting = diesel::sql_query("SELECT COUNT(*) AS number FROM pg_stat_activity s WHERE $1::bigint::integer=ANY(pg_blocking_pids(s.pid)) AND s.wait_event_type='Lock' AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=s.pid AND l.locktype='advisory' AND NOT l.granted)")
            .bind::<diesel::sql_types::BigInt,_>(reader_pid).get_result::<Number>(&mut conn).await.unwrap().number;
        if waiting > 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < writer_deadline,
            "original AA append did not reach the held review advisory cut"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
            .await
            .is_err(),
        "AA successor passed an active review qualification cut"
    );
    diesel::sql_query("ROLLBACK")
        .execute(&mut held)
        .await
        .unwrap();
    drop(held);
    assert_eq!(
        reader.await.unwrap().unwrap().status,
        arkret_models_integration::management_review::ManagementReviewStatus::Approved
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), writer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn management_review_aa_missing_observation() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::MissingObservation),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_authoritative_empty_requires_head_and_real_first_append() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        true,
        false,
        Some(ManagementAaCase::EmptyAuthorityHead),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_stale_observation_refuses_before_private_request() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::StaleObservation),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_wrong_full_account_is_not_projected_to_a_signer() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::WrongFullAccount),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_wrong_receiving_station_is_not_current_qualification() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::WrongReceivingStation),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_terminal_caller_cannot_create_private_intent() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::CallerTerminal),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_terminal_controller_supersedes_and_consumes_nothing() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::ControllerTerminal),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_terminal_retained_vote_supersedes_and_consumes_nothing() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::RetainedVoteTerminal),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_unused_foreign_admin_is_never_resolved() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        true,
        false,
        Some(ManagementAaCase::UnusedForeignAdministrator),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_signed_successor_waits_for_held_review_cut() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::WriterHeldCut),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_real_expiry_consumes_nothing() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::RealExpiry),
    )))
    .await
    .unwrap();
}

#[tokio::test]
async fn management_review_aa_consumed_exact_replay_survives_later_terminal_account() {
    tokio::spawn(Box::pin(management_review_atomic_join_scenario(
        false,
        false,
        Some(ManagementAaCase::ConsumedReplay),
    )))
    .await
    .unwrap();
}

// Supplementary current-consumer fixtures. These are native accepted-history
// imports, not normal Coauth issuance or HTTP pairing evidence. Every Agent
// retains its complete accepted PCR/DID binding, real runtime signature and
// encrypted verifier custody through the original production owners.
struct OwnedConsumerCandidate {
    account: AccountId,
    endpoint: coland_storage::AgentEndpointGuard,
    join: coland_storage::AuthorityCommitTransaction,
    _vault: DeliveryScopeVault,
}

struct OwnedConsumerFixture {
    _database: TestDatabase,
    pool: coland_storage_postgres::PgPool,
    station: historical_control_source::HistoricalControlStation,
    controller: pcr_genesis::PcrGenesisFixture,
    founder: AccountId,
    root_event_ref: arkret_wire::EventId,
    controller_join: coland_storage::AuthorityCommitTransaction,
    head: coland_storage::AuthorityCommitTransaction,
    agents: Vec<OwnedConsumerCandidate>,
}

fn boxed_owned_consumer_fixture(
    count: usize,
) -> Pin<Box<dyn Future<Output = OwnedConsumerFixture> + Send>> {
    Box::pin(owned_consumer_fixture(count))
}

async fn owned_consumer_fixture(count: usize) -> OwnedConsumerFixture {
    use coland_storage::{AgentControlAdmissionWrite, AgentParticipationStore};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        ed25519_dalek::SigningKey::from_bytes(&[83; 32])
            .verifying_key()
            .as_bytes(),
    );
    let station = historical_control_source::HistoricalControlStation::new_with_assertion_keys(
        "owned-consumer-supplement",
        [83; 32],
        &[("notary-key", &public)],
    );
    let controller = Box::pin(accepted_controller(&pool, station.did.clone())).await;
    let founder = Box::pin(ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        station.did.clone(),
        "owned-consumer-founder",
    ))
    .await;
    assert_ne!(controller.history.account, founder);
    let bootstrap = ordinary_realm::bootstrap_unit_with_history_for_account(
        &format!("owned-consumer-{}", uuid::Uuid::now_v7()),
        "public",
        "since_join",
        &founder,
        &station.did,
    );
    let bootstrap = Box::pin(ordinary_realm::source_bootstrap(&pool, bootstrap)).await;
    fixture_bootstrap_step(
        &pool,
        &bootstrap,
        bootstrap.transactions[0].commit.committed_at,
    )
    .await
    .unwrap();
    let root_event_ref = bootstrap.transactions[0].event.event_id.clone();
    let parent = bootstrap.transactions.last().unwrap();
    let controller_actor = arkret_wire::ActorId::account(controller.history.account.clone());
    let join = ordinary_realm::next_request_for_actor(
        parent,
        EventKind::MemberState,
        controller_actor.clone(),
        serde_json::json!({"member_id":controller_actor,"membership":"join"}),
        parent.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let join = Box::pin(ordinary_realm::source_request(&pool, join)).await;
    fixture_commit_step(&pool, join.clone()).await.unwrap();
    let mut head = join.authority_commit.clone();
    let realm = head.event.realm_id.clone();
    let mut scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope =
        serde_json::from_value(serde_json::json!({
            "actions":[arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                arkret_wire::CapabilityActionId::CircleMemberAdd,
                arkret_wire::CapabilityActionId::MessageCreate,
                arkret_wire::CapabilityActionId::EventRead,
                "ak.self.committed_event.resource.get.v1",
                arkret_wire::ServiceOperationId::SELF_BLOB_RESOURCE_GET_V1,
                arkret_wire::ServiceOperationId::SELF_BLOB_RESOURCE_HEAD_V1,
                arkret_wire::CapabilityActionId::ObjectReadContent,
                arkret_wire::CapabilityActionId::ObjectReadMetadata],
            "resources":[{"kind":"operation","operation":arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1},
                {"kind":"realm","realm_id":realm}]
        }))
        .unwrap();
    scope.actions =
        arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(&scope.actions).unwrap();
    let device_guard =
        Box::pin(controller.admit_founding_device(&PgPersistenceStore::new(pool.clone())))
            .await
            .unwrap();
    let mut agents = Vec::new();
    for index in 0..count {
        // Each actual Provision advances the controller PCR. The next Agent
        // must extend that accepted head, not reuse the genesis entry1 cut.
        let controller_head = PgAuthorityCommitStore { pool: pool.clone() }
            .held_stream_head_commit(&controller.unit.transactions[1].commit.stream_ref)
            .await
            .unwrap()
            .unwrap();
        let did = historical_control_source::managed_agent_did(
            &controller.history.account.principal_id,
            &format!("consumer-{index}"),
            controller_head.committed_at,
        );
        let (account, genesis, _) = Box::pin(provision_owned_agent_binding_phase_at_head(
            &pool,
            &controller,
            did.clone(),
            Some(&scope),
            true,
            None,
            &[102; 32],
            Some(&controller_head),
        ))
        .await;
        let mut authorization = sidecar_agent::agent_key_authorization(
            &did,
            &controller.history.account.principal_id,
            genesis.commit.committed_at,
        );
        authorization["agent_key_scope"] = serde_json::to_value(&scope).unwrap();
        authorization["audience"] = serde_json::json!([station.core]);
        let key = sidecar_agent::agent_control_event(
            &controller.history.device_verification_method,
            controller.history.founding_device_signing_seed,
            &controller.history.account,
            &account,
            &genesis.event.realm_id,
            &format!("{did}#managed-controller"),
            authorization,
            genesis.commit.committed_at,
        );
        let committed = sidecar_agent::station_successor(&genesis.commit, &key, &station.did, 1);
        Box::pin(historical_control_source::admit_control(
            &coland_storage_postgres::PgActorProfileStore { pool: pool.clone() },
            &pool,
            AgentControlAdmissionWrite {
                commit: coland_storage::AuthorityCommitTransaction {
                    expected_authority: genesis.expected_authority.clone(),
                    event: key.clone(),
                    commit: committed.clone(),
                    producer_signer_fact: None,
                    mls_state: None,
                    welcomes: Vec::new(),
                    recipient_queue_capacity: 0,
                },
                queued_at: committed.committed_at,
            },
        ))
        .await
        .unwrap();
        let agent_join = ordinary_realm::next_request_for_actor(
            &head,
            EventKind::MemberState,
            arkret_wire::ActorId::account(controller.history.account.clone()),
            serde_json::json!({"member_id":arkret_wire::ActorId::account(account.clone()),"membership":"join",
                "agent_controller_binding":{"controller_account_id":controller.history.account,
                    "controller_membership_generation_ref":join.authority_commit.event.event_id}}),
            head.commit.committed_at.max(committed.committed_at)
                + chrono::TimeDelta::milliseconds(1),
        );
        let agent_join = Box::pin(ordinary_realm::source_request(&pool, agent_join)).await;
        fixture_commit_step(&pool, agent_join.clone())
            .await
            .unwrap();
        let endpoint = coland_storage::AgentEndpointGuard {
            pcr_realm_id: genesis.event.realm_id.clone(),
            agent_id: account.principal_id.clone(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: key.event_id.clone(),
                commit_id: committed.commit_id.clone(),
                stream_ref: committed.stream_ref.clone(),
                stream_position: committed.stream_position,
            },
            verification_method: arkret_wire::DidUrl::new(
                key.payload["verification_method"].as_str().unwrap(),
            )
            .unwrap(),
        };
        let (vault, _) = Box::pin(retain_delivery_scope_for_runtime(
            &pool,
            &station,
            &controller,
            &account,
            &key,
            &scope,
            &endpoint,
            true,
        ))
        .await;
        let public = agent_mode_request(
            &agent_join.authority_commit,
            "public",
            None,
            &controller,
            &account,
            &device_guard,
        );
        let public = Box::pin(ordinary_realm::source_request(&pool, public)).await;
        fixture_commit_step(&pool, public.clone()).await.unwrap();
        assert!(
            coland_storage_postgres::PgAgentParticipationStore { pool: pool.clone() }
                .compare_and_swap_selection(
                    serde_json::json!({"agent_id":account.principal_id,
                        "scope_kind":"realm","scope_key":format!("realm:{realm}"),
                        "realm_id":realm,"scope":{"kind":"realm","realm_id":realm},
                        "version":1,"reply_message":true,"reaction_add":false,
                        "reaction_remove":false,"accept_third_party_mention":false,
                        "act_on_behalf":false}),
                    0,
                )
                .await
                .unwrap()
        );
        head = public.authority_commit;
        agents.push(OwnedConsumerCandidate {
            account,
            endpoint,
            join: agent_join.authority_commit,
            _vault: vault,
        });
    }
    OwnedConsumerFixture {
        _database: database,
        pool,
        station,
        controller,
        founder,
        root_event_ref,
        controller_join: join.authority_commit,
        head,
        agents,
    }
}

fn owned_consumer_signed_request(
    previous: &coland_storage::AuthorityCommitTransaction,
    agent: &OwnedConsumerCandidate,
    kind: EventKind,
    scope: arkret_wire::ScopeRef,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> coland_storage::EventCommitRequest {
    let event = ordinary_realm::event_for_actor(
        kind,
        scope,
        arkret_wire::ActorId::account(agent.account.clone()),
        payload,
        at,
    );
    let event = device_authorization_history::sign_event(
        event,
        agent.endpoint.verification_method.clone(),
        [0x61; 32],
    );
    assert!(event.executed_by.is_none());
    assert!(event.human_device_producer().unwrap().is_none());
    // Real Agent proof verification, independently of the store's native
    // accepted-current recheck. No Human/Device fixture signer is substituted.
    let envelope = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(&event)
        .unwrap();
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        event.producer_proof.as_ref().unwrap(),
        &envelope,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: ed25519_dalek::SigningKey::from_bytes(&[0x61; 32])
                .verifying_key()
                .as_bytes()
                .to_vec(),
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let stream =
        arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .unwrap();
    let mut request = ordinary_realm::request_for_event(previous, event, at);
    if previous.commit.stream_ref != stream {
        request.authority_commit.commit.stream_position = 0;
        request.authority_commit.commit.previous_commit_ref = None;
    }
    request.authority_commit.commit.stream_ref = stream;
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::Agent {
        pcr_realm_id: agent.endpoint.pcr_realm_id.clone(),
        agent_id: agent.endpoint.agent_id.clone(),
        authorization_ref: agent.endpoint.authorization_ref.clone(),
        verification_method: agent.endpoint.verification_method.clone(),
    });
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    ordinary_realm::seal_final_commit(&mut request.authority_commit.commit);
    request
}

async fn owned_consumer_footprint(
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
    let extra = diesel::sql_query(
        "SELECT jsonb_build_object( \
         'circle_members',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY to_jsonb(c)::text),'[]'::jsonb) FROM circle_member_state_current_results c WHERE realm_id=$1), \
         'quota',(SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]'::jsonb) FROM capability_quota_counters q), \
         'quota_consumptions',(SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]'::jsonb) FROM capability_quota_consumptions q), \
         'projection_events',(SELECT COUNT(*) FROM projection_events WHERE realm_id=$1)) AS value",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<Row>(&mut *conn)
    .await
    .unwrap()
    .value;
    drop(conn);
    serde_json::json!({"current":agent_mode_footprint(pool, realm).await,"extra":extra,
        "delivery_digest":owned_welcome_footprint(pool, realm, realm).await})
}

async fn owned_consumer_root_grant(
    fixture: &OwnedConsumerFixture,
    previous: &coland_storage::AuthorityCommitTransaction,
    subject: &arkret_wire::ActorId,
    actions: &[&str],
    resources: serde_json::Value,
    constraints: Option<serde_json::Value>,
) -> coland_storage::EventCommitRequest {
    let mut grant = serde_json::json!({"schema":"ak.schema.capability.v1",
        "realm_id":previous.event.realm_id,"issuer_id":arkret_wire::ActorId::account(fixture.founder.clone()),
        "subject":subject,"actions":actions,"resources":resources,
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":previous.event.realm_id,
            "authority_event_ref":fixture.root_event_ref,"authority_generation":0}],
        "issued_at":arkret_canonical::format_timestamp_canonical(previous.commit.committed_at)});
    if let Some(constraints) = constraints {
        grant["constraints"] = constraints;
    }
    let request = ordinary_realm::next_request_for_actor(
        previous,
        EventKind::CapabilityGrant,
        arkret_wire::ActorId::account(fixture.founder.clone()),
        serde_json::json!({"grant":grant}),
        previous.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    Box::pin(ordinary_realm::source_request(&fixture.pool, request)).await
}

async fn owned_consumer_refused_without_effects(
    fixture: &OwnedConsumerFixture,
    request: coland_storage::EventCommitRequest,
    code: coland_storage::ConflictCode,
) {
    let realm = &fixture.head.event.realm_id;
    let before = owned_consumer_footprint(&fixture.pool, realm).await;
    let event_id = request.authority_commit.event.event_id.clone();
    let error = fixture_commit_step(&fixture.pool, request)
        .await
        .unwrap_err();
    assert_eq!(error.conflict_code(), Some(code));
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    assert!(store.queued_event(&event_id).await.unwrap().is_none());
    assert!(store.committed_event(&event_id).await.unwrap().is_none());
    let after = owned_consumer_footprint(&fixture.pool, realm).await;
    assert!(
        before == after,
        "refused signed Event changed business footprint"
    );
}

async fn owned_consumer_circle_scenario(deny_join: bool) {
    use arkret_wire::{ActorId, ScopeRef};
    let fixture = boxed_owned_consumer_fixture(1).await;
    let agent = &fixture.agents[0];
    let realm = &fixture.head.event.realm_id;
    let created_at = fixture.head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let create = Box::pin(ordinary_realm::source_request(
        &fixture.pool,
        ordinary_realm::next_request_for_actor(
            &fixture.head, EventKind::CircleCreate,
            ActorId::account(fixture.founder.clone()),
            serde_json::json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
                "title":"Actual Agent self-entry","display":{"short_name":"Owned", "color_token":"blue","symbol":{"glyph":"lock"}},
                "directory_visibility":"members","join_rule":"public","history_access":"since_join",
                "state":"active","created_by":ActorId::account(fixture.founder.clone()),
                "created_at":arkret_canonical::format_timestamp_canonical(created_at)}}), created_at,
        ),
    )).await;
    fixture_commit_step(&fixture.pool, create.clone())
        .await
        .unwrap();
    let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let scope = ScopeRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let member = ActorId::account(agent.account.clone());
    let parent = Box::pin(ordinary_realm::parent_membership_revision(
        &fixture.pool,
        realm,
        &member,
    ))
    .await;
    assert_eq!(
        parent,
        serde_json::json!({"commit_id":agent.join.commit.commit_id,
        "stream_position":agent.join.commit.stream_position})
    );
    let payload = serde_json::json!({"circle_id":circle,"member_id":member,"membership":"join",
        "expected_membership":null,"parent_membership_revision":parent});
    let no_grant = owned_consumer_signed_request(
        &create.authority_commit,
        agent,
        EventKind::CircleMemberState,
        scope.clone(),
        payload.clone(),
        created_at + chrono::TimeDelta::milliseconds(1),
    );
    owned_consumer_refused_without_effects(
        &fixture,
        no_grant,
        coland_storage::ConflictCode::CapabilityDenied,
    )
    .await;

    // This is a normal Circle capability, never the closed Owned-Agent
    // special issuer source (which does not grant CircleMemberAdd).
    let controller_grant = Box::pin(owned_consumer_root_grant(
        &fixture,
        &create.authority_commit,
        &ActorId::account(fixture.controller.history.account.clone()),
        &["ak.circle.member.add"],
        serde_json::json!([{"kind":"circle","realm_id":realm,"circle_id":circle}]),
        None,
    ))
    .await;
    fixture_commit_step(&fixture.pool, controller_grant.clone())
        .await
        .unwrap();
    let permission = Box::pin(owned_consumer_root_grant(
        &fixture,
        &controller_grant.authority_commit,
        &member,
        &["ak.circle.member.add"],
        serde_json::json!([{"kind":"circle","realm_id":realm,"circle_id":circle}]),
        None,
    ))
    .await;
    fixture_commit_step(&fixture.pool, permission.clone())
        .await
        .unwrap();
    let mut circle_head = permission.authority_commit.clone();
    if deny_join {
        // Actual Circle policy source, with parent Realm default Allow.
        // Circle does not gain the Realm controller-written Join carve-out
        // or the unrelated MemberState management-review carrier.
        let policy_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
        let at =
            permission.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1);
        let event = ordinary_realm::event_for_actor(
            EventKind::PolicySet,
            scope.clone(),
            ActorId::account(fixture.founder.clone()),
            serde_json::json!({"policy_id":policy_id,"expected_revision":null,
                "value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":realm,
                    "policy_kind":"agent","default_effect":"allow",
                    "created_by":ActorId::account(fixture.founder.clone()),"created_at":arkret_canonical::format_timestamp_canonical(at),
                    "rules":[{"rule_id":"circle_owned_join_deny","kind":"agent","effect":"deny",
                        "agent_target":{"kind":"all"},"agent_operations":["join"]}]}}),
            at,
        );
        let mut policy = ordinary_realm::request_for_event(&permission.authority_commit, event, at);
        policy.authority_commit.commit.stream_ref =
            arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap();
        policy.authority_commit.commit.stream_position = 0;
        policy.authority_commit.commit.previous_commit_ref = None;
        ordinary_realm::seal_final_commit(&mut policy.authority_commit.commit);
        let policy = Box::pin(ordinary_realm::source_request(&fixture.pool, policy)).await;
        fixture_commit_step(&fixture.pool, policy.clone())
            .await
            .unwrap();
        circle_head = policy.authority_commit;
    }
    let mut wrong_parent = payload.clone();
    wrong_parent["parent_membership_revision"]["commit_id"] =
        serde_json::json!(create.authority_commit.commit.commit_id);
    let wrong = owned_consumer_signed_request(
        &circle_head,
        agent,
        EventKind::CircleMemberState,
        scope.clone(),
        wrong_parent,
        circle_head.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    owned_consumer_refused_without_effects(
        &fixture,
        wrong,
        coland_storage::ConflictCode::FailedPrecondition,
    )
    .await;
    let join = owned_consumer_signed_request(
        &circle_head,
        agent,
        EventKind::CircleMemberState,
        scope.clone(),
        payload,
        circle_head.commit.committed_at + chrono::TimeDelta::milliseconds(2),
    );
    if deny_join {
        owned_consumer_refused_without_effects(
            &fixture,
            join,
            coland_storage::ConflictCode::CapabilityDenied,
        )
        .await;
    } else {
        let outcome = fixture_commit_step(&fixture.pool, join.clone())
            .await
            .unwrap();
        assert!(outcome.event_inserted);
        let accepted = PgAuthorityCommitStore {
            pool: fixture.pool.clone(),
        }
        .committed_event(&join.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
        assert!(accepted.event == join.authority_commit.event);
        assert!(accepted.commit == join.authority_commit.commit);
        // A management Allow is a separate gate, not automatic MLS membership.
        let mut conn = fixture.pool.get().await.unwrap();
        use diesel::sql_types::{BigInt, Text};
        use diesel_async::RunQueryDsl;
        #[derive(diesel::QueryableByName)]
        struct Counts {
            #[diesel(sql_type = BigInt)]
            joined: i64,
            #[diesel(sql_type = BigInt)]
            groups: i64,
        }
        let counts = diesel::sql_query("SELECT (SELECT COUNT(*) FROM circle_member_state_current_results WHERE circle_id=$1 AND member_id=$2 AND membership='join') AS joined, (SELECT COUNT(*) FROM mls_group_current_results WHERE realm_id=$3) AS groups")
            .bind::<Text,_>(circle.as_str()).bind::<Text,_>(member.to_string()).bind::<Text,_>(realm.as_str())
            .get_result::<Counts>(&mut *conn).await.unwrap();
        assert_eq!(counts.joined, 1);
        assert_eq!(
            counts.groups, 0,
            "Circle membership cannot fabricate Add or Welcome"
        );
    }
}

#[tokio::test]
async fn owned_agent_self_circle_join_requires_actual_grant_and_exact_parent_current() {
    fixture_step(Box::pin(owned_consumer_circle_scenario(false))).await;
}

#[tokio::test]
async fn owned_agent_self_circle_join_obeys_actual_circle_policy_deny() {
    fixture_step(Box::pin(owned_consumer_circle_scenario(true))).await;
}

async fn owned_consumer_quota_scenario() {
    use arkret_wire::{ActorId, ScopeRef};
    let fixture = boxed_owned_consumer_fixture(2).await;
    let realm = &fixture.head.event.realm_id;
    let controller = ActorId::account(fixture.controller.history.account.clone());
    let at = fixture.head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let strand = Box::pin(ordinary_realm::source_request(
        &fixture.pool,
        ordinary_realm::next_request_for_actor(
            &fixture.head,
            EventKind::StrandCreate,
            ActorId::account(fixture.founder.clone()),
            serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
                "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":"Owned shared quota"},"state":"active",
                "created_by":ActorId::account(fixture.founder.clone()),
                "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        ),
    ))
    .await;
    fixture_commit_step(&fixture.pool, strand.clone())
        .await
        .unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = Box::pin(ordinary_realm::source_request(&fixture.pool,
        ordinary_realm::next_request_for_actor(&strand.authority_commit, EventKind::RealmSetDefaultStrand,
            ActorId::account(fixture.founder.clone()),
            serde_json::json!({"realm_id":realm,"strand_id":strand_id,"expected_default_strand_id":null}),
            at + chrono::TimeDelta::milliseconds(1)))).await;
    fixture_commit_step(&fixture.pool, default.clone())
        .await
        .unwrap();
    let quota = Box::pin(owned_consumer_root_grant(&fixture, &default.authority_commit,
        &controller, &["ak.message.create"], serde_json::json!([{"kind":"realm","realm_id":realm}]),
        Some(serde_json::json!([{"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow",
            "max_operations":1,"period":"P1D","constraint_scope":"per_actor"}])))).await;
    fixture_commit_step(&fixture.pool, quota.clone())
        .await
        .unwrap();
    let parent_grant_id =
        arkret_wire::GrantId::from_event_id(&quota.authority_commit.event.event_id);
    let mut head = quota.authority_commit.clone();
    for agent in &fixture.agents {
        let issued = head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
        let source = arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::OwnedAgent {
            realm_id: realm.clone(),
            controller_account_id: fixture.controller.history.account.clone(),
            controller_join_event_id: fixture.controller_join.event.event_id.clone(),
            agent_join_event_id: agent.join.event.event_id.clone(),
        };
        let grant = ordinary_realm::next_request_for_actor(
            &head,
            EventKind::CapabilityGrant,
            controller.clone(),
            serde_json::json!({"grant":{"schema":"ak.schema.capability.v1",
                "realm_id":realm,"issuer_id":controller,"subject":ActorId::account(agent.account.clone()),
                "actions":["ak.message.create"],"resources":[{"kind":"realm","realm_id":realm}],
                "constraints":[{"constraint_kind":"authority_control","effect":"allow","max_authority_depth":0,"authority_regrant_allowed":false}],
                "issuer_authority_refs":[source],"issued_at":arkret_canonical::format_timestamp_canonical(issued)}}),
            issued,
        );
        let grant = Box::pin(ordinary_realm::source_request(&fixture.pool, grant)).await;
        fixture_commit_step(&fixture.pool, grant.clone())
            .await
            .unwrap();
        head = grant.authority_commit;
    }
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let candidates = [
        owned_consumer_signed_request(
            &head,
            &fixture.agents[0],
            EventKind::MessageCreate,
            scope.clone(),
            ordinary_realm::message_payload(&strand_id, "first real Agent"),
            head.commit.committed_at + chrono::TimeDelta::milliseconds(1),
        ),
        owned_consumer_signed_request(
            &head,
            &fixture.agents[1],
            EventKind::MessageCreate,
            scope,
            ordinary_realm::message_payload(&strand_id, "second real Agent"),
            head.commit.committed_at + chrono::TimeDelta::milliseconds(2),
        ),
    ];
    assert_ne!(
        candidates[0].authority_commit.event.event_id,
        candidates[1].authority_commit.event.event_id
    );
    let (first, second) = tokio::join!(
        fixture_commit_step(&fixture.pool, candidates[0].clone()),
        fixture_commit_step(&fixture.pool, candidates[1].clone())
    );
    assert_eq!(
        usize::from(first.is_ok()) + usize::from(second.is_ok()),
        1,
        "both Agent Events cannot reserve the last controller unit"
    );
    let (winner, loser, error) = if first.is_ok() {
        (0, 1, second.unwrap_err())
    } else {
        (1, 0, first.unwrap_err())
    };
    assert!(
        matches!(
            error.conflict_code(),
            Some(
                coland_storage::ConflictCode::RateLimited
                    | coland_storage::ConflictCode::TemporarilyUnavailable
            )
        ),
        "first loser must be the registered quota or concurrent-head refusal"
    );
    let winner_request = &candidates[winner];
    let loser_request = &candidates[loser];
    let before = owned_consumer_footprint(&fixture.pool, realm).await;
    let duplicate = fixture_commit_step(&fixture.pool, winner_request.clone())
        .await
        .unwrap();
    assert!(!duplicate.event_inserted);
    assert!(
        before == owned_consumer_footprint(&fixture.pool, realm).await,
        "exact accepted signed Event replay must not consume quota again"
    );
    // Keep the original loser signature/Event exactly; only the Station's
    // proposed Commit cursor advances to the newly accepted stream head.
    let mut retry = ordinary_realm::request_for_event(
        &winner_request.authority_commit,
        loser_request.authority_commit.event.clone(),
        winner_request.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    retry.self_producer_guard = loser_request.self_producer_guard.clone();
    retry.realm_fanout_source = loser_request.realm_fanout_source.clone();
    assert!(retry.authority_commit.event == loser_request.authority_commit.event);
    ordinary_realm::seal_final_commit(&mut retry.authority_commit.commit);
    owned_consumer_refused_without_effects(
        &fixture,
        retry,
        coland_storage::ConflictCode::RateLimited,
    )
    .await;
    use diesel::sql_types::{BigInt, Text};
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Counter {
        #[diesel(sql_type = BigInt)]
        consumed: i64,
        #[diesel(sql_type = Text)]
        counter_key: String,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let rows = diesel::sql_query("SELECT consumed,counter_key FROM capability_quota_counters WHERE grant_id=$1 ORDER BY counter_key")
        .bind::<Text,_>(parent_grant_id.as_str()).load::<Counter>(&mut *conn).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].consumed, 1);
    let original_key: Vec<String> = serde_json::from_str(&rows[0].counter_key).unwrap();
    assert!(
        original_key == ["per_actor".to_owned(), controller.to_string()],
        "reservation keeps the exact original parent controller counter key"
    );
    for agent in &fixture.agents {
        assert!(!original_key.contains(&ActorId::account(agent.account.clone()).to_string()));
    }
}

#[tokio::test]
async fn owned_agent_signed_events_share_the_last_controller_quota_and_replay_once() {
    fixture_step(Box::pin(owned_consumer_quota_scenario())).await;
}

struct OwnedConsumerHttpFixture {
    state: coland_http::state::AppState,
    service: std::sync::Arc<salvo::Service>,
    base_url: String,
    token: String,
    key: ed25519_dalek::SigningKey,
    issuer_task: tokio::task::JoinHandle<()>,
    issuer_status: std::sync::Arc<std::sync::atomic::AtomicU16>,
    object_storage: Option<std::sync::Arc<dyn coland_services::delivery::ObjectStoragePort>>,
    grant_expires_at: chrono::DateTime<chrono::Utc>,
    delivery_session_scope: (Vec<String>, serde_json::Map<String, serde_json::Value>),
    _receiver_directory: Option<OwnedCertificateDirectory>,
    // Keep the foreign Station's exclusive migrated database lease alive for
    // its AppState. DeviceInventory belongs to exactly one serving Station.
    _receiver_database: Option<TestDatabase>,
}
impl Drop for OwnedConsumerHttpFixture {
    fn drop(&mut self) {
        self.issuer_task.abort();
    }
}

// Exact-token issuer fixture over the real introspection transport. The
// resource-server route, DPoP verification and current delivery gates are
// production code; this is deliberately not normal Coauth OAuth evidence.
async fn owned_consumer_http_fixture(fixture: &OwnedConsumerFixture) -> OwnedConsumerHttpFixture {
    let agent = &fixture.agents[0];
    Box::pin(owned_consumer_http_for_endpoint(
        &fixture.pool,
        &fixture.station,
        &fixture.controller.history.account,
        &fixture.head.event.realm_id,
        &agent.account,
        &agent.endpoint,
        &agent._vault,
    ))
    .await
}

async fn owned_consumer_http_for_endpoint(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    controller: &AccountId,
    realm: &arkret_wire::RealmId,
    agent: &AccountId,
    endpoint: &coland_storage::AgentEndpointGuard,
    vault: &DeliveryScopeVault,
) -> OwnedConsumerHttpFixture {
    owned_consumer_http_for_endpoint_with_storage(
        pool,
        station,
        controller,
        realm,
        agent,
        endpoint,
        vault,
        None,
        chrono::TimeDelta::hours(1),
        None,
    )
    .await
}

async fn owned_consumer_http_for_endpoint_with_storage(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    controller: &AccountId,
    realm: &arkret_wire::RealmId,
    agent: &AccountId,
    endpoint: &coland_storage::AgentEndpointGuard,
    vault: &DeliveryScopeVault,
    object_storage: Option<std::sync::Arc<dyn coland_services::delivery::ObjectStoragePort>>,
    grant_lifetime: chrono::TimeDelta,
    receiving_station: Option<&historical_control_source::HistoricalControlStation>,
) -> OwnedConsumerHttpFixture {
    use arkret_models_collaboration::session_grants::*;
    use arkret_models_identity::session_credential::*;
    use sha2::{Digest, Sha256};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let channel = uuid::Uuid::now_v7().to_string();
    let receiver_database = if receiving_station.is_some() {
        Some(TestDatabase::lease().await)
    } else {
        None
    };
    let receiver_pool = receiver_database
        .as_ref()
        .map(TestDatabase::pool)
        .unwrap_or_else(|| pool.clone());
    let persistence = std::sync::Arc::new(PgPersistenceStore::new(receiver_pool.clone()));
    let receiver = receiving_station.unwrap_or(station);
    let identity = receiver
        .install_runtime_identity(persistence.as_ref())
        .await;
    let mut config = coland_test_support::app_config();
    config.development_mode = true;
    // A foreign receiver has its own encrypted service vault. It neither
    // imports the owning Station's private custody nor asserts remote Agent
    // qualification. This request is rejected at the original Account binding.
    let receiver_directory = if receiving_station.is_some() {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!(
            "arkret-owned-receiver-vault-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = OwnedCertificateDirectory(directory);
        let values = std::collections::BTreeMap::from([
            (
                "COLAND_KEYSTORE_BACKEND".to_owned(),
                "encrypted_file".to_owned(),
            ),
            (
                "COLAND_KEYSTORE_PATH".to_owned(),
                directory
                    .0
                    .join("receiver-private-vault.enc")
                    .to_str()
                    .unwrap()
                    .to_owned(),
            ),
            (
                "COLAND_KEYSTORE_MASTER_KEY".to_owned(),
                arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            ),
        ]);
        config.key_store = coland_http::config::KeyStoreConfig::from_values(&values).unwrap();
        Some(directory)
    } else {
        config.key_store = vault.config.clone();
        None
    };
    let receiver_key_store = config.key_store.clone();
    config.public_base_url = if receiving_station.is_some() {
        identity
            .identity()
            .unwrap()
            .registration_key
            .public_base_url()
            .as_str()
            .to_owned()
    } else {
        vault.state.config().public_base_url.clone()
    };
    config.trust_domain = vault.state.config().trust_domain.clone();
    config.session_grant_introspection_url = Some(format!(
        "{origin}/_coauth/internal/session-grants/introspect"
    ));
    config.account_authority_url = Some(origin.clone());
    config.register_test_internal_authority_channel(channel.clone());
    let state =
        coland_test_support::app_state_with_identity(config, persistence, identity, [83; 32])
            .with_verifier_private_keystore(std::sync::Arc::from(
                receiver_key_store
                    .open(coland_http::config::SERVICE_IDENTITY_KEYSTORE_APP)
                    .unwrap()
                    .unwrap(),
            ));
    let state = if let Some(storage) = object_storage.as_ref() {
        let identity = state.service_identity_state();
        let serving = identity.identity().unwrap();
        coland_http::state::AppState::from_runtime(
            state.config().clone(),
            coland_http::state::AppStateRuntime {
                persistence: coland_services::persistence::PersistenceHandle::from_shared(
                    std::sync::Arc::new(PgPersistenceStore::new(receiver_pool.clone())),
                ),
                projections: coland_services::projection::ProjectionService::new(
                    &state.service_id().to_string(),
                ),
                realm_directory: coland_http::state::build_realm_directory(
                    state.config(),
                    &serving.did,
                    &serving.service_id,
                    [83; 32],
                ),
                object_storage: storage.clone(),
                settings_persistence: std::sync::Arc::new(OwnedConsumerFixtureSettings),
                runtime_health: std::sync::Arc::new(OwnedConsumerFixtureHealth {
                    pool: receiver_pool.clone(),
                }),
                event_broadcast: coland_http::state::EventBroadcast::new(1024),
                storage_mode: "postgres",
            },
            (*identity).clone(),
            (*state.service_resolution_commitment()).clone(),
            [83; 32],
        )
        .with_verifier_private_keystore(std::sync::Arc::from(
            receiver_key_store
                .open(coland_http::config::SERVICE_IDENTITY_KEYSTORE_APP)
                .unwrap()
                .unwrap(),
        ))
    } else {
        state
    };
    // Requested material stays bound to the original authenticated owning
    // Station; a receiver cannot reinterpret it as its own accepted custody.
    let evidence = vault
        .state
        .qualified_agent_scope_evidence(endpoint)
        .await
        .unwrap();
    let scope = &evidence
        .command()
        .requested_scope_disclosure
        .requested_scope;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]);
    let jwk = arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&key.verifying_key());
    let token = uuid::Uuid::now_v7().to_string();
    // This fixture requests no external egress endpoint. Operation/action
    // permissions stay in the original scopes; they are not endpoint URLs.
    let details = serde_json::json!({"controller_principal_id":controller.principal_id,
        "agent_key_authorization_ref":endpoint.authorization_ref.event_id,
        "realm_ids":[realm],"strand_ids":[],"resources":{"realm_ids":[realm],"strand_ids":[]},
        "constraints":{"allowed_tracks":[],"allowed_data_labels":[],"allowed_endpoints":[]},
        "capability_grant_refs":[],"policy_refs":[]});
    let grant_expires_at =
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now() + grant_lifetime);
    let grant = SessionGrantValidationMetadata {
        id:arkret_identifiers::SessionGrantId::from_issuance_digest(Sha256::digest(token.as_bytes()).into()),
        issuer_id:"ak:did_core:web:coauth.example".parse().unwrap(), account_id:agent.clone(),device_id:None,
        audience_id:state.service_core_id(),scopes:scope.actions.clone(),
        expires_at:grant_expires_at,revoked_at:None,
        revocation_ref:format!("ak:session:{}",uuid::Uuid::now_v7()),
        session_public_key:CanonicalSessionPublicJwk::new(serde_json::to_string(&serde_json::json!({
            "crv":"Ed25519","kty":"OKP","x":arkret_canonical::base64url_encode(key.verifying_key().to_bytes())})).unwrap()).unwrap(),
        cnf_jkt:arkret_signatures::dpop::dpop_jwk_thumbprint(&jwk).unwrap(),credential_class:SessionGrantCredentialClass::Standard,
        holder_binding:SessionGrantHolderBinding::AgentRuntime { agent_id:agent.principal_id.clone(),
            agent_key_authorization_ref:endpoint.authorization_ref.event_id.clone(),
            verification_method:endpoint.verification_method.clone() },device_binding:None,
        scope_details:Some(details.as_object().unwrap().clone()),
    };
    grant.validate().unwrap();
    let delivery_session_scope = (grant.scopes.clone(), grant.scope_details.clone().unwrap());
    let outcome = SessionGrantValidationOutcome {
        active: true,
        status: arkret_models_identity::admin_grant::SessionGrantAdminIntrospectionStatus::Active,
        proof_required: false,
        one_time_use_consumed: false,
        grant: Some(grant),
    };
    outcome.validate().unwrap();
    let expected_token = token.clone();
    let audience = state.service_core_id();
    let issuer_status = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(200));
    let answer_status = issuer_status.clone();
    let issuer_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let (header_end, length) = loop {
                let mut chunk = [0u8; 2048];
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                assert!(bytes.len() < 16384);
                if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    assert_eq!(
                        headers.lines().next(),
                        Some("POST /_coauth/internal/session-grants/introspect HTTP/1.1")
                    );
                    assert!(headers.lines().any(|line| {
                        line.eq_ignore_ascii_case(&format!("authorization: Bearer {channel}"))
                    }));
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while bytes.len() < header_end + length {
                let mut chunk = [0u8; 2048];
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                assert!(bytes.len() < 16384);
            }
            let SessionGrantValidationInput::ByJwt(input) =
                serde_json::from_slice::<SessionGrantValidationInput>(
                    &bytes[header_end..header_end + length],
                )
                .unwrap()
            else {
                panic!("exact-token introspection required")
            };
            assert!(input.grant_jwt == expected_token);
            assert!(input.audience_id.as_ref() == Some(&audience));
            let status = answer_status.load(std::sync::atomic::Ordering::SeqCst);
            let answer = if status == 200 {
                arkret_canonical::canonical_json_bytes(&outcome).unwrap()
            } else {
                arkret_canonical::canonical_json_bytes(
                    &arkret_wire::Problem::from_code(
                        "temporarily_unavailable",
                        "authority unavailable",
                    )
                    .with_status(503),
                )
                .unwrap()
            };
            stream.write_all(format!("HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",if status == 200 { "OK" } else { "Service Unavailable" },answer.len()).as_bytes()).await.unwrap();
            stream.write_all(&answer).await.unwrap();
        }
    });
    OwnedConsumerHttpFixture {
        state: state.clone(),
        service: std::sync::Arc::new(coland_http::service(state.clone())),
        base_url: state
            .config()
            .public_base_url
            .trim_end_matches('/')
            .to_owned(),
        token,
        key,
        issuer_task,
        issuer_status,
        object_storage,
        grant_expires_at,
        delivery_session_scope,
        _receiver_directory: receiver_directory,
        _receiver_database: receiver_database,
    }
}

// Move the original physical response to one ordinary fixture task while it
// polls its original guarded body. Restore the same response afterwards; no
// frame is read ahead and cancellation drops that body through fixture_step.
async fn owned_consumer_take_response_bytes(
    response: &mut salvo::Response,
) -> salvo::Result<bytes::Bytes> {
    use salvo::test::ResponseExt;
    let mut original = std::mem::take(response);
    let (original, result) = fixture_step(async move {
        let result = original.take_bytes(None).await;
        (original, result)
    })
    .await;
    *response = original;
    result
}

async fn owned_consumer_take_response_json<T>(response: &mut salvo::Response) -> salvo::Result<T>
where
    T: serde::de::DeserializeOwned + Send + 'static,
{
    use salvo::test::ResponseExt;
    let mut original = std::mem::take(response);
    let (original, result) = fixture_step(async move {
        let result = original.take_json::<T>().await;
        (original, result)
    })
    .await;
    *response = original;
    result
}

fn owned_consumer_phase(phase: &'static str) {
    use std::io::Write;
    writeln!(std::io::stdout().lock(), "owned consumer phase={phase}").unwrap();
}

async fn owned_consumer_assert_http_status(
    response: &mut salvo::Response,
    expected: salvo::http::StatusCode,
    stage: &'static str,
) {
    if response.status_code != Some(expected) {
        let status = response.status_code.map(|status| status.as_u16());
        let bytes = owned_consumer_take_response_bytes(response).await.unwrap();
        let code = serde_json::from_slice::<arkret_wire::Problem>(&bytes)
            .ok()
            .and_then(|problem| problem.error_code());
        panic!("owned consumer stage={stage} status={status:?} registered_code={code:?}");
    }
}

async fn owned_consumer_http_get(
    http: &OwnedConsumerHttpFixture,
    path: &str,
    operation: &str,
) -> salvo::Response {
    Box::pin(owned_consumer_http_get_at_receiver(
        http, path, operation, false,
    ))
    .await
}

async fn owned_consumer_http_get_at_receiver(
    http: &OwnedConsumerHttpFixture,
    path: &str,
    operation: &str,
    canonical_receiver_url: bool,
) -> salvo::Response {
    use salvo::test::TestClient;
    let service = http.service.clone();
    let token = http.token.clone();
    let key = http.key.clone();
    let base_url = http.base_url.clone();
    let path = path.to_owned();
    let operation = operation.to_owned();
    // Keep the original production router and request, but poll its handler in
    // the same cancellation-safe ordinary task boundary as native fixture UOWs.
    // The large parent scenario frame must not stack beneath the HTTP poll.
    fixture_step(async move {
        let dpop = arkret_signatures::dpop::build_dpop_proof(
            &arkret_signatures::dpop::DpopProofRequest::new("GET", format!("{base_url}{path}"))
                .access_token(token.clone()),
            &key,
        )
        .unwrap();
        let request_url = if canonical_receiver_url {
            format!("{base_url}{path}")
        } else {
            format!("http://server{path}")
        };
        TestClient::get(request_url)
            .add_header("Authorization", format!("DPoP {token}"), true)
            .add_header("DPoP", dpop.header_value, true)
            .add_header("Arkret-Operation", operation, true)
            .send(service.as_ref())
            .await
    })
    .await
}

// These setup assertions call the original held-cut consumer with the exact
// issuer scope. They localize a refusal without copying its qualification
// algorithm or replacing the subsequent authenticated HTTP assertion.
async fn owned_consumer_assert_delivery_setup(
    fixture: &OwnedConsumerFixture,
    http: &OwnedConsumerHttpFixture,
) {
    let agent = &fixture.agents[0];
    let record = coland_storage::AgentStore::get(
        &coland_storage_postgres::PgAgentStore {
            pool: fixture.pool.clone(),
        },
        agent.account.principal_id.as_str(),
    )
    .await
    .unwrap_or_else(|_| panic!("owned setup stage=current_runtime_record unavailable"))
    .unwrap_or_else(|| panic!("owned setup stage=current_runtime_record absent"));
    assert!(
        record.state == arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
            && record.authorized_event_ref.as_deref()
                == Some(agent.endpoint.authorization_ref.event_id.as_str())
            && record.authorized_verification_method.as_deref()
                == Some(agent.endpoint.verification_method.as_str())
            && record.current_signer_evidence.is_some()
            && record.paired_request_digest.is_some(),
        "owned setup stage=current_runtime_record exact binding"
    );
    let receipt = coland_storage::AgentStore::pairing_receipt(
        &coland_storage_postgres::PgAgentStore {
            pool: fixture.pool.clone(),
        },
        agent.endpoint.authorization_ref.event_id.as_str(),
    )
    .await
    .unwrap_or_else(|_| panic!("owned setup stage=original_active_receipt unavailable"))
    .unwrap_or_else(|| panic!("owned setup stage=original_active_receipt absent"));
    assert!(
        receipt.request_digest == record.paired_request_digest.as_ref().unwrap().as_str()
            && receipt.scope_custody_ref.is_some()
            && serde_json::to_value(&receipt.outcome).unwrap()["activation_state"] == "active",
        "owned setup stage=original_active_receipt exact binding"
    );
    let evidence = Box::pin(http.state.qualified_agent_scope_evidence(&agent.endpoint))
        .await
        .unwrap_or_else(|_| panic!("owned setup stage=qualified_private_custody unavailable"));
    let mut input = coland_storage::AccountContentDeliveryInput {
        realms: vec![fixture.head.event.realm_id.clone()],
        agent_endpoint: Some(agent.endpoint.clone()),
        qualified_agent_scope_evidence: Some(evidence),
        credential_expires_at: Some(http.grant_expires_at),
        agent_session_scope: Some(http.delivery_session_scope.clone()),
        ..Default::default()
    };
    let before = owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await;
    for stage in [
        "held_current_owner_pair_custody",
        "held_full_event_read_deliver_scope_lastguard",
    ] {
        if stage == "held_full_event_read_deliver_scope_lastguard" {
            input.committed_events = vec![arkret_wire::CommittedEventView::Full(
                arkret_wire::CommittedEventFullView {
                    event: fixture.head.event.clone(),
                    commit: fixture.head.commit.clone(),
                },
            )];
        }
        let guard =
            fixture_delivery_step(&fixture.pool, &agent.account, &fixture.station.core, &input)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "owned setup stage={stage} registered_conflict={:?}",
                        error.conflict_code()
                    )
                })
                .unwrap_or_else(|| panic!("owned setup stage={stage} no current guard"));
        assert!(
            guard.permits_handoff(),
            "owned setup stage={stage} handoff refused"
        );
        guard.finish().await.unwrap_or_else(|error| {
            panic!(
                "owned setup stage={stage} finish registered_conflict={:?}",
                error.conflict_code()
            )
        });
        assert!(
            before == owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await,
            "owned setup stage={stage} read-only cut changed business effects"
        );
    }
}

async fn owned_consumer_http_read_scenario(policy_deny: bool) {
    use arkret_wire::ActorId;
    let fixture = boxed_owned_consumer_fixture(1).await;
    let realm = &fixture.head.event.realm_id;
    let agent = &fixture.agents[0];
    let parent = Box::pin(owned_consumer_root_grant(
        &fixture,
        &fixture.head,
        &ActorId::account(fixture.controller.history.account.clone()),
        &["ak.event.read"],
        serde_json::json!([{"kind":"realm","realm_id":realm}]),
        None,
    ))
    .await;
    fixture_commit_step(&fixture.pool, parent.clone())
        .await
        .unwrap();
    let permission = Box::pin(owned_consumer_root_grant(
        &fixture,
        &parent.authority_commit,
        &ActorId::account(agent.account.clone()),
        &["ak.event.read"],
        serde_json::json!([{"kind":"realm","realm_id":realm}]),
        None,
    ))
    .await;
    fixture_commit_step(&fixture.pool, permission.clone())
        .await
        .unwrap();
    let http = Box::pin(owned_consumer_http_fixture(&fixture)).await;
    Box::pin(owned_consumer_assert_delivery_setup(&fixture, &http)).await;
    // The original resource handler keeps typed selector rejection as 404.
    // A matching operation scope supplies no authority for malformed content.
    let malformed_before = owned_consumer_footprint(&fixture.pool, realm).await;
    let mut malformed = Box::pin(owned_consumer_http_get(
        &http,
        "/_arkret/self/committed-events/not-a-formal-selector",
        arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
    ))
    .await;
    owned_consumer_assert_http_status(
        &mut malformed,
        salvo::http::StatusCode::NOT_FOUND,
        "original_handler_invalid_event_selector",
    )
    .await;
    assert!(
        malformed_before == owned_consumer_footprint(&fixture.pool, realm).await,
        "typed selector refusal has zero business effects"
    );
    // Read accepted public mode, not a private authorization or scope command.
    let path = format!(
        "/_arkret/self/committed-events/{}",
        fixture.head.event.event_id
    );
    let mut response = Box::pin(owned_consumer_http_get(
        &http,
        &path,
        "ak.self.committed_event.resource.get.v1",
    ))
    .await;
    owned_consumer_assert_http_status(
        &mut response,
        salvo::http::StatusCode::OK,
        "owned_consumer_http_read_scenario",
    )
    .await;
    let read = owned_consumer_take_response_json::<arkret_wire::CommittedEventView>(&mut response)
        .await
        .unwrap();
    let arkret_wire::CommittedEventView::Full(full) = read else {
        panic!("exact authorized Event must be full")
    };
    assert!(full.event == fixture.head.event);
    assert!(full.commit == fixture.head.commit);
    // Removing an explicit EventRead grant does not remove the conventional
    // joined-member reading path. Keep that formal positive before applying
    // the actual current management or owner-membership refusal.
    let revoke=Box::pin(ordinary_realm::source_request(&fixture.pool,
        ordinary_realm::next_request_for_actor(&permission.authority_commit,EventKind::CapabilityRevoke,
            ActorId::account(fixture.founder.clone()),
            serde_json::json!({"grant_id":arkret_wire::GrantId::from_event_id(&parent.authority_commit.event.event_id),
                "expected_revision":{"commit_id":parent.authority_commit.commit.commit_id,
                    "stream_position":parent.authority_commit.commit.stream_position}}),
            permission.authority_commit.commit.committed_at+chrono::TimeDelta::milliseconds(1)))).await;
    fixture_commit_step(&fixture.pool, revoke.clone())
        .await
        .unwrap();
    let mut baseline = Box::pin(owned_consumer_http_get(
        &http,
        &path,
        "ak.self.committed_event.resource.get.v1",
    ))
    .await;
    assert_eq!(baseline.status_code, Some(salvo::http::StatusCode::OK));
    let baseline =
        owned_consumer_take_response_json::<arkret_wire::CommittedEventView>(&mut baseline)
            .await
            .unwrap();
    assert!(
        matches!(baseline, arkret_wire::CommittedEventView::Full(_)),
        "conventional joined-member reading does not require explicit EventRead grant"
    );
    let at = revoke.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let removal = if policy_deny {
        let policy_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
        ordinary_realm::next_request_for_actor(
            &revoke.authority_commit,
            EventKind::PolicySet,
            ActorId::account(fixture.founder.clone()),
            serde_json::json!({"policy_id":policy_id,"expected_revision":null,
                "value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":realm,
                    "policy_kind":"agent","default_effect":"allow",
                    "created_by":ActorId::account(fixture.founder.clone()),
                    "created_at":arkret_canonical::format_timestamp_canonical(at),
                    "rules":[{"rule_id":"current_read_delivery_deny","kind":"agent","effect":"deny",
                        "agent_target":{"kind":"controller","controller_account_id":fixture.controller.history.account},
                        "agent_operations":["read","deliver"]}]}}),
            at,
        )
    } else {
        ordinary_realm::next_request_for_actor(
            &revoke.authority_commit,
            EventKind::MemberState,
            ActorId::account(fixture.controller.history.account.clone()),
            serde_json::json!({"member_id":ActorId::account(fixture.controller.history.account.clone()),
                "membership":"leave"}),
            at,
        )
    };
    let removal = Box::pin(ordinary_realm::source_request(&fixture.pool, removal)).await;
    fixture_commit_step(&fixture.pool, removal).await.unwrap();
    let before = owned_consumer_footprint(&fixture.pool, realm).await;
    // Prove the original disclosure reader's registered refusal before the
    // public route maps it. Keep the large reader future on the existing
    // cancellation-safe fixture task boundary, not beneath this scenario.
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let issuer = http.state.service_core_id();
    let event_id = fixture.head.event.event_id.clone();
    let caller = ActorId::account(agent.account.clone());
    let refused_read = fixture_step(async move {
        store
            .committed_event_for_member(&event_id, &caller, &issuer)
            .await
    })
    .await;
    let Err(error) = refused_read else {
        panic!("owned consumer stage=current_read_refusal unexpected successful lookup");
    };
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::CapabilityDenied),
        "owned consumer stage=current_read_refusal registered code"
    );
    assert!(
        before == owned_consumer_footprint(&fixture.pool, realm).await,
        "registered current read refusal has zero business effects"
    );
    let mut refused = Box::pin(owned_consumer_http_get(
        &http,
        &path,
        "ak.self.committed_event.resource.get.v1",
    ))
    .await;
    owned_consumer_assert_http_status(
        &mut refused,
        salvo::http::StatusCode::FORBIDDEN,
        "owned_consumer_current_read_refusal",
    )
    .await;
    let problem = owned_consumer_take_response_json::<arkret_wire::Problem>(&mut refused)
        .await
        .unwrap();
    assert_eq!(
        problem.error_code(),
        Some(arkret_wire::error_codes::ErrorCode::CapabilityDenied)
    );
    assert!(
        before == owned_consumer_footprint(&fixture.pool, realm).await,
        "post-withdrawal HTTP read cannot write business effects"
    );
}

#[tokio::test]
async fn owned_agent_committed_event_http_read_rechecks_owner_leave_before_bytes() {
    fixture_step(Box::pin(owned_consumer_http_read_scenario(false))).await;
}

#[tokio::test]
async fn owned_agent_committed_event_http_read_rechecks_policy_deny_before_bytes() {
    fixture_step(Box::pin(owned_consumer_http_read_scenario(true))).await;
}

// Original physical subscription route continuation.
// This invokes the original public NDJSON subscription route and physically
// polls its response body. A 30-second production wait is retained unchanged.
async fn owned_consumer_next_body_frame(body: &mut salvo::http::ResBody) -> Option<Vec<u8>> {
    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(35),
        owned_consumer_poll_body_frame(body),
    )
    .await
    .expect("original bounded route produced a physical frame");
    frame.map(|frame| {
        frame
            .expect("physical response body")
            .into_data()
            .expect("data frame")
            .to_vec()
    })
}

async fn owned_consumer_poll_body_frame(
    body: &mut salvo::http::ResBody,
) -> Option<Result<salvo::http::body::Frame<bytes::Bytes>, std::io::Error>> {
    use salvo::http::body::Body;
    let mut original = std::mem::take(body);
    let (original, frame) = fixture_step(async move {
        owned_consumer_phase("physical_body_poll");
        let frame = std::future::poll_fn(|cx| Pin::new(&mut original).poll_frame(cx)).await;
        (original, frame)
    })
    .await;
    *body = original;
    frame
}

async fn owned_consumer_policy_event(
    fixture: &OwnedConsumerFixture,
    head: &coland_storage::AuthorityCommitTransaction,
    effect: &str,
    previous: Option<&coland_storage::AuthorityCommitTransaction>,
) -> coland_storage::EventCommitRequest {
    let at = head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let policy_id = previous
        .map(|row| row.event.payload["policy_id"].as_str().unwrap().to_owned())
        .unwrap_or_else(|| format!("ak:policy:{}", uuid::Uuid::now_v7()));
    let expected = previous.map(|row| {
        serde_json::json!({"commit_id":row.commit.commit_id,
        "stream_position":row.commit.stream_position})
    });
    let request = ordinary_realm::next_request_for_actor(
        head,
        EventKind::PolicySet,
        arkret_wire::ActorId::account(fixture.founder.clone()),
        serde_json::json!({"policy_id":policy_id,"expected_revision":expected,
            "value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":head.event.realm_id,
                "policy_kind":"agent","default_effect":"allow",
                "created_by":arkret_wire::ActorId::account(fixture.founder.clone()),
                "created_at":previous.map(|p|p.event.payload["value"]["created_at"].clone())
                    .unwrap_or_else(||serde_json::json!(arkret_canonical::format_timestamp_canonical(at))),
                "rules":[{"rule_id":"actual_delivery_current","kind":"agent","effect":effect,
                    "agent_target":{"kind":"controller","controller_account_id":fixture.controller.history.account},
                    "agent_operations":["read","deliver"]}]}}),
        at,
    );
    Box::pin(ordinary_realm::source_request(&fixture.pool, request)).await
}

async fn owned_consumer_subscription_scenario(policy_deny: bool) {
    use arkret_models_collaboration::sync_frames::committed_event_subscribe::{
        CommittedEventSubscribeFrame as Frame, CommittedEventSubscribeFrameKind as Kind,
    };
    let fixture = boxed_owned_consumer_fixture(1).await;
    let realm = &fixture.head.event.realm_id;
    let http = Box::pin(owned_consumer_http_fixture(&fixture)).await;
    let path = format!("/_arkret/self/committed-events/subscribe?realm_ids={realm}");
    owned_consumer_phase("ndjson_baseline_request");
    let mut baseline = Box::pin(owned_consumer_http_get(
        &http,
        &path,
        "ak.self.committed_event.stream.subscribe.v1",
    ))
    .await;
    assert_eq!(baseline.status_code, Some(salvo::http::StatusCode::OK));
    let mut body = baseline.take_body();
    owned_consumer_phase("ndjson_baseline_checkpoint");
    let checkpoint: Frame =
        serde_json::from_slice(&owned_consumer_next_body_frame(&mut body).await.unwrap()).unwrap();
    checkpoint.validate().unwrap();
    assert_eq!(checkpoint.kind, Kind::Checkpoint);
    assert!(checkpoint.cursor.is_some());
    let allow = Box::pin(owned_consumer_policy_event(
        &fixture,
        &fixture.head,
        "allow",
        None,
    ))
    .await;
    fixture_commit_step(&fixture.pool, allow.clone())
        .await
        .unwrap();
    owned_consumer_phase("ndjson_accepted_event");
    let delivered: Frame =
        serde_json::from_slice(&owned_consumer_next_body_frame(&mut body).await.unwrap()).unwrap();
    delivered.validate().unwrap();
    assert_eq!(delivered.kind, Kind::CommittedEvent);
    let arkret_wire::CommittedEventView::Full(full) = delivered.committed_event().unwrap() else {
        panic!("allowed source must be physically complete");
    };
    assert!(full.event == allow.authority_commit.event);
    assert!(full.commit == allow.authority_commit.commit);
    assert!(
        delivered.cursor.is_some(),
        "exact physical Event carries its cursor"
    );
    // The idle response already emitted its checkpoint. It rolls over after
    // the later accepted Event instead of repeating an unchanged checkpoint.
    assert!(owned_consumer_next_body_frame(&mut body).await.is_none());

    // A second ordinary subscription starts from the actual accepted current
    // head. It must stop before yielding the later current-change Event.
    owned_consumer_phase("ndjson_current_request");
    let mut active = Box::pin(owned_consumer_http_get(
        &http,
        &path,
        "ak.self.committed_event.stream.subscribe.v1",
    ))
    .await;
    assert_eq!(active.status_code, Some(salvo::http::StatusCode::OK));
    let mut body = active.take_body();
    let checkpoint: Frame =
        serde_json::from_slice(&owned_consumer_next_body_frame(&mut body).await.unwrap()).unwrap();
    assert_eq!(checkpoint.kind, Kind::Checkpoint);
    let changed = if policy_deny {
        Box::pin(owned_consumer_policy_event(
            &fixture,
            &allow.authority_commit,
            "deny",
            Some(&allow.authority_commit),
        ))
        .await
    } else {
        Box::pin(ordinary_realm::source_request(&fixture.pool,
            ordinary_realm::next_request_for_actor(&allow.authority_commit, EventKind::MemberState,
                arkret_wire::ActorId::account(fixture.controller.history.account.clone()),
                serde_json::json!({"member_id":arkret_wire::ActorId::account(fixture.controller.history.account.clone()),
                    "membership":"leave"}),
                allow.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1)))).await
    };
    fixture_commit_step(&fixture.pool, changed).await.unwrap();
    let before = owned_consumer_footprint(&fixture.pool, realm).await;
    owned_consumer_phase("ndjson_current_refusal");
    let terminal: Frame =
        serde_json::from_slice(&owned_consumer_next_body_frame(&mut body).await.unwrap()).unwrap();
    terminal.validate().unwrap();
    assert!(
        matches!(terminal.kind, Kind::Unauthorized | Kind::ResyncRequired),
        "only original payload-free closed terminal control is permitted"
    );
    assert!(terminal.payload.is_none() && terminal.cursor.is_none());
    assert!(owned_consumer_next_body_frame(&mut body).await.is_none());
    assert!(before == owned_consumer_footprint(&fixture.pool, realm).await);
}

#[tokio::test]
async fn owned_agent_committed_subscription_rechecks_owner_leave_before_next_frame() {
    fixture_step(Box::pin(owned_consumer_subscription_scenario(false))).await;
}

#[tokio::test]
async fn owned_agent_committed_subscription_rechecks_policy_deny_before_next_frame() {
    fixture_step(Box::pin(owned_consumer_subscription_scenario(true))).await;
}

// The original HTTP fixture retains its actual AppState,
// and the accepted provision/key/session scope to include original Blob
// GET/HEAD and ObjectReadContent/ObjectReadMetadata operations.
async fn owned_consumer_blob_source(
    fixture: &OwnedConsumerFixture,
    http: &OwnedConsumerHttpFixture,
    bytes: &[u8],
) -> (
    arkret_wire::BlobRef,
    coland_storage::AuthorityCommitTransaction,
) {
    use arkret_wire::ActorId;
    let realm = &fixture.head.event.realm_id;
    let at = fixture.head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let strand = Box::pin(ordinary_realm::source_request(
        &fixture.pool,
        ordinary_realm::next_request_for_actor(
            &fixture.head,
            EventKind::StrandCreate,
            ActorId::account(fixture.founder.clone()),
            serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
                "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":"Real accepted attachment source"},"state":"active",
                "created_by":ActorId::account(fixture.founder.clone()),
                "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        ),
    ))
    .await;
    fixture_commit_step(&fixture.pool, strand.clone())
        .await
        .unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let reference = arkret_wire::BlobRef::from_bytes(bytes);
    let sha256 = reference
        .as_str()
        .strip_prefix("ak:blob:sha256:")
        .unwrap()
        .to_owned();
    let (storage_key, storage_backend) = if let Some(storage) = http.object_storage.as_ref() {
        let key = storage.object_key_for_sha256(&sha256);
        storage.put(&key, bytes.to_vec()).await.unwrap();
        (key, storage.backend_name())
    } else {
        let key = http.state.test_object_key_for_sha256(&sha256);
        http.state
            .test_put_object(&key, bytes.to_vec())
            .await
            .unwrap();
        (key, "memory".to_owned())
    };
    coland_storage::BlobStore::put(
        &coland_storage_postgres::PgBlobStore {
            pool: fixture.pool.clone(),
        },
        reference.as_str(),
        &coland_storage::BlobRecord {
            sha256,
            size_bytes: bytes.len() as i64,
            storage_backend,
            storage_key,
            media_type: "application/octet-stream".into(),
            filename: Some("accepted-fixture.bin".into()),
            realm_id: Some(realm.to_string()),
            encryption: None,
            legal_hold: false,
            redacted: false,
            visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
            uploaded_by: ActorId::account(fixture.founder.clone()).to_string(),
            created_at: arkret_canonical::normalize_timestamp_canonical(at),
        },
    )
    .await
    .unwrap();
    let mut payload = ordinary_realm::message_payload(&strand_id, "Accepted attachment source");
    payload["blob_refs"] = serde_json::json!([reference]);
    let message_at = at + chrono::TimeDelta::milliseconds(1);
    // Signed refs do not bypass the original MessageCreate send cut. This
    // current joined controller has read grants, but no MessageCreate grant.
    let denied = Box::pin(ordinary_realm::source_request(
        &fixture.pool,
        ordinary_realm::next_request_for_actor(
            &strand.authority_commit,
            EventKind::MessageCreate,
            ActorId::account(fixture.controller.history.account.clone()),
            payload.clone(),
            message_at,
        ),
    ))
    .await;
    let before = owned_consumer_footprint(&fixture.pool, realm).await;
    let refused = fixture_commit_step(&fixture.pool, denied)
        .await
        .unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(coland_storage::ConflictCode::CapabilityDenied)
    );
    assert!(before == owned_consumer_footprint(&fixture.pool, realm).await);
    let message = Box::pin(ordinary_realm::source_request(
        &fixture.pool,
        ordinary_realm::next_request_for_actor(
            &strand.authority_commit,
            EventKind::MessageCreate,
            ActorId::account(fixture.founder.clone()),
            payload,
            message_at,
        ),
    ))
    .await;
    fixture_commit_step(&fixture.pool, message.clone())
        .await
        .unwrap();
    // The real transaction accepted this exact producer-signed metadata and
    // atomically wrote its canonical source, Commit, and typed current carrier.
    {
        use diesel::sql_types::{Jsonb, Text};
        use diesel_async::RunQueryDsl;
        #[derive(diesel::QueryableByName)]
        struct AcceptedAttachment {
            #[diesel(sql_type = Jsonb)]
            event: serde_json::Value,
            #[diesel(sql_type = Jsonb)]
            commit: serde_json::Value,
            #[diesel(sql_type = Jsonb)]
            value: serde_json::Value,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let accepted = diesel::sql_query(
            "SELECT e.envelope AS event,c.commit_json AS commit,m.value FROM message_revision_current_results m \
             JOIN realm_commits c ON c.commit_id=m.current_commit_id \
             JOIN canonical_events e ON e.pk=c.event_pk \
             WHERE m.realm_id=$1 AND m.message_id=$2 AND e.state='committed' \
               AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position",
        )
        .bind::<Text, _>(realm.as_str())
        .bind::<Text, _>(
            arkret_wire::MessageId::from_event_id(&message.authority_commit.event.event_id).as_str(),
        )
        .get_result::<AcceptedAttachment>(&mut *conn)
        .await
        .unwrap();
        assert!(accepted.event == serde_json::to_value(&message.authority_commit.event).unwrap());
        assert!(accepted.commit == serde_json::to_value(&message.authority_commit.commit).unwrap());
        assert!(
            accepted.value
                == serde_json::to_value(&message.authority_commit.event.payload).unwrap()
        );
        let typed: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
            serde_json::from_value(accepted.value).unwrap();
        assert!(typed.blob_refs == vec![reference.to_string()]);
    }
    (reference, message.authority_commit)
}

async fn owned_consumer_http_blob_request(
    http: &OwnedConsumerHttpFixture,
    path: &str,
    head: bool,
    range: Option<&str>,
) -> salvo::Response {
    use salvo::test::TestClient;
    let service = http.service.clone();
    let token = http.token.clone();
    let key = http.key.clone();
    let base_url = http.base_url.clone();
    let path = path.to_owned();
    let range = range.map(str::to_owned);
    fixture_step(async move {
        let (method, operation) = if head {
            (
                "HEAD",
                arkret_wire::ServiceOperationId::SELF_BLOB_RESOURCE_HEAD_V1,
            )
        } else {
            (
                "GET",
                arkret_wire::ServiceOperationId::SELF_BLOB_RESOURCE_GET_V1,
            )
        };
        let proof = arkret_signatures::dpop::build_dpop_proof(
            &arkret_signatures::dpop::DpopProofRequest::new(method, format!("{base_url}{path}"))
                .access_token(token.clone()),
            &key,
        )
        .unwrap();
        let mut request = if head {
            TestClient::head(format!("http://server{path}"))
        } else {
            TestClient::get(format!("http://server{path}"))
        };
        request = request
            .add_header("Authorization", format!("DPoP {token}"), true)
            .add_header("DPoP", proof.header_value, true)
            .add_header("Arkret-Operation", operation, true);
        if let Some(range) = range {
            request = request.add_header("Range", range, true);
        }
        request.send(service.as_ref()).await
    })
    .await
}

async fn owned_consumer_blob_scenario(policy_deny: bool) {
    let fixture = boxed_owned_consumer_fixture(1).await;
    let http = Box::pin(owned_consumer_http_fixture(&fixture)).await;
    let original = b"physical accepted attachment bytes, never logged";
    let (reference, source) = Box::pin(owned_consumer_blob_source(&fixture, &http, original)).await;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("blob_ref", reference.as_str())
        .append_pair("realm_id", source.event.realm_id.as_str())
        .append_pair("purpose", "message_attachment")
        .finish();
    let path = format!("/_arkret/self/blob/get?{query}");
    for (head, range) in [(false, None), (true, None), (false, Some("bytes=2-8"))] {
        let mut response =
            Box::pin(owned_consumer_http_blob_request(&http, &path, head, range)).await;
        owned_consumer_assert_http_status(
            &mut response,
            if range.is_some() {
                salvo::http::StatusCode::PARTIAL_CONTENT
            } else {
                salvo::http::StatusCode::OK
            },
            "blob_get_head_range_positive",
        )
        .await;
        let expected = if let Some(_) = range {
            &original[2..=8]
        } else {
            original.as_slice()
        };
        assert_eq!(
            response.headers().get("content-length").unwrap(),
            expected.len().to_string().as_str()
        );
        let bytes = owned_consumer_take_response_bytes(&mut response)
            .await
            .unwrap();
        assert!(if head {
            bytes.is_empty()
        } else {
            bytes.as_ref() == expected
        });
    }
    let at = source.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let changed = if policy_deny {
        Box::pin(owned_consumer_policy_event(&fixture, &source, "deny", None)).await
    } else {
        Box::pin(ordinary_realm::source_request(&fixture.pool,
            ordinary_realm::next_request_for_actor(&source,EventKind::MemberState,
                arkret_wire::ActorId::account(fixture.controller.history.account.clone()),
                serde_json::json!({"member_id":arkret_wire::ActorId::account(fixture.controller.history.account.clone()),
                    "membership":"leave"}),at))).await
    };
    fixture_commit_step(&fixture.pool, changed).await.unwrap();
    let before = owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await;
    for (head, range) in [(false, None), (true, None), (false, Some("bytes=2-8"))] {
        let mut response =
            Box::pin(owned_consumer_http_blob_request(&http, &path, head, range)).await;
        assert_eq!(
            response.status_code,
            Some(salvo::http::StatusCode::NOT_FOUND)
        );
        for protected in [
            "digest",
            "content-range",
            "content-disposition",
            "accept-ranges",
        ] {
            assert!(response.headers().get(protected).is_none());
        }
        if head {
            assert!(
                owned_consumer_take_response_bytes(&mut response)
                    .await
                    .unwrap()
                    .is_empty()
            );
        } else {
            let problem = owned_consumer_take_response_json::<arkret_wire::Problem>(&mut response)
                .await
                .unwrap();
            assert_eq!(
                problem.error_code(),
                Some(arkret_wire::error_codes::ErrorCode::NotFound)
            );
        }
        assert!(before == owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await);
    }
}

#[tokio::test]
async fn owned_agent_blob_get_head_range_rechecks_owner_leave_before_physical_bytes() {
    fixture_step(Box::pin(owned_consumer_blob_scenario(false))).await;
}

#[tokio::test]
async fn owned_agent_blob_get_head_range_rechecks_policy_deny_before_physical_bytes() {
    fixture_step(Box::pin(owned_consumer_blob_scenario(true))).await;
}

// A physical HTTP response owns the original PostgreSQL delivery guard until
// its body completes. Confirm a real competing current writer is lock-waiting,
// then release the original body normally; no synthesized current rows.
async fn owned_consumer_blob_held_writer_scenario() {
    use diesel::sql_types::BigInt;
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Pid {
        #[diesel(sql_type=BigInt)]
        number: i64,
    }
    let fixture = boxed_owned_consumer_fixture(1).await;
    let http = Box::pin(owned_consumer_http_fixture(&fixture)).await;
    let original = b"attachment body held by original delivery transaction";
    let (reference, source) = Box::pin(owned_consumer_blob_source(&fixture, &http, original)).await;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("blob_ref", reference.as_str())
        .append_pair("realm_id", source.event.realm_id.as_str())
        .append_pair("purpose", "message_attachment")
        .finish();
    let path = format!("/_arkret/self/blob/get?{query}");
    let leave=Box::pin(ordinary_realm::source_request(&fixture.pool,
        ordinary_realm::next_request_for_actor(&source,EventKind::MemberState,
            arkret_wire::ActorId::account(fixture.controller.history.account.clone()),
            serde_json::json!({"member_id":arkret_wire::ActorId::account(fixture.controller.history.account.clone()),
                "membership":"leave"}),source.commit.committed_at+chrono::TimeDelta::milliseconds(1)))).await;
    let mut response = Box::pin(owned_consumer_http_blob_request(&http, &path, false, None)).await;
    owned_consumer_assert_http_status(
        &mut response,
        salvo::http::StatusCode::OK,
        "blob_held_writer_positive",
    )
    .await;
    let mut conn = fixture.pool.get().await.unwrap();
    let holders=diesel::sql_query("SELECT DISTINCT pid::bigint AS number FROM pg_locks WHERE locktype='advisory' AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
        .load::<Pid>(&mut *conn).await.unwrap();
    assert!(
        !holders.is_empty(),
        "response must hold a real delivery advisory cut"
    );
    let writer_pool = fixture.pool.clone();
    let writer = tokio::spawn(async move { fixture_commit_step(&writer_pool, leave).await });
    // Own the original writer's cancellation through its complete lifecycle.
    struct Cancel(tokio::task::AbortHandle);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _cancel = Cancel(writer.abort_handle());
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let mut blocked=false;
            for holder in &holders {
                // Both the delivery and the writer acquire the original Realm
                // row cut before the later PCR/AA advisory locks. Observe that
                // exact FOR UPDATE wait, not a later lock the writer cannot
                // reach until this physical body releases its original guard.
                let waiting=diesel::sql_query("SELECT COUNT(*)::bigint AS number FROM pg_stat_activity s WHERE $1::bigint::integer=ANY(pg_blocking_pids(s.pid)) AND s.wait_event_type='Lock' AND s.query LIKE '%FROM realm_authorities WHERE realm_id=$1 FOR UPDATE%' AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=s.pid AND l.locktype IN ('tuple','transactionid') AND NOT l.granted)")
                    .bind::<BigInt,_>(holder.number).get_result::<Pid>(&mut *conn).await.unwrap();
                blocked|=waiting.number>0;
            }
            if blocked {break;}
            assert!(!writer.is_finished(),"current writer cannot commit before physical handoff releases its cut");
            tokio::task::yield_now().await;
        }
    }).await.expect("actual writer reached held delivery lock");
    assert!(!writer.is_finished());
    drop(conn);
    let bytes = owned_consumer_take_response_bytes(&mut response)
        .await
        .unwrap();
    assert!(bytes.as_ref() == original);
    writer.await.unwrap().unwrap();
    let before = owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await;
    let mut refused = Box::pin(owned_consumer_http_blob_request(&http, &path, false, None)).await;
    assert_eq!(
        refused.status_code,
        Some(salvo::http::StatusCode::NOT_FOUND)
    );
    let problem = owned_consumer_take_response_json::<arkret_wire::Problem>(&mut refused)
        .await
        .unwrap();
    assert_eq!(
        problem.error_code(),
        Some(arkret_wire::error_codes::ErrorCode::NotFound)
    );
    assert!(before == owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await);
}

#[tokio::test]
async fn owned_agent_blob_physical_body_holds_current_cut_until_handoff_finishes() {
    fixture_step(Box::pin(owned_consumer_blob_held_writer_scenario())).await;
}

// The same accepted inputs and private custody move into one cancellation-safe
// task. No identity, signature, accepted row or recipient cursor is rebuilt.
struct OwnedConsumerDeviceFlow {
    pool: coland_storage_postgres::PgPool,
    station: historical_control_source::HistoricalControlStation,
    principal: std::sync::Arc<pcr_genesis::PcrGenesisFixture>,
    agent: AccountId,
    endpoint: coland_storage::AgentEndpointGuard,
    vault: DeliveryScopeVault,
    delivery: arkret_wire::MlsWelcomeDelivery,
    realm: arkret_wire::RealmId,
    realm_template: coland_storage::AuthorityCommitTransaction,
    key_event: arkret_wire::Event,
    key_commit: arkret_wire::RealmCommit,
    controller_group: arkret_mls::ArkretMlsGroup,
    public_tracker: arkret_mls::MlsPublicGroupTracker,
    continuation: bool,
    policy_deny: bool,
}
async fn owned_consumer_device_flow(mut input: Box<OwnedConsumerDeviceFlow>) {
    let controller = &input.principal.history.account;
    if input.continuation {
        let http = Box::pin(owned_consumer_http_for_endpoint(
            &input.pool,
            &input.station,
            controller,
            &input.realm,
            &input.agent,
            &input.endpoint,
            &input.vault,
        ))
        .await;
        let cursor = Box::pin(owned_consumer_exact_welcome_cursor(
            &http,
            "/_arkret/self/device_messages?limit=1",
            &input.delivery,
        ))
        .await;
        // Only after the original GET persists its actual cursor, queue the
        // later genuine Welcome through the same Sidecar's real endpoint
        // replacement: one accepted Remove+Add, with a fresh claim/package.
        let later = Box::pin(owned_consumer_queue_later_welcome(
            &input.pool,
            &input.station,
            &input.principal,
            &input.agent,
            &input.key_event,
            &input.key_commit,
            &input.realm,
            &input.realm_template,
            &input.delivery.effective_scope,
            &mut input.controller_group,
            &mut input.public_tracker,
        ))
        .await;
        assert!(later.welcome_id != input.delivery.welcome_id);
        assert!(later.effective_scope == input.delivery.effective_scope);
        assert!(later.commit_event_ref != input.delivery.commit_event_ref);
        assert!(later.keypackage_claim_ref != input.delivery.keypackage_claim_ref);
        let path = format!("/_arkret/self/device_messages?limit=1&after={cursor}");
        let _later_cursor =
            Box::pin(owned_consumer_exact_welcome_cursor(&http, &path, &later)).await;
        Box::pin(owned_consumer_device_messages_refusal(
            &input.pool,
            controller,
            &input.endpoint,
            &input.realm,
            &input.realm_template,
            &http,
            &path,
            input.policy_deny,
            true,
        ))
        .await;
    } else {
        Box::pin(owned_consumer_device_messages_scenario(
            &input.pool,
            &input.station,
            &input.principal,
            &input.agent,
            &input.endpoint,
            &input.vault,
            &input.delivery,
            &input.realm_template,
            input.policy_deny,
        ))
        .await;
    }
}

// Production recipient-private DeviceMessages reads over a real producer-signed
// Welcome from original KeyPackage claim and accepted MLS Add. This does not
// synthesize ACK/consume or pretend an exact-token issuer is normal OAuth.
async fn owned_consumer_device_messages_scenario(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent: &AccountId,
    endpoint: &coland_storage::AgentEndpointGuard,
    vault: &DeliveryScopeVault,
    welcome: &arkret_wire::MlsWelcomeDelivery,
    realm_template: &coland_storage::AuthorityCommitTransaction,
    policy_deny: bool,
) {
    use arkret_models_collaboration::device_messages::{
        DeviceMessagesGetOutcome, RecipientDelivery,
    };
    let realm = &welcome.realm_id;
    let controller = &principal.history.account;
    let http = Box::pin(owned_consumer_http_for_endpoint(
        pool, station, controller, realm, agent, endpoint, vault,
    ))
    .await;
    let path = "/_arkret/self/device_messages?limit=100";
    let mut response = Box::pin(owned_consumer_http_get(
        &http,
        path,
        arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
    ))
    .await;
    owned_consumer_assert_http_status(
        &mut response,
        salvo::http::StatusCode::OK,
        "owned_consumer_device_messages_scenario",
    )
    .await;
    let actual = owned_consumer_take_response_json::<DeviceMessagesGetOutcome>(&mut response)
        .await
        .unwrap();
    let welcomes = actual
        .deliveries
        .iter()
        .filter_map(|item| match item {
            RecipientDelivery::MlsWelcome { mls_welcome } => Some(mls_welcome),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(welcomes.len(), 1);
    assert!(
        arkret_canonical::canonical_json_bytes(welcomes[0]).unwrap()
            == arkret_canonical::canonical_json_bytes(welcome).unwrap(),
        "recipient queue exposes exact signed Welcome, not a reconstructed body"
    );
    assert!(
        actual
            .ack_token
            .as_ref()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        actual
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.is_empty())
    );
    Box::pin(owned_consumer_device_messages_refusal(
        pool,
        controller,
        endpoint,
        realm,
        realm_template,
        &http,
        path,
        policy_deny,
        false,
    ))
    .await;
}

async fn owned_consumer_device_messages_refusal(
    pool: &coland_storage_postgres::PgPool,
    controller: &AccountId,
    endpoint: &coland_storage::AgentEndpointGuard,
    realm: &arkret_wire::RealmId,
    realm_template: &coland_storage::AuthorityCommitTransaction,
    http: &OwnedConsumerHttpFixture,
    path: &str,
    policy_deny: bool,
    require_zero_newcut: bool,
) {
    // Read the actual governing Realm head: MLS sidecar commits are not that
    // stream and cannot be substituted as the next current writer's parent.
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let stream = arkret_wire::CommitStreamRef::from_scope(
        &arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
    )
    .unwrap();
    let head = store
        .held_stream_head_commit(&stream)
        .await
        .unwrap()
        .unwrap();
    let mut parent = realm_template.clone();
    parent.event = store
        .committed_event(&head.event_ref)
        .await
        .unwrap()
        .unwrap()
        .event;
    parent.commit = head;
    parent.mls_state = None;
    parent.welcomes.clear();
    if policy_deny {
        Box::pin(import_agent_management_policy(
            pool, &parent, controller, None, "deny", "deliver",
        ))
        .await;
    } else {
        let leave = Box::pin(ordinary_realm::source_request(
            pool,
            ordinary_realm::next_request_for_actor(
                &parent,
                EventKind::MemberState,
                arkret_wire::ActorId::account(controller.clone()),
                serde_json::json!({"member_id":arkret_wire::ActorId::account(controller.clone()),
                    "membership":"leave"}),
                parent.commit.committed_at + chrono::TimeDelta::milliseconds(1),
            ),
        ))
        .await;
        fixture_commit_step(pool, leave).await.unwrap();
    }
    let before = owned_welcome_footprint(pool, realm, &endpoint.pcr_realm_id).await;
    let private_before = if require_zero_newcut {
        Some(owned_consumer_private_queue_cut_footprint(pool).await)
    } else {
        None
    };
    let mut refused = Box::pin(owned_consumer_http_get(
        &http,
        path,
        arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
    ))
    .await;
    assert_eq!(
        refused.status_code,
        Some(salvo::http::StatusCode::FORBIDDEN)
    );
    let bytes = owned_consumer_take_response_bytes(&mut refused)
        .await
        .unwrap();
    let problem = serde_json::from_slice::<arkret_wire::Problem>(&bytes).unwrap();
    assert_eq!(
        problem.error_code(),
        Some(arkret_wire::error_codes::ErrorCode::CapabilityDenied)
    );
    let public = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
    assert!(
        public.get("deliveries").is_none()
            && public.get("ack_token").is_none()
            && public.get("next_cursor").is_none(),
        "refused route emits no Welcome or private queue coordinates"
    );
    assert!(
        before == owned_welcome_footprint(pool, realm, &endpoint.pcr_realm_id).await,
        "refused physical read cannot consume Welcome, quota, notification or relay effects"
    );
    if let Some(before) = private_before {
        assert!(
            before == owned_consumer_private_queue_cut_footprint(pool).await,
            "refused continuation cannot allocate an ACK/cursor cut or mutate queue progress"
        );
    }
}

#[tokio::test]
async fn owned_agent_device_messages_rechecks_owner_leave_before_signed_welcome_bytes() {
    boxed_owned_welcome(OwnedWelcomeCase::DeviceMessagesOwnerLeave).await;
}
#[tokio::test]
async fn owned_agent_device_messages_rechecks_policy_deny_before_signed_welcome_bytes() {
    boxed_owned_welcome(OwnedWelcomeCase::DeviceMessagesPolicyDeny).await;
}

// Actual TLS upgrade and original WebSocket SDK frames. openssl is only the
// test TLS transport, with an explicit temporary CA and exact hostname check;
// tungstenite remains the original RFC 6455 handshake/frame implementation.
struct OwnedOpenSslTransport {
    child: std::process::Child,
    read: std::process::ChildStdout,
    write: std::process::ChildStdin,
}
impl std::io::Read for OwnedOpenSslTransport {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.read, bytes)
    }
}
impl std::io::Write for OwnedOpenSslTransport {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.write, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.write)
    }
}
impl Drop for OwnedOpenSslTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
type OwnedTlsWebSocket = tokio_tungstenite::tungstenite::WebSocket<OwnedOpenSslTransport>;
struct OwnedCertificateDirectory(std::path::PathBuf);
impl Drop for OwnedCertificateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct OwnedTlsServer {
    task: tokio::task::JoinHandle<()>,
    handle: salvo::server::ServerHandle,
}
impl Drop for OwnedTlsServer {
    fn drop(&mut self) {
        self.handle.stop_forceful();
        self.task.abort();
    }
}
struct OwnedWebSocketFixture {
    socket: Option<OwnedTlsWebSocket>,
    server: OwnedTlsServer,
    _directory: OwnedCertificateDirectory,
    client_pid: u32,
    // A shared control shape is decoded only through this actual Open/Opened
    // channel binding, never through serde's untagged variant order.
    channels: std::collections::BTreeMap<String, (arkret_wire::WebSocketOperationId, bool)>,
}
impl Drop for OwnedWebSocketFixture {
    fn drop(&mut self) {
        // Also unblock an in-flight owned blocking read on caller cancellation.
        if self.client_pid != 0 && self.socket.is_none() {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &self.client_pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        self.socket.take();
        self.server.handle.stop_forceful();
        self.server.task.abort();
    }
}
async fn owned_consumer_ws_connect(http: &OwnedConsumerHttpFixture) -> OwnedWebSocketFixture {
    use std::os::unix::fs::PermissionsExt;

    use salvo::conn::rustls::{Keycert, RustlsConfig};
    use salvo::conn::{Acceptor, Listener, TcpListener};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    // This fixture starts the original TLS listener without the binary's main.
    // Match its declared process provider before any RustlsConfig is built;
    // retain the real CA/hostname validation and every socket authentication gate.
    static TLS_PROVIDER: std::sync::Once = std::sync::Once::new();
    TLS_PROVIDER.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("original Coland ring TLS provider must be selected exactly once");
    });
    let host = url::Url::parse(&http.base_url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_owned();
    let origin = http.base_url.clone();
    let base = origin.replacen("https://", "wss://", 1) + "/_arkret/ws";
    let directory =
        std::env::temp_dir().join(format!("arkret-owned-ws-tls-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = OwnedCertificateDirectory(directory);
    let certificate = directory.0.join("certificate.pem");
    let private_key = directory.0.join("private-key.pem");
    let config = directory.0.join("certificate.cnf");
    std::fs::write(&config,format!("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN={host}\n[ext]\nsubjectAltName=DNS:{host}\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n")).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let generated = std::process::Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config",
        ])
        .arg(&config)
        .arg("-keyout")
        .arg(&private_key)
        .arg("-out")
        .arg(&certificate)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(generated.success(), "temporary pinned test CA creation");
    for path in [&certificate, &private_key] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let acceptor = TcpListener::new("127.0.0.1:0")
        .rustls(RustlsConfig::new(
            Keycert::new()
                .cert_from_path(&certificate)
                .unwrap()
                .key_from_path(&private_key)
                .unwrap(),
        ))
        .bind()
        .await;
    let address = acceptor.holdings()[0]
        .local_addr
        .clone()
        .into_std()
        .unwrap();
    let server = salvo::Server::new(acceptor);
    let handle = server.handle();
    let service = coland_http::service(http.state.clone());
    let server_task = tokio::spawn(async move {
        server.serve(service).await;
    });
    let server = OwnedTlsServer {
        task: server_task,
        handle,
    };
    let (socket, pid) = tokio::task::spawn_blocking(move || {
        let mut child = std::process::Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &address.to_string(),
                "-servername",
                &host,
                "-verify_hostname",
                &host,
                "-verify_return_error",
                "-CAfile",
            ])
            .arg(&certificate)
            .arg("-quiet")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let read = child.stdout.take().unwrap();
        let write = child.stdin.take().unwrap();
        let transport = OwnedOpenSslTransport { child, read, write };
        let mut request = base.into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Origin", origin.parse().unwrap());
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            arkret_wire::websocket_binding::WEBSOCKET_SUBPROTOCOL
                .parse()
                .unwrap(),
        );
        let (socket, response) =
            tokio_tungstenite::tungstenite::client(request, transport).unwrap();
        assert_eq!(response.status().as_u16(), 101);
        assert_eq!(
            response.headers().get("Sec-WebSocket-Protocol").unwrap(),
            arkret_wire::websocket_binding::WEBSOCKET_SUBPROTOCOL
        );
        (socket, pid)
    })
    .await
    .unwrap();
    OwnedWebSocketFixture {
        socket: Some(socket),
        server,
        _directory: directory,
        client_pid: pid,
        channels: std::collections::BTreeMap::new(),
    }
}
async fn owned_consumer_ws_send(
    ws: &mut OwnedWebSocketFixture,
    frame: arkret_models_collaboration::sync_frames::websocket::WebSocketClientFrame,
) {
    let opened = match &frame {
        arkret_models_collaboration::sync_frames::websocket::WebSocketClientFrame::Open {
            channel_id,
            operation_id,
            ..
        } => {
            assert!(
                !ws.channels.contains_key(channel_id),
                "actual socket channel cannot be rebound"
            );
            Some((channel_id.clone(), *operation_id))
        }
        _ => None,
    };
    let mut socket = ws.socket.take().unwrap();
    let bytes = arkret_canonical::canonical_json_string(&frame).unwrap();
    ws.socket = Some(
        tokio::task::spawn_blocking(move || {
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(bytes.into()))
                .unwrap();
            socket
        })
        .await
        .unwrap(),
    );
    if let Some((channel_id, operation_id)) = opened {
        assert!(
            ws.channels
                .insert(channel_id, (operation_id, false))
                .is_none()
        );
    }
}
async fn owned_consumer_ws_read(
    ws: &mut OwnedWebSocketFixture,
) -> arkret_models_collaboration::sync_frames::websocket::WebSocketServerFrame {
    let mut socket = ws.socket.take().unwrap();
    let channels = ws.channels.clone();
    let (socket, frame) = tokio::task::spawn_blocking(move || {
        loop {
            match socket.read().unwrap() {
                tokio_tungstenite::tungstenite::Message::Text(text) => {
                    let frame = arkret_models_collaboration::sync_frames::websocket::WebSocketFrameIngress::new(262_144, None)
                        .decode_server_frame_for_channels(text.as_bytes(), |channel_id| {
                            channels.get(channel_id).and_then(|(operation, opened)| opened.then_some(*operation))
                        })
                        .unwrap_or_else(|error| panic!("original socket typed channel schema close_code={:?}", error.close_code));
                    frame.validate().unwrap();
                    break (socket, frame);
                }
                tokio_tungstenite::tungstenite::Message::Ping(bytes) => {
                    socket
                        .send(tokio_tungstenite::tungstenite::Message::Pong(bytes))
                        .unwrap();
                }
                _ => panic!("only registered text frame or transport ping is expected"),
            }
        }
    })
    .await
    .unwrap();
    ws.socket = Some(socket);
    use arkret_models_collaboration::sync_frames::websocket::WebSocketServerFrame;
    match &frame {
        WebSocketServerFrame::Opened {
            channel_id,
            operation_id,
        } => {
            let (requested, opened) = ws
                .channels
                .get_mut(channel_id)
                .expect("Opened must acknowledge the actual requested channel");
            assert!(
                !*opened && requested == operation_id,
                "Opened must retain the exact requested operation"
            );
            *opened = true;
        }
        WebSocketServerFrame::Data { channel_id, .. }
        | WebSocketServerFrame::ChannelControl { channel_id, .. } => {
            assert!(
                ws.channels
                    .get(channel_id)
                    .is_some_and(|(_, opened)| *opened),
                "physical payload requires an actual Opened channel"
            );
        }
        WebSocketServerFrame::Closed { channel_id, .. } => {
            assert!(
                ws.channels.remove(channel_id).is_some(),
                "Closed must bind an actual requested channel"
            );
        }
        WebSocketServerFrame::ChannelError { channel_id, .. } => {
            assert!(
                ws.channels.contains_key(channel_id),
                "ChannelError must bind an actual requested channel"
            );
        }
        _ => {}
    }
    frame
}
// Only closed frame/rail enums and registered error codes may enter a
// failed-stage diagnostic. No channel id, cursor, token or content is rendered.
fn owned_consumer_ws_diagnostic(
    stage: &'static str,
    frame: &arkret_models_collaboration::sync_frames::websocket::WebSocketServerFrame,
) {
    use std::io::Write;

    use arkret_models_collaboration::sync_frames::websocket::*;
    let (kind, rail, code) = match frame {
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Events(_),
            ..
        } => ("data", "events", None),
        WebSocketServerFrame::ChannelControl {
            payload: WebSocketChannelControlPayload::Events(_),
            ..
        } => ("control", "events", None),
        WebSocketServerFrame::ChannelControl {
            payload: WebSocketChannelControlPayload::Account(_),
            ..
        } => ("control", "account", None),
        WebSocketServerFrame::ChannelControl {
            payload: WebSocketChannelControlPayload::Signal(_),
            ..
        } => ("control", "signal", None),
        WebSocketServerFrame::ChannelControl {
            payload: WebSocketChannelControlPayload::Heartbeat(_),
            ..
        } => ("control", "heartbeat", None),
        WebSocketServerFrame::ChannelError { error, .. } => {
            ("channel_error", "none", Some(error.code))
        }
        WebSocketServerFrame::Closed { .. } => ("closed", "none", None),
        _ => ("other_registered_frame", "none", None),
    };
    writeln!(
        std::io::stdout().lock(),
        "owned socket stage={stage} frame={kind} rail={rail} registered_code={code:?}"
    )
    .unwrap();
}
async fn owned_consumer_ws_non_ping(
    ws: &mut OwnedWebSocketFixture,
) -> arkret_models_collaboration::sync_frames::websocket::WebSocketServerFrame {
    use arkret_models_collaboration::sync_frames::websocket::*;
    loop {
        let frame = owned_consumer_ws_read(ws).await;
        if let WebSocketServerFrame::Ping { ping_id, .. } = frame {
            owned_consumer_ws_send(ws, WebSocketClientFrame::Pong { ping_id }).await;
        } else {
            return frame;
        }
    }
}
async fn owned_consumer_websocket_scenario(policy_deny: bool) {
    use arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrameKind as Kind;
    use arkret_models_collaboration::sync_frames::websocket::*;
    let fixture = boxed_owned_consumer_fixture(1).await;
    let http = Box::pin(owned_consumer_http_fixture(&fixture)).await;
    let mut ws = Box::pin(owned_consumer_ws_connect(&http)).await;
    let WebSocketServerFrame::Challenge {
        connection_id,
        nonce,
        ..
    } = owned_consumer_ws_non_ping(&mut ws).await
    else {
        panic!("real socket challenge required");
    };
    let base = http.base_url.replacen("https://", "wss://", 1) + "/_arkret/ws";
    let proof = arkret_signatures::websocket_auth::build_websocket_auth_proof(
        &arkret_signatures::websocket_auth::WebSocketAuthProofRequest {
            base_url: &base,
            session_grant: &http.token,
            nonce: &nonce,
            issued_at: chrono::Utc::now(),
            jti: &uuid::Uuid::now_v7().to_string(),
        },
        &http.key,
    )
    .unwrap();
    owned_consumer_ws_send(
        &mut ws,
        WebSocketClientFrame::Authenticate {
            connection_id: connection_id.clone(),
            session_grant: http.token.clone(),
            dpop_proof: proof.compact_jws,
        },
    )
    .await;
    assert!(
        matches!(owned_consumer_ws_non_ping(&mut ws).await,WebSocketServerFrame::Welcome{connection_id:actual,..}if actual==connection_id)
    );
    let channel = "owned-current-delivery".to_owned();
    owned_consumer_ws_send(
        &mut ws,
        WebSocketClientFrame::Open {
            channel_id: channel.clone(),
            operation_id: arkret_wire::WebSocketOperationId::CommittedEventStreamSubscribe,
            parameters: WebSocketOpenParameters::Events(WebSocketEventsOpenParameters {
                realm_ids: Some(vec![fixture.head.event.realm_id.clone()]),
                ..Default::default()
            }),
        },
    )
    .await;
    assert!(
        matches!(owned_consumer_ws_non_ping(&mut ws).await,WebSocketServerFrame::Opened{channel_id,..}if channel_id==channel)
    );
    let checkpoint = owned_consumer_ws_non_ping(&mut ws).await;
    owned_consumer_ws_diagnostic("events_checkpoint", &checkpoint);
    assert!(
        matches!(checkpoint,WebSocketServerFrame::ChannelControl{channel_id,payload:WebSocketChannelControlPayload::Events(frame),..}
        if channel_id==channel && frame.kind==Kind::Checkpoint && frame.cursor.is_some())
    );
    let allow = Box::pin(owned_consumer_policy_event(
        &fixture,
        &fixture.head,
        "allow",
        None,
    ))
    .await;
    fixture_commit_step(&fixture.pool, allow.clone())
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let cursor = loop {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(40),
            "actual socket delivered accepted full Event"
        );
        match owned_consumer_ws_non_ping(&mut ws).await {
            WebSocketServerFrame::ChannelControl {
                channel_id,
                payload: WebSocketChannelControlPayload::Heartbeat(_),
                ..
            } => assert!(channel_id == channel),
            WebSocketServerFrame::ChannelControl {
                channel_id,
                payload: WebSocketChannelControlPayload::Events(frame),
                ..
            } if frame.kind == Kind::Heartbeat => {
                assert!(channel_id == channel && frame.cursor.is_none() && frame.payload.is_none());
            }
            WebSocketServerFrame::Data {
                channel_id,
                payload: WebSocketDataPayload::Events(frame),
            } => {
                assert!(channel_id == channel && frame.kind == Kind::CommittedEvent);
                let arkret_wire::CommittedEventView::Full(full) = frame.committed_event().unwrap()
                else {
                    panic!("full Event required");
                };
                assert!(
                    full.event == allow.authority_commit.event
                        && full.commit == allow.authority_commit.commit
                );
                break frame.cursor.clone().unwrap();
            }
            _ => panic!("unexpected original socket delivery rail"),
        }
    };
    assert!(!cursor.is_empty());
    // Consume the normal checkpoint; the same open channel remains authenticated.
    let checkpoint = owned_consumer_ws_non_ping(&mut ws).await;
    owned_consumer_ws_diagnostic("events_checkpoint", &checkpoint);
    assert!(
        matches!(checkpoint,WebSocketServerFrame::ChannelControl{channel_id,payload:WebSocketChannelControlPayload::Events(frame),..}
        if channel_id==channel && frame.kind==Kind::Checkpoint)
    );
    let changed = if policy_deny {
        Box::pin(owned_consumer_policy_event(
            &fixture,
            &allow.authority_commit,
            "deny",
            Some(&allow.authority_commit),
        ))
        .await
    } else {
        Box::pin(ordinary_realm::source_request(&fixture.pool,ordinary_realm::next_request_for_actor(&allow.authority_commit,
            EventKind::MemberState,arkret_wire::ActorId::account(fixture.controller.history.account.clone()),
            serde_json::json!({"member_id":arkret_wire::ActorId::account(fixture.controller.history.account.clone()),"membership":"leave"}),
            allow.authority_commit.commit.committed_at+chrono::TimeDelta::milliseconds(1)))).await
    };
    fixture_commit_step(&fixture.pool, changed).await.unwrap();
    let before = owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await;
    let started = std::time::Instant::now();
    let mut terminal = false;
    loop {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(40),
            "current change must terminate original socket channel"
        );
        match owned_consumer_ws_non_ping(&mut ws).await {
            WebSocketServerFrame::ChannelControl {
                channel_id,
                payload: WebSocketChannelControlPayload::Heartbeat(_),
                ..
            } => assert!(channel_id == channel),
            WebSocketServerFrame::ChannelControl {
                channel_id,
                payload: WebSocketChannelControlPayload::Events(frame),
                ..
            } if frame.kind == Kind::Heartbeat => {
                assert!(channel_id == channel && frame.cursor.is_none() && frame.payload.is_none());
            }
            WebSocketServerFrame::ChannelControl {
                channel_id,
                payload: WebSocketChannelControlPayload::Events(frame),
                ..
            } => {
                assert!(
                    channel_id == channel
                        && matches!(frame.kind, Kind::Unauthorized | Kind::ResyncRequired)
                );
                assert!(frame.payload.is_none() && frame.cursor.is_none());
                terminal = true;
            }
            WebSocketServerFrame::Closed { channel_id, reason } => {
                assert!(
                    channel_id == channel && terminal && reason == WebSocketClosedReason::Completed
                );
                break;
            }
            WebSocketServerFrame::Data { .. } => {
                panic!("current refusal forbids physical socket Data")
            }
            _ => panic!("only original payload-free terminal rail is allowed"),
        }
    }
    assert!(before == owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await);
    let mut socket = ws.socket.take().unwrap();
    tokio::task::spawn_blocking(move || {
        socket.close(None).unwrap();
        loop {
            match socket.read() {
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => break,
                Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed) => break,
                Ok(_) => {}
                Err(_) => panic!("original TLS socket close handshake"),
            }
        }
        // Drop owned TLS process only after original WebSocket Close handoff.
        drop(socket);
    })
    .await
    .unwrap();
    ws.client_pid = 0;
    ws.server
        .handle
        .stop_graceful(Some(std::time::Duration::from_secs(5)));
    (&mut ws.server.task).await.unwrap();
}
#[tokio::test]
async fn owned_agent_websocket_rechecks_owner_leave_before_physical_data() {
    fixture_step(Box::pin(owned_consumer_websocket_scenario(false))).await;
}
#[tokio::test]
async fn owned_agent_websocket_rechecks_policy_deny_before_physical_data() {
    fixture_step(Box::pin(owned_consumer_websocket_scenario(true))).await;
}

// A real native Owned recipient and exact accepted content are locally
// deliverable, but another serving Station has no registered remote governing
// barrier. Separately, a real foreign Station AppState and standard HTTP router
// reject this original Account through the subject/audience binding; its issuer
// response never substitutes a foreign Account for the accepted local one.
// Neither layer claims a remote authenticated content-barrier positive, normal
// OAuth issuance, or coverage of unregistered remote entry points.
async fn owned_consumer_remote_barrier_scenario() {
    let fixture = boxed_owned_consumer_fixture(1).await;
    let agent = &fixture.agents[0];
    let evidence = agent
        ._vault
        .state
        .qualified_agent_scope_evidence(&agent.endpoint)
        .await
        .unwrap();
    let scope = &evidence
        .command()
        .requested_scope_disclosure
        .requested_scope;
    let details=serde_json::json!({"controller_principal_id":fixture.controller.history.account.principal_id,
        "agent_key_authorization_ref":agent.endpoint.authorization_ref.event_id,
        "realm_ids":[fixture.head.event.realm_id],"strand_ids":[],
        "resources":{"realm_ids":[fixture.head.event.realm_id],"strand_ids":[]},
        "constraints":{"allowed_tracks":[],"allowed_data_labels":[],"allowed_endpoints":[]},
        "capability_grant_refs":[],"policy_refs":[]}).as_object().unwrap().clone();
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![fixture.head.event.realm_id.clone()],
        committed_events: vec![arkret_wire::CommittedEventView::Full(
            arkret_wire::CommittedEventFullView {
                event: fixture.head.event.clone(),
                commit: fixture.head.commit.clone(),
            },
        )],
        agent_session_scope: Some((scope.actions.clone(), details)),
        agent_endpoint: Some(agent.endpoint.clone()),
        qualified_agent_scope_evidence: Some(evidence),
        credential_expires_at: Some(chrono::Utc::now() + chrono::TimeDelta::minutes(5)),
        ..Default::default()
    };
    let before = owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await;
    let local = fixture_delivery_step(&fixture.pool, &agent.account, &fixture.station.core, &input)
        .await
        .unwrap()
        .unwrap();
    assert!(local.permits_handoff());
    local.finish().await.unwrap();
    let foreign: arkret_wire::DidCoreId = "ak:did_core:web:remote-serving.example".parse().unwrap();
    let error = fixture_delivery_step(&fixture.pool, &agent.account, &foreign, &input)
        .await
        .err()
        .expect("foreign receiver cannot invent current governing barrier");
    assert!(
        matches!(error,coland_storage::PersistenceError::Conflict(ref message)
        if message=="revision_unavailable: no authenticated current governing delivery barrier"),
        "exact original registered unavailable boundary required"
    );
    assert!(before == owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await);

    let http = Box::new(Box::pin(owned_consumer_http_fixture(&fixture)).await);
    let receiver = historical_control_source::HistoricalControlStation::new(
        "owned-consumer-remote-receiver",
        [0x74; 32],
    );
    let remote = Box::new(
        Box::pin(owned_consumer_http_for_endpoint_with_storage(
            &fixture.pool,
            &fixture.station,
            &fixture.controller.history.account,
            &fixture.head.event.realm_id,
            &agent.account,
            &agent.endpoint,
            &agent._vault,
            None,
            chrono::TimeDelta::hours(1),
            Some(&receiver),
        ))
        .await,
    );
    let receiver_pool = remote
        ._receiver_database
        .as_ref()
        .expect("foreign Station holds an independent migrated database lease")
        .pool();
    let receiver_store = PgAuthorityCommitStore {
        pool: receiver_pool.clone(),
    };
    assert!(
        receiver_store
            .committed_event(&fixture.head.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let before_receiver =
        owned_consumer_footprint(&receiver_pool, &fixture.head.event.realm_id).await;
    assert!(
        before_receiver["current"]["events"] == 0
            && before_receiver["current"]["commits"] == 0
            && before_receiver["current"]["authority"].is_null()
    );
    assert!(http.state.service_core_id() == fixture.station.core);
    assert!(http.state.config().trust_domain == remote.state.config().trust_domain);
    assert!(http.key.verifying_key() == remote.key.verifying_key());
    assert!(http.delivery_session_scope == remote.delivery_session_scope);
    assert!(
        http.grant_expires_at > chrono::Utc::now() && remote.grant_expires_at > chrono::Utc::now()
    );
    assert!(remote.base_url == remote.state.config().public_base_url.trim_end_matches('/'));
    assert!(
        remote.state.service_core_id() == receiver.core
            && receiver.core != agent.account.station_id
    );
    let path = format!(
        "/_arkret/self/committed-events/{}",
        fixture.head.event.event_id
    );
    let before_http = owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await;
    let mut local_response = Box::pin(owned_consumer_http_get_at_receiver(
        &http,
        &path,
        arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
        true,
    ))
    .await;
    owned_consumer_assert_http_status(
        &mut local_response,
        salvo::http::StatusCode::OK,
        "original_account_local_route_exact_content",
    )
    .await;
    let local_view =
        owned_consumer_take_response_json::<arkret_wire::CommittedEventView>(&mut local_response)
            .await
            .unwrap();
    let arkret_wire::CommittedEventView::Full(local_full) = local_view else {
        panic!("local premise requires the complete original accepted Event and Commit");
    };
    assert!(local_full.event == fixture.head.event && local_full.commit == fixture.head.commit);
    assert!(
        before_http == owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await
    );
    let mut remote_response = Box::pin(owned_consumer_http_get_at_receiver(
        &remote,
        &path,
        arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
        true,
    ))
    .await;
    owned_consumer_assert_http_status(
        &mut remote_response,
        salvo::http::StatusCode::UNAUTHORIZED,
        "original_account_foreign_receiver_closed_subject_audience",
    )
    .await;
    let bytes = owned_consumer_take_response_bytes(&mut remote_response)
        .await
        .unwrap();
    let problem: arkret_wire::Problem = serde_json::from_slice(&bytes).unwrap();
    assert!(problem.error_code() == Some(arkret_wire::ErrorCode::Unauthenticated));
    assert!(serde_json::from_slice::<arkret_wire::CommittedEventView>(&bytes).is_err());
    let closed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        closed.get("cursor").is_none()
            && closed.get("payload").is_none()
            && closed.get("event").is_none()
            && closed.get("commit").is_none()
    );
    for private_record in [
        arkret_canonical::canonical_json_bytes(&fixture.head.event).unwrap(),
        arkret_canonical::canonical_json_bytes(&fixture.head.commit).unwrap(),
        arkret_canonical::canonical_json_bytes(
            input
                .qualified_agent_scope_evidence
                .as_ref()
                .unwrap()
                .command(),
        )
        .unwrap(),
    ] {
        assert!(
            !bytes
                .windows(private_record.len())
                .any(|window| window == private_record.as_slice())
        );
    }
    assert!(
        before_http == owned_consumer_footprint(&fixture.pool, &fixture.head.event.realm_id).await
    );
    assert!(
        before_receiver
            == owned_consumer_footprint(&receiver_pool, &fixture.head.event.realm_id).await
    );
}
#[tokio::test]
async fn owned_agent_remote_receiver_without_current_governing_barrier_yields_no_guard() {
    fixture_step(Box::pin(owned_consumer_remote_barrier_scenario())).await;
}

// The existing accepted Sidecar's actual private controller group replaces
// the same Agent endpoint with a fresh claimed KeyPackage. Its one real
// Remove+Add Commit produces the later signed Welcome without another singleton
// or MLS Genesis. No delivery row, cursor, ciphertext or proof is fabricated.
async fn owned_consumer_queue_later_welcome(
    pool: &coland_storage_postgres::PgPool,
    station: &historical_control_source::HistoricalControlStation,
    principal: &std::sync::Arc<pcr_genesis::PcrGenesisFixture>,
    agent: &AccountId,
    key_event: &arkret_wire::Event,
    key_commit: &arkret_wire::RealmCommit,
    realm_id: &arkret_wire::RealmId,
    realm_template: &coland_storage::AuthorityCommitTransaction,
    scope: &arkret_wire::ScopeRef,
    group: &mut arkret_mls::ArkretMlsGroup,
    tracker: &mut arkret_mls::MlsPublicGroupTracker,
) -> arkret_wire::MlsWelcomeDelivery {
    use coland_storage::AuthorityCommitStore;
    let controller = &principal.history.account;
    let station_did = station.did.clone();
    let resolution = station.history.clone();
    let authorization =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            key_event,
        )
        .unwrap();
    assert_eq!(authorization.agent_id, agent.principal_id);
    assert_eq!(
        authorization.accountable_principal_id,
        controller.principal_id
    );
    assert_eq!(key_commit.event_ref, key_event.event_id);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let accepted_authorization = store
        .committed_event(&key_event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        accepted_authorization.event == *key_event,
        "continuation retains the original accepted authorization Event"
    );
    assert!(
        accepted_authorization.commit.commit_id == key_commit.commit_id
            && accepted_authorization.commit.stream_ref == key_commit.stream_ref
            && accepted_authorization.commit.stream_position == key_commit.stream_position,
        "continuation uses the original exact authorization Commit coordinates"
    );
    use arkret_models_crypto::MlsGovernanceBindingPayload;
    use arkret_wire::{ActorId, ScopeRef};
    use coland_storage::{MlsGroupCurrentStore, MlsKeyPackageStore};
    use diesel::sql_types::{BigInt, Text};
    use diesel_async::RunQueryDsl;
    let ScopeRef::Sidecar {
        realm_id: scope_realm,
        sidecar_id: sidecar,
    } = scope
    else {
        panic!("continuation must retain the original accepted Sidecar scope");
    };
    assert_eq!(scope_realm, realm_id);
    let stream = arkret_wire::CommitStreamRef::from_scope(scope, None).unwrap();
    let current = store
        .held_stream_head_commit(&stream)
        .await
        .unwrap()
        .unwrap();
    let mut head = realm_template.clone();
    head.event = store
        .committed_event(&current.event_ref)
        .await
        .unwrap()
        .unwrap()
        .event;
    head.commit = current;
    head.mls_state = None;
    head.welcomes.clear();
    let at = head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let cut = read(&pool, realm_id, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    let actor = ActorId::account(agent.clone());
    // Use the exact DID URL from the already accepted runtime authorization;
    // Account principal_id is a core ID, not a DID or a method factory.
    let method = authorization.verification_method;
    assert!(
        authorization.public_key.key.as_str()
            == arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[0x61; 32])
                    .verifying_key()
                    .as_bytes()
            )
    );
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
    let mut record = coland_storage::AgentStore::get(
        &coland_storage_postgres::PgAgentStore { pool: pool.clone() },
        agent.principal_id.as_str(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        record.authorized_verification_method.as_deref(),
        Some(method.as_str())
    );
    assert_eq!(
        record.authorized_event_ref.as_deref(),
        Some(key_event.event_id.as_str())
    );
    // Read through the original persistence-to-service projection; the storage
    // record is not itself the application runtime-binding carrier.
    let pairing = coland_services::persistence_identity::build_persistence_identity_services(
        std::sync::Arc::new(PgPersistenceStore::new(pool.clone())),
        std::sync::Arc::new(
            coland_http::state::did_resolver_chain::build_coland_did_resolver(
                &coland_test_support::app_config(),
            ),
        ),
    )
    .agent_pairing;
    let accepted_runtime = pairing
        .agent(agent.principal_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(
        accepted_runtime.runtime_bindings().is_ok(),
        "continuation starts with the original accepted runtime binding"
    );
    let accepted_key_digest =
        arkret_signatures::agent::agent_runtime_public_key_digest(&authorization.public_key)
            .unwrap();
    assert!(
        record.authorized_public_key_digest.as_deref() == Some(accepted_key_digest.as_str()),
        "continuation preserves the accepted runtime key digest domain"
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
             })).unwrap(), accepted_authorization.commit.commit_id.clone(),
            accepted_authorization.commit.committed_at,
        ).unwrap();
    assert!(
        record.current_signer_evidence.as_ref() == Some(&evidence),
        "continuation retains the same accepted signer evidence"
    );
    assert!(
        record.signer_resolution_evidence_ref.as_ref()
            == Some(&evidence.signer_evidence_ref().unwrap()),
        "continuation retains the same content-addressed signer evidence reference"
    );
    record.signer_resolution_evidence_ref = Some(evidence.signer_evidence_ref().unwrap());
    record.current_signer_evidence = Some(evidence);
    // Key-management §7.9 uses the decoded runtime key's sole digest domain,
    // not the digest of its PublicKey JSON carrier. Re-indexing this same
    // accepted authorization must preserve its original qualified binding.
    record.authorized_public_key_digest = Some(accepted_key_digest.to_string());
    coland_storage::AgentStore::put(
        &coland_storage_postgres::PgAgentStore { pool: pool.clone() },
        record,
    )
    .await
    .unwrap();
    let retained_runtime = pairing
        .agent(agent.principal_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(
        retained_runtime.runtime_bindings().is_ok(),
        "continuation retains the complete accepted runtime binding"
    );
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
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([41; 32])).unwrap();
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
        request_digest: format!("sha256:{}", "7".repeat(64)),
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
        base.current_key_access_revision,
        cut.participant_authority_digest.clone(),
        cut.authority_stream_head.clone(),
    )
    .unwrap();
    assert_eq!(group.export_state_record().unwrap().epoch, base.epoch);
    assert_eq!(
        group
            .member_endpoint_replacement_actor(&package.endpoint, &actor)
            .unwrap(),
        Some(actor.clone()),
    );
    // Preserve the complete map authenticated by the preceding accepted Add.
    // The real replacement transition below may assign a different leaf index;
    // the public tracker supplies positions and keys, never endpoint authority.
    let prior_bindings = group.verified_leaf_bindings().unwrap();
    let add = group
        .replace_member_endpoint(&package, &actor, Some(&binding))
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
    assert_eq!(
        consumed_proposals
            .iter()
            .filter(|p| p.proposal_type == 3)
            .count(),
        1
    );
    assert_eq!(
        consumed_proposals
            .iter()
            .filter(|p| p.proposal_type == 1)
            .count(),
        1
    );
    assert_eq!(
        tracker
            .leaves()
            .unwrap()
            .iter()
            .filter(|leaf| leaf.actor_id == actor)
            .count(),
        1
    );
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
            at,
        ),
        principal.history.device_verification_method.clone(),
        principal.history.founding_device_signing_seed,
    );
    let mut request = ordinary_realm::request_for_event(&head, event, at);
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
    let request = Box::pin(ordinary_realm::source_request(&pool, request)).await;
    fixture_commit_step(pool, request.clone()).await.unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: request.authority_commit.event.clone(),
        commit: request.authority_commit.commit.clone(),
    };

    group.install_accepted_commit(&accepted, &base).unwrap();
    let mut recipient = arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
        identity, &delivery, &accepted,
    )
    .unwrap();
    // Install bindings only after the original signed replacement/claim has
    // won admission. Both private groups must carry the accepted transition's
    // complete map before export; joining a Welcome alone does not install it.
    let bindings = tracker
        .leaves()
        .unwrap()
        .into_iter()
        .map(|leaf| {
            let mut matching = prior_bindings
                .iter()
                .filter(|bound| bound.actor_id == leaf.actor_id);
            let mut bound = matching.next().unwrap().clone();
            assert!(matching.next().is_none());
            assert_eq!(bound.signature_key, leaf.signature_key);
            if leaf.actor_id == ActorId::account(agent.clone()) {
                assert_eq!(bound.endpoint, package.endpoint);
                assert_eq!(delivery.recipient_actor_id, bound.actor_id);
            } else {
                assert_eq!(leaf.actor_id, ActorId::account(controller.clone()));
                assert!(bound.device_authorize_event_id.is_some());
            }
            bound.leaf_index = leaf.leaf_index;
            bound
        })
        .collect::<Vec<_>>();
    assert_eq!(bindings.len(), prior_bindings.len());
    group
        .install_verified_leaf_bindings(bindings.clone())
        .unwrap();
    recipient.install_verified_leaf_bindings(bindings).unwrap();
    assert_eq!(group.export_state_record().unwrap().epoch, base.epoch + 1);
    assert_eq!(
        recipient.export_state_record().unwrap().epoch,
        base.epoch + 1
    );
    delivery
}

async fn owned_consumer_private_queue_cut_footprint(
    pool: &coland_storage_postgres::PgPool,
) -> String {
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT jsonb_build_object( \
        'ack',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY ack_token),'[]'::jsonb) FROM agent_recipient_delivery_ack_tokens x), \
        'cursor',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM sync_cursor_handles x), \
        'queue',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY welcome_id),'[]'::jsonb) FROM mls_welcome_deliveries x)) AS value"
    ).get_result::<Row>(&mut *conn).await.unwrap();
    arkret_canonical::canonical_sha256(&row.value).unwrap()
}

async fn owned_consumer_exact_welcome_cursor(
    http: &OwnedConsumerHttpFixture,
    path: &str,
    welcome: &arkret_wire::MlsWelcomeDelivery,
) -> String {
    use arkret_models_collaboration::device_messages::{
        DeviceMessagesGetOutcome, RecipientDelivery,
    };
    let mut response = Box::pin(owned_consumer_http_get(
        http,
        path,
        arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
    ))
    .await;
    owned_consumer_assert_http_status(
        &mut response,
        salvo::http::StatusCode::OK,
        "owned_consumer_exact_welcome_cursor",
    )
    .await;
    let actual = owned_consumer_take_response_json::<DeviceMessagesGetOutcome>(&mut response)
        .await
        .unwrap();
    assert_eq!(actual.deliveries.len(), 1);
    let RecipientDelivery::MlsWelcome { mls_welcome } = &actual.deliveries[0] else {
        panic!("actual producer-signed Welcome required");
    };
    assert!(
        arkret_canonical::canonical_json_bytes(mls_welcome).unwrap()
            == arkret_canonical::canonical_json_bytes(welcome).unwrap()
    );
    assert!(
        actual
            .ack_token
            .as_ref()
            .is_some_and(|token| !token.is_empty())
    );
    actual
        .next_cursor
        .filter(|cursor| !cursor.is_empty())
        .expect("actual original server cursor")
}

#[tokio::test]
async fn owned_agent_device_messages_continuation_owner_leave_allocates_no_new_cut() {
    boxed_owned_welcome(OwnedWelcomeCase::DeviceMessagesContinuationOwnerLeave).await;
}
#[tokio::test]
async fn owned_agent_device_messages_continuation_policy_deny_allocates_no_new_cut() {
    boxed_owned_welcome(OwnedWelcomeCase::DeviceMessagesContinuationPolicyDeny).await;
}

// Test-only adapter: the original object port supplies two actual byte chunks.
// Releasing its second chunk changes no authority clock, queue or current row.
struct OwnedConsumerTwoChunkStorage {
    objects: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    release_second: std::sync::Arc<tokio::sync::Semaphore>,
    second_read: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl OwnedConsumerTwoChunkStorage {
    fn new() -> Self {
        Self {
            objects: Default::default(),
            release_second: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
            second_read: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}
#[async_trait::async_trait]
impl coland_services::delivery::ObjectStoragePort for OwnedConsumerTwoChunkStorage {
    fn backend_name(&self) -> String {
        "held-two-chunk-fixture".to_owned()
    }
    fn object_key_for_sha256(&self, sha256: &str) -> String {
        format!("sha256/{sha256}")
    }
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        self.objects.lock().unwrap().insert(key.to_owned(), bytes);
        Ok(())
    }
    async fn put_file(&self, key: &str, path: &std::path::Path) -> Result<(), String> {
        self.put(key, std::fs::read(path).map_err(|error| error.to_string())?)
            .await
    }
    async fn get(&self, key: &str) -> Result<Vec<u8>, String> {
        self.objects
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| "fixture object absent".into())
    }
    async fn get_range_stream(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<futures_util::stream::BoxStream<'static, Result<bytes::Bytes, String>>, String>
    {
        use futures_util::StreamExt;
        let bytes = self.get(key).await?;
        let start = usize::try_from(range.start).map_err(|error| error.to_string())?;
        let end = usize::try_from(range.end).map_err(|error| error.to_string())?;
        let bytes = bytes
            .get(start..end)
            .ok_or_else(|| "fixture range invalid".to_owned())?;
        if bytes.len() < 2 {
            return Err("two physical chunks require at least two bytes".into());
        }
        let split = bytes.len() / 2;
        let first = bytes::Bytes::copy_from_slice(&bytes[..split]);
        let second = bytes::Bytes::copy_from_slice(&bytes[split..]);
        let release = self.release_second.clone();
        let read = self.second_read.clone();
        Ok(futures_util::stream::once(async move { Ok(first) })
            .chain(futures_util::stream::once(async move {
                release
                    .acquire()
                    .await
                    .map_err(|_| "fixture release closed".to_owned())?
                    .forget();
                read.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(second)
            }))
            .boxed())
    }
    async fn delete(&self, key: &str) -> Result<(), String> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
}
struct OwnedConsumerFixtureSettings;
#[async_trait::async_trait]
impl coland_services::governance::RuntimeSettingsPort for OwnedConsumerFixtureSettings {
    async fn load_overrides(
        &self,
    ) -> coland_services::ServiceResult<Vec<(String, serde_json::Value)>> {
        Ok(Vec::new())
    }
    async fn store_override(
        &self,
        _: &str,
        _: &serde_json::Value,
        _: &str,
    ) -> coland_services::ServiceResult<()> {
        Ok(())
    }
}
struct OwnedConsumerFixtureHealth {
    pool: coland_storage_postgres::PgPool,
}
#[async_trait::async_trait]
impl coland_services::jobs::RuntimeHealthPort for OwnedConsumerFixtureHealth {
    async fn database_ready(&self) -> bool {
        self.pool.get().await.is_ok()
    }
    fn storage_mode(&self) -> &'static str {
        "postgres"
    }
    fn migrations_applied(&self) -> bool {
        true
    }
    fn database_configured(&self) -> bool {
        true
    }
    fn database_pool_in_use(&self) -> u32 {
        0
    }
}
async fn owned_consumer_blob_two_chunk_expiry_scenario() {
    let fixture = boxed_owned_consumer_fixture(1).await;
    let agent = &fixture.agents[0];
    let storage = std::sync::Arc::new(OwnedConsumerTwoChunkStorage::new());
    let http = Box::pin(owned_consumer_http_for_endpoint_with_storage(
        &fixture.pool,
        &fixture.station,
        &fixture.controller.history.account,
        &fixture.head.event.realm_id,
        &agent.account,
        &agent.endpoint,
        &agent._vault,
        Some(storage.clone()),
        chrono::TimeDelta::seconds(10),
        None,
    ))
    .await;
    let original = b"first physical chunk/second physical chunk";
    let (reference, source) = Box::pin(owned_consumer_blob_source(&fixture, &http, original)).await;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("blob_ref", reference.as_str())
        .append_pair("realm_id", source.event.realm_id.as_str())
        .append_pair("purpose", "message_attachment")
        .finish();
    let path = format!("/_arkret/self/blob/get?{query}");
    let before = owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await;
    let mut response = Box::pin(owned_consumer_http_blob_request(&http, &path, false, None)).await;
    owned_consumer_assert_http_status(
        &mut response,
        salvo::http::StatusCode::OK,
        "blob_two_chunk_before_expiry",
    )
    .await;
    assert!(chrono::Utc::now() < http.grant_expires_at);
    let mut body = response.take_body();
    let first = owned_consumer_poll_body_frame(&mut body)
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(first.as_ref() == &original[..original.len() / 2]);
    assert_eq!(
        storage
            .second_read
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    // Use the actual finite issuer deadline, not a replacement clock or TTL.
    let remaining = http.grant_expires_at - chrono::Utc::now();
    if remaining > chrono::TimeDelta::zero() {
        tokio::time::sleep(remaining.to_std().unwrap() + std::time::Duration::from_millis(2)).await;
    }
    assert!(chrono::Utc::now() >= http.grant_expires_at);
    storage.release_second.add_permits(1);
    // The original Blob production guard must observe expiry after the backend
    // delivers its next chunk and before emitting any of those physical bytes.
    assert!(
        owned_consumer_poll_body_frame(&mut body)
            .await
            .is_some_and(|frame| frame.is_err())
    );
    assert_eq!(
        storage
            .second_read
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(owned_consumer_poll_body_frame(&mut body).await.is_none());
    drop(body);
    assert!(before == owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await);
    let mut expired = Box::pin(owned_consumer_http_blob_request(&http, &path, false, None)).await;
    assert_eq!(
        expired.status_code,
        Some(salvo::http::StatusCode::UNAUTHORIZED)
    );
    let problem = owned_consumer_take_response_json::<arkret_wire::Problem>(&mut expired)
        .await
        .unwrap();
    // api-conventions §3.2/§3.3 requires unauthenticated for this original
    // self-path expired grant presentation; no second body chunk is disclosed.
    assert_eq!(
        problem.error_code(),
        Some(arkret_wire::error_codes::ErrorCode::Unauthenticated)
    );
    assert!(before == owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await);
    // A real subsequent governing write completes after the errored body has
    // released its held delivery cut. It uses the original accepted source/UOW.
    let leave = Box::pin(ordinary_realm::source_request(&fixture.pool,
        ordinary_realm::next_request_for_actor(&source, EventKind::MemberState,
            arkret_wire::ActorId::account(fixture.controller.history.account.clone()),
            serde_json::json!({"member_id":arkret_wire::ActorId::account(fixture.controller.history.account.clone()),"membership":"leave"}),
            source.commit.committed_at + chrono::TimeDelta::milliseconds(1)))).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture_commit_step(&fixture.pool, leave),
    )
    .await
    .expect("expired physical body releases original governing cut")
    .unwrap();
}
#[tokio::test]
async fn owned_agent_blob_second_physical_chunk_is_withheld_after_real_session_expiry() {
    fixture_step(Box::pin(owned_consumer_blob_two_chunk_expiry_scenario())).await;
}

// This uses the original exact-token issuer HTTP transport, DPoP and the
// full standard resource router. It proves an authority failure is distinct
// from an invalid/expired holder, without copying authority into the fixture.
async fn owned_consumer_blob_issuer_unavailable_scenario() {
    let fixture = boxed_owned_consumer_fixture(1).await;
    let http = Box::pin(owned_consumer_http_fixture(&fixture)).await;
    let original = b"accepted attachment withheld on unavailable authority";
    let (reference, source) = Box::pin(owned_consumer_blob_source(&fixture, &http, original)).await;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("blob_ref", reference.as_str())
        .append_pair("realm_id", source.event.realm_id.as_str())
        .append_pair("purpose", "message_attachment")
        .finish();
    let path = format!("/_arkret/self/blob/get?{query}");
    let mut baseline = Box::pin(owned_consumer_http_blob_request(&http, &path, false, None)).await;
    owned_consumer_assert_http_status(
        &mut baseline,
        salvo::http::StatusCode::OK,
        "blob_authority_available",
    )
    .await;
    assert!(
        owned_consumer_take_response_bytes(&mut baseline)
            .await
            .unwrap()
            .as_ref()
            == original
    );
    let before = owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await;
    // Blob GET permits a fresh cached introspection result. Use a separate
    // genuinely issued fixture credential that has never been introspected,
    // with the same accepted Actor/key/scope and original serving Station.
    // Do not mutate or bypass the production cache/freshness contract.
    let unavailable = Box::pin(owned_consumer_http_fixture(&fixture)).await;
    assert!(unavailable.token != http.token);
    assert!(unavailable.delivery_session_scope == http.delivery_session_scope);
    assert!(unavailable.base_url == http.base_url);
    unavailable
        .issuer_status
        .store(503, std::sync::atomic::Ordering::SeqCst);
    for head in [false] {
        let mut response = Box::pin(owned_consumer_http_blob_request(
            &unavailable,
            &path,
            head,
            None,
        ))
        .await;
        assert_eq!(
            response.status_code,
            Some(salvo::http::StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(
            response
                .headers()
                .get(salvo::http::header::RETRY_AFTER)
                .unwrap(),
            "1"
        );
        if !head {
            let body = owned_consumer_take_response_bytes(&mut response)
                .await
                .unwrap();
            assert!(!body.windows(original.len()).any(|bytes| bytes == original));
            let problem: arkret_wire::Problem = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                problem.error_code(),
                Some(arkret_wire::error_codes::ErrorCode::TemporarilyUnavailable)
            );
            assert!(!problem.extensions.contains_key("event"));
            assert!(!problem.extensions.contains_key("commit"));
            assert!(!problem.extensions.contains_key("cursor"));
        } else {
            assert!(
                owned_consumer_take_response_bytes(&mut response)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(before == owned_consumer_footprint(&fixture.pool, &source.event.realm_id).await);
    }
}
#[tokio::test]
async fn owned_agent_blob_authority_dependency_failure_preserves_503_and_yields_no_bytes() {
    fixture_step(Box::pin(owned_consumer_blob_issuer_unavailable_scenario())).await;
}

async fn native_reply_human_scoped_request(
    pool: &coland_storage_postgres::PgPool,
    template: &coland_storage::AuthorityCommitTransaction,
    previous: Option<&coland_storage::AuthorityCommitTransaction>,
    kind: EventKind,
    scope: arkret_wire::ScopeRef,
    actor: arkret_wire::ActorId,
    payload: serde_json::Value,
) -> coland_storage::EventCommitRequest {
    let at = previous.unwrap_or(template).commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let event = ordinary_realm::event_for_actor(kind, scope.clone(), actor, payload, at);
    let mut request = ordinary_realm::request_for_event(template, event, at);
    request.authority_commit.commit.stream_ref =
        arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap();
    request.authority_commit.commit.stream_position =
        previous.map(|p| p.commit.stream_position + 1).unwrap_or(0);
    request.authority_commit.commit.previous_commit_ref =
        previous.map(|p| p.commit.commit_id.clone());
    Box::pin(ordinary_realm::source_request(pool, request)).await
}

async fn native_reply_key_revoke_request(
    fixture: &NativeReplyPreparationFixture,
) -> coland_storage::AgentControlAdmissionWrite {
    let agent = &fixture.original.agents[0];
    let store = PgAuthorityCommitStore {
        pool: fixture.original.pool.clone(),
    };
    let key = store
        .committed_event(&agent.endpoint.authorization_ref.event_id)
        .await
        .unwrap()
        .unwrap();
    let at = chrono::Utc::now().max(key.commit.committed_at + chrono::TimeDelta::milliseconds(1));
    let payload = arkret_models_collaboration::events_payloads::agent::AgentKeyRevokePayload {
        agent_id: agent.account.principal_id.clone(),
        key_id: arkret_wire::NonEmptyString::new(agent.endpoint.verification_method.as_str())
            .unwrap(),
        revoked_by: fixture
            .original
            .controller
            .history
            .account
            .principal_id
            .clone(),
        revoked_at: at,
        reason: None,
    };
    let mut event = ordinary_realm::event_for_actor(
        EventKind::AgentKeyRevoke,
        arkret_wire::ScopeRef::Realm {
            realm_id: agent.endpoint.pcr_realm_id.clone(),
        },
        arkret_wire::ActorId::account(agent.account.clone()),
        serde_json::to_value(payload).unwrap(),
        at,
    );
    event.executed_by = key.event.executed_by.clone();
    event.authorization_ref = key.event.authorization_ref.clone();
    let event = device_authorization_history::sign_event(
        event,
        fixture
            .original
            .controller
            .history
            .device_verification_method
            .clone(),
        fixture
            .original
            .controller
            .history
            .founding_device_signing_seed,
    );
    let commit = sidecar_agent::station_successor(
        &key.commit,
        &event,
        &fixture.original.station.did,
        (at - key.commit.committed_at)
            .num_seconds()
            .saturating_add(1)
            .max(1),
    );
    let authority = store
        .current_authority(&agent.endpoint.pcr_realm_id)
        .await
        .unwrap()
        .unwrap();
    coland_storage::AgentControlAdmissionWrite {
        commit: coland_storage::AuthorityCommitTransaction {
            expected_authority: authority,
            event,
            commit: commit.clone(),
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
        queued_at: commit.committed_at,
    }
}

async fn native_reply_key_revoke_step(
    pool: coland_storage_postgres::PgPool,
    request: coland_storage::AgentControlAdmissionWrite,
) -> coland_storage::PersistenceResult<coland_storage::AgentControlAdmissionOutcome> {
    fixture_step(async move {
        Box::pin(historical_control_source::admit_control(
            &coland_storage_postgres::PgActorProfileStore { pool: pool.clone() },
            &pool,
            request,
        ))
        .await
    })
    .await
}

// These supplementary native tests reuse real accepted control/content history
// and the original exact-token issuer fixture. The AA helper explicitly imports
// signed native fixture records; it is not normal Coauth issuance evidence.
// No provider runs here. Main's physical provider/journal boundary has its own
// acceptance obligations, independent of these PostgreSQL preparation tests.
struct NativeReplyPreparationFixture {
    original: OwnedConsumerFixture,
    _http: OwnedConsumerHttpFixture,
    head: coland_storage::AuthorityCommitTransaction,
    strand: arkret_wire::StrandId,
    source: arkret_wire::CommittedEventFullView,
    input: coland_storage::AccountContentDeliveryInput,
}

async fn native_reply_preparation_fixture(
    controller_constraints: Option<serde_json::Value>,
    grant_message: bool,
    lifetime: chrono::TimeDelta,
) -> NativeReplyPreparationFixture {
    Box::pin(native_reply_preparation_fixture_in_scope(
        controller_constraints,
        grant_message,
        lifetime,
        false,
    ))
    .await
}

async fn native_reply_preparation_fixture_in_scope(
    controller_constraints: Option<serde_json::Value>,
    grant_message: bool,
    lifetime: chrono::TimeDelta,
    in_circle: bool,
) -> NativeReplyPreparationFixture {
    Box::pin(native_reply_preparation_fixture_with_body(
        controller_constraints,
        grant_message,
        lifetime,
        in_circle,
        true,
    ))
    .await
}

async fn native_reply_preparation_fixture_with_body(
    controller_constraints: Option<serde_json::Value>,
    grant_message: bool,
    lifetime: chrono::TimeDelta,
    in_circle: bool,
    grant_body: bool,
) -> NativeReplyPreparationFixture {
    use coland_storage::AgentParticipationStore;
    let original = boxed_owned_consumer_fixture(1).await;
    let realm = original.head.event.realm_id.clone();
    let mut head = original.head.clone();
    if grant_message {
        for actor in [
            arkret_wire::ActorId::account(original.controller.history.account.clone()),
            arkret_wire::ActorId::account(original.agents[0].account.clone()),
        ] {
            let constraints = if actor.as_account_id() == Some(&original.controller.history.account)
            {
                controller_constraints.clone()
            } else {
                None
            };
            let request = Box::pin(owned_consumer_root_grant(
                &original,
                &head,
                &actor,
                &["ak.message.create", "ak.circle.member.add"],
                serde_json::json!([{"kind":"realm","realm_id":realm}]),
                constraints,
            ))
            .await;
            fixture_commit_step(&original.pool, request.clone())
                .await
                .unwrap();
            head = request.authority_commit;
        }
    }
    if grant_body {
        for actor in [
            arkret_wire::ActorId::account(original.controller.history.account.clone()),
            arkret_wire::ActorId::account(original.agents[0].account.clone()),
        ] {
            let request = Box::pin(owned_consumer_root_grant(
                &original,
                &head,
                &actor,
                &[arkret_wire::CapabilityActionId::ObjectReadContent.as_str()],
                serde_json::json!([{"kind":"realm","realm_id":realm}]),
                None,
            ))
            .await;
            fixture_commit_step(&original.pool, request.clone())
                .await
                .unwrap();
            head = request.authority_commit;
        }
    }
    assert!(
        coland_storage_postgres::PgAgentParticipationStore {
            pool: original.pool.clone(),
        }
        .compare_and_swap_selection(
            serde_json::json!({"agent_id":original.agents[0].account.principal_id,
            "scope_kind":"realm","scope_key":format!("realm:{realm}"),
            "realm_id":realm,"scope":{"kind":"realm","realm_id":realm},
            "version":2,"reply_message":true,"reaction_add":false,
            "reaction_remove":false,"accept_third_party_mention":true,
            "act_on_behalf":false}),
            1,
        )
        .await
        .unwrap()
    );
    let mut effective_scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    if in_circle {
        let at = head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
        let create = Box::pin(ordinary_realm::source_request(&original.pool,
            ordinary_realm::next_request_for_actor(&head,EventKind::CircleCreate,
                arkret_wire::ActorId::account(original.founder.clone()),
                serde_json::json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
                    "title":"Native exact Circle reply","display":{"short_name":"Reply","color_token":"blue","symbol":{"glyph":"lock"}},
                    "directory_visibility":"members","join_rule":"public","history_access":"since_join",
                    "state":"active","created_by":arkret_wire::ActorId::account(original.founder.clone()),
                    "created_at":arkret_canonical::format_timestamp_canonical(at)}}),at))).await;
        fixture_commit_step(&original.pool, create.clone())
            .await
            .unwrap();
        head = create.authority_commit;
        let circle = arkret_wire::CircleId::from_event_id(&head.event.event_id);
        effective_scope = arkret_wire::ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle.clone(),
        };
        let mut circle_head: Option<coland_storage::AuthorityCommitTransaction> = None;
        for account in [
            &original.founder,
            &original.controller.history.account,
            &original.agents[0].account,
        ] {
            let actor = arkret_wire::ActorId::account(account.clone());
            let parent = Box::pin(ordinary_realm::parent_membership_revision(
                &original.pool,
                &realm,
                &actor,
            ))
            .await;
            let payload = serde_json::json!({"circle_id":circle,"member_id":actor,"membership":"join",
                "expected_membership":null,"parent_membership_revision":parent});
            let request = if account == &original.agents[0].account {
                let previous = circle_head.as_ref().unwrap();
                Box::pin(ordinary_realm::source_request(
                    &original.pool,
                    owned_consumer_signed_request(
                        previous,
                        &original.agents[0],
                        EventKind::CircleMemberState,
                        effective_scope.clone(),
                        payload,
                        previous.commit.committed_at + chrono::TimeDelta::milliseconds(1),
                    ),
                ))
                .await
            } else {
                Box::pin(native_reply_human_scoped_request(
                    &original.pool,
                    &head,
                    circle_head.as_ref(),
                    EventKind::CircleMemberState,
                    effective_scope.clone(),
                    actor,
                    payload,
                ))
                .await
            };
            fixture_commit_step(&original.pool, request.clone())
                .await
                .unwrap();
            circle_head = Some(request.authority_commit);
        }
        head = circle_head.unwrap();
    }
    let at = head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let strand_request = Box::pin(ordinary_realm::source_request(
        &original.pool,
        ordinary_realm::next_request_for_actor(
            &head,
            EventKind::StrandCreate,
            arkret_wire::ActorId::account(original.founder.clone()),
            serde_json::json!({"object":{"schema":"ak.schema.strand.v1",
                "realm_id":realm,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":"Native public reply input"},"state":"active",
                "created_by":arkret_wire::ActorId::account(original.founder.clone()),
                "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        ),
    ))
    .await;
    let strand_request = if in_circle {
        Box::pin(native_reply_human_scoped_request(
            &original.pool,
            &head,
            Some(&head),
            EventKind::StrandCreate,
            effective_scope.clone(),
            arkret_wire::ActorId::account(original.founder.clone()),
            serde_json::to_value(&strand_request.authority_commit.event.payload).unwrap(),
        ))
        .await
    } else {
        strand_request
    };
    fixture_commit_step(&original.pool, strand_request.clone())
        .await
        .unwrap();
    let strand =
        arkret_wire::StrandId::from_event_id(&strand_request.authority_commit.event.event_id);
    let message = Box::pin(ordinary_realm::source_request(
        &original.pool,
        ordinary_realm::next_request_for_actor(
            &strand_request.authority_commit,
            EventKind::MessageCreate,
            arkret_wire::ActorId::account(original.founder.clone()),
            ordinary_realm::message_payload(&strand, "Accepted third-party native reply source"),
            at + chrono::TimeDelta::milliseconds(1),
        ),
    ))
    .await;
    let message = if in_circle {
        Box::pin(native_reply_human_scoped_request(
            &original.pool,
            &strand_request.authority_commit,
            Some(&strand_request.authority_commit),
            EventKind::MessageCreate,
            effective_scope,
            arkret_wire::ActorId::account(original.founder.clone()),
            ordinary_realm::message_payload(&strand, "Accepted third-party native reply source"),
        ))
        .await
    } else {
        message
    };
    fixture_commit_step(&original.pool, message.clone())
        .await
        .unwrap();
    let source = PgAuthorityCommitStore {
        pool: original.pool.clone(),
    }
    .committed_event(&message.authority_commit.event.event_id)
    .await
    .unwrap()
    .unwrap();
    let source = arkret_wire::CommittedEventFullView {
        event: source.event,
        commit: source.commit,
    };
    source.validate_shape().unwrap();
    assert_eq!(
        source.event.event_id,
        message.authority_commit.event.event_id
    );
    assert_eq!(
        source.commit.commit_id,
        message.authority_commit.commit.commit_id
    );
    assert_eq!(
        source.event.actor_id.as_account_id(),
        Some(&original.founder)
    );
    let agent = &original.agents[0];
    let http = Box::pin(owned_consumer_http_for_endpoint_with_storage(
        &original.pool,
        &original.station,
        &original.controller.history.account,
        &realm,
        &agent.account,
        &agent.endpoint,
        &agent._vault,
        None,
        lifetime,
        None,
    ))
    .await;
    let mut response = Box::pin(owned_consumer_http_get(
        &http,
        &format!("/_arkret/self/committed-events/{}", source.event.event_id),
        "ak.self.committed_event.resource.get.v1",
    ))
    .await;
    owned_consumer_assert_http_status(
        &mut response,
        salvo::http::StatusCode::OK,
        "native_reply_exact_input_authenticated_baseline",
    )
    .await;
    let delivered =
        owned_consumer_take_response_json::<arkret_wire::CommittedEventView>(&mut response)
            .await
            .unwrap();
    assert!(
        delivered == arkret_wire::CommittedEventView::Full(source.clone()),
        "normal DPoP route returns the same complete accepted source before native preparation"
    );
    let evidence = Box::pin(http.state.qualified_agent_scope_evidence(&agent.endpoint))
        .await
        .unwrap();
    let observed = Box::pin(management_current_for_accounts(
        &original.pool,
        &original.station,
        &[
            original.controller.history.account.clone(),
            original.founder.clone(),
        ],
    ))
    .await;
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![realm],
        committed_events: vec![arkret_wire::CommittedEventView::Full(source.clone())],
        agent_endpoint: Some(agent.endpoint.clone()),
        qualified_agent_scope_evidence: Some(evidence),
        credential_expires_at: Some(http.grant_expires_at),
        agent_session_scope: Some(http.delivery_session_scope.clone()),
        account_status_observations: observed.observations,
        ..Default::default()
    };
    NativeReplyPreparationFixture {
        original,
        _http: http,
        head: message.authority_commit,
        strand,
        source,
        input,
    }
}

fn native_reply_preparation_step(
    fixture: &NativeReplyPreparationFixture,
    input: &coland_storage::AccountContentDeliveryInput,
    deployment: arkret_models_collaboration::governance::agent_participation::ParticipationBits,
) -> Pin<
    Box<
        dyn Future<
                Output = coland_storage::PersistenceResult<
                    Box<dyn coland_storage::AccountContentDeliveryGuard>,
                >,
            > + Send,
    >,
> {
    let pool = fixture.original.pool.clone();
    let agent = fixture.original.agents[0].account.clone();
    let controller = fixture.original.controller.history.account.clone();
    let caller = fixture.original.founder.clone();
    let station = fixture.original.station.core.clone();
    let source = fixture.source.clone();
    let strand = fixture.strand.clone();
    let input = input.clone();
    Box::pin(async move {
        fixture_step(async move {
            PgAuthorityCommitStore { pool }
                .acquire_native_message_reply_preparation(
                    coland_storage::NativeMessageReplyPreparation {
                        agent: &agent,
                        controller: &controller,
                        caller: &caller,
                        station: &station,
                        source: &source,
                        strand: &strand,
                        input: &input,
                        deployment,
                    },
                )
                .await
        })
        .await
    })
}

async fn native_reply_refused_unchanged(
    fixture: &NativeReplyPreparationFixture,
    input: &coland_storage::AccountContentDeliveryInput,
    deployment: arkret_models_collaboration::governance::agent_participation::ParticipationBits,
) {
    let realm = &fixture.source.event.realm_id;
    let before = owned_consumer_footprint(&fixture.original.pool, realm).await;
    let result = native_reply_preparation_step(fixture, input, deployment).await;
    assert!(
        result.is_err(),
        "native authoring must not return a provider preparation guard"
    );
    drop(result);
    assert!(before == owned_consumer_footprint(&fixture.original.pool, realm).await);
}

async fn native_reply_policy_deny(fixture: &NativeReplyPreparationFixture, operation: &str) {
    let at = fixture.head.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let policy = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let request = Box::pin(ordinary_realm::source_request(&fixture.original.pool,
        ordinary_realm::next_request_for_actor(&fixture.head, EventKind::PolicySet,
            arkret_wire::ActorId::account(fixture.original.founder.clone()),
            serde_json::json!({"policy_id":policy,"expected_revision":null,
                "value":{"schema":"ak.schema.policy.v1","id":policy,
                    "realm_id":fixture.source.event.realm_id,"policy_kind":"agent",
                    "default_effect":"allow",
                    "created_by":arkret_wire::ActorId::account(fixture.original.founder.clone()),
                    "created_at":arkret_canonical::format_timestamp_canonical(at),
                    "rules":[{"rule_id":"native_reply_current_deny","kind":"agent","effect":"deny",
                        "agent_target":{"kind":"controller","controller_account_id":fixture.original.controller.history.account},
                        "agent_operations":[operation]}]}}), at))).await;
    fixture_commit_step(&fixture.original.pool, request)
        .await
        .unwrap();
}

#[tokio::test]
async fn native_public_reply_unreserved_guard_uses_exact_accepted_source() {
    use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
    fixture_step(async {
        let fixture = Box::pin(native_reply_preparation_fixture(
            None,
            true,
            chrono::TimeDelta::hours(1),
        ))
        .await;
        let before =
            owned_consumer_footprint(&fixture.original.pool, &fixture.source.event.realm_id).await;
        let guard = native_reply_preparation_step(&fixture, &fixture.input, ParticipationBits::ALL)
            .await
            .unwrap();
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        assert!(
            before
                == owned_consumer_footprint(&fixture.original.pool, &fixture.source.event.realm_id)
                    .await
        );
        let mut substituted = fixture.input.clone();
        substituted.committed_events.clear();
        native_reply_refused_unchanged(&fixture, &substituted, ParticipationBits::ALL).await;
        let accepted = PgAuthorityCommitStore {
            pool: fixture.original.pool.clone(),
        }
        .committed_event(&fixture.source.event.event_id)
        .await
        .unwrap()
        .unwrap();
        let accepted = arkret_wire::CommittedEventFullView {
            event: accepted.event,
            commit: accepted.commit,
        };
        accepted.validate_shape().unwrap();
        assert!(
            accepted == fixture.source,
            "the source remains the original complete accepted Event/Commit"
        );
        let revised = Box::pin(native_reply_human_scoped_request(
            &fixture.original.pool, &fixture.head, Some(&fixture.head),
            EventKind::MessageRevise, fixture.source.event.scope_ref.clone(),
            arkret_wire::ActorId::account(fixture.original.founder.clone()),
            serde_json::json!({"message_id":arkret_wire::MessageId::from_event_id(&fixture.source.event.event_id),
                "content":{"kind":"ak.content.text","body":"Current accepted replacement","format":"plain"}}),
        )).await;
        fixture_commit_step(&fixture.original.pool, revised).await.unwrap();
        // The original accepted Create and issuer material are unchanged;
        // the authoritative Message current now covers a different revision.
        native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
        let circle = Box::pin(native_reply_preparation_fixture_in_scope(
            None,
            true,
            chrono::TimeDelta::hours(1),
            true,
        ))
        .await;
        assert!(matches!(
            circle.source.event.scope_ref,
            arkret_wire::ScopeRef::Circle { .. }
        ));
        let guard = native_reply_preparation_step(&circle, &circle.input, ParticipationBits::ALL)
            .await
            .unwrap();
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn native_public_reply_quota_or_unknown_future_fields_never_consume() {
    use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
    fixture_step(async {
        for constraints in [
            serde_json::json!([{"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow",
                "max_operations":1,"period":"P1D","constraint_scope":"per_realm"}]),
            serde_json::json!([{"constraint_kind":"field_access","effect":"allow","allowed_write_fields":["metadata.title"]}]),
        ] {
            let fixture = Box::pin(native_reply_preparation_fixture(Some(constraints), true, chrono::TimeDelta::hours(1))).await;
            let footprint = owned_consumer_footprint(&fixture.original.pool, &fixture.source.event.realm_id).await;
            assert_eq!(footprint["extra"]["quota"], serde_json::json!([]));
            assert_eq!(footprint["extra"]["quota_consumptions"], serde_json::json!([]));
            native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
        }
        let fixture=Box::pin(native_reply_preparation_fixture(None,true,chrono::TimeDelta::hours(1))).await;
        let guard=native_reply_preparation_step(&fixture,&fixture.input,ParticipationBits::ALL).await.unwrap();
        assert!(guard.permits_handoff());guard.finish().await.unwrap();
        let denying=Box::pin(owned_consumer_root_grant(&fixture.original,&fixture.head,
            &arkret_wire::ActorId::account(fixture.original.controller.history.account.clone()),
            &["ak.message.create"],serde_json::json!([{"kind":"realm","realm_id":fixture.source.event.realm_id}]),
            Some(serde_json::json!([{"constraint_kind":"scope_limitation","effect":"deny",
                "denied_strand_ids":[fixture.strand]}])))).await;
        fixture_commit_step(&fixture.original.pool,denying).await.unwrap();
        native_reply_refused_unchanged(&fixture,&fixture.input,ParticipationBits::ALL).await;
    }).await;
}

#[tokio::test]
async fn native_public_reply_execute_serve_and_public_participation_are_independent() {
    use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
    use coland_storage::AgentParticipationStore;
    fixture_step(async {
        for operation in ["execute", "serve"] {
            let fixture = Box::pin(native_reply_preparation_fixture(None, true, chrono::TimeDelta::hours(1))).await;
            let guard = native_reply_preparation_step(&fixture, &fixture.input, ParticipationBits::ALL).await.unwrap();
            assert!(guard.permits_handoff()); guard.finish().await.unwrap();
            native_reply_policy_deny(&fixture, operation).await;
            native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
        }
        let fixture = Box::pin(native_reply_preparation_fixture(None, true, chrono::TimeDelta::hours(1))).await;
        let mut deployment = ParticipationBits::ALL;
        deployment.accept_third_party_mention = false;
        native_reply_refused_unchanged(&fixture, &fixture.input, deployment).await;
        let realm = &fixture.source.event.realm_id;
        assert!(coland_storage_postgres::PgAgentParticipationStore { pool: fixture.original.pool.clone() }
            .compare_and_swap_selection(serde_json::json!({"agent_id":fixture.original.agents[0].account.principal_id,
                "scope_kind":"realm","scope_key":format!("realm:{realm}"),"realm_id":realm,
                "scope":{"kind":"realm","realm_id":realm},"version":3,"reply_message":false,
                "reaction_add":false,"reaction_remove":false,"accept_third_party_mention":true,"act_on_behalf":false}),2)
            .await.unwrap());
        native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
        assert!(coland_storage_postgres::PgAgentParticipationStore {pool:fixture.original.pool.clone()}
            .compare_and_swap_selection(serde_json::json!({"agent_id":fixture.original.agents[0].account.principal_id,
                "scope_kind":"realm","scope_key":format!("realm:{realm}"),"realm_id":realm,
                "scope":{"kind":"realm","realm_id":realm},"version":4,"reply_message":true,
                "reaction_add":false,"reaction_remove":false,"accept_third_party_mention":true,"act_on_behalf":false}),3)
            .await.unwrap());
        let restored=native_reply_preparation_step(&fixture,&fixture.input,ParticipationBits::ALL).await.unwrap();
        assert!(restored.permits_handoff());restored.finish().await.unwrap();
        let guard = Box::pin(fixture.original.controller.admit_founding_device(
            &PgPersistenceStore::new(fixture.original.pool.clone()))).await.unwrap();
        let request = Box::pin(ordinary_realm::source_request(&fixture.original.pool,
            agent_mode_request(&fixture.head, "private", Some(arkret_wire::CurrentRevision {
                commit_id:fixture.original.head.commit.commit_id.clone(),
                stream_position:fixture.original.head.commit.stream_position,
            }), &fixture.original.controller, &fixture.original.agents[0].account, &guard))).await;
        fixture_commit_step(&fixture.original.pool, request).await.unwrap();
        native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
    }).await;
}

#[tokio::test]
async fn native_public_reply_caller_membership_and_controller_upper_bound_are_required() {
    use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
    fixture_step(async {
        let no_body = Box::pin(native_reply_preparation_fixture_with_body(
            None, true, chrono::TimeDelta::hours(1), false, false,
        )).await;
        // The exact original Event GET already succeeded in setup and the
        // MessageCreate grant exists. Neither substitutes for body permission.
        native_reply_refused_unchanged(&no_body, &no_body.input, ParticipationBits::ALL).await;
        let denied = Box::pin(native_reply_preparation_fixture(None, false, chrono::TimeDelta::hours(1))).await;
        native_reply_refused_unchanged(&denied, &denied.input, ParticipationBits::ALL).await;
        let fixture = Box::pin(native_reply_preparation_fixture(None, true, chrono::TimeDelta::hours(1))).await;
        let guard = native_reply_preparation_step(&fixture, &fixture.input, ParticipationBits::ALL).await.unwrap();
        assert!(guard.permits_handoff()); guard.finish().await.unwrap();
        let leave = Box::pin(ordinary_realm::source_request(&fixture.original.pool,
            ordinary_realm::next_request_for_actor(&fixture.head, EventKind::MemberState,
                arkret_wire::ActorId::account(fixture.original.founder.clone()),
                serde_json::json!({"member_id":arkret_wire::ActorId::account(fixture.original.founder.clone()),"membership":"leave"}),
                fixture.head.commit.committed_at+chrono::TimeDelta::milliseconds(1)))).await;
        fixture_commit_step(&fixture.original.pool, leave).await.unwrap();
        native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
    }).await;
}

#[tokio::test]
async fn native_public_reply_real_session_expiry_and_accepted_key_revoke_close_handoff() {
    use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
    fixture_step(async {
        let fixture = Box::pin(native_reply_preparation_fixture(
            None,
            true,
            chrono::TimeDelta::seconds(10),
        ))
        .await;
        let guard = native_reply_preparation_step(&fixture, &fixture.input, ParticipationBits::ALL)
            .await
            .unwrap();
        assert!(guard.permits_handoff());
        let duration = (fixture._http.grant_expires_at - chrono::Utc::now())
            .to_std()
            .unwrap_or_default();
        tokio::time::sleep(duration + std::time::Duration::from_millis(1)).await;
        assert!(
            !guard.permits_handoff(),
            "the original issuer grant really expired while the cut was held"
        );
        guard.finish().await.unwrap();
        native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
        let fixture = Box::pin(native_reply_preparation_fixture(
            None,
            true,
            chrono::TimeDelta::hours(1),
        ))
        .await;
        let live = native_reply_preparation_step(&fixture, &fixture.input, ParticipationBits::ALL)
            .await
            .unwrap();
        assert!(live.permits_handoff());
        live.finish().await.unwrap();
        let request = native_reply_key_revoke_request(&fixture).await;
        native_reply_key_revoke_step(fixture.original.pool.clone(), request)
            .await
            .unwrap();
        native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
    })
    .await;
}

#[tokio::test]
async fn native_public_reply_guard_holds_actual_writer_until_finish_or_cancel() {
    use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
    use diesel::sql_types::BigInt;
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Pid {
        #[diesel(sql_type=BigInt)]
        number: i64,
    }
    fixture_step(async {
        // Original PCR lock contention must refuse without waiting while
        // the business cut is held. No caller/owner PCR proof is skipped.
        let contended = Box::pin(native_reply_preparation_fixture(None,true,chrono::TimeDelta::hours(1))).await;
        let mut blocker = contended.original.pool.get().await.unwrap();
        diesel::sql_query("BEGIN").execute(&mut *blocker).await.unwrap();
        diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
            .bind::<diesel::sql_types::Text,_>(contended.original.controller.unit.transactions[0].event.realm_id.as_str())
            .execute(&mut *blocker).await.unwrap();
        let error = match native_reply_preparation_step(&contended,&contended.input,ParticipationBits::ALL).await {
            Err(error) => error,
            Ok(guard) => {drop(guard);panic!("PCR contention cannot return an unheld authority guard");}
        };
        assert!(matches!(error,coland_storage::PersistenceError::Conflict(ref code)
            if code.starts_with("revision_unavailable:")));
        let mut probe = contended.original.pool.get().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                diesel::sql_query("BEGIN").execute(&mut *probe).await.unwrap();
                let released = diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE NOWAIT")
                    .bind::<diesel::sql_types::Text,_>(contended.source.event.realm_id.as_str())
                    .execute(&mut *probe).await.is_ok();
                diesel::sql_query("ROLLBACK").execute(&mut *probe).await.unwrap();
                if released {break;}
                tokio::task::yield_now().await;
            }
        }).await.expect("refused acquire releases the complete business cut");
        diesel::sql_query("ROLLBACK").execute(&mut *blocker).await.unwrap();
        drop(probe);drop(blocker);
        let guard = native_reply_preparation_step(&contended,&contended.input,ParticipationBits::ALL).await.unwrap();
        assert!(guard.permits_handoff());guard.finish().await.unwrap();
        for (cancel,pcr_writer) in [(false,false),(true,false),(false,true),(true,true)] {

            let fixture = Box::pin(native_reply_preparation_fixture(None, true, chrono::TimeDelta::hours(1))).await;
            let leave = Box::pin(ordinary_realm::source_request(&fixture.original.pool,
                ordinary_realm::next_request_for_actor(&fixture.head,EventKind::MemberState,
                    arkret_wire::ActorId::account(fixture.original.controller.history.account.clone()),
                    serde_json::json!({"member_id":arkret_wire::ActorId::account(fixture.original.controller.history.account.clone()),"membership":"leave"}),
                    fixture.head.commit.committed_at+chrono::TimeDelta::milliseconds(1)))).await;
            let revoke = native_reply_key_revoke_request(&fixture).await;
            let guard = native_reply_preparation_step(&fixture, &fixture.input, ParticipationBits::ALL).await.unwrap();
            assert!(guard.permits_handoff());
            let mut conn = fixture.original.pool.get().await.unwrap();
            let holders = diesel::sql_query("SELECT DISTINCT pid::bigint AS number FROM pg_locks WHERE locktype='advisory' AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
                .load::<Pid>(&mut *conn).await.unwrap();
            assert!(!holders.is_empty());
            let pool = fixture.original.pool.clone();
            let writer = tokio::spawn(async move {
                if pcr_writer {native_reply_key_revoke_step(pool,revoke).await.unwrap();}
                else {fixture_commit_step(&pool,leave).await.unwrap();}
            });
            struct Cancel(tokio::task::AbortHandle);
            impl Drop for Cancel {fn drop(&mut self) {self.0.abort();}}
            let _cancel = Cancel(writer.abort_handle());
            tokio::time::timeout(std::time::Duration::from_secs(5),async {
                loop {
                    let mut blocked = false;
                    for holder in &holders {
                        let waiting = diesel::sql_query("SELECT COUNT(*)::bigint AS number FROM pg_stat_activity s WHERE $1::bigint::integer=ANY(pg_blocking_pids(s.pid)) AND s.wait_event_type='Lock' AND s.query LIKE '%FROM realm_authorities WHERE realm_id=$1 FOR UPDATE%' AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=s.pid AND l.locktype IN ('tuple','transactionid') AND NOT l.granted)")
                            .bind::<BigInt,_>(holder.number).get_result::<Pid>(&mut *conn).await.unwrap();
                        blocked |= waiting.number>0;
                    }
                    if blocked {break;}
                    assert!(!writer.is_finished()); tokio::task::yield_now().await;
                }
            }).await.expect("actual current writer waits for the original native preparation holder");
            assert!(!writer.is_finished()); assert!(guard.permits_handoff()); drop(conn);
            if cancel {drop(guard);} else {guard.finish().await.unwrap();}
            tokio::time::timeout(std::time::Duration::from_secs(5),writer).await.unwrap().unwrap();
            native_reply_refused_unchanged(&fixture, &fixture.input, ParticipationBits::ALL).await;
        }
    }).await;
}
