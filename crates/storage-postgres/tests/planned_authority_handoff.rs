//! Planned handoff freezing, complete import and historical Snapshot reads on PG.
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/historical_human.rs"]
mod historical_human;

use arkret_models_collaboration::authority_commit::{
    HistoricalProducerSignerFactEntry, historical_signer_facts_digest,
};
use arkret_wire::{ActorId, DetachedSignatureContext, EventKind, RealmCommitAuthorityRef};
use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork, SelfProducerCommitGuard};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use historical_human::{HumanFixture, ordinary_realm};

async fn request(
    fixture: &HumanFixture,
    pool: &PgPool,
    previous: &coland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    payload: serde_json::Value,
) -> coland_storage::EventCommitRequest {
    let at = previous.commit.committed_at + chrono::TimeDelta::seconds(1);
    let raw = ordinary_realm::next_request_for_actor(
        previous,
        kind,
        ActorId::account(fixture.pcr.history.account.clone()),
        payload,
        at,
    );
    let event = device_authorization_history::sign_event(
        raw.authority_commit.event,
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let mut request = ordinary_realm::request_for_event(previous, event, at);
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request.self_producer_guard = Some(SelfProducerCommitGuard::HumanDevice(fixture.guard.clone()));
    ordinary_realm::source_request(pool, request).await
}

async fn inventory(
    store: &PgAuthorityCommitStore,
    realm: &arkret_wire::RealmId,
) -> Vec<HistoricalProducerSignerFactEntry> {
    let mut entries = Vec::new();
    for full in store.handoff_originals(realm).await.unwrap() {
        if full.commit.producer_signer_fact_digest.is_some() {
            entries.push(HistoricalProducerSignerFactEntry {
                target: arkret_wire::CommittedEventRef {
                    event_id: full.event.event_id.clone(),
                    commit_id: full.commit.commit_id.clone(),
                    stream_ref: full.commit.stream_ref.clone(),
                    stream_position: full.commit.stream_position,
                },
                producer_signer_fact: store
                    .producer_signer_fact(&full.event, &full.commit)
                    .await
                    .unwrap()
                    .unwrap(),
            });
        }
    }
    entries.sort_by_key(|entry| {
        (
            arkret_canonical::canonical_json_bytes(&entry.target.stream_ref).unwrap(),
            entry.target.stream_position,
            entry.target.event_id.to_string(),
            entry.target.commit_id.to_string(),
        )
    });
    entries
}

#[tokio::test]
async fn every_stream_checks_genesis_successors_and_cross_stream_predecessors() {
    // This is the PG append boundary, after the caller's domain admission.
    // It does not assert Circle/Sidecar membership or plaintext eligibility.
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = Box::pin(HumanFixture::new(
        &pool,
        "did:web:stream-chain.example".parse().unwrap(),
    ))
    .await;
    Box::pin(fixture.admit(&pool)).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let realm_tail = fixture.unit.transactions.last().unwrap().clone();
    let pcr_tail = fixture.pcr.unit.transactions.last().unwrap().clone();
    let circle = arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [61; 32],
    ));
    let sidecar = arkret_wire::SidecarId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [62; 32],
    ));
    let pcr_foreign = pcr_tail.commit.commit_id.clone();
    let cases = [
        (
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_tail.event.realm_id.clone(),
            },
            realm_tail.clone(),
            true,
        ),
        (
            arkret_wire::ScopeRef::Circle {
                realm_id: realm_tail.event.realm_id.clone(),
                circle_id: circle,
            },
            realm_tail.clone(),
            false,
        ),
        (
            arkret_wire::ScopeRef::Sidecar {
                realm_id: realm_tail.event.realm_id.clone(),
                sidecar_id: sidecar,
            },
            realm_tail.clone(),
            false,
        ),
        (
            arkret_wire::ScopeRef::Realm {
                realm_id: pcr_tail.event.realm_id.clone(),
            },
            pcr_tail,
            true,
        ),
    ];
    for (scope, mut previous, held) in cases {
        let foreign = if previous.event.realm_id == realm_tail.event.realm_id {
            pcr_foreign.clone()
        } else {
            realm_tail.commit.commit_id.clone()
        };
        let stream = arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap();
        for offset in 0..2 {
            let at = previous.commit.committed_at + chrono::TimeDelta::seconds(1);
            let raw = ordinary_realm::event_for_actor(
                EventKind::MessageCreate,
                scope.clone(),
                ActorId::account(fixture.pcr.history.account.clone()),
                serde_json::json!({
                    "strand_id":arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[63;32])),
                    "track_name":"discussion","content":{"kind":"ak.content.text","body":"append boundary","format":"plain"}
                }),
                at,
            );
            let event = device_authorization_history::sign_event(
                raw,
                fixture.pcr.history.device_verification_method.clone(),
                fixture.pcr.history.founding_device_signing_seed,
            );
            let mut request = historical_human::request_for_event(&fixture, &previous, event, at);
            request.authority_commit.commit.stream_ref = stream.clone();
            if !held && offset == 0 {
                request.authority_commit.commit.stream_position = 0;
                request.authority_commit.commit.previous_commit_ref = None;
            }
            historical_human::seal_commit(
                &mut request.authority_commit.commit,
                &fixture.pcr.history.station_did,
            );
            store
                .queue_event(&request.authority_commit.event, at)
                .await
                .unwrap();
            let before = store.held_stream_head_commit(&stream).await.unwrap();
            for negative in 0..3 {
                let mut bad = request.authority_commit.clone();
                match negative {
                    0 => bad.commit.stream_position += 2,
                    1 => {
                        if bad.commit.stream_position > 0 {
                            bad.commit.stream_position -= 1;
                        } else {
                            bad.commit.stream_position = 1;
                        }
                    }
                    _ => bad.commit.previous_commit_ref = Some(foreign.clone()),
                }
                bad.commit.commit_id =
                    arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                        arkret_canonical::canonical_json_bytes(
                            &arkret_canonical::unsigned_value(
                                &bad.commit,
                                &["commit_id", "signature"],
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ));
                bad.commit.signature = arkret_signatures::detached_object::sign_detached_object(
                    &arkret_canonical::unsigned_value(&bad.commit, &["signature"]).unwrap(),
                    DetachedSignatureContext::RealmCommit,
                    bad.commit.signature.verification_method.clone(),
                    bad.commit.committed_at,
                    &ed25519_dalek::SigningKey::from_bytes(
                        &historical_human::station_authority_seed(),
                    ),
                )
                .unwrap();
                assert!(
                    store.commit_transaction(&bad).await.is_err(),
                    "{stream:?} negative {negative}"
                );
                assert_eq!(
                    store.held_stream_head_commit(&stream).await.unwrap(),
                    before
                );
            }
            assert_eq!(
                store
                    .commit_transaction(&request.authority_commit)
                    .await
                    .unwrap(),
                coland_storage::AuthorityCommitWriteOutcome::Committed
            );
            assert_eq!(
                store
                    .commit_transaction(&request.authority_commit)
                    .await
                    .unwrap(),
                coland_storage::AuthorityCommitWriteOutcome::Duplicate
            );
            previous = request.authority_commit;
        }
    }
}

#[test]
fn handoff_freezes_writes_preserves_current_and_reads_old_snapshots() {
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(Box::pin(call_current_handoff_scenario()));
    })
    .join()
    .unwrap();
}

async fn call_current_handoff_scenario() {
    eprintln!("[2133-handoff] starting complete PG fixture");
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture_pool = pool.clone();
    let fixture = tokio::spawn(async move {
        std::sync::Arc::new(
            Box::pin(HumanFixture::new(
                &fixture_pool,
                "did:web:handoff-old.example".parse().unwrap(),
            ))
            .await,
        )
    })
    .await
    .unwrap();
    let admitted_fixture = fixture.clone();
    let admitted_pool = pool.clone();
    tokio::spawn(async move {
        Box::pin(admitted_fixture.admit(&admitted_pool)).await;
    })
    .await
    .unwrap();
    eprintln!("[2133-handoff] accepted founder fixture");
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let mut watch_tail = fixture.unit.transactions.last().unwrap().clone();
    let realm = watch_tail.event.realm_id.clone();
    let watcher = ActorId::account(fixture.pcr.history.account.clone());
    let mut strands = Vec::new();
    for label in ["Written Watch", "Never Written Watch"] {
        let created_at = watch_tail.commit.committed_at + chrono::TimeDelta::seconds(1);
        eprintln!("[call-current-handoff] preparing Strand {label}");
        let create = Box::pin(isolated_request(
            &fixture,
            &pool,
            &watch_tail,
            EventKind::StrandCreate,
            serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
                "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":label},"state":"active","created_by":watcher,
                "created_at":arkret_canonical::format_timestamp_canonical(created_at)}}),
        ))
        .await;
        eprintln!("[call-current-handoff] admitting Strand {label}");
        Box::pin(isolated_commit(&pool, create.clone()))
            .await
            .unwrap();
        strands.push(arkret_wire::StrandId::from_event_id(
            &create.authority_commit.event.event_id,
        ));
        watch_tail = create.authority_commit;
    }
    let set = Box::pin(isolated_request(&fixture, &pool, &watch_tail, EventKind::StrandWatchSet,
        serde_json::json!({"strand_id":strands[0],"watcher_actor_id":watcher,"level":"all","level_public":true}))).await;
    Box::pin(isolated_commit(&pool, set.clone())).await.unwrap();
    let clear = Box::pin(isolated_request(&fixture, &pool, &set.authority_commit, EventKind::StrandWatchSet,
        serde_json::json!({"strand_id":strands[0],"watcher_actor_id":watcher,"level":null,"expected_value":{"level":"all","level_public":true}}))).await;
    Box::pin(isolated_commit(&pool, clear.clone()))
        .await
        .unwrap();
    watch_tail = clear.authority_commit.clone();
    let call = Box::pin(isolated_request(
        &fixture,
        &pool,
        &watch_tail,
        EventKind::CallCreate,
        serde_json::json!({"initial_state":"connecting"}),
    ))
    .await;
    Box::pin(isolated_commit(&pool, call.clone()))
        .await
        .unwrap();
    let call_id = arkret_wire::CallId::from_event_id(&call.authority_commit.event.event_id);
    let device = &fixture.pcr.history.founding_device_id;
    let media_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let multikey =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(media_key.verifying_key().as_bytes());
    let issuer_did: arkret_wire::Did = format!("did:key:{multikey}").parse().unwrap();
    let issuer = arkret_wire::project_did_to_core_id(&issuer_did).unwrap();
    let issuer_kid = format!("{issuer_did}#{multikey}");
    let service = Box::pin(isolated_request(
        &fixture,
        &pool,
        &call.authority_commit,
        EventKind::RealmMediaService,
        serde_json::json!({"value":{"service_id":issuer,"foci":[{
            "focus_id":"handoff-media","focus_kind":"livekit",
            "token_endpoint":"https://media.example/token","connect_url":"wss://media.example"
        }]}}),
    ))
    .await;
    Box::pin(isolated_commit(&pool, service.clone()))
        .await
        .unwrap();
    let participant = format!("ak:rtc_participant:{}", uuid::Uuid::now_v7());
    let expires_at = service.authority_commit.commit.committed_at + chrono::TimeDelta::minutes(10);
    let fields = arkret_signatures::media::ParticipantBindingContext {
        actor_id: &watcher,
        call_id: &call_id,
        device_id: device,
        expires_at,
        focus_id: "handoff-media",
        participant_id: &participant,
        realm_id: &realm,
        issuer_kid: &issuer_kid,
        media: arkret_models_collaboration::call_invitation::CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
    };
    use ed25519_dalek::Signer as _;
    let signature = arkret_canonical::base64url_encode(
        media_key
            .sign(&arkret_signatures::media::participant_binding_signing_input(&fields).unwrap())
            .to_bytes(),
    );
    let mut joined = Box::pin(isolated_request(&fixture, &pool, &service.authority_commit,
        EventKind::CallState, serde_json::json!({"call_id":call_id,
            "focus":{"mode":"sfu","session_focus":"handoff-media"},
            "roster_delta":{"op":"join","participant":{
                "actor_id":watcher,"device_id":device,"focus_id":"handoff-media",
                "participant_id":participant,"media":{"audio":true,"video":false,"screen":false},
                "participant_binding":{"expires_at":arkret_canonical::format_timestamp_canonical(expires_at),
                    "issuer_kid":issuer_kid,"signature":signature}
            }}}))).await;
    joined.verified_media_participant = arkret_signatures::media::VerifiedCallParticipant::verify(
        &joined.authority_commit.event,
        &issuer,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: media_key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    Box::pin(isolated_commit(&pool, joined.clone()))
        .await
        .unwrap();
    let kick_at = joined.authority_commit.commit.committed_at + chrono::TimeDelta::seconds(1);
    let kicked = Box::pin(isolated_request(&fixture, &pool, &joined.authority_commit, EventKind::CallState,
        serde_json::json!({"call_id":call_id,"moderation_delta":{"op":"remove_participant","removal":{
            "actor_id":watcher,"device_id":device,"action":"kick",
            "removed_by":watcher.signing_principal_id(),"removed_at":arkret_canonical::format_timestamp_canonical(kick_at)
        }}}))).await;
    Box::pin(isolated_commit(&pool, kicked.clone()))
        .await
        .unwrap();
    watch_tail = kicked.authority_commit.clone();
    let tail = &watch_tail;
    let account = fixture.pcr.history.account.clone();
    let next: arkret_wire::DidCoreId = "ak:did_core:web:handoff-new.example".parse().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let at = chrono::Utc::now();
    let sign_old = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            arkret_wire::DidUrl::new("did:web:handoff-old.example#authority").unwrap(),
            &key,
            at,
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let old_snapshot = store
        .issue_realm_state_snapshot_for_account(&realm, &account, &account.station_id, &sign_old)
        .await
        .unwrap()
        .unwrap();
    eprintln!("[2133-handoff] issued original Snapshot");
    for payload in [
        serde_json::json!({"expected_governance_generation":"1","expected_realm_stream_commit_id":tail.commit.commit_id,"new_governance_station_id":next}),
        serde_json::json!({"expected_governance_generation":"0","expected_realm_stream_commit_id":arkret_wire::RealmCommitId::from_digest([7;32]),"new_governance_station_id":next}),
        serde_json::json!({"expected_governance_generation":"0","expected_realm_stream_commit_id":tail.commit.commit_id,"new_governance_station_id":account.station_id}),
    ] {
        let bad = Box::pin(isolated_request(
            &fixture,
            &pool,
            tail,
            EventKind::RealmGovernanceStationChange,
            payload,
        ))
        .await;
        assert!(Box::pin(isolated_commit(&pool, bad)).await.is_err());
        assert_eq!(
            store.current_authority(&realm).await.unwrap(),
            Some(tail.expected_authority.clone())
        );
    }
    let change = Box::pin(isolated_request(&fixture,&pool,tail,EventKind::RealmGovernanceStationChange,
        serde_json::json!({"expected_governance_generation":"0","expected_realm_stream_commit_id":tail.commit.commit_id,"new_governance_station_id":next}))).await;
    Box::pin(isolated_commit(&pool, change.clone()))
        .await
        .unwrap();
    let later = Box::pin(isolated_request(
        &fixture,
        &pool,
        &change.authority_commit,
        EventKind::RealmProfile,
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Must not commit"}),
    ))
    .await;
    assert!(
        Box::pin(isolated_commit(&pool, later.clone()))
            .await
            .is_err()
    );
    let material = store
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    let snapshot = sign_old(&material).unwrap();
    let facts = inventory(&store, &realm).await;
    let heads = material.visible_stream_heads.clone();
    let (management, private_bytes) = store.export_management_private_state(&realm).await.unwrap();
    store
        .import_management_private_state(&management, &private_bytes)
        .await
        .unwrap();
    let mut handoff = arkret_wire::RealmAuthorityHandoff {
        management_private_state_digest: Some(management.digest().unwrap()),
        pcr_private_state_digest: None,
        handoff_id: arkret_wire::RealmAuthorityHandoffId::from_digest([41; 32]),
        realm_id: realm.clone(),
        from_generation: 0,
        to_generation: 1,
        from_service_id: account.station_id.clone(),
        to_service_id: next.clone(),
        change_event_ref: change.authority_commit.event.event_id.clone(),
        change_commit_id: change.authority_commit.commit.commit_id.clone(),
        final_stream_heads_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&heads).unwrap(),
        )
        .unwrap(),
        historical_signer_facts_digest: Some(historical_signer_facts_digest(&facts).unwrap()),
        snapshot_ref: snapshot.snapshot_id.clone(),
        old_authority_signature: ordinary_realm::signature(&account.station_id, at),
        new_authority_acceptance_signature: ordinary_realm::signature(&next, at),
    };
    let unsigned = arkret_canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )
    .unwrap();
    handoff.old_authority_signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        arkret_wire::DidUrl::new("did:web:handoff-old.example#authority").unwrap(),
        at,
        &key,
    )
    .unwrap();
    handoff.new_authority_acceptance_signature =
        arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            arkret_wire::DidUrl::new("did:web:handoff-new.example#authority").unwrap(),
            at,
            &key,
        )
        .unwrap();
    let mut missing = handoff.clone();
    missing.historical_signer_facts_digest =
        Some(historical_signer_facts_digest(&facts[1..]).unwrap());
    assert!(
        store
            .install_handoff_with_private_state(&missing, &heads, &snapshot, None, &management)
            .await
            .is_err()
    );
    let mut partial = material.clone();
    partial.current_state_entries.pop();
    let partial_snapshot = sign_old(&partial).unwrap();
    let mut partial_handoff = handoff.clone();
    partial_handoff.snapshot_ref = partial_snapshot.snapshot_id.clone();
    assert!(
        store
            .install_handoff_with_private_state(
                &partial_handoff,
                &heads,
                &partial_snapshot,
                None,
                &management
            )
            .await
            .is_err()
    );
    assert_eq!(
        store.current_authority(&realm).await.unwrap(),
        Some(tail.expected_authority.clone())
    );
    store
        .install_handoff_with_private_state(&handoff, &heads, &snapshot, None, &management)
        .await
        .unwrap();
    eprintln!("[2133-handoff] activated complete handoff");
    store
        .install_handoff_with_private_state(&handoff, &heads, &snapshot, None, &management)
        .await
        .unwrap();
    eprintln!("[2133-handoff] replayed complete handoff");
    assert!(Box::pin(isolated_commit(&pool, later)).await.is_err());
    eprintln!("[2133-handoff] refused old authority write");
    let installed = store.current_authority(&realm).await.unwrap().unwrap();
    assert_eq!(installed.generation, 1);
    assert_eq!(installed.service_id, next);
    let scan = arkret_wire::StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        },
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 500,
    };
    let coland_storage::AccountStreamScan::Page(old_station_page) = store
        .scan_stream_for_account(&scan, &account, &account.station_id)
        .await
        .unwrap()
    else {
        panic!("the outgoing governor must retain its hosted Account's proved history");
    };
    old_station_page.validate_for_request(&scan).unwrap();
    eprintln!("[2133-handoff] outgoing self scan retained");
    assert_eq!(
        old_station_page.committed_events.last().unwrap().commit(),
        &change.authority_commit.commit
    );

    for (index, strand) in strands.iter().enumerate() {
        let query =
            arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody {
                realm_id: realm.clone(),
                strand_id: strand.clone(),
                watcher_actor_id: watcher.clone(),
            };
        match store.strand_watch_current_for_account(&query, &account, &next).await.unwrap() {
            coland_storage::SelfExactCurrentRead::Answer(arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentResponseBody::Current { governance_generation, current_state: result, .. }) if index == 0 => {
                assert_eq!(governance_generation, 1);
                assert_eq!(result.revision.commit_id, clear.authority_commit.commit.commit_id);
                assert_eq!(serde_json::to_value(result.value).unwrap(), serde_json::Value::Null);
            },
            coland_storage::SelfExactCurrentRead::Answer(arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentResponseBody::NeverWritten { governance_generation, .. }) if index == 1 => assert_eq!(governance_generation, 1),
            other => panic!("complete nonzero tenure must retain Watch presence: {other:?}"),
        }
    }
    let sign_new = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            arkret_wire::DidUrl::new("did:web:handoff-new.example#authority").unwrap(),
            &key,
            at,
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let new_snapshot = store
        .issue_realm_state_snapshot_for_account(&realm, &account, &next, &sign_new)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(new_snapshot.governance_generation, 1);
    let roster = new_snapshot
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            arkret_wire::CurrentState::Value {
                selector: arkret_wire::CurrentSelector::CallRoster { call_id: actual },
                value,
                ..
            } if actual == &call_id => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(roster["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        roster["last_source"]["source_commit"],
        serde_json::json!(joined.authority_commit.commit)
    );
    assert_eq!(
        roster["last_source"]["source_commit"]["governance_generation"],
        0
    );
    eprintln!("[2133-handoff] issued successor Snapshot");
    let minimum = store
        .realm_state_snapshot_material_for_account(&realm, &account)
        .await
        .unwrap()
        .unwrap();
    store
        .install_verified_account_snapshot(&account, &account.station_id, &new_snapshot, &minimum)
        .await
        .unwrap();
    eprintln!("[2133-handoff] retained verified successor Snapshot");
    assert_eq!(
        store
            .issued_realm_state_snapshot(
                &realm,
                &account,
                &new_snapshot.snapshot_id,
                &account.station_id
            )
            .await
            .unwrap(),
        Some(new_snapshot.clone())
    );
    eprintln!("[2133-handoff] outgoing exact successor Snapshot retained");

    assert_eq!(
        new_snapshot.current_state_entries,
        old_snapshot.current_state_entries
    );
    assert_eq!(
        store
            .issued_realm_state_snapshot(&realm, &account, &old_snapshot.snapshot_id, &next)
            .await
            .unwrap(),
        Some(old_snapshot)
    );
    eprintln!("[2133-handoff] exact original old Snapshot retained");
    let mut replay = handoff.clone();
    replay.new_authority_acceptance_signature.signature =
        arkret_wire::Base64UrlString::new("YmFk").unwrap();
    assert!(
        store
            .install_handoff_with_private_state(&replay, &heads, &snapshot, None, &management)
            .await
            .is_err()
    );
    eprintln!("[2133-handoff] refused changed handoff replay");
    // A new tenure extends the imported predecessor; it never restarts position.
    let mut next_tail = change.authority_commit.clone();
    next_tail.expected_authority = installed;
    let mut fresh = Box::pin(isolated_request(
        &fixture,
        &pool,
        &next_tail,
        EventKind::CallState,
        serde_json::json!({"call_id":call_id,"roster_delta":{"op":"leave","actor_id":watcher,
            "device_id":device,"expected_revision":{"commit_id":joined.authority_commit.commit.commit_id,
                "stream_position":joined.authority_commit.commit.stream_position}}}),
    ))
    .await;
    fresh.authority_commit.commit.governance_generation = 1;
    fresh.authority_commit.commit.authority_ref =
        RealmCommitAuthorityRef::Handoff(handoff.handoff_id.clone());
    historical_human::seal_commit(
        &mut fresh.authority_commit.commit,
        &"did:web:handoff-new.example".parse().unwrap(),
    );
    // The successor accepts an independent HTTP command. Keep this real
    // admission on its own default-runtime task, with cancellation tied to
    // the fixture, rather than nesting its poll stack in the whole lifecycle.
    let mut admissions = tokio::task::JoinSet::new();
    let successor_pool = pool.clone();
    let successor_request = fresh.clone();
    admissions.spawn(async move {
        PgEventCommitUnitOfWork::new(successor_pool)
            .commit_event(*successor_request)
            .await
            .unwrap();
    });
    admissions.join_next().await.unwrap().unwrap();
    let after = store
        .realm_state_snapshot_material_for_account(&realm, &account)
        .await
        .unwrap()
        .unwrap();
    let roster = after
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            arkret_wire::CurrentState::Value {
                selector: arkret_wire::CurrentSelector::CallRoster { call_id: actual },
                value,
                ..
            } if actual == &call_id => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(roster["entries"], serde_json::json!([]));
    assert_eq!(
        roster["last_source"]["source_commit"],
        serde_json::json!(fresh.authority_commit.commit)
    );
    let moderation = after
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            arkret_wire::CurrentState::Value {
                selector: arkret_wire::CurrentSelector::CallModeration { call_id: actual },
                value,
                ..
            } if actual == &call_id => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(moderation["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        moderation["last_source"]["source_commit"],
        serde_json::json!(kicked.authority_commit.commit)
    );
    eprintln!(
        "[call-current-handoff] original_generation_zero_sources=2 successor_empty_roster_last_source=1 retained_kick=1"
    );
    eprintln!("[2133-handoff] successor extended original chain");
    assert_eq!(
        fresh.authority_commit.commit.previous_commit_ref,
        Some(change.authority_commit.commit.commit_id)
    );
    store
        .install_handoff_with_private_state(&handoff, &heads, &snapshot, None, &management)
        .await
        .unwrap();
    let application = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::new(std::sync::Arc::new(
            coland_storage_postgres::PgPersistenceStore::new(pool),
        )),
        1024,
    );
    let frozen = application.handoff_originals(&realm, 0).await.unwrap();
    assert!(
        frozen
            .iter()
            .all(|full| full.commit.governance_generation == 0)
    );
    assert!(
        !frozen
            .iter()
            .any(|full| full.event.event_id == fresh.authority_commit.event.event_id)
    );
    assert_eq!(
        frozen
            .iter()
            .filter(|full| full.commit.producer_signer_fact_digest.is_some())
            .count(),
        facts.len()
    );
}

/// Keep producer-material preparation off the retained lifecycle poll frame.
async fn isolated_request(
    fixture: &std::sync::Arc<HumanFixture>,
    pool: &PgPool,
    previous: &coland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    payload: serde_json::Value,
) -> Box<coland_storage::EventCommitRequest> {
    let fixture = fixture.clone();
    let pool = pool.clone();
    let previous = Box::new(previous.clone());
    tokio::spawn(async move {
        Box::new(Box::pin(request(&fixture, &pool, &previous, kind, payload)).await)
    })
    .await
    .unwrap()
}

/// Poll each real admission on a fresh default-stack worker, so the retained
/// lifecycle fixture never shares its poll frame with the accepting unit.
async fn isolated_commit(
    pool: &PgPool,
    request: Box<coland_storage::EventCommitRequest>,
) -> coland_storage::PersistenceResult<()> {
    let pool = pool.clone();
    let mut admissions = tokio::task::JoinSet::new();
    admissions.spawn(async move {
        PgEventCommitUnitOfWork::new(pool)
            .commit_event(*request)
            .await
            .map(|_| ())
    });
    admissions.join_next().await.unwrap().unwrap()
}
