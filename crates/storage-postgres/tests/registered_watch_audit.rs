//! Real PostgreSQL acceptance, rollback and durable audit observation fences.
//! The storage fixture has accepted PCR history; HTTP ingress is tested separately.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_models_collaboration::authority_commit::{
    AuditPairedEventUnitKind, AuditPairedEventUnitSubmission,
};
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, WatchAuditReadRequest,
};
use arkret_wire::{ActorId, EventAdmissionSubmission, EventKind, ScopeRef};
use coland_storage::{
    AuthorityCommitStore, EventBatchCommitRequest, EventCommitRequest, EventCommitUnitOfWork,
    RegisteredAuditCommit, RegisteredAuditOutcome,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use serde_json::json;

fn batch(events: Vec<EventCommitRequest>, unit: RegisteredAuditCommit) -> EventBatchCommitRequest {
    EventBatchCommitRequest {
        audit_unit: Some(unit),
        events,
        franking_replay_nonce: None,
        realm_organization_proof: None,
        invite_claim_proof: None,
        event_approvals: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}
async fn open(pool: &PgPool, seed: &str) -> ordinary_realm::Discussion {
    let mut discussion = ordinary_realm::open_human_discussion(pool, seed).await;
    let actor = discussion.head.authority_commit.event.actor_id.clone();
    let realm = discussion.realm_id();
    let grant = ordinary_realm::event(
        EventKind::CapabilityGrant,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor.signing_principal_id(),
        &ordinary_realm::station(),
        json!({"grant": {"schema":"ak.schema.capability.v1", "realm_id":realm,
            "issuer_id":actor, "subject":actor,
            "actions":["ak.strand.watch.set.others","ak.audit.accessed","ak.realm.notification.audit"],
            "resources":[{"kind":"realm","realm_id":realm,"match_scope":"realm_wide"}],"constraints":[],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":realm.event_id(),"authority_generation":0}],
            "issued_at":arkret_canonical::format_timestamp_canonical(discussion.committed_at())}}),
        discussion.committed_at(),
    );
    let grant = ordinary_realm::source_request(
        pool,
        ordinary_realm::request_for_event(
            &discussion.head.authority_commit,
            grant,
            discussion.committed_at(),
        ),
    )
    .await;
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(grant.clone())
        .await
        .unwrap();
    discussion.head = grant;
    discussion
}

fn watcher() -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:watch-target.example".parse().unwrap(),
        ordinary_realm::station(),
    ))
}
async fn pair(
    pool: &PgPool,
    discussion: &ordinary_realm::Discussion,
    previous: &coland_storage::AuthorityCommitTransaction,
    level: &str,
    expected: Option<serde_json::Value>,
) -> EventBatchCommitRequest {
    let actor = previous.event.actor_id.clone();
    let mut payload =
        json!({"strand_id": discussion.strand_id, "watcher_actor_id": watcher(), "level":level});
    if let Some(value) = expected {
        payload["expected_value"] = value;
    }
    let business = ordinary_realm::event(
        EventKind::StrandWatchSet,
        ScopeRef::Realm {
            realm_id: discussion.realm_id(),
        },
        actor.signing_principal_id(),
        &ordinary_realm::station(),
        payload,
        discussion.committed_at(),
    );
    let business = ordinary_realm::source_request(
        pool,
        ordinary_realm::request_for_event(previous, business, discussion.committed_at()),
    )
    .await;
    let mut audit = ordinary_realm::event(
        EventKind::AuditAccessed,
        business.authority_commit.event.scope_ref.clone(),
        actor.signing_principal_id(),
        &ordinary_realm::station(),
        json!({"access_kind":"watch_set_others", "writer_actor_id":actor,
            "target_actor_id":watcher(),"target_ref":discussion.strand_id,
            "paired_event_id":business.authority_commit.event.event_id,
            "purpose":"registered audit storage verification",
            "accessed_at":arkret_canonical::format_timestamp_canonical(discussion.committed_at())}),
        discussion.committed_at(),
    );
    audit.semantic_refs = vec![arkret_wire::SemanticRef {
        role: "audit_pair".to_owned(),
        id: business.authority_commit.event.event_id.to_string(),
        critical: true,
    }];
    ordinary_realm::reseal(&mut audit);
    let audit = ordinary_realm::source_request(
        pool,
        ordinary_realm::request_for_event(
            &business.authority_commit,
            audit,
            discussion.committed_at(),
        ),
    )
    .await;
    let request = AuditPairedEventUnitSubmission {
        unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
        events: [
            EventAdmissionSubmission::new(business.authority_commit.event.clone()),
            EventAdmissionSubmission::new(audit.authority_commit.event.clone()),
        ],
    };
    request.validate().unwrap();
    batch(
        vec![business, audit],
        RegisteredAuditCommit::Pair {
            request: Box::new(request),
            approvals: [None, None],
        },
    )
}
async fn read(
    pool: &PgPool,
    discussion: &ordinary_realm::Discussion,
    previous: &coland_storage::AuthorityCommitTransaction,
    target: ActorId,
    purpose: &str,
) -> EventBatchCommitRequest {
    let actor = previous.event.actor_id.clone();
    let event = ordinary_realm::event(
        EventKind::AuditAccessed,
        ScopeRef::Realm {
            realm_id: discussion.realm_id(),
        },
        actor.signing_principal_id(),
        &ordinary_realm::station(),
        json!({"access_kind":"watch_audit_read","writer_actor_id":actor,"target_actor_id":target,
            "target_ref":discussion.strand_id,"purpose":purpose,
            "accessed_at":arkret_canonical::format_timestamp_canonical(discussion.committed_at())}),
        discussion.committed_at(),
    );
    let event = ordinary_realm::source_request(
        pool,
        ordinary_realm::request_for_event(previous, event, discussion.committed_at()),
    )
    .await;
    let request = WatchAuditReadRequest {
        audit_submission: EventAdmissionSubmission::new(event.authority_commit.event.clone()),
    };
    request.validate().unwrap();
    batch(
        vec![event],
        RegisteredAuditCommit::WatchRead {
            request: Box::new(request),
        },
    )
}
#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type=BigInt)]
    count: i64,
}
async fn event_count(pool: &PgPool, realm: &arkret_wire::RealmId) -> i64 {
    diesel::sql_query("SELECT count(*) AS count FROM canonical_events WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Count>(&mut *pool.get().await.unwrap())
        .await
        .unwrap()
        .count
}

#[tokio::test]
async fn audit_pair_commits_once_and_exact_replay_preserves_both_source_commits() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let discussion = open(&pool, "audit-pair-exact").await;
    let request = pair(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        "all",
        None,
    )
    .await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let count = event_count(&pool, &discussion.realm_id()).await;
    let result = uow
        .commit_event_batch(request.clone())
        .await
        .unwrap()
        .audit_outcome
        .unwrap();
    assert_eq!(event_count(&pool, &discussion.realm_id()).await, count + 2);
    assert_eq!(
        uow.commit_event_batch(request.clone())
            .await
            .unwrap()
            .audit_outcome,
        Some(result.clone())
    );
    assert_eq!(event_count(&pool, &discussion.realm_id()).await, count + 2);
    let archive = PgAuthorityCommitStore { pool: pool.clone() }
        .registered_audit_result(&request.events[0].authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(archive.outcome, result);
}

#[tokio::test]
async fn failed_second_slot_rolls_back_business_projection_and_stream_position() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let discussion = open(&pool, "audit-pair-rollback").await;
    let good = pair(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        "participating",
        None,
    )
    .await;
    let mut bad = good.clone();
    bad.events[1].event.event_id = "deliberately-unbound-audit-record".to_owned();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let count = event_count(&pool, &discussion.realm_id()).await;
    assert!(uow.commit_event_batch(bad).await.is_err());
    assert_eq!(event_count(&pool, &discussion.realm_id()).await, count);
    assert!(
        uow.commit_event_batch(good)
            .await
            .unwrap()
            .audit_outcome
            .is_some()
    );
}

#[tokio::test]
async fn paired_watch_cas_conflict_and_standalone_audit_leave_no_effects() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let discussion = open(&pool, "audit-pair-cas").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let first = pair(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        "all",
        None,
    )
    .await;
    uow.commit_event_batch(first.clone()).await.unwrap();
    let next = pair(
        &pool,
        &discussion,
        &first.events[1].authority_commit,
        "mentions_only",
        None,
    )
    .await;
    let count = event_count(&pool, &discussion.realm_id()).await;
    assert!(uow.commit_event_batch(next).await.is_err());
    let standalone = read(
        &pool,
        &discussion,
        &first.events[1].authority_commit,
        watcher(),
        "standalone forbidden",
    )
    .await;
    assert!(
        uow.commit_event(standalone.events[0].clone())
            .await
            .is_err()
    );
    assert_eq!(event_count(&pool, &discussion.realm_id()).await, count);
}

#[tokio::test]
async fn audit_read_freezes_never_written_and_replay_does_not_read_later_watch() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let discussion = open(&pool, "audit-read-frozen").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let request = read(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        watcher(),
        "frozen absence",
    )
    .await;
    let first = uow
        .commit_event_batch(request.clone())
        .await
        .unwrap()
        .audit_outcome
        .unwrap();
    let RegisteredAuditOutcome::WatchRead(outcome) = &first else {
        panic!("read outcome expected")
    };
    assert!(matches!(
        outcome.current,
        StrandWatchCurrentOutcome::NeverWritten { .. }
    ));
    assert_eq!(
        outcome.audit_commit,
        request.events[0].authority_commit.commit
    );
    let later = pair(
        &pool,
        &discussion,
        &request.events[0].authority_commit,
        "all",
        None,
    )
    .await;
    uow.commit_event_batch(later).await.unwrap();
    let count = event_count(&pool, &discussion.realm_id()).await;
    assert_eq!(
        uow.commit_event_batch(request).await.unwrap().audit_outcome,
        Some(first)
    );
    assert_eq!(event_count(&pool, &discussion.realm_id()).await, count);
}

#[tokio::test]
async fn audit_read_freezes_written_current_and_revoked_permission_hides_replay() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let discussion = open(&pool, "audit-read-revoke").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let write = pair(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        "all",
        None,
    )
    .await;
    uow.commit_event_batch(write.clone()).await.unwrap();
    let request = read(
        &pool,
        &discussion,
        &write.events[1].authority_commit,
        watcher(),
        "frozen current",
    )
    .await;
    let result = uow
        .commit_event_batch(request.clone())
        .await
        .unwrap()
        .audit_outcome
        .unwrap();
    let RegisteredAuditOutcome::WatchRead(outcome) = result else {
        panic!("read outcome expected")
    };
    assert!(matches!(
        outcome.current,
        StrandWatchCurrentOutcome::Current { .. }
    ));
    let grant_tx = &discussion.head.authority_commit;
    let revoke = ordinary_realm::event(
        EventKind::CapabilityRevoke,
        ScopeRef::Realm {
            realm_id: discussion.realm_id(),
        },
        grant_tx.event.actor_id.signing_principal_id(),
        &ordinary_realm::station(),
        json!({"grant_id":arkret_wire::GrantId::from_event_id(&grant_tx.event.event_id),
            "expected_revision":{"commit_id":grant_tx.commit.commit_id,"stream_position":grant_tx.commit.stream_position}}),
        discussion.committed_at(),
    );
    let revoke = ordinary_realm::source_request(
        &pool,
        ordinary_realm::request_for_event(
            &request.events[0].authority_commit,
            revoke,
            discussion.committed_at(),
        ),
    )
    .await;
    uow.commit_event(revoke).await.unwrap();
    let count = event_count(&pool, &discussion.realm_id()).await;
    assert!(matches!(
        uow.commit_event_batch(request).await.unwrap_err(),
        coland_storage::PersistenceError::NotFound(_)
    ));
    assert_eq!(event_count(&pool, &discussion.realm_id()).await, count);
}

#[tokio::test]
async fn changed_complete_pair_cannot_reuse_its_business_event_fence() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let discussion = open(&pool, "audit-pair-duplicate-conflict").await;
    let good = pair(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        "all",
        None,
    )
    .await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event_batch(good.clone()).await.unwrap();
    let mut changed = good.clone();
    let mut audit = changed.events[1].authority_commit.event.clone();
    audit.payload.insert(
        "purpose".to_owned(),
        json!("another complete unit using one accepted business Event"),
    );
    ordinary_realm::reseal(&mut audit);
    changed.events[1] = ordinary_realm::source_request(
        &pool,
        ordinary_realm::request_for_event(
            &changed.events[0].authority_commit,
            audit,
            discussion.committed_at(),
        ),
    )
    .await;
    let Some(RegisteredAuditCommit::Pair { request, .. }) = &mut changed.audit_unit else {
        unreachable!()
    };
    request.events[1] =
        EventAdmissionSubmission::new(changed.events[1].authority_commit.event.clone());
    let count = event_count(&pool, &discussion.realm_id()).await;
    let error = uow
        .commit_event_batch(changed)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate_conflict"), "{error}");
    assert_eq!(event_count(&pool, &discussion.realm_id()).await, count);
}

async fn copy_private_database(source: &str, destination: &str) {
    let source = source.to_owned();
    let destination = destination.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        use std::process::{Command, Stdio};
        // Planned handoff is activation of pre-imported private durable state.
        // Transfer the whole database, including hidden streams, private audit,
        // nonce fences and outbox, independently of ordinary member disclosure.
        let dump = Command::new("pg_dump")
            .args([
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                &source,
            ])
            .output()
            .expect("pg_dump available");
        assert!(
            dump.status.success(),
            "private source export: {}",
            String::from_utf8_lossy(&dump.stderr)
        );
        let mut child = Command::new("psql")
            .args([
                "--quiet",
                "--single-transaction",
                "--set=ON_ERROR_STOP=1",
                &destination,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("psql available");
        child.stdin.take().unwrap().write_all(&dump.stdout).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "private atomic import: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn complete_forward_unit_survives_independent_database_and_adapter_reopen() {
    let source = TestDatabase::lease().await;
    let destination = TestDatabase::lease().await;
    assert_ne!(source.url(), destination.url());
    let pool = source.pool();
    let discussion = open(&pool, "audit-origin-cold").await;
    let prepared = pair(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        "all",
        None,
    )
    .await;
    let RegisteredAuditCommit::Pair { request, .. } = prepared.audit_unit.as_ref().unwrap() else {
        panic!("pair")
    };
    let request = request.clone();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .retain_registered_pair_forward(&request, None)
        .await
        .unwrap();
    assert!(
        store
            .registered_audit_result(&request.events[0].event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let original = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(prepared)
        .await
        .unwrap()
        .audit_outcome
        .unwrap();
    let RegisteredAuditOutcome::Pair(accepted) = &original else {
        panic!("pair")
    };
    store
        .retain_registered_pair_forward(&request, Some(accepted))
        .await
        .unwrap();
    copy_private_database(source.url(), destination.url()).await;
    // Remove the governor archive on the origin copy: the cold origin must
    // recover only from its own complete frozen request and verified ACK.
    diesel::sql_query("DELETE FROM registered_audit_units")
        .execute(&mut *destination.pool().get().await.unwrap())
        .await
        .unwrap();
    let reopened = PgAuthorityCommitStore {
        pool: destination.pool(),
    };
    for slot in &request.events {
        let retained = reopened
            .registered_audit_result(&slot.event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            retained.canonical_request,
            arkret_canonical::canonical_json_bytes(&request).unwrap()
        );
        assert_eq!(retained.outcome, original);
    }
    let mut changed = *request.clone();
    changed.events[1]
        .event
        .payload
        .insert("purpose".into(), json!("changed origin"));
    ordinary_realm::reseal(&mut changed.events[1].event);
    let error = reopened
        .retain_registered_pair_forward(&changed, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("duplicate_conflict"), "{error}");
    assert_eq!(
        event_count(&pool, &discussion.realm_id()).await,
        event_count(&destination.pool(), &discussion.realm_id()).await
    );
}

#[tokio::test]
async fn independent_handoff_preserves_unit_fences_and_frozen_reads_and_rejects_incomplete_import()
{
    use arkret_models_collaboration::authority_commit::{
        HistoricalProducerSignerFactEntry, historical_signer_facts_digest,
    };
    let source = TestDatabase::lease().await;
    let destination = TestDatabase::lease().await;
    let pool = source.pool();
    let discussion = open(&pool, "audit-private-handoff").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let observed = read(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        watcher(),
        "before pair frozen",
    )
    .await;
    let frozen = uow
        .commit_event_batch(observed.clone())
        .await
        .unwrap()
        .audit_outcome
        .unwrap();
    let pair = pair(
        &pool,
        &discussion,
        &observed.events[0].authority_commit,
        "all",
        None,
    )
    .await;
    let original = uow
        .commit_event_batch(pair.clone())
        .await
        .unwrap()
        .audit_outcome
        .unwrap();
    let old = PgAuthorityCommitStore { pool: pool.clone() };
    let realm = discussion.realm_id();
    let next: arkret_wire::DidCoreId = "ak:did_core:web:audit-next.example".parse().unwrap();
    let previous = &pair.events[1].authority_commit;
    let change = ordinary_realm::event(
        EventKind::RealmGovernanceStationChange,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        previous.event.actor_id.signing_principal_id(),
        &ordinary_realm::station(),
        json!({"expected_governance_generation":0,"expected_realm_stream_commit_id":previous.commit.commit_id,"new_governance_station_id":next}),
        discussion.committed_at(),
    );
    let change = ordinary_realm::source_request(
        &pool,
        ordinary_realm::request_for_event(previous, change, discussion.committed_at()),
    )
    .await;
    uow.commit_event(change.clone()).await.unwrap();
    let material = old
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        arkret_wire::DidUrl::new("did:web:ordinary-station.example#authority").unwrap(),
        &key,
        discussion.committed_at(),
    )
    .unwrap();
    let mut facts = Vec::new();
    for full in old.handoff_originals(&realm).await.unwrap() {
        if let Some(fact) = old
            .producer_signer_fact(&full.event, &full.commit)
            .await
            .unwrap()
        {
            facts.push(HistoricalProducerSignerFactEntry {
                target: arkret_wire::CommittedEventRef {
                    event_id: full.event.event_id,
                    commit_id: full.commit.commit_id,
                    stream_ref: full.commit.stream_ref,
                    stream_position: full.commit.stream_position,
                },
                producer_signer_fact: fact,
            });
        }
    }
    facts.sort_by_key(|entry| {
        (
            arkret_canonical::canonical_json_bytes(&entry.target.stream_ref).unwrap(),
            entry.target.stream_position,
            entry.target.event_id.to_string(),
            entry.target.commit_id.to_string(),
        )
    });
    let heads = material.visible_stream_heads;
    let mut handoff = arkret_wire::RealmAuthorityHandoff {
        pcr_private_state_digest: None,
        handoff_id: arkret_wire::RealmAuthorityHandoffId::from_digest([63; 32]),
        realm_id: realm.clone(),
        from_generation: 0,
        to_generation: 1,
        from_service_id: ordinary_realm::station(),
        to_service_id: next.clone(),
        change_event_ref: change.authority_commit.event.event_id.clone(),
        change_commit_id: change.authority_commit.commit.commit_id.clone(),
        final_stream_heads_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&heads).unwrap(),
        )
        .unwrap(),
        historical_signer_facts_digest: Some(historical_signer_facts_digest(&facts).unwrap()),
        snapshot_ref: snapshot.snapshot_id.clone(),
        old_authority_signature: ordinary_realm::signature(
            &ordinary_realm::station(),
            discussion.committed_at(),
        ),
        new_authority_acceptance_signature: ordinary_realm::signature(
            &next,
            discussion.committed_at(),
        ),
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
        arkret_wire::DetachedSignatureContext::RealmAuthorityHandoffOld,
        arkret_wire::DidUrl::new("did:web:ordinary-station.example#authority").unwrap(),
        discussion.committed_at(),
        &key,
    )
    .unwrap();
    handoff.new_authority_acceptance_signature =
        arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            arkret_wire::DidUrl::new("did:web:audit-next.example#authority").unwrap(),
            discussion.committed_at(),
            &key,
        )
        .unwrap();
    copy_private_database(source.url(), destination.url()).await;
    let new = PgAuthorityCommitStore {
        pool: destination.pool(),
    };
    assert_ne!(source.url(), destination.url());
    let business = &pair.events[0].authority_commit.event.event_id;
    let mut conn = destination.pool().get().await.unwrap();
    diesel::sql_query("UPDATE registered_audit_units SET private_audit_digest='incomplete' WHERE business_event_id=$1")
        .bind::<Text,_>(business.as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    let error = new
        .install_handoff(&handoff, &heads, &snapshot)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("revision_unavailable"),
        "{error}"
    );
    assert_eq!(
        new.current_authority(&realm)
            .await
            .unwrap()
            .unwrap()
            .generation,
        0
    );
    // Re-import the frozen complete source after the rejected activation.
    copy_private_database(source.url(), destination.url()).await;
    new.install_handoff(&handoff, &heads, &snapshot)
        .await
        .unwrap();
    let reopened = PgAuthorityCommitStore {
        pool: destination.pool(),
    };
    assert_eq!(
        reopened
            .current_authority(&realm)
            .await
            .unwrap()
            .unwrap()
            .service_id,
        next
    );
    for (event_id, outcome) in [
        (business, &original),
        (&observed.events[0].authority_commit.event.event_id, &frozen),
    ] {
        assert_eq!(
            &reopened
                .registered_audit_result(event_id)
                .await
                .unwrap()
                .unwrap()
                .outcome,
            outcome
        );
    }
    let before = event_count(&destination.pool(), &realm).await;
    let replay = PgEventCommitUnitOfWork::new(destination.pool())
        .commit_event_batch(pair)
        .await
        .unwrap()
        .audit_outcome
        .unwrap();
    assert_eq!(replay, original);
    // Old frozen reads cannot establish the new generation's current cut.
    let error = PgEventCommitUnitOfWork::new(destination.pool())
        .commit_event_batch(observed)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("revision_unavailable"),
        "{error}"
    );
    assert_eq!(event_count(&destination.pool(), &realm).await, before);
}
