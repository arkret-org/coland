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
