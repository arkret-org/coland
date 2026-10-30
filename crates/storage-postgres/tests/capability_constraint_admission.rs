//! Capability Grant constraints at the accepting transaction on real
//! PostgreSQL (`authz/constraint-schema.md` §8.1, §15.4, §16;
//! `authz/capabilities.md` §3.2; `models/realm-and-space.md` §2.6.0).
//!
//! * A hard rate quota a grant carries is reserved with the Event it admits: the Event over the
//!   quota is refused with zero writes, and an exact retry of an admitted Event counts once.
//! * A `deny` constraint of any effective grant refuses the Event even when another grant alone
//!   would allow it.
//! * A temporal recurrence outside its window leaves the grant unsatisfied.
//! * An archived Realm admits only its exemption set.
//! * The Realm authority row lock is the cut's dependency lock: a revocation committed while an
//!   admission waits for that lock is observed by it.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, ConflictCode, EventCommitRequest,
    EventCommitUnitOfWork,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Text};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use ordinary_realm::message_payload;

fn local<'a>(
    pool: &'a PgPool,
    label: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = arkret_wire::ActorId> + Send + 'a>> {
    Box::pin(async move {
        arkret_wire::ActorId::account(
            ordinary_realm::human_profile::admit(pool, &ordinary_realm::station(), label).await,
        )
    })
}

fn founder_actor() -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(ordinary_realm::human_profile::account(
        &ordinary_realm::station(),
        "ordinary-founder",
    ))
}

fn by<'a>(
    pool: &'a PgPool,
    previous: &'a AuthorityCommitTransaction,
    kind: arkret_wire::EventKind,
    actor: &'a arkret_wire::ActorId,
    payload: serde_json::Value,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + Send + 'a>> {
    Box::pin(async move {
        ordinary_realm::source_request(
            pool,
            ordinary_realm::next_request_for_actor(
                previous,
                kind,
                actor.clone(),
                payload,
                previous.commit.committed_at,
            ),
        )
        .await
    })
}

/// An open Realm with an active default discussion Strand and a joined
/// `member`.
struct Discussion {
    realm_id: arkret_wire::RealmId,
    strand_id: arkret_wire::StrandId,
    root_event_ref: String,
    head: EventCommitRequest,
}

fn discussion<'a>(
    pool: &'a PgPool,
    seed: &'a str,
    member: &'a arkret_wire::ActorId,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Discussion> + Send + 'a>> {
    Box::pin(async move {
        let opened = ordinary_realm::open_human_discussion(pool, seed).await;
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let realm_id = opened.realm_id().clone();
        let strand_id = opened.strand_id.clone();
        let default = opened.head;
        let join = by(
            &pool,
            &default.authority_commit,
            arkret_wire::EventKind::MemberState,
            member,
            serde_json::json!({
                "realm_id": realm_id,
                "member_id": member,
                "membership": "join",
                "reason": "fixture join",
            }),
        )
        .await;
        uow.commit_event(join.clone()).await.unwrap();
        let root_event_ref = root_event_ref(pool, &realm_id).await;
        Discussion {
            realm_id,
            strand_id,
            root_event_ref,
            head: join,
        }
    })
}

async fn root_event_ref(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> String {
    #[derive(diesel::QueryableByName)]
    struct RootRow {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_states WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .unwrap()
    .authority_event_ref
}

/// The root controller's grant of `actions` over the whole Realm to
/// `subject` with `constraints`.
fn grant<'a>(
    pool: &'a PgPool,
    discussion: &'a Discussion,
    previous: &'a AuthorityCommitTransaction,
    subject: &'a arkret_wire::ActorId,
    actions: &'a [&'a str],
    constraints: serde_json::Value,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + Send + 'a>> {
    Box::pin(async move {
        let realm_id = &discussion.realm_id;
        let mut payload = serde_json::json!({
                "grant": {
                    "schema": "ak.schema.capability.v1",
                    "realm_id": realm_id,
                    "issuer_id": founder_actor(),
                    "subject": subject,
                    "actions": actions,
                    "resources": [{"kind": "realm", "realm_id": realm_id}],
                    "constraints": constraints,
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": realm_id,
                        "authority_event_ref": discussion.root_event_ref,
                        "authority_generation": "0"
                    }],
                    "issued_at": arkret_canonical::format_timestamp_canonical(
                        previous.commit.committed_at
                    ),
                }
        });
        if constraints.as_array().is_some_and(Vec::is_empty) {
            payload["grant"]
                .as_object_mut()
                .unwrap()
                .remove("constraints");
        }
        by(
            &pool,
            previous,
            arkret_wire::EventKind::CapabilityGrant,
            &founder_actor(),
            payload,
        )
        .await
    })
}

fn message<'a>(
    pool: &'a PgPool,
    discussion: &'a Discussion,
    previous: &'a AuthorityCommitTransaction,
    author: &'a arkret_wire::ActorId,
    body: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + Send + 'a>> {
    Box::pin(async move {
        by(
            &pool,
            previous,
            arkret_wire::EventKind::MessageCreate,
            author,
            message_payload(&discussion.strand_id, body),
        )
        .await
    })
}

async fn assert_refused(
    pool: &PgPool,
    uow: &PgEventCommitUnitOfWork,
    request: EventCommitRequest,
    code: ConflictCode,
) {
    let error = uow.commit_event(request.clone()).await.unwrap_err();
    assert_eq!(error.conflict_code(), Some(code), "{error}");
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none(),
        "a refused Event is not committed"
    );
}

async fn quota_consumed(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = BigInt)]
        consumed: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COALESCE(SUM(consumed),0)::bigint AS consumed FROM capability_quota_counters",
    )
    .get_result::<Row>(&mut *conn)
    .await
    .unwrap()
    .consumed
}

async fn durable_rows(pool: &PgPool) -> Vec<(String, i64, String)> {
    #[derive(diesel::QueryableByName)]
    struct Table {
        #[diesel(sql_type = Text)]
        tablename: String,
    }
    #[derive(diesel::QueryableByName)]
    struct Contents {
        #[diesel(sql_type = BigInt)]
        rows: i64,
        #[diesel(sql_type = Text)]
        digest: String,
    }
    let mut conn = pool.get().await.unwrap();
    let tables = diesel::sql_query(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
    )
    .load::<Table>(&mut conn)
    .await
    .unwrap();
    let mut snapshot = Vec::new();
    for table in tables {
        let quoted = table.tablename.replace('"', "\"\"");
        let query = format!(
            "SELECT COUNT(*) AS rows, \
             md5(COALESCE(string_agg(row_to_json(t)::text, '' ORDER BY row_to_json(t)::text), '')) AS digest \
             FROM public.\"{quoted}\" t"
        );
        let contents = diesel::sql_query(query)
            .get_result::<Contents>(&mut conn)
            .await
            .unwrap();
        snapshot.push((table.tablename, contents.rows, contents.digest));
    }
    snapshot
}

#[tokio::test]
async fn unknown_temporal_refusals_cannot_be_bleached_and_write_nothing() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    for (name, recurrence) in [
        (
            "timezone",
            serde_json::json!({"frequency":"daily", "timezone":"Missing/Zone"}),
        ),
        (
            "frequency",
            serde_json::json!({"frequency":"monthly", "timezone":"UTC"}),
        ),
    ] {
        for effect in ["deny", "quarantine", "require_review"] {
            let label = format!("unknown-{name}-{effect}").replace('_', "-");
            let member = local(&pool, &label).await;
            let discussion = discussion(&pool, &label, &member).await;
            let open = grant(
                &pool,
                &discussion,
                &discussion.head.authority_commit,
                &member,
                &["ak.message.create"],
                serde_json::json!([]),
            )
            .await;
            uow.commit_event(open.clone()).await.unwrap();
            let control = message(
                &pool,
                &discussion,
                &open.authority_commit,
                &member,
                "allowed",
            )
            .await;
            uow.commit_event(control.clone()).await.unwrap();
            let refusing = grant(
                &pool,
                &discussion,
                &control.authority_commit,
                &member,
                &["ak.message.create"],
                serde_json::json!([{
                    "constraint_kind":"temporal", "constraint_subkind":"window",
                    "effect":effect, "recurrence":recurrence,
                }]),
            )
            .await;
            uow.commit_event(refusing.clone()).await.unwrap();
            let request = message(
                &pool,
                &discussion,
                &refusing.authority_commit,
                &member,
                "refused",
            )
            .await;
            let before = durable_rows(&pool).await;
            let quota_before = quota_consumed(&pool).await;
            assert_refused(
                &pool,
                &uow,
                request,
                if effect == "deny" {
                    ConflictCode::CapabilityDenied
                } else {
                    ConflictCode::FailedPrecondition
                },
            )
            .await;
            assert_eq!(durable_rows(&pool).await, before, "{name}: {effect}");
            assert_eq!(quota_consumed(&pool).await, quota_before);
        }
    }
}

#[tokio::test]
async fn a_rate_quota_is_reserved_with_the_event_it_admits() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = local(&pool, "quota-alice").await;
    let discussion = discussion(&pool, "quota-realm", &alice).await;
    let quota = grant(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([{
            "constraint_kind": "quota",
            "constraint_subkind": "rate",
            "effect": "allow",
            "max_operation_count": 1,
            "period": "P1D",
            "constraint_scope": "per_realm"
        }]),
    )
    .await;
    uow.commit_event(quota.clone()).await.unwrap();
    let first = message(&pool, &discussion, &quota.authority_commit, &alice, "first").await;
    uow.commit_event(first.clone()).await.unwrap();
    assert_eq!(quota_consumed(&pool).await, 1);
    // An exact retry of the admitted Event does not count again.
    uow.commit_event(first.clone()).await.unwrap();
    assert_eq!(quota_consumed(&pool).await, 1);
    assert_refused(
        &pool,
        &uow,
        message(
            &pool,
            &discussion,
            &first.authority_commit,
            &alice,
            "second",
        )
        .await,
        ConflictCode::RateLimited,
    )
    .await;
    assert_eq!(quota_consumed(&pool).await, 1);
    // The root controller's owner aggregate owes no quota.
    uow.commit_event(
        message(
            &pool,
            &discussion,
            &first.authority_commit,
            &founder_actor(),
            "owner",
        )
        .await,
    )
    .await
    .unwrap();
    assert_eq!(quota_consumed(&pool).await, 1);
}

#[tokio::test]
async fn a_deny_constraint_of_any_grant_refuses_and_recurrence_bounds_a_grant() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = local(&pool, "deny-alice").await;
    let discussion = discussion(&pool, "deny-realm", &alice).await;
    let open = grant(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([]),
    )
    .await;
    uow.commit_event(open.clone()).await.unwrap();
    let hello = message(&pool, &discussion, &open.authority_commit, &alice, "hello").await;
    uow.commit_event(hello.clone()).await.unwrap();
    let denying = grant(
        &pool,
        &discussion,
        &hello.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([{
            "constraint_kind": "scope_limitation",
            "effect": "deny",
            "denied_strand_ids": [discussion.strand_id]
        }]),
    )
    .await;
    uow.commit_event(denying.clone()).await.unwrap();
    assert_refused(
        &pool,
        &uow,
        message(
            &pool,
            &discussion,
            &denying.authority_commit,
            &alice,
            "denied",
        )
        .await,
        ConflictCode::CapabilityDenied,
    )
    .await;

    // Bob's only grant is valid on a weekday hour the accepting commit is
    // not in: its window is never satisfied.
    let bob = local(&pool, "deny-bob").await;
    let bob_join = by(
        &pool,
        &denying.authority_commit,
        arkret_wire::EventKind::MemberState,
        &bob,
        serde_json::json!({
            "realm_id": discussion.realm_id,
            "member_id": bob,
            "membership": "join",
            "reason": "fixture join",
        }),
    )
    .await;
    uow.commit_event(bob_join.clone()).await.unwrap();
    let committed_at = bob_join.authority_commit.commit.committed_at;
    let closed_hour = (committed_at + chrono::TimeDelta::hours(12))
        .format("%H:00")
        .to_string();
    let closed_end = (committed_at + chrono::TimeDelta::hours(13))
        .format("%H:00")
        .to_string();
    let windowed = grant(
        &pool,
        &discussion,
        &bob_join.authority_commit,
        &bob,
        &["ak.message.create"],
        serde_json::json!([{
            "constraint_kind": "temporal",
            "constraint_subkind": "window",
            "effect": "allow",
            "recurrence": {
                "frequency": "daily",
                "window_start": closed_hour,
                "window_end": closed_end,
                "timezone": "UTC"
            }
        }]),
    )
    .await;
    uow.commit_event(windowed.clone()).await.unwrap();
    assert_refused(
        &pool,
        &uow,
        message(
            &pool,
            &discussion,
            &windowed.authority_commit,
            &bob,
            "off hours",
        )
        .await,
        ConflictCode::CapabilityDenied,
    )
    .await;
}

#[tokio::test]
async fn an_archived_realm_admits_only_its_exemption_set() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = local(&pool, "archive-alice").await;
    let discussion = discussion(&pool, "archive-realm", &alice).await;
    let admin = grant(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([]),
    )
    .await;
    uow.commit_event(admin.clone()).await.unwrap();
    let archive = by(
        &pool,
        &admin.authority_commit,
        arkret_wire::EventKind::RealmArchive,
        &founder_actor(),
        serde_json::json!({"reason": "fixture archive"}),
    )
    .await;
    uow.commit_event(archive.clone()).await.unwrap();
    assert_refused(
        &pool,
        &uow,
        message(
            &pool,
            &discussion,
            &archive.authority_commit,
            &alice,
            "archived",
        )
        .await,
        ConflictCode::RealmFrozen,
    )
    .await;
    assert_refused(
        &pool,
        &uow,
        grant(
            &pool,
            &discussion,
            &archive.authority_commit,
            &alice,
            &["ak.realm.admin"],
            serde_json::json!([]),
        )
        .await,
        ConflictCode::RealmFrozen,
    )
    .await;
    // Revocation is in the exemption set.
    let revoke = by(
        &pool,
        &archive.authority_commit,
        arkret_wire::EventKind::CapabilityRevoke,
        &founder_actor(),
        serde_json::json!({
            "grant_id": arkret_wire::GrantId::from_event_id(&admin.authority_commit.event.event_id),
            "expected_revision": {
                "commit_id": admin.authority_commit.commit.commit_id,
                "stream_position": admin.authority_commit.commit.stream_position,
            },
        }),
    )
    .await;
    uow.commit_event(revoke.clone()).await.unwrap();
    let restore = by(
        &pool,
        &revoke.authority_commit,
        arkret_wire::EventKind::RealmRestore,
        &founder_actor(),
        serde_json::json!({"reason": "fixture restore"}),
    )
    .await;
    uow.commit_event(restore.clone()).await.unwrap();
    uow.commit_event(
        message(
            &pool,
            &discussion,
            &restore.authority_commit,
            &founder_actor(),
            "restored",
        )
        .await,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn an_admission_waiting_on_the_realm_lock_observes_a_concurrent_revocation() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = local(&pool, "lock-alice").await;
    let discussion = discussion(&pool, "lock-realm", &alice).await;
    let writer = grant(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([]),
    )
    .await;
    uow.commit_event(writer.clone()).await.unwrap();
    let grant_id = arkret_wire::GrantId::from_event_id(&writer.authority_commit.event.event_id);

    // A concurrent Realm-stream writer holds the authority row lock and
    // closes the grant inside its still-open transaction.
    let mut holder = pool.get().await.unwrap();
    holder.batch_execute("BEGIN").await.unwrap();
    diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(discussion.realm_id.as_str())
        .execute(&mut *holder)
        .await
        .unwrap();
    diesel::sql_query(
        "UPDATE capability_grant_current_states \
         SET status='revoked',value=jsonb_set(value,'{status}','\"revoked\"') \
         WHERE realm_id=$1 AND grant_id=$2",
    )
    .bind::<Text, _>(discussion.realm_id.as_str())
    .bind::<Text, _>(grant_id.as_str())
    .execute(&mut *holder)
    .await
    .unwrap();

    let waiting = message(
        &pool,
        &discussion,
        &writer.authority_commit,
        &alice,
        "racing",
    )
    .await;
    let event_id = waiting.authority_commit.event.event_id.clone();
    let task_pool = pool.clone();
    let admission = tokio::spawn(async move {
        PgEventCommitUnitOfWork::new(task_pool)
            .commit_event(waiting)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        !admission.is_finished(),
        "the admission waits for the Realm authority lock"
    );
    holder.batch_execute("COMMIT").await.unwrap();
    let error = admission.await.unwrap().unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(ConflictCode::CapabilityDenied),
        "{error}"
    );
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn grant_admission_requires_the_registered_strand_field_allowance_without_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let member = local(&pool, "required-field-grantee").await;
    let discussion = discussion(&pool, "required-field-admission", &member).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());

    for constraints in [
        serde_json::json!([]),
        serde_json::json!([{
            "constraint_kind":"field_access", "effect":"allow",
            "allowed_write_fields":[]
        }]),
        serde_json::json!([{
            "constraint_kind":"field_access", "effect":"allow",
            "applies_to_actions":["ak.morph.update"],
            "allowed_write_fields":["content", "encrypted_content"]
        }]),
    ] {
        let candidate = grant(
            &pool,
            &discussion,
            &discussion.head.authority_commit,
            &member,
            &["ak.strand.update", "ak.morph.update"],
            constraints,
        )
        .await;
        let before = durable_rows(&pool).await;
        assert_refused(&pool, &uow, candidate, ConflictCode::FailedPrecondition).await;
        assert_eq!(durable_rows(&pool).await, before);
    }

    let permission = grant(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        &member,
        &["ak.strand.update"],
        serde_json::json!([{
            "constraint_kind":"field_access", "effect":"allow",
            "allowed_write_fields":["content", "encrypted_content"]
        }]),
    )
    .await;
    uow.commit_event(permission).await.unwrap();
}

#[tokio::test]
async fn strand_patch_exact_resource_and_field_grant_are_decided_at_the_pg_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let member = local(&pool, "strand-field-editor").await;
    let discussion = discussion(&pool, "strand-field-grant-cut", &member).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut permission = grant(
        &pool,
        &discussion,
        &discussion.head.authority_commit,
        &member,
        &["ak.strand.update"],
        serde_json::json!([{
            "constraint_kind":"field_access",
            "effect":"allow",
            "allowed_write_fields":["metadata.title"]
        }]),
    )
    .await;
    permission
        .authority_commit
        .event
        .payload
        .get_mut("grant")
        .unwrap()["resources"] = serde_json::json!([arkret_wire::WireResourceSelector::strand(
        discussion.realm_id.clone(),
        discussion.strand_id.clone()
    )]);
    ordinary_realm::reseal(&mut permission.authority_commit.event);
    permission = ordinary_realm::request_for_event(
        &discussion.head.authority_commit,
        permission.authority_commit.event,
        discussion.head.authority_commit.commit.committed_at,
    );
    permission = ordinary_realm::source_request(&pool, permission).await;
    uow.commit_event(permission.clone()).await.unwrap();
    let allowed = by(
        &pool,
        &permission.authority_commit,
        arkret_wire::EventKind::StrandUpdate,
        &member,
        serde_json::json!({
            "target_ref": discussion.strand_id,
            "patch":{"metadata.title":{"$op":"set","value":"Authorized title"}}
        }),
    )
    .await;
    uow.commit_event(allowed.clone()).await.unwrap();
    let before = PgAuthorityCommitStore { pool: pool.clone() }
        .realm_state_snapshot_material(&discussion.realm_id)
        .await
        .unwrap()
        .unwrap();
    for payload in [
        serde_json::json!({
            "target_ref":discussion.strand_id,
            "patch":{"metadata.summary":{"$op":"set","value":"Unpermitted field"}}
        }),
        serde_json::json!({
            "target_ref":arkret_wire::StrandId::from_event_id(&permission.authority_commit.event.event_id),
            "patch":{"metadata.title":{"$op":"set","value":"Unpermitted target"}}
        }),
    ] {
        let refused = by(
            &pool,
            &allowed.authority_commit,
            arkret_wire::EventKind::StrandUpdate,
            &member,
            payload,
        )
        .await;
        #[derive(diesel::QueryableByName, Debug, PartialEq)]
        struct Counts {
            #[diesel(sql_type = BigInt)]
            events: i64,
            #[diesel(sql_type = BigInt)]
            commits: i64,
        }
        let mut conn = pool.get().await.unwrap();
        let query = "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS events, \
                     (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS commits";
        let counts: Counts = diesel::sql_query(query)
            .bind::<Text, _>(discussion.realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_refused(&pool, &uow, refused, ConflictCode::CapabilityDenied).await;
        let after_counts: Counts = diesel::sql_query(query)
            .bind::<Text, _>(discussion.realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_eq!(counts, after_counts);
        assert_eq!(
            PgAuthorityCommitStore { pool: pool.clone() }
                .realm_state_snapshot_material(&discussion.realm_id)
                .await
                .unwrap()
                .unwrap(),
            before,
        );
    }
}
