//! 2040-M04: the grantee is a third native Human, never either controller.
//!
//! Every positive and refusal crosses the real PostgreSQL Event UoW. The
//! existing native Owner fixture supplies accepted PCR/Device/Profile sources
//! and finite C consent. This is not a deployed peer/HTTP test.

use std::future::Future;
use std::pin::Pin;

use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, IssuerAuthorityRef,
};
use arkret_wire::{ActorId, EventKind, GrantId, RealmAuthorityRootValue, RealmId, StrandId};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CapabilityGrantCurrentStateRecord,
    CapabilityGrantCurrentStateStore, CapabilityGrantCurrentStatus, ConflictCode,
    EventCommitRequest, EventCommitUnitOfWork,
};
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgCapabilityGrantCurrentStateStore, PgEventCommitUnitOfWork, PgPool,
};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

use super::{native_owner, ordinary_realm};

type CaseFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

fn by<'a>(
    pool: &'a PgPool,
    previous: &'a AuthorityCommitTransaction,
    kind: EventKind,
    actor: &'a ActorId,
    payload: Value,
) -> CaseFuture<'a, EventCommitRequest> {
    Box::pin(async move {
        let request = ordinary_realm::next_human_request_for_actor(
            previous,
            kind,
            actor.clone(),
            payload,
            native_owner::now(),
        );
        ordinary_realm::case_future(|| ordinary_realm::source_request(pool, request)).await
    })
}

fn grant_payload(
    realm: &RealmId,
    root: &RealmAuthorityRootValue,
    issuer: &ActorId,
    subject: &ActorId,
) -> Value {
    let at = native_owner::now();
    let source = IssuerAuthorityRef::RealmRoot {
        realm_id: realm.clone(),
        authority_event_ref: root.authority_event_ref.clone(),
        authority_generation: root.authority_generation,
    };
    json!({"grant":{
        "schema":"ak.schema.capability.v1", "realm_id":realm,
        "issuer_id":issuer, "subject":subject, "actions":["ak.message.create"],
        "resources":[{"kind":"realm","realm_id":realm}],
        "constraints":[{"constraint_kind":"temporal","constraint_subkind":"window",
            "effect":"allow","expires_at":arkret_canonical::format_timestamp_canonical(
                at + chrono::TimeDelta::minutes(15))}],
        "issuer_authority_refs":[source],
        "issued_at":arkret_canonical::format_timestamp_canonical(at)
    }})
}

fn grant_row(row: &CapabilityGrantCurrentStateRecord) -> Value {
    let status = match row.status {
        CapabilityGrantCurrentStatus::Active => "active",
        CapabilityGrantCurrentStatus::Revoked => "revoked",
        CapabilityGrantCurrentStatus::Relinquished => "relinquished",
    };
    json!({"realm_id":row.realm_id,"grant_id":row.grant_id,"status":status,
        "value":row.value,"revision":row.revision,"source":row.source})
}

#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn default_strand(pool: &PgPool, realm: &RealmId) -> StrandId {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT value FROM realm_set_default_strand_current_states WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<JsonRow>(&mut conn)
    .await
    .unwrap();
    serde_json::from_value(row.value["default_strand_id"].clone()).unwrap()
}

#[derive(diesel::QueryableByName)]
struct TableRow {
    #[diesel(sql_type = Text)]
    tablename: String,
}

#[derive(diesel::QueryableByName)]
struct TableContents {
    #[diesel(sql_type = BigInt)]
    rows: i64,
    #[diesel(sql_type = Text)]
    digest: String,
}

/// Compare every public table, including Events, stream heads, projections,
/// quota/approval reservations and retained signer material, around a refusal.
async fn durable_rows(pool: &PgPool) -> Vec<(String, i64, String)> {
    let mut conn = pool.get().await.unwrap();
    let tables = diesel::sql_query(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
    )
    .load::<TableRow>(&mut conn)
    .await
    .unwrap();
    let mut result = Vec::new();
    for table in tables {
        let quoted = table.tablename.replace('"', "\"\"");
        let query = format!(
            "SELECT COUNT(*) AS rows, \
             md5(COALESCE(string_agg(row_to_json(t)::text, '' ORDER BY row_to_json(t)::text), '')) AS digest \
             FROM public.\"{quoted}\" t"
        );
        let row = diesel::sql_query(query)
            .get_result::<TableContents>(&mut conn)
            .await
            .unwrap();
        result.push((table.tablename, row.rows, row.digest));
    }
    result
}

fn refuse_without_writes<'a>(
    pool: &'a PgPool,
    uow: &'a PgEventCommitUnitOfWork,
    request: EventCommitRequest,
    expected: ConflictCode,
) -> CaseFuture<'a, ()> {
    Box::pin(async move {
        let before = durable_rows(pool).await;
        let event_id = request.authority_commit.event.event_id.clone();
        let error = uow.commit_event(request).await.unwrap_err();
        assert_eq!(error.conflict_code(), Some(expected), "{error}");
        assert!(
            PgAuthorityCommitStore { pool: pool.clone() }
                .committed_event(&event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(durable_rows(pool).await, before, "refusal must be atomic");
    })
}

fn accept<'a>(
    uow: &'a PgEventCommitUnitOfWork,
    request: &'a EventCommitRequest,
) -> CaseFuture<'a, ()> {
    Box::pin(async move {
        uow.commit_event(request.clone()).await.unwrap();
    })
}

#[tokio::test]
async fn third_grantees_accepted_authority_survives_owner_transfer_but_revocation_never_revives() {
    ordinary_realm::case_future(|| async {
        let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let native = ordinary_realm::case_future(|| {
            native_owner::prepared(&pool, "third-grantee-owner-transfer")
        })
        .await;
        let (member, joined) = ordinary_realm::case_future(|| {
            native.joined_human_after(native.accepted_predecessor(), "owner-third-grantee-d")
        })
        .await;
        assert_ne!(member, native.author);
        assert_ne!(member, native.successor);
        let a = ActorId::account(native.author.clone());
        let b = ActorId::account(native.successor.clone());
        let d = ActorId::account(member);
        let strand = default_strand(&pool, &native.realm).await;
        let root: RealmAuthorityRootValue =
            serde_json::from_value(native_owner::root_value(&pool, &native.realm).await).unwrap();
        assert_eq!(root.controller_actor_id, a);
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let grants = PgCapabilityGrantCurrentStateStore { pool: pool.clone() };

        // This member is not an implicit root or a public-policy substitute.
        let ungranted = by(
            &pool,
            &joined,
            EventKind::MessageCreate,
            &d,
            ordinary_realm::message_payload(&strand, "D before any Grant"),
        )
        .await;
        refuse_without_writes(&pool, &uow, ungranted, ConflictCode::CapabilityDenied).await;

        let original = by(
            &pool,
            &joined,
            EventKind::CapabilityGrant,
            &a,
            grant_payload(&native.realm, &root, &a, &d),
        )
        .await;
        accept(&uow, &original).await;
        let grant_id = GrantId::from_event_id(&original.authority_commit.event.event_id);
        let active = grants.get(&native.realm, &grant_id).await.unwrap().unwrap();
        assert_eq!(active.status, CapabilityGrantCurrentStatus::Active);
        assert_eq!(
            active.source.event_id,
            original.authority_commit.event.event_id
        );
        assert_eq!(
            active.revision.commit_id,
            original.authority_commit.commit.commit_id
        );
        assert_eq!(active.value.issuer_id, a);
        assert_eq!(active.value.issuer_authority_refs.len(), 1);
        assert_eq!(
            active.value.issuer_authority_refs,
            vec![IssuerAuthorityRef::RealmRoot {
                realm_id: native.realm.clone(),
                authority_event_ref: root.authority_event_ref.clone(),
                authority_generation: root.authority_generation,
            }]
        );
        assert_eq!(active.value.authority_depth, 1);
        assert_eq!(
            active.value.authority_root_ref,
            AuthorityRootRef::RealmRoot {
                realm_id: native.realm.clone(),
                authority_event_ref: root.authority_event_ref.clone(),
                authority_generation: root.authority_generation,
            }
        );
        let expires_at = active
            .value
            .constraints
            .iter()
            .filter_map(|constraint| constraint.expires_at.as_ref())
            .min()
            .copied()
            .expect("the accepted original carries its real finite window");
        let original_stored = native
            .store
            .committed_event(&original.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original_stored.event, original.authority_commit.event);
        assert_eq!(original_stored.commit, original.authority_commit.commit);
        let active_json = grant_row(&active);

        let first = by(
            &pool,
            &original.authority_commit,
            EventKind::MessageCreate,
            &d,
            ordinary_realm::message_payload(&strand, "D exercises A's accepted Grant"),
        )
        .await;
        accept(&uow, &first).await;
        let transfer = ordinary_realm::case_future(|| {
            native.transfer_after(
                &first.authority_commit,
                &native.author,
                &native.successor,
                "owner-successor-third-grantee-owner-transfer",
            )
        })
        .await;
        accept(&uow, &transfer.request).await;
        let after: RealmAuthorityRootValue =
            serde_json::from_value(native_owner::root_value(&pool, &native.realm).await).unwrap();
        assert_eq!(after.controller_actor_id, b);
        assert_ne!(after.controller_actor_id, d);
        assert_eq!(after.controller_epoch, root.controller_epoch + 1);
        assert_eq!(after.authority_generation, root.authority_generation);
        assert_eq!(after.authority_event_ref, root.authority_event_ref);
        assert_eq!(
            grant_row(&grants.get(&native.realm, &grant_id).await.unwrap().unwrap()),
            active_json,
            "transfer must not rewrite the already accepted Grant"
        );

        let surviving = by(
            &pool,
            &transfer.request.authority_commit,
            EventKind::MessageCreate,
            &d,
            ordinary_realm::message_payload(&strand, "D still uses A's original Grant under B"),
        )
        .await;
        assert!(surviving.authority_commit.commit.committed_at < expires_at);
        accept(&uow, &surviving).await;
        assert!(native_owner::now() < expires_at);
        assert_eq!(
            native
                .store
                .committed_event(&original.authority_commit.event.event_id)
                .await
                .unwrap()
                .unwrap(),
            original_stored,
            "D used A's retained accepted original, not a reissued Grant"
        );

        // A's former controller status cannot approve a new root-sourced Grant.
        let old_a_new_grant = by(
            &pool,
            &surviving.authority_commit,
            EventKind::CapabilityGrant,
            &a,
            grant_payload(&native.realm, &root, &a, &d),
        )
        .await;
        refuse_without_writes(&pool, &uow, old_a_new_grant, ConflictCode::CapabilityDenied).await;

        let revoke = by(
            &pool,
            &surviving.authority_commit,
            EventKind::CapabilityRevoke,
            &b,
            json!({"grant_id":grant_id,"expected_commit_id":active.revision.commit_id}),
        )
        .await;
        accept(&uow, &revoke).await;
        let revoked = grants.get(&native.realm, &grant_id).await.unwrap().unwrap();
        assert_eq!(revoked.status, CapabilityGrantCurrentStatus::Revoked);
        assert_eq!(
            revoked.source.event_id,
            revoke.authority_commit.event.event_id
        );
        assert_eq!(
            revoked.revision.commit_id,
            revoke.authority_commit.commit.commit_id
        );
        let revoked_json = grant_row(&revoked);
        let under_b = by(
            &pool,
            &revoke.authority_commit,
            EventKind::MessageCreate,
            &d,
            ordinary_realm::message_payload(&strand, "B revoked D's accepted Grant"),
        )
        .await;
        assert!(under_b.authority_commit.commit.committed_at < expires_at);
        refuse_without_writes(&pool, &uow, under_b, ConflictCode::CapabilityDenied).await;
        assert!(
            native_owner::now() < expires_at,
            "the refusal must be caused by revocation while the original window remains open"
        );
        let return_to_a = ordinary_realm::case_future(|| {
            native.transfer_after(
                &revoke.authority_commit,
                &native.successor,
                &native.author,
                "ordinary-founder",
            )
        })
        .await;
        accept(&uow, &return_to_a.request).await;
        let returned: RealmAuthorityRootValue =
            serde_json::from_value(native_owner::root_value(&pool, &native.realm).await).unwrap();
        assert_eq!(returned.controller_actor_id, a);
        assert_ne!(returned.controller_actor_id, d);
        assert_eq!(returned.controller_epoch, root.controller_epoch + 2);
        assert_eq!(returned.authority_generation, root.authority_generation);
        assert_eq!(returned.authority_event_ref, root.authority_event_ref);
        assert_eq!(
            grant_row(&grants.get(&native.realm, &grant_id).await.unwrap().unwrap()),
            revoked_json,
            "returning to A cannot rewrite or resurrect its revoked Grant"
        );
        let not_revived = by(
            &pool,
            &return_to_a.request.authority_commit,
            EventKind::MessageCreate,
            &d,
            ordinary_realm::message_payload(&strand, "A returned, but D's Grant is revoked"),
        )
        .await;
        assert!(not_revived.authority_commit.commit.committed_at < expires_at);
        refuse_without_writes(&pool, &uow, not_revived, ConflictCode::CapabilityDenied).await;
        assert!(
            native_owner::now() < expires_at,
            "a slow runner must not let expiry disguise revival of a revoked Grant"
        );
        assert_eq!(
            native
                .store
                .committed_event(&original.authority_commit.event.event_id)
                .await
                .unwrap()
                .unwrap(),
            original_stored,
            "revoke and both transfers preserve A's immutable original"
        );
    })
    .await;
}
