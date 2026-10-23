//! Real PostgreSQL executor of the shared Pin admission fixture.
//! Accepted Human PCR and Profile fixtures exercise the storage admission boundary.

#[path = "../tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
use coland_storage::EventCommitUnitOfWork;
use diesel::sql_types::{BigInt, Text};
use horme::RunQueryDsl;
use ordinary_realm::{next_request, open_discussion};
use serde_json::{Value, json};

use crate::{PgEventCommitUnitOfWork, PgPool, TestDatabase};

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn founder() -> arkret_wire::DidCoreId {
    ordinary_realm::human_profile::account(&ordinary_realm::station(), "ordinary-founder")
        .principal_id
}

pub async fn run_pin_admission_fixture() -> Vec<(&'static str, usize)> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../arkret-spec/spec/v1/artifacts/fixtures/shared-pin-admission-fixture.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["runner"]["entrypoint"],
        "ak.suite.pin.admission_and_scope.v1"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    let case = |id: &str| cases.iter().find(|case| case["case_id"] == id).unwrap();
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = Box::pin(open_discussion(&pool, "pin-admission")).await;
    let realm = discussion.realm_id();
    let at = discussion.committed_at();
    let message = crate::boxed_future(|| {
        ordinary_realm::source_request(
            &pool,
            discussion.message_after(&discussion.head.authority_commit, "pin this", at),
        )
    })
    .await;
    crate::boxed_future(|| uow.commit_event(message.clone()))
        .await
        .unwrap();
    let target = arkret_wire::MessageId::from_event_id(&message.authority_commit.event.event_id);
    let home = json!({"kind":"strand","id":discussion.strand_id});
    let add = json!({"pin_scope":home,"target_ref":target,"rank":"a0"});
    let no_grant = crate::boxed_future(|| {
        ordinary_realm::source_request(
            &pool,
            next_request(
                &message.authority_commit,
                arkret_wire::EventKind::PinAdd,
                &founder(),
                add.clone(),
                at,
            ),
        )
    })
    .await;
    let baseline = count(&pool, "realm_commits", &realm).await;
    assert!(
        crate::boxed_future(|| uow.commit_event(no_grant))
            .await
            .unwrap_err()
            .to_string()
            .contains(
                case("owner_without_explicit_pin_grant")["expected_error_code"]
                    .as_str()
                    .unwrap()
            )
    );
    assert_eq!(
        count(&pool, "realm_commits", &realm).await - baseline,
        case("owner_without_explicit_pin_grant")["expected_committed_writes"]
            .as_i64()
            .unwrap()
    );
    let grant = crate::boxed_future(|| ordinary_realm::source_request(&pool, next_request(
        &message.authority_commit,
        arkret_wire::EventKind::CapabilityGrant,
        &founder(),
        json!({"grant":{
            "schema":arkret_wire::SchemaId::CAPABILITY_V1,"realm_id":realm,"issuer_id":founder_actor(),"subject":founder_actor(),
            "actions":fixture["owner_grant_actions"],"resources":[{"kind":"realm","realm_id":realm}],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":discussion.unit.transactions[0].event.event_id,"authority_generation":0}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    ))).await;
    crate::boxed_future(|| uow.commit_event(grant.clone()))
        .await
        .unwrap();
    let reorder = crate::boxed_future(|| {
        ordinary_realm::source_request(
            &pool,
            next_request(
                &grant.authority_commit,
                arkret_wire::EventKind::PinReorder,
                &founder(),
                json!({"pin_scope":home,"target_ref":target,"rank":"b0"}),
                at,
            ),
        )
    })
    .await;
    let baseline = count(&pool, "realm_commits", &realm).await;
    assert!(
        crate::boxed_future(|| uow.commit_event(reorder))
            .await
            .unwrap_err()
            .to_string()
            .contains(
                case("reorder_before_add")["expected_reason_code"]
                    .as_str()
                    .unwrap()
            )
    );
    assert_eq!(
        count(&pool, "realm_commits", &realm).await - baseline,
        case("reorder_before_add")["expected_committed_writes"]
            .as_i64()
            .unwrap()
    );
    let add = crate::boxed_future(|| {
        ordinary_realm::source_request(
            &pool,
            next_request(
                &grant.authority_commit,
                arkret_wire::EventKind::PinAdd,
                &founder(),
                add,
                at,
            ),
        )
    })
    .await;
    crate::boxed_future(|| uow.commit_event(add.clone()))
        .await
        .unwrap();
    let stale = crate::boxed_future(|| {
        ordinary_realm::source_request(
            &pool,
            next_request(
                &add.authority_commit,
                arkret_wire::EventKind::PinReorder,
                &founder(),
                json!({"pin_scope":home,"target_ref":target,"rank":"b0","expected_rank":"wrong"}),
                at,
            ),
        )
    })
    .await;
    let baseline = count(&pool, "realm_commits", &realm).await;
    assert!(
        crate::boxed_future(|| uow.commit_event(stale))
            .await
            .unwrap_err()
            .to_string()
            .contains("expected_rank")
    );
    assert_eq!(
        count(&pool, "realm_commits", &realm).await - baseline,
        case("stale_rank")["expected_committed_writes"]
            .as_i64()
            .unwrap()
    );
    let reorder = crate::boxed_future(|| {
        ordinary_realm::source_request(
            &pool,
            next_request(
                &add.authority_commit,
                arkret_wire::EventKind::PinReorder,
                &founder(),
                json!({"pin_scope":home,"target_ref":target,"rank":"b0","expected_rank":"a0"}),
                at,
            ),
        )
    })
    .await;
    crate::boxed_future(|| uow.commit_event(reorder.clone()))
        .await
        .unwrap();
    let remove = crate::boxed_future(|| {
        ordinary_realm::source_request(
            &pool,
            next_request(
                &reorder.authority_commit,
                arkret_wire::EventKind::PinRemove,
                &founder(),
                json!({"pin_scope":home,"target_ref":target,"expected_rank":"b0"}),
                at,
            ),
        )
    })
    .await;
    crate::boxed_future(|| uow.commit_event(remove.clone()))
        .await
        .unwrap();
    let resurrect = crate::boxed_future(|| {
        ordinary_realm::source_request(
            &pool,
            next_request(
                &remove.authority_commit,
                arkret_wire::EventKind::PinReorder,
                &founder(),
                json!({"pin_scope":home,"target_ref":target,"rank":"c0"}),
                at,
            ),
        )
    })
    .await;
    let baseline = count(&pool, "realm_commits", &realm).await;
    assert!(
        crate::boxed_future(|| uow.commit_event(resurrect))
            .await
            .unwrap_err()
            .to_string()
            .contains(
                case("reorder_after_remove")["expected_reason_code"]
                    .as_str()
                    .unwrap()
            )
    );
    assert_eq!(
        count(&pool, "realm_commits", &realm).await - baseline,
        case("reorder_after_remove")["expected_committed_writes"]
            .as_i64()
            .unwrap()
    );
    let snapshot = coland_storage_postgres::account_snapshot_material(
        &pool,
        &realm,
        &arkret_wire::AccountId::new(founder(), ordinary_realm::station()),
    )
    .await
    .unwrap()
    .unwrap();
    let pin = snapshot
        .current_state_entries
        .iter()
        .find_map(|entry| match entry {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Pin { .. },
                value,
                ..
            } => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        pin["assertions"].as_array().unwrap().len() as u64,
        case("dot_set_keeps_add_reorder_remove")["expected_assertion_count"]
            .as_u64()
            .unwrap()
    );
    let other = Box::pin(open_discussion(&pool, "foreign-pin-target")).await;
    let foreign = other.message_after(&other.head.authority_commit, "private foreign message", at);
    crate::boxed_future(|| uow.commit_event(foreign.clone()))
        .await
        .unwrap();
    let forbidden = crate::boxed_future(|| ordinary_realm::source_request(&pool, next_request(
        &remove.authority_commit,
        arkret_wire::EventKind::PinAdd,
        &founder(),
        json!({"pin_scope":home,"target_ref":arkret_wire::MessageId::from_event_id(&foreign.authority_commit.event.event_id),"rank":"d0"}),
        at,
    ))).await;
    let baseline = count(&pool, "realm_commits", &realm).await;
    assert_eq!(
        case("foreign_or_hidden_target")["expected_error_code"],
        "not_found"
    );
    assert!(matches!(
        crate::boxed_future(|| uow.commit_event(forbidden))
            .await
            .unwrap_err(),
        coland_storage::PersistenceError::NotFound(_)
    ));
    assert_eq!(
        count(&pool, "realm_commits", &realm).await - baseline,
        case("foreign_or_hidden_target")["expected_committed_writes"]
            .as_i64()
            .unwrap()
    );
    vec![
        ("owner_without_explicit_pin_grant", 2),
        ("reorder_before_add", 2),
        ("reorder_after_remove", 2),
        ("foreign_or_hidden_target", 3),
        ("stale_rank", 2),
        ("dot_set_keeps_add_reorder_remove", 1),
    ]
}

async fn count(pool: &PgPool, table: &str, realm_id: &arkret_wire::RealmId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    let row: Count = diesel::sql_query(format!(
        "SELECT COUNT(*) AS count FROM {table} WHERE realm_id=$1"
    ))
    .bind::<Text, _>(realm_id.as_str())
    .get_result(&mut conn)
    .await
    .unwrap();
    row.count
}

fn founder_actor() -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        founder(),
        ordinary_realm::station(),
    ))
}
