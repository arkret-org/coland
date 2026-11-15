//! Large active Reaction shapes use the original atomic snapshot budget.

use coland_storage::{AuthorityCommitTransaction, ConflictCode, EventCommitRequest};

use super::reaction_scale::{batch, current, sourced_reaction};
use super::*;

const ACTIVE_KEYS_PER_TRANSACTION: usize = 64;
const MAX_ACTIVE_KEYS: usize = 40_000;

fn active_key(index: usize) -> String {
    format!("k{index:07}{}", "x".repeat(120))
}

async fn write_summary(
    pool: &PgPool,
    previous: &AuthorityCommitTransaction,
    target: &arkret_wire::MessageId,
) -> Value {
    let mut projection = current(pool, target).await;
    let active = projection.as_object_mut().unwrap().remove("value").unwrap();
    projection["value_digest"] = json!(arkret_canonical::canonical_sha256(&active).unwrap());
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let mut conn = pool.get().await.unwrap();
    let durable = diesel::sql_query(
        r#"SELECT jsonb_build_object(
          'events',(SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1),
          'commits',(SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1),
          'projection_events',(SELECT COUNT(*) FROM projection_events WHERE realm_id=$1),
          'approval',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text),'[]') FROM event_approval_private_audit a WHERE realm_id=$1),
          'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM federation_outbox o),
          'event_outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM event_federation_outbox o),
          'quota_consumptions',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM capability_quota_consumptions q JOIN capability_grant_current_states g ON g.grant_id=q.grant_id WHERE g.realm_id=$1),
          'quota_counters',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM capability_quota_counters q JOIN capability_grant_current_states g ON g.grant_id=q.grant_id WHERE g.realm_id=$1),
          'quota_buckets',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM capability_quota_buckets q JOIN capability_grant_current_states g ON g.grant_id=q.grant_id WHERE g.realm_id=$1)
        ) AS value"#,
    )
    .bind::<Text, _>(previous.event.realm_id.as_str())
    .get_result::<ValueRow>(&mut conn)
    .await
    .unwrap()
    .value;
    drop(conn);
    json!({"projection":projection,"durable":durable,"head":store.stream_head(&previous.commit.stream_ref).await.unwrap()})
}

async fn additions(
    pool: &PgPool,
    previous: &AuthorityCommitTransaction,
    target: &arkret_wire::MessageId,
    first: usize,
    count: usize,
) -> Vec<EventCommitRequest> {
    let mut previous = previous.clone();
    let mut events = Vec::with_capacity(count);
    for index in first..first + count {
        let add = sourced_reaction(
            pool,
            &previous,
            target,
            arkret_wire::EventKind::ReactionAdd,
            &active_key(index),
            previous.commit.committed_at + chrono::Duration::milliseconds(1),
        )
        .await;
        previous = add.authority_commit.clone();
        events.push(add);
    }
    events
}

#[tokio::test]
async fn active_reaction_shape_obeys_the_original_snapshot_budget_and_rolls_back_the_whole_write() {
    ordinary_realm::case_future(active_capacity_case).await;
}

async fn active_capacity_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = Box::pin(open_discussion(&pool, "reaction-active-capacity")).await;
    let message = Box::pin(ordinary_realm::source_request(
        &pool,
        discussion.message_after(
            &discussion.head.authority_commit,
            "large active shape",
            discussion.committed_at(),
        ),
    ))
    .await;
    uow.commit_event(message.clone()).await.unwrap();
    let target = arkret_wire::MessageId::from_event_id(&message.authority_commit.event.event_id);
    let realm = message.authority_commit.event.realm_id.clone();
    let mut previous = message.authority_commit;
    let mut active = 0usize;
    let mut last_accepted = None;
    // Batches only amortize the native transaction. All original Event
    // proofs, source preparation and individual current writers still run.
    loop {
        assert!(
            active < MAX_ACTIVE_KEYS,
            "native active capacity was never enforced"
        );
        let events = additions(
            &pool,
            &previous,
            &target,
            active,
            ACTIVE_KEYS_PER_TRANSACTION,
        )
        .await;
        let candidate = events.last().unwrap().clone();
        let before = if active > 0 {
            Some(write_summary(&pool, &previous, &target).await)
        } else {
            None
        };
        match uow.commit_event_batch(batch(events)).await {
            Ok(_) => {
                active += ACTIVE_KEYS_PER_TRANSACTION;
                previous = candidate.authority_commit.clone();
                last_accepted = Some(candidate);
            }
            Err(error) => {
                assert_eq!(
                    error.conflict_code(),
                    Some(ConflictCode::SnapshotCapacityExceeded),
                    "{error}"
                );
                assert_eq!(
                    write_summary(&pool, &previous, &target).await,
                    before.unwrap()
                );
                break;
            }
        }
    }
    // Settle the last bounded batch one original Event at a time, so this
    // is the actual last allowed shape followed by the first refused add.
    let mut single_rejected = false;
    for _ in 0..ACTIVE_KEYS_PER_TRANSACTION {
        let add = additions(&pool, &previous, &target, active, 1)
            .await
            .remove(0);
        let before = write_summary(&pool, &previous, &target).await;
        match uow.commit_event(add.clone()).await {
            Ok(_) => {
                active += 1;
                previous = add.authority_commit.clone();
                last_accepted = Some(add);
            }
            Err(error) => {
                assert_eq!(
                    error.conflict_code(),
                    Some(ConflictCode::SnapshotCapacityExceeded),
                    "{error}"
                );
                assert_eq!(write_summary(&pool, &previous, &target).await, before);
                single_rejected = true;
                break;
            }
        }
    }
    assert!(single_rejected);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let material = store
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        previous.commit.signature.verification_method.clone(),
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
        previous.commit.committed_at,
    )
    .unwrap();
    let bytes = arkret_canonical::canonical_json_bytes(&snapshot).unwrap();
    coland_storage::enforce_inline_realm_state_snapshot_capacity(&snapshot).unwrap();
    assert!(bytes.len() <= coland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES);
    let retained = current(&pool, &target).await;
    assert_eq!(
        retained["value"]["entries"].as_array().unwrap().len(),
        active
    );
    assert_eq!(retained["commit_id"], json!(previous.commit.commit_id));
    eprintln!(
        "[reaction-capacity] active_keys={active} complete_signed_bytes={}",
        bytes.len()
    );
    let before = write_summary(&pool, &previous, &target).await;
    assert!(
        !uow.commit_event(last_accepted.unwrap())
            .await
            .unwrap()
            .event_inserted
    );
    assert_eq!(write_summary(&pool, &previous, &target).await, before);
    // Reclaim active capacity through real removes, retaining all audit
    // Events. Two entries leave room despite decimal position width changes.
    for index in 0..2 {
        let remove = sourced_reaction(
            &pool,
            &previous,
            &target,
            arkret_wire::EventKind::ReactionRemove,
            &active_key(index),
            previous.commit.committed_at + chrono::Duration::milliseconds(1),
        )
        .await;
        uow.commit_event(remove.clone()).await.unwrap();
        previous = remove.authority_commit;
    }
    let add = additions(&pool, &previous, &target, active, 1)
        .await
        .remove(0);
    uow.commit_event(add.clone()).await.unwrap();
    let after = current(&pool, &target).await;
    let entries = after["value"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), active - 1);
    assert!(
        entries
            .iter()
            .all(|entry| entry["key"] != active_key(0) && entry["key"] != active_key(1))
    );
    let newest = entries
        .iter()
        .find(|entry| entry["key"] == active_key(active))
        .unwrap();
    assert_eq!(
        newest["source"]["event_id"],
        json!(add.authority_commit.event.event_id)
    );
    assert_eq!(
        after["commit_id"],
        json!(add.authority_commit.commit.commit_id)
    );
}
