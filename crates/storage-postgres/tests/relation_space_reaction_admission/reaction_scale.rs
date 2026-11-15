//! Native governing writes retain audit history without retaining removed keys.

use coland_storage::{AuthorityCommitTransaction, EventBatchCommitRequest, EventCommitRequest};

use super::*;

const HISTORICAL_KEYS: usize = 100_000;
const KEYS_PER_TRANSACTION: usize = 128;

pub(super) fn batch(events: Vec<EventCommitRequest>) -> EventBatchCommitRequest {
    EventBatchCommitRequest {
        audit_unit: None,
        events,
        realm_organization_proof: None,
        event_approvals: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}

pub(super) async fn sourced_reaction(
    pool: &PgPool,
    previous: &AuthorityCommitTransaction,
    target: &arkret_wire::MessageId,
    kind: arkret_wire::EventKind,
    key: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> EventCommitRequest {
    Box::pin(ordinary_realm::source_request(
        pool,
        next_request(
            previous,
            kind,
            &founder(),
            json!({"target_ref":target,"key":key}),
            at,
        ),
    ))
    .await
}

pub(super) async fn current(pool: &PgPool, target: &arkret_wire::MessageId) -> Value {
    value(pool, "SELECT jsonb_build_object('value',value,'commit_id',current_commit_id,'position',current_stream_position,'live_bytes',pg_column_size(value)) AS value FROM message_reactions_current_states WHERE target_ref=$1", target.as_str()).await
}

#[tokio::test]
async fn a_hundred_thousand_removed_keys_leave_one_empty_current_row_and_real_revision() {
    // Box the complete case: native producer preparation has a large future
    // even though each production transaction holds only a bounded batch.
    ordinary_realm::case_future(removed_key_history_case).await;
}

async fn removed_key_history_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = Box::pin(open_discussion(&pool, "reaction-removed-key-history")).await;
    let message = Box::pin(ordinary_realm::source_request(
        &pool,
        discussion.message_after(
            &discussion.head.authority_commit,
            "current size follows active keys",
            discussion.committed_at(),
        ),
    ))
    .await;
    uow.commit_event(message.clone()).await.unwrap();
    let realm = message.authority_commit.event.realm_id.clone();
    let target = arkret_wire::MessageId::from_event_id(&message.authority_commit.event.event_id);
    let start = discussion.committed_at();
    let mut previous = message.authority_commit;
    let mut first_add = None;
    let mut empty_live_bytes = None;
    for first_key in (0..HISTORICAL_KEYS).step_by(KEYS_PER_TRANSACTION) {
        let end = (first_key + KEYS_PER_TRANSACTION).min(HISTORICAL_KEYS);
        let mut events = Vec::with_capacity((end - first_key) * 2);
        for index in first_key..end {
            let key = format!("removed-{index:06}");
            let add = sourced_reaction(
                &pool,
                &previous,
                &target,
                arkret_wire::EventKind::ReactionAdd,
                &key,
                start + chrono::Duration::milliseconds((index * 2 + 1) as i64),
            )
            .await;
            first_add.get_or_insert_with(|| add.authority_commit.event.event_id.clone());
            previous = add.authority_commit.clone();
            events.push(add);
            let remove = sourced_reaction(
                &pool,
                &previous,
                &target,
                arkret_wire::EventKind::ReactionRemove,
                &key,
                start + chrono::Duration::milliseconds((index * 2 + 2) as i64),
            )
            .await;
            previous = remove.authority_commit.clone();
            events.push(remove);
        }
        // Each Event still passes the production same-cut authorization,
        // producer source, contiguous Commit and projection writers. This is
        // an internal storage batch, not a new wire batch operation.
        uow.commit_event_batch(batch(events)).await.unwrap();
        let retained = current(&pool, &target).await;
        assert_eq!(retained["value"], json!({"entries":[]}));
        assert_eq!(retained["commit_id"], json!(previous.commit.commit_id));
        assert_eq!(retained["position"], json!(previous.commit.stream_position));
        let live_bytes = retained["live_bytes"].as_u64().unwrap();
        assert_eq!(*empty_live_bytes.get_or_insert(live_bytes), live_bytes);
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&retained["value"]).unwrap(),
            b"{\"entries\":[]}",
        );
        if end % 8_192 == 0 || end == HISTORICAL_KEYS {
            eprintln!("[reaction-history] removed_keys={end} current_entries=0");
        }
    }
    assert_eq!(
        count(&pool, "message_reactions_current_states", &realm).await,
        1
    );
    let mut conn = pool.get().await.unwrap();
    let history = diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.realm_id=$1 AND e.state='committed' AND e.kind IN ('ak.reaction.add','ak.reaction.remove') AND e.envelope#>>'{payload,target_ref}'=$2")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(target.as_str())
        .get_result::<Count>(&mut conn).await.unwrap().count;
    assert_eq!(history, (HISTORICAL_KEYS * 2) as i64);
    drop(conn);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(
        store
            .committed_event(&first_add.unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .committed_event(&previous.event.event_id)
            .await
            .unwrap()
            .is_some()
    );
    let snapshot = coland_storage_postgres::account_snapshot_material(
        &pool,
        &realm,
        founder_actor().as_account_id().unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let row = snapshot.current_state_entries.iter().find(|row| matches!(row,
        arkret_wire::CurrentState::Value {selector:arkret_wire::CurrentSelector::MessageReactions {target_ref},..} if target_ref==target.as_str()
    )).unwrap();
    assert!(
        matches!(row,arkret_wire::CurrentState::Value {value,revision,..}
        if value==&json!({"entries":[]}) && revision.commit_id==previous.commit.commit_id
            && revision.stream_position==previous.commit.stream_position)
    );
}
