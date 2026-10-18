//! Real PG and the production peer authority port with an authenticated peer
//! context. Transport signature middleware is outside this test's boundary.
use super::*;

pub(super) async fn terminal_persistent_rows(
    pool: &coland_storage_postgres::PgPool,
) -> serde_json::Value {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Table {
        #[diesel(sql_type = diesel::sql_types::Text)]
        tablename: String,
    }
    #[derive(diesel::QueryableByName)]
    struct Rows {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let tables = diesel::sql_query("SELECT tablename::text AS tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%current_results' OR tablename IN ('canonical_events','realm_commits','realm_authorities','federation_outbox','event_federation_outbox','replica_stream_anchors','replica_authorization_rows','replica_authorization_cuts','account_summary_current','account_summary_versions','account_summary_clock','current_result_heads','current_result_versions','direct_conversation_founding_slots','agent_producer_signer_keys','account_device_signer_evidence','account_device_committed_evidence','forwarded_producer_device_evidence','forwarded_producer_agent_evidence','governance_unscoped_signer_evidence')) ORDER BY tablename")
        .load::<Table>(&mut *conn).await.unwrap();
    let mut snapshot = serde_json::Map::new();
    for table in tables {
        assert!(
            table
                .tablename
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        let query = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM public.{} r",
            table.tablename
        );
        let rows = diesel::sql_query(query)
            .get_result::<Rows>(&mut *conn)
            .await
            .unwrap();
        snapshot.insert(table.tablename, rows.value);
    }
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_authorities",
        "federation_outbox",
        "event_federation_outbox",
        "realm_bootstrap_current_results",
        "replica_stream_anchors",
        "replica_authorization_rows",
        "replica_authorization_cuts",
        "account_summary_current",
        "account_summary_versions",
        "account_summary_clock",
    ] {
        assert!(
            snapshot.contains_key(table),
            "missing acceptance footprint table: {table}"
        );
    }
    serde_json::Value::Object(snapshot)
}

#[tokio::test]
async fn peer_forwarded_destroy_reaches_the_shared_cut_and_leaves_zero_writes() {
    use arkret_models_collaboration::authority_commit::{
        AuthorityForwardBranch, PeerAuthorityForwardEventRequest, PeerAuthoritySubmitRequest,
    };

    let (governor_state, governor_pool, _governor_lease) =
        station("https://terminal-governor.internal/".into());
    let (origin, origin_pool, _origin_lease) = station("https://terminal-origin.internal/".into());
    let governor = Box::pin(historical_human::HumanFixture::new(
        &governor_pool,
        governor_state.service_did(),
    ))
    .await;
    Box::pin(governor.admit(&governor_pool)).await;
    let human = Box::pin(historical_human::HumanFixture::new(
        &origin_pool,
        origin.service_did(),
    ))
    .await;
    let previous = governor.unit.transactions.last().unwrap();
    let candidate = Box::pin(foreign_request(
        &origin,
        &human,
        &governor,
        previous,
        EventKind::RealmDestroy,
        serde_json::json!({"reason":"no registered confirmation carrier"}),
    ))
    .await;
    let request = PeerAuthorityForwardEventRequest {
        branch: AuthorityForwardBranch::AuthorityForward,
        event_submission: EventAdmissionSubmission::new(candidate.authority_commit.event.clone()),
        producer_device_evidence: Some(
            candidate
                .forwarded_producer_evidence
                .as_ref()
                .unwrap()
                .evidence
                .clone(),
        ),
        producer_managed_provenance: None,
        producer_agent_evidence: None,
        mls_genesis_material: None,
    };
    request.validate().unwrap();
    let peer = coland_services::authority_commit::AuthenticatedPeerContext {
        source_service_id: origin.service_core_id(),
        replay_receipt: None,
    };

    let before = terminal_persistent_rows(&governor_pool).await;
    let error = governor_state
        .authority()
        .submit_peer(
            &peer,
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(request),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("failed_precondition"), "{error}");
    assert!(
        error
            .to_string()
            .contains("v1 has no registered destructive confirmation carrier"),
        "{error}"
    );
    assert!(
        !error.to_string().contains("realm_terminal_state"),
        "{error}"
    );
    assert_eq!(terminal_persistent_rows(&governor_pool).await, before);
    let store = PgAuthorityCommitStore {
        pool: governor_pool,
    };
    assert!(
        store
            .committed_event(&candidate.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}
