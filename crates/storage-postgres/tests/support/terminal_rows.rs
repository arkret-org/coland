//! Durable acceptance footprints shared by terminal-state refusal tests.

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
    let tables = diesel::sql_query("SELECT tablename::text AS tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%current_states' OR tablename IN ('canonical_events','realm_commits','realm_authorities','federation_outbox','event_federation_outbox','replica_stream_anchors','replica_authorization_rows','replica_authorization_cuts','account_summary_current','account_summary_versions','account_summary_clock','current_state_heads','current_state_versions','direct_conversation_founding_slots')) ORDER BY tablename")
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
        "realm_bootstrap_current_states",
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
