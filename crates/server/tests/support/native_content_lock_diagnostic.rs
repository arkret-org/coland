//! Actual conflict-time row-lock observations scoped to one leased test DB.
pub(super) async fn run<F>(pool: coland_storage_postgres::PgPool, scenario: F)
where
    F: std::future::Future<Output = ()>,
{
    let _ = tracing_subscriber::fmt()
        .with_env_filter("coland_storage_postgres::applet_content_delivery=debug,coland_http::routing::identity::applet_managed_device=debug,coland_http::routing::mls::mls_keypackage_native=debug,coland_http::routing::identity::device_messages::native=debug")
        .with_test_writer()
        .try_init();
    use diesel_async::{RunQueryDsl as _, SimpleAsyncConnection as _};
    use futures_util::FutureExt as _;
    #[derive(diesel::QueryableByName)]
    struct OriginalDiagnosticSchema {
        #[diesel(sql_type = diesel::sql_types::Text)]
        definition: String,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        extension_existed: bool,
        #[diesel(sql_type = diesel::sql_types::Text)]
        row_lock_function: String,
    }
    let mut connection = pool.get().await.unwrap();
    // Slots retain schema functions across leases. Capture the exact original
    // and restore it after success or panic before releasing this lease.
    let original = diesel::sql_query("SELECT pg_get_functiondef('public.lock_native_content_realm_authority(text)'::regprocedure) AS definition, EXISTS(SELECT 1 FROM pg_extension WHERE extname='pgrowlocks') AS extension_existed, COALESCE((SELECT quote_ident(n.nspname)||'.pgrowlocks' FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pgrowlocks'),'public.pgrowlocks') AS row_lock_function")
        .get_result::<OriginalDiagnosticSchema>(&mut connection).await.unwrap();
    let install = r#"
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgrowlocks WITH SCHEMA public;
CREATE OR REPLACE FUNCTION public.lock_native_content_realm_authority(target_realm text)
RETURNS SETOF public.realm_authorities LANGUAGE plpgsql AS $diagnostic$
DECLARE observation jsonb;
BEGIN
    RETURN QUERY SELECT a.* FROM public.realm_authorities a
        WHERE a.realm_id=target_realm FOR SHARE NOWAIT;
EXCEPTION WHEN lock_not_available THEN
    SELECT jsonb_build_object(
        'target_realm',target_realm,'failed_reader_pid',pg_backend_pid(),
        'actual_tuple_locks',(
            SELECT COALESCE(jsonb_agg(jsonb_build_object(
                'locked_row',l.locked_row::text,'locker',l.locker::text,
                'multi',l.multi,'xids',l.xids::text,'modes',l.modes,'pids',l.pids,
                'members',(
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'xid',m.xid::text,'mode',m.mode,'pid',m.pid,
                        'conflicts_with_for_share',m.mode IN ('For Update','For No Key Update','Update','No Key Update'),
                        'activity',(SELECT to_jsonb(s) FROM pg_stat_activity s
                            WHERE s.pid=m.pid AND s.datname=current_database()),
                        'locks',(SELECT COALESCE(jsonb_agg(to_jsonb(p)),'[]'::jsonb)
                            FROM pg_locks p WHERE p.pid=m.pid))),'[]'::jsonb)
                    FROM unnest(l.xids,l.modes,l.pids) AS m(xid,mode,pid)
                ))),'[]'::jsonb)
            FROM __ROW_LOCK_FUNCTION__('public.realm_authorities') l
            JOIN public.realm_authorities a ON a.ctid=l.locked_row
            WHERE a.realm_id=target_realm
        )
    ) INTO observation;
    RAISE EXCEPTION 'native content authority cut is changing; conflict-time row-lock oracle=%',observation
        USING ERRCODE='40001';
END;
$diagnostic$;
COMMIT;
"#.replace("__ROW_LOCK_FUNCTION__", &original.row_lock_function);
    if let Err(error) = connection.batch_execute(&install).await {
        let _ = connection.batch_execute("ROLLBACK").await;
        panic!("install owned native row-lock diagnostic: {error}");
    }
    drop(connection);
    let outcome = std::panic::AssertUnwindSafe(scenario).catch_unwind().await;
    let restored = async {
        let mut connection = pool.get().await.map_err(|error| error.to_string())?;
        connection
            .batch_execute(&original.definition)
            .await
            .map_err(|error| error.to_string())?;
        if !original.extension_existed {
            connection
                .batch_execute("DROP EXTENSION pgrowlocks")
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok::<_, String>(())
    }
    .await;
    if let Err(error) = &restored {
        eprintln!("owned native diagnostic schema restoration failed: {error}");
    }
    match outcome {
        Ok(()) => restored.unwrap(),
        Err(original_panic) => std::panic::resume_unwind(original_panic),
    }
}
