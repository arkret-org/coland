//! Existing real PostgreSQL frozen-source restore, shared by handoff tests.
use coland_storage_postgres::PgPool;

#[derive(diesel::QueryableByName)]
struct FrozenJson {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    value: serde_json::Value,
}

pub async fn copy_frozen_archive_preserving_deployment(
    source: &str,
    destination: &str,
    incoming_pool: &PgPool,
) {
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::{AsyncConnection as _, RunQueryDsl as _};
    const DEPLOYMENT_TABLES: [&str; 5] = [
        "device_inventory_station",
        "devices",
        "service_identity",
        "webvh_documents",
        "webvh_log_events",
    ];
    let mut retained = Vec::new();
    let mut conn = incoming_pool.get().await.unwrap();
    for table in DEPLOYMENT_TABLES {
        let query =
            format!("SELECT COALESCE(jsonb_agg(to_jsonb(r)),'[]'::jsonb) AS value FROM {table} r");
        let rows = diesel::sql_query(query)
            .get_result::<FrozenJson>(&mut conn)
            .await
            .unwrap();
        retained.push((table, rows.value.as_array().unwrap().clone()));
    }
    drop(conn);
    let source = source.to_owned();
    let destination = destination.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        // Keep the complete schema in the dump: excluding devices while
        // dropping its default-value function would break restore dependencies.
        let dump =
            Command::new(std::env::var_os("COTEST_PG_DUMP").unwrap_or_else(|| "pg_dump".into()))
                .args(["--clean", "--if-exists", "--no-owner", "--no-privileges"])
                .arg(source)
                .output()
                .expect("frozen source pg_dump");
        assert!(dump.status.success(), "frozen source export failed");
        let mut child =
            Command::new(std::env::var_os("COTEST_PSQL").unwrap_or_else(|| "psql".into()))
                .args([
                    "-X",
                    "--quiet",
                    "--single-transaction",
                    "--set=ON_ERROR_STOP=1",
                ])
                .arg(destination)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("frozen target psql");
        child.stdin.take().unwrap().write_all(&dump.stdout).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "frozen target import failed");
    })
    .await
    .unwrap();
    let mut conn = incoming_pool.get().await.unwrap();
    conn.transaction::<(), diesel::result::Error, _>(async move |conn| {
        for table in ["service_identity", "devices", "device_inventory_station"] {
            diesel::sql_query(format!("DELETE FROM {table}"))
                .execute(&mut *conn)
                .await?;
        }
        for (table, records) in retained {
            for record in records {
                if matches!(table, "webvh_documents" | "webvh_log_events") {
                    // Source method history can remain. A colliding receiving
                    // record must already be exact; no blind conflict swallowing.
                    let id = record["id"].as_str().unwrap();
                    let found = diesel::sql_query(format!(
                        "SELECT to_jsonb(r) AS value FROM {table} r WHERE id=$1"
                    ))
                    .bind::<Text, _>(id)
                    .load::<FrozenJson>(&mut *conn)
                    .await?;
                    assert!(found.len() <= 1);
                    if let Some(found) = found.as_slice().first() {
                        assert!(found.value == record, "conflicting deployment history");
                        continue;
                    }
                }
                let query = format!(
                    "INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table},$1)"
                );
                diesel::sql_query(query)
                    .bind::<Jsonb, _>(&record)
                    .execute(&mut *conn)
                    .await?;
            }
        }
        Ok(())
    })
    .await
    .unwrap();
}
