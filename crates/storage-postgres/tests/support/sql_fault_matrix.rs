//! Exhaust every actual row write, including writes performed by SQL triggers.
//! Sequence counters deliberately survive rollback; no protocol row does.
use std::collections::BTreeMap;
use std::future::Future;

use coland_storage::{PersistenceError, PersistenceResult};
use coland_storage_postgres::PgPool;
use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl;

#[derive(diesel::QueryableByName)]
struct Table {
    #[diesel(sql_type = Text)]
    name: String,
}
#[derive(diesel::QueryableByName)]
struct Rows {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

async fn tables(pool: &PgPool) -> Vec<String> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT tablename AS name FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
    )
    .load::<Table>(&mut conn)
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.name)
    .collect()
}

pub async fn snapshot(pool: &PgPool) -> BTreeMap<String, serde_json::Value> {
    let tables = tables(pool).await;
    let mut conn = pool.get().await.unwrap();
    let mut result = BTreeMap::new();
    for table in tables {
        let table_identifier = table.replace('"', "\"\"");
        let value = diesel::sql_query(format!("SELECT COALESCE(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) AS value FROM (SELECT to_jsonb(t) AS v FROM public.\"{table_identifier}\" t) rows"))
            .get_result::<Rows>(&mut conn).await.unwrap().value;
        result.insert(table, value);
    }
    result
}

async fn install(pool: &PgPool, tables: &[String], point: u64) {
    let mut conn = pool.get().await.unwrap();
    for sql in [
        "CREATE SEQUENCE authority_unit_fault_counter",
        "CREATE SEQUENCE authority_unit_fault_target",
        "CREATE FUNCTION authority_unit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE position bigint; target bigint; BEGIN position:=nextval('authority_unit_fault_counter'); SELECT last_value INTO target FROM authority_unit_fault_target; IF position=target THEN RAISE EXCEPTION 'authority_unit_fault:%:%:%',TG_TABLE_NAME,TG_OP,position; END IF; IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW; END; $$",
    ] {
        diesel::sql_query(sql).execute(&mut conn).await.unwrap();
    }
    diesel::sql_query(format!(
        "SELECT setval('authority_unit_fault_target',{point},true)"
    ))
    .execute(&mut conn)
    .await
    .unwrap();
    for table in tables {
        let table = table.replace('"', "\"\"");
        diesel::sql_query(format!("CREATE TRIGGER authority_unit_fault BEFORE INSERT OR UPDATE OR DELETE ON public.\"{table}\" FOR EACH ROW EXECUTE FUNCTION authority_unit_fault()"))
            .execute(&mut conn).await.unwrap();
    }
}

async fn remove(pool: &PgPool, tables: &[String]) {
    let mut conn = pool.get().await.unwrap();
    for table in tables {
        let table = table.replace('"', "\"\"");
        diesel::sql_query(format!(
            "DROP TRIGGER authority_unit_fault ON public.\"{table}\""
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    }
    for sql in [
        "DROP FUNCTION authority_unit_fault()",
        "DROP SEQUENCE authority_unit_fault_counter",
        "DROP SEQUENCE authority_unit_fault_target",
    ] {
        diesel::sql_query(sql).execute(&mut conn).await.unwrap();
    }
}

/// Reuse the exact intent through every failure until its first successful
/// commit. A non-injected refusal is a test failure, never an uncovered point.
pub async fn exhaust_writes<T, F, Fut>(pool: &PgPool, name: &str, mut commit: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = PersistenceResult<T>>,
{
    let tables = tables(pool).await;
    let before = snapshot(pool).await;
    for point in 1..=512 {
        install(pool, &tables, point).await;
        let outcome = commit().await;
        remove(pool, &tables).await;
        match outcome {
            Ok(result) => {
                assert!(point > 1, "{name} did not perform a durable write");
                println!(
                    "{name}: {} injected write failures, one successful commit",
                    point - 1
                );
                return result;
            }
            Err(error) => {
                assert!(
                    matches!(error, PersistenceError::Database(_)),
                    "{name}/{point}: {error}"
                );
                assert!(
                    error.to_string().contains("authority_unit_fault:"),
                    "{name}/{point}: {error}"
                );
                println!("{name}/{point}: {error}");
                assert_eq!(
                    snapshot(pool).await,
                    before,
                    "{name}/{point}: a failed unit changed durable rows"
                );
            }
        }
    }
    panic!("{name}: write inventory exceeded the test's guard bound");
}
