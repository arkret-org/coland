use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::RunQueryDsl;
use serde_json::Value;

use super::{PgPool, pg_conn};

#[derive(QueryableByName)]
struct SettingRow {
    #[diesel(sql_type = Text)]
    key: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

pub async fn load_settings_overrides(
    pool: &PgPool,
) -> coland_storage::PersistenceResult<Vec<(String, Value)>> {
    let mut conn = pg_conn(pool)
        .await
        .map_err(coland_storage::PersistenceError::database)?;
    let rows = sql_query("SELECT key, value FROM server_settings")
        .get_results::<SettingRow>(&mut conn)
        .await
        .map_err(coland_storage::PersistenceError::database)?;
    Ok(rows.into_iter().map(|row| (row.key, row.value)).collect())
}

pub async fn store_settings_override(
    pool: &PgPool,
    key: &str,
    value: &Value,
    updated_by: &str,
) -> coland_storage::PersistenceResult<()> {
    let mut conn = pg_conn(pool)
        .await
        .map_err(coland_storage::PersistenceError::database)?;
    sql_query(
        "INSERT INTO server_settings (key, value, updated_by, updated_at) \
         VALUES ($1, $2, $3, NOW()) \
         ON CONFLICT (key) DO UPDATE SET \
            value = EXCLUDED.value, \
            updated_by = EXCLUDED.updated_by, \
            updated_at = NOW()",
    )
    .bind::<Text, _>(key)
    .bind::<Jsonb, _>(value)
    .bind::<Text, _>(updated_by)
    .execute(&mut conn)
    .await
    .map(|_| ())
    .map_err(coland_storage::PersistenceError::database)
}
