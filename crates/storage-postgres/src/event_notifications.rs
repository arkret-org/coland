//! Cross-process wakeups carry a small reference, never the full Event.
//! These expiring relay records are not protocol history or an outbound saga;
//! disconnected clients recover through the durable standard sync path.

use diesel::sql_types::{Text, Uuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};

use super::{PgPool, pg_conn};

#[derive(QueryableByName)]
struct PayloadRow {
    #[diesel(sql_type = Text)]
    payload: String,
}

pub async fn publish_event_notification(
    pool: &PgPool,
    payload: &str,
) -> anyhow::Result<uuid::Uuid> {
    let id = uuid::Uuid::now_v7();
    let payload = payload.to_owned();
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, anyhow::Error, _>(async move |conn| {
        sql_query("INSERT INTO event_notification_relay (id, payload) VALUES ($1, $2)")
            .bind::<Uuid, _>(id)
            .bind::<Text, _>(payload)
            .execute(&mut *conn)
            .await?;
        sql_query("SELECT pg_notify('coland_event_notifications', $1)")
            .bind::<Text, _>(id.to_string())
            .execute(&mut *conn)
            .await?;
        // Bounded cleanup avoids a large maintenance transaction on publish.
        sql_query(
            "DELETE FROM event_notification_relay WHERE id IN \
                 (SELECT id FROM event_notification_relay \
                  WHERE created_at < NOW() - INTERVAL '1 day' \
                  ORDER BY created_at, id LIMIT 128)",
        )
        .execute(&mut *conn)
        .await?;
        Ok(id)
    })
    .await
}

pub async fn load_event_notification(
    pool: &PgPool,
    id: uuid::Uuid,
) -> anyhow::Result<Option<String>> {
    let mut conn = pg_conn(pool).await?;
    Ok(
        sql_query("SELECT payload FROM event_notification_relay WHERE id = $1")
            .bind::<Uuid, _>(id)
            .get_result::<PayloadRow>(&mut *conn)
            .await
            .optional()?
            .map(|row| row.payload),
    )
}
