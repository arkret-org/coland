//! The moderation queue View (`moderation-queue-item.schema.json`).
//!
//! content-moderation.md §3.3 makes the queue item a read-side View over the
//! accepted `moderation_report` typed current family and the `moderation_state`
//! records that point at it; the Station keeps no independently writable queue
//! state. Every member is derived here from one REPEATABLE READ snapshot:
//!
//! - visibility of a Realm's reports is limited to its moderators: the current Realm root
//!   controller or the Actor subject of an active, chain-intact Capability Grant for the moderation
//!   decision on the exact scope, judged at this same cut; Circle reports require explicit Circle
//!   coverage even for the Realm root controller (no existence oracle);
//! - `status` folds the report family with `moderation_state`: an item is `resolved` once a
//!   committed decision names the report itself, or names the reported target after the report was
//!   accepted; lifts never reopen it;
//! - `visibility` takes the first matching branch of §3.3 item 3 (the supported reports target
//!   Realm or Circle content);
//! - `created_at` is the accepting RealmCommit time;
//! - local workflow members (`priority`, `assigned_to_ids`, `audit_refs`) and the optional
//!   `evidence_policy` are omitted: this Station has none.

use arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload;
use arkret_models_collaboration::governance::moderation_queue::{
    ModerationQueueItem, ModerationQueueStatus, ModerationQueueVisibility,
};
use diesel::sql_types::Nullable;

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Bool, Jsonb, ModerationStore, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz,
    Value, async_trait, pg_conn, sql_query,
};

pub struct PgModerationStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RealmRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct ReportRow {
    #[diesel(sql_type = Text)]
    report_event_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    committed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("stored moderation report View source: {detail}"))
}

#[derive(QueryableByName)]
struct DecisionRow {
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
    #[diesel(sql_type = Text)]
    target_ref: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

/// Every committed decision assertion of the Realm with the target it was
/// recorded under and its accepting Realm-stream position.
async fn realm_decisions(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> PersistenceResult<Vec<DecisionRow>> {
    sql_query(
        "SELECT s.target_ref, c.stream_position, c.stream_ref \
         FROM moderation_state_current_states s \
         CROSS JOIN LATERAL jsonb_array_elements(s.value->'assertions') a \
         JOIN realm_commits c ON c.realm_id=s.realm_id \
          AND c.commit_json->>'event_ref'=left(a->>'tag_id', length(a->>'tag_id')-2) \
         WHERE s.realm_id=$1 AND a->'value' ? 'decision'",
    )
    .bind::<Text, _>(realm_id)
    .load::<DecisionRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)
}

async fn realm_queue_items(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    actor: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Vec<ModerationQueueItem>> {
    let rows = sql_query(
        "SELECT r.report_event_id, r.value, c.committed_at, r.current_stream_position, c.stream_ref \
         FROM moderation_report_current_states r \
         LEFT JOIN realm_commits c ON c.commit_id=r.current_commit_id \
          AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position \
          AND c.commit_json->>'event_ref'=r.report_event_id \
         WHERE r.realm_id=$1 ORDER BY r.current_stream_position ASC",
    )
    .bind::<Text, _>(realm_id)
    .load::<ReportRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let decisions = realm_decisions(conn, realm_id).await?;
    let realm = arkret_wire::RealmId::new(realm_id.to_owned()).map_err(corrupt)?;
    let mut items = Vec::new();
    for row in rows {
        let stream: arkret_wire::CommitStreamRef =
            serde_json::from_value(row.stream_ref.clone()).map_err(corrupt)?;
        let scope = scope_from_stream(&stream)?;
        if !moderator(conn, &realm, &scope, actor, at).await? {
            continue;
        }
        let encrypted = sql_query("SELECT EXISTS (SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND e.state='committed' AND e.kind='ak.mls.genesis' AND c.stream_ref=$2) AS present")
            .bind::<Text,_>(realm_id).bind::<Jsonb,_>(&row.stream_ref).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
        let committed_at = row
            .committed_at
            .ok_or_else(|| corrupt("report row has no covering Realm-stream Commit"))?;
        let event_id = arkret_wire::EventId::new(row.report_event_id).map_err(corrupt)?;
        let report: ModerationReportPayload = serde_json::from_value(row.value).map_err(corrupt)?;
        let resolved = decisions.iter().any(|decision| {
            decision.stream_ref == row.stream_ref
                && (decision.target_ref == event_id.as_str()
                    || (decision.target_ref == report.target_ref.as_str()
                        && decision.stream_position > row.current_stream_position))
        });
        let visibility = if !encrypted {
            ModerationQueueVisibility::PlaintextEvidence
        } else if report.evidence_package.is_some() {
            ModerationQueueVisibility::EncryptedEvidence
        } else if report.franking_proof.is_some() {
            ModerationQueueVisibility::FrankingProofOnly
        } else {
            ModerationQueueVisibility::MetadataOnly
        };
        items.push(ModerationQueueItem {
            id: ModerationQueueItem::id_for_report(&event_id),
            report,
            status: if resolved {
                ModerationQueueStatus::Resolved
            } else {
                ModerationQueueStatus::Submitted
            },
            priority: None,
            visibility,
            assigned_to_ids: None,
            evidence_policy: None,
            audit_refs: None,
            created_at: arkret_canonical::normalize_timestamp_canonical(committed_at),
            updated_at: None,
        })
    }
    Ok(items)
}

#[derive(QueryableByName)]
struct ReviewEventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    assertion_value: Value,
    #[diesel(sql_type = BigInt)]
    digest_suite: i64,
    #[diesel(sql_type = Text)]
    digest: String,
    #[diesel(sql_type = Text)]
    target_ref: String,
}

async fn pending_review_events(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    actor: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Vec<arkret_wire::Event>> {
    let rows = sql_query(
        "SELECT e.envelope, a->'value' AS assertion_value, e.digest_suite::bigint AS digest_suite, \
         CASE e.digest_suite WHEN 1 THEN 'sha256:' WHEN 2 THEN 'blake3:' END || encode(e.digest,'hex') AS digest, \
         s.target_ref FROM moderation_state_current_states s \
         CROSS JOIN LATERAL jsonb_array_elements(s.value->'assertions') a \
         JOIN realm_commits c ON c.realm_id=s.realm_id \
          AND c.commit_json->>'event_ref'=left(a->>'tag_id',length(a->>'tag_id')-2) \
         JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE s.realm_id=$1 AND a->'value'->>'decision'='require_review' \
          AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s.value->'assertions') lifted \
           WHERE lifted->'value'->>'decision_ref'=c.commit_json->>'event_ref') \
         ORDER BY c.stream_ref::text,c.stream_position",
    )
    .bind::<Text, _>(realm_id)
    .load::<ReviewEventRow>(&mut *conn)
    .await.map_err(PersistenceError::database)?;
    let realm = arkret_wire::RealmId::new(realm_id.to_owned()).map_err(corrupt)?;
    let mut events = Vec::new();
    for row in rows {
        let event: arkret_wire::Event = serde_json::from_value(row.envelope).map_err(corrupt)?;
        let suite = match row.digest_suite {
            1 => arkret_canonical::DigestSuite::Sha256,
            2 => arkret_canonical::DigestSuite::Blake3,
            _ => return Err(corrupt("unknown pending review digest suite")),
        };
        if event.kind != arkret_wire::EventKind::ModerationDecision
            || event.realm_id.as_str() != realm_id
            || event.payload.get("target_ref").and_then(Value::as_str)
                != Some(row.target_ref.as_str())
            || serde_json::to_value(&event.payload).map_err(corrupt)? != row.assertion_value
            || event
                .derive_event_id_with_digest_suite(suite)
                .map_err(corrupt)?
                != event.event_id
            || event
                .event_digest_with_digest_suite(suite)
                .map_err(corrupt)?
                != row.digest
        {
            return Err(corrupt(
                "pending review Event differs from its accepted assertion",
            ));
        }
        if moderator(conn, &realm, &event.scope_ref, actor, at).await? {
            events.push(event);
        }
    }
    Ok(events)
}

async fn management_view_in_connection(
    conn: &mut AsyncPgConnection,
    actor: &arkret_wire::ActorId,
    realm_filter: Option<&arkret_wire::RealmId>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<coland_storage::ModerationManagementView> {
    let realms = sql_query(
        "SELECT realm_id FROM (SELECT realm_id FROM moderation_report_current_states \
         UNION SELECT realm_id FROM moderation_state_current_states) realms \
         WHERE $1::text IS NULL OR realm_id=$1 ORDER BY realm_id",
    )
    .bind::<Nullable<Text>, _>(realm_filter.map(arkret_wire::RealmId::as_str))
    .load::<RealmRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut view = coland_storage::ModerationManagementView::default();
    for RealmRow { realm_id } in realms {
        view.items
            .extend(realm_queue_items(conn, &realm_id, actor, at).await?);
        view.pending_review_events
            .extend(pending_review_events(conn, &realm_id, actor, at).await?);
    }
    Ok(view)
}

#[async_trait]
impl ModerationStore for PgModerationStore {
    async fn queue_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<ModerationQueueItem>> {
        Ok(self.management_view_for_actor(actor, realm_id).await?.items)
    }

    async fn management_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<coland_storage::ModerationManagementView> {
        let at = chrono::Utc::now();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            management_view_in_connection(conn, actor, realm_id, at)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn report_count(&self) -> PersistenceResult<u64> {
        let mut conn = crate::pg_db(&self.pool);
        let count = sql_query("SELECT COUNT(*) AS count FROM moderation_report_current_states")
            .get_result::<CountRow>(&mut conn)
            .await
            .map_err(PersistenceError::database)?
            .count;
        u64::try_from(count).map_err(corrupt)
    }
}

fn scope_from_stream(
    stream: &arkret_wire::CommitStreamRef,
) -> PersistenceResult<arkret_wire::ScopeRef> {
    match stream {
        arkret_wire::CommitStreamRef::Realm { realm_id } => Ok(arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        }),
        arkret_wire::CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } => Ok(arkret_wire::ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        }),
        _ => Err(corrupt("moderation source is not a Realm or Circle stream")),
    }
}

async fn moderator(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
    actor: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    crate::moderation_report_current_states::scope_moderator(
        conn,
        realm,
        scope,
        actor,
        &[
            arkret_wire::CapabilityActionId::POLICY_MANAGE,
            arkret_wire::CapabilityActionId::MODERATION_DECISION,
        ],
        at,
    )
    .await
}
