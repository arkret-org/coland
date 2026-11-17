use super::{
    Jsonb, MemberIdentityEventRecord, MemberIdentityStore, MemberIdentitySubjectKey,
    PersistenceError, PersistenceResult, PgPool, QueryableByName, RunQueryDsl, Text, Value,
    async_trait, sql_query,
};

/// Reads accepted Event/Commit facts for identity hydration.
/// It cannot manufacture accepted identity assertions.
pub struct PgMemberIdentityStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct AcceptedIdentityRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Jsonb)]
    raw_event: Value,
}

#[async_trait]
impl MemberIdentityStore for PgMemberIdentityStore {
    async fn snapshot_events(&self) -> PersistenceResult<Vec<MemberIdentityEventRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(
            "SELECT c.commit_json->>'event_ref' AS event_id,e.envelope AS raw_event \
             FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
             WHERE e.kind='ak.member.identity.update' AND e.state='committed' \
               AND c.realm_id=e.realm_id AND c.stream_ref->>'kind'='realm' \
               AND c.stream_ref->>'realm_id'=e.realm_id ORDER BY c.commit_json->>'event_ref'",
        )
        .load::<AcceptedIdentityRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                let payload = row.raw_event.get("payload").ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "accepted identity payload missing".to_owned(),
                    )
                })?;
                let typed: arkret_models_identity::MemberIdentityUpdatePayload =
                    serde_json::from_value(payload.clone()).map_err(PersistenceError::database)?;
                let carrier = payload.get("identity_payload").ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "accepted identity carrier missing".to_owned(),
                    )
                })?;
                Ok(MemberIdentityEventRecord {
                    event_id: row.event_id,
                    subject: MemberIdentitySubjectKey {
                        realm_id: typed.realm_id.to_string(),
                        actor_id: typed.member_id.to_string(),
                        segment: "member_identity".to_owned(),
                    },
                    payload_digest: arkret_canonical::canonical_sha256(carrier)
                        .map_err(PersistenceError::database)?,
                    replaces: typed
                        .replaces
                        .into_iter()
                        .map(|edge| coland_storage::MemberIdentityReplacementEdge {
                            event_id: edge.event_id.to_string(),
                            payload_digest: edge.payload_digest.to_string(),
                        })
                        .collect(),
                    raw_event: row.raw_event,
                })
            })
            .collect()
    }
}
