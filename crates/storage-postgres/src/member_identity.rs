use super::{
    HandleClaimEvidenceRecord, Jsonb, MemberIdentityEventRecord, MemberIdentityStore,
    MemberIdentitySubjectKey, Nullable, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, Text, Timestamptz, Value, async_trait, sql_query,
};

/// Reads accepted Event/Commit facts for identity hydration and stores local
/// handle-claim evidence. It cannot manufacture accepted identity assertions.
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

#[derive(QueryableByName)]
struct HandleClaimRow {
    #[diesel(sql_type = Text)]
    digest: String,
    #[diesel(sql_type = Text)]
    subject_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    issuer_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Nullable<Text>)]
    audience: Option<String>,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Text>)]
    revocation_digest: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    cache_expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    visibility: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

impl From<HandleClaimRow> for HandleClaimEvidenceRecord {
    fn from(row: HandleClaimRow) -> Self {
        Self {
            digest: row.digest,
            subject_id: row.subject_id,
            issuer_id: row.issuer_id,
            audience: row.audience,
            status: row.status,
            revocation_digest: row.revocation_digest,
            cache_expires_at: row.cache_expires_at,
            visibility: row.visibility,
            expires_at: row.expires_at,
            envelope: row.envelope,
        }
    }
}

const HANDLE_CLAIM_COLUMNS: &str = "digest, subject_id, issuer_id, audience, \
     status, revocation_digest, cache_expires_at, visibility, expires_at, envelope";

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

    async fn put_handle_claim(&self, record: &HandleClaimEvidenceRecord) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "INSERT INTO member_identity_handle_claims \
             (digest, subject_id, issuer_id, audience, status, revocation_digest, \
              cache_expires_at, visibility, expires_at, envelope) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (subject_id, digest) DO UPDATE SET \
                issuer_id = EXCLUDED.issuer_id, \
                audience = EXCLUDED.audience, \
                status = EXCLUDED.status, \
                revocation_digest = EXCLUDED.revocation_digest, \
                cache_expires_at = EXCLUDED.cache_expires_at, \
                visibility = EXCLUDED.visibility, \
                expires_at = EXCLUDED.expires_at, \
                envelope = EXCLUDED.envelope",
        )
        .bind::<Text, _>(&record.digest)
        .bind::<Text, _>(&record.subject_id)
        .bind::<Text, _>(&record.issuer_id)
        .bind::<Nullable<Text>, _>(&record.audience)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Text>, _>(&record.revocation_digest)
        .bind::<Timestamptz, _>(record.cache_expires_at)
        .bind::<Nullable<Text>, _>(&record.visibility)
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Jsonb, _>(&record.envelope)
        .execute(&mut conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn delete_handle_claims_for_subject(
        &self,
        subject_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<usize> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM member_identity_handle_claims WHERE subject_id = $1")
            .bind::<Text, _>(subject_id)
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)
    }

    async fn snapshot_handle_claims(&self) -> PersistenceResult<Vec<HandleClaimEvidenceRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {HANDLE_CLAIM_COLUMNS} FROM member_identity_handle_claims \
             ORDER BY subject_id, digest"
        ))
        .load::<HandleClaimRow>(&mut conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(HandleClaimEvidenceRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }
}
