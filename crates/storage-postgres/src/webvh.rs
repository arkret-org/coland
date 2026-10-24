use super::{
    AsyncConnection, BigInt, Integer, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    ServiceIdentitySuccessor, ServiceRegistrationCommitOutcome, Text, Timestamptz, Value,
    WebvhDocumentRecord, WebvhLogCommitOutcome, WebvhLogRecord, WebvhStore, async_trait,
    decode_registration_outcome, pg_conn, registration_as_existing, registrations_match, sql_query,
    valid_new_service_registration_records, webvh_freshness_on_put,
};
pub struct PgWebvhStore {
    pub pool: PgPool,
}

async fn retain_service_receipt_in_connection(
    conn: &mut super::AsyncPgConnection,
    receipt: &arkret_models_identity::service_identity::ServiceRegistrationReceipt,
) -> Result<(), PgTransactionError> {
    let inserted=sql_query("INSERT INTO service_registration_receipts AS r(service_id,version_id,event_digest,receipt,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_id,version_id) DO UPDATE SET receipt=EXCLUDED.receipt WHERE r.event_digest=EXCLUDED.event_digest AND r.receipt=EXCLUDED.receipt")
        .bind::<Text,_>(receipt.service_id.as_str()).bind::<Text,_>(&receipt.version_id).bind::<Text,_>(&receipt.log_head_digest)
        .bind::<Jsonb,_>(serde_json::to_value(receipt).map_err(PersistenceError::database)?)
        .bind::<Timestamptz,_>(receipt.issued_at).execute(conn).await?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: native service receipt differs from retained original".into(),
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn commit_service_mapping_in_connection(
    conn: &mut super::AsyncPgConnection,
    stored: &arkret_identity::service_identity::StoredDidCoreIdentity,
    replace: bool,
) -> Result<(), PgTransactionError> {
    stored.validate().map_err(PersistenceError::database)?;
    stored
        .did_document
        .validate_for(&stored.identity.registration_key)
        .map_err(PersistenceError::database)?;
    if stored.registration_receipt.provider_id != stored.identity.service_id {
        return Err(PersistenceError::Conflict(
            "failed_precondition: only the owning Provider can migrate its registration mapping"
                .into(),
        )
        .into());
    }
    arkret_signatures::service_identity::verify_registration_receipt_proof(
        &stored.registration_receipt,
        &stored.did_document,
    )
    .map_err(PersistenceError::database)?;
    let key = &stored.identity.registration_key;
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(stored.identity.service_id.as_str())
        .execute(&mut *conn)
        .await?;
    let head=sql_query("SELECT id AS event_digest,did,sequence,operation,created_at FROM webvh_log_events WHERE split_part(did,':',3)=split_part($1,':',3) ORDER BY sequence DESC LIMIT 1")
        .bind::<Text,_>(stored.identity.did.as_str()).get_result::<WebvhLogRow>(&mut *conn).await?;
    if head.event_digest != stored.registration_receipt.log_head_digest
        || head.operation.get("state")
            != Some(
                &serde_json::to_value(&stored.did_document).map_err(PersistenceError::database)?,
            )
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: registration mapping differs from the accepted native head"
                .into(),
        )
        .into());
    }
    retain_service_receipt_in_connection(conn, &stored.registration_receipt).await?;
    let kind = key.service_kind().as_str();
    let base = key.public_base_url().as_str();
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("service-registration:{kind}:{base}"))
        .execute(&mut *conn)
        .await?;
    let existing=sql_query("SELECT outcome FROM service_identity_registrations WHERE service_kind=$1 AND public_base_url=$2 FOR UPDATE")
        .bind::<Text,_>(kind).bind::<Text,_>(base).get_result::<ServiceRegistrationRow>(&mut *conn).await.optional()?;
    if let Some(existing) = existing {
        let existing = decode_registration_outcome(existing.outcome)?;
        if existing.registration_receipt.service_id != stored.identity.service_id {
            return Err(PersistenceError::Conflict(
                "failed_precondition: registration target belongs to another service".into(),
            )
            .into());
        }
        if !replace {
            return Ok(());
        }
    }
    let outcome = arkret_models_identity::service_identity::ServiceRegistrationResponseBody {
        did_document: stored.did_document.clone(),
        registration_receipt: stored.registration_receipt.clone(),
        created: false,
    };
    sql_query("INSERT INTO service_identity_registrations(service_kind,public_base_url,service_id,version_id,inception_digest,outcome,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7) ON CONFLICT(service_kind,public_base_url) DO UPDATE SET version_id=EXCLUDED.version_id,inception_digest=EXCLUDED.inception_digest,outcome=EXCLUDED.outcome,updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(kind).bind::<Text,_>(base).bind::<Text,_>(stored.identity.service_id.as_str())
        .bind::<Text,_>(&stored.identity.version_id).bind::<Text,_>(&stored.registration_receipt.log_head_digest)
        .bind::<Jsonb,_>(serde_json::to_value(outcome).map_err(PersistenceError::database)?)
        .bind::<Timestamptz,_>(stored.stored_at).execute(conn).await?;
    Ok(())
}
#[derive(QueryableByName)]
struct WebvhDocumentRow {
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Jsonb)]
    did_document: Value,
    #[diesel(sql_type = Nullable<Text>)]
    key_log_head: Option<String>,
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    #[diesel(sql_type = Jsonb)]
    method_evidence: Value,
    #[diesel(sql_type = Timestamptz)]
    fetched_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<WebvhDocumentRow> for WebvhDocumentRecord {
    fn from(row: WebvhDocumentRow) -> Self {
        Self {
            did: row.did,
            did_document: row.did_document,
            key_log_head: row.key_log_head,
            sequence: row.sequence.max(0) as u64,
            method_evidence: row.method_evidence,
            fetched_at: row.fetched_at,
            expires_at: row.expires_at,
            updated_at: row.updated_at,
        }
    }
}
#[derive(QueryableByName)]
struct WebvhLogRow {
    #[diesel(sql_type = Text)]
    event_digest: String,
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    #[diesel(sql_type = Jsonb)]
    operation: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}
#[derive(QueryableByName)]
struct ServiceIdentityJsonRow {
    #[diesel(sql_type = Jsonb)]
    identity: Value,
}
#[derive(QueryableByName)]
struct WebvhCommitLockRow {
    #[diesel(sql_type = Integer)]
    ok: i32,
}
#[derive(QueryableByName)]
struct ServiceRegistrationRow {
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
}
#[derive(QueryableByName)]
struct ExistingDidRow {
    #[diesel(sql_type = Text)]
    did: String,
}
impl From<WebvhLogRow> for WebvhLogRecord {
    fn from(row: WebvhLogRow) -> Self {
        Self {
            event_digest: row.event_digest,
            did: row.did,
            sequence: row.sequence.max(0) as u64,
            operation: row.operation,
            created_at: row.created_at,
        }
    }
}
#[async_trait]
impl WebvhStore for PgWebvhStore {
    async fn retain_service_registration_receipts(
        &self,
        receipts: Vec<arkret_models_identity::service_identity::ServiceRegistrationReceipt>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            for receipt in receipts {
                let entry=sql_query("SELECT id AS event_digest,did,sequence,operation,created_at FROM webvh_log_events WHERE id=$1")
                    .bind::<Text,_>(&receipt.log_head_digest).get_result::<WebvhLogRow>(&mut *conn).await?;
                let document: arkret_models_identity::service_identity::ServiceDidDocument=serde_json::from_value(entry.operation["state"].clone()).map_err(PersistenceError::database)?;
                receipt.validate_for(&receipt.registration_key,&arkret_wire::project_did_to_core_id(&document.id).map_err(PersistenceError::database)?,&document.id).map_err(PersistenceError::database)?;
                document.validate_for(&receipt.registration_key).map_err(PersistenceError::database)?;
                arkret_signatures::service_identity::verify_registration_receipt_proof(&receipt,&document).map_err(PersistenceError::database)?;
                retain_service_receipt_in_connection(conn,&receipt).await?;
            }
            Ok(())
        }).await.map_err(PgTransactionError::into_persistence)
    }
    async fn service_registration_receipts(
        &self,
        service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<arkret_models_identity::service_identity::ServiceRegistrationReceipt>>
    {
        #[derive(QueryableByName)]
        struct Receipt {
            #[diesel(sql_type=Jsonb)]
            receipt: Value,
        }
        let mut conn = crate::pg_db(&self.pool);
        sql_query("SELECT r.receipt FROM service_registration_receipts r JOIN webvh_log_events e ON e.id=r.event_digest WHERE r.service_id=$1 ORDER BY e.sequence")
            .bind::<Text,_>(service_id.as_str()).load::<Receipt>(&mut conn).await.map_err(PersistenceError::database)?
            .into_iter().map(|row|serde_json::from_value(row.receipt).map_err(PersistenceError::database)).collect()
    }
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "WITH head AS ( \
                SELECT operation #>> '{state,id}' AS did, sequence, id AS event_digest, operation->'state' AS state FROM webvh_log_events \
                WHERE did LIKE 'did:webvh:%' AND $1 LIKE 'did:webvh:%' \
                  AND split_part(did, ':', 3) = split_part($1, ':', 3) \
                  AND EXISTS (SELECT 1 FROM webvh_log_events alias \
                              WHERE alias.operation #>> '{state,id}' = $1) \
                ORDER BY sequence DESC LIMIT 1 \
             ) SELECT id AS did, did_document, key_log_head, sequence, method_evidence, \
             fetched_at, expires_at, updated_at \
             FROM webvh_documents WHERE id = COALESCE((SELECT did FROM head), $1) \
               AND (NOT EXISTS (SELECT 1 FROM head) OR \
                    (sequence = (SELECT sequence FROM head) AND key_log_head = (SELECT event_digest FROM head) \
                     AND did_document = (SELECT state FROM head)))",
        )
        .bind::<Text, _>(did)
        .get_result::<WebvhDocumentRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
        expected_log_url: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        #[derive(QueryableByName)]
        struct Candidate {
            #[diesel(sql_type=Text)]
            did: String,
        }
        let expected = url::Url::parse(expected_log_url).map_err(PersistenceError::database)?;
        // Only subjects of retained native entries establish hosting aliases.
        // Neither a resolution-cache row nor alsoKnownAs grants a hosting URL.
        // Load only identifiers until the unique hosted identity is established.
        let candidates = sql_query("SELECT DISTINCT operation #>> '{state,id}' AS did FROM webvh_log_events WHERE right(operation #>> '{state,id}', char_length($1) + 7) = ':webvh:' || $1")
            .bind::<Text,_>(local_id).load::<Candidate>(&mut conn).await.map_err(PersistenceError::database)?;
        let mut hosted = None;
        let mut hosted_core = None;
        for candidate in candidates {
            let matches = arkret_wire::Did::new(candidate.did.clone())
                .ok()
                .and_then(|did| arkret_identity::DidWebvhResolver::log_url(&did).ok())
                .and_then(|url| url::Url::parse(&url).ok())
                .is_some_and(|url| url == expected);
            if matches {
                let did = arkret_wire::Did::new(&candidate.did)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                let core = arkret_wire::project_did_to_core_id(&did)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                if hosted_core.as_ref().is_some_and(|prior| prior != &core) {
                    return Err(PersistenceError::Conflict(
                        "ambiguous local DID hosting".into(),
                    ));
                }
                hosted_core = Some(core);
                hosted = Some(candidate.did);
            }
        }
        let Some(hosted) = hosted else {
            return Ok(None);
        };
        drop(conn);
        self.get_document(&hosted).await
    }

    async fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        // Writes are ingestion: stamp freshness evidence with "now"
        // (`fetched_at = now`, `expires_at = now + high-risk baseline TTL`).
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        sql_query(
            "INSERT INTO webvh_documents \
             (id, did_document, key_log_head, sequence, method_evidence, \
              fetched_at, expires_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO UPDATE SET \
                did_document = EXCLUDED.did_document, \
                key_log_head = EXCLUDED.key_log_head, \
                sequence = EXCLUDED.sequence, \
                method_evidence = EXCLUDED.method_evidence, \
                fetched_at = EXCLUDED.fetched_at, \
                expires_at = EXCLUDED.expires_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.did)
        .bind::<Jsonb, _>(&record.did_document)
        .bind::<Nullable<Text>, _>(&record.key_log_head)
        .bind::<BigInt, _>(record.sequence as i64)
        .bind::<Jsonb, _>(&record.method_evidence)
        .bind::<Timestamptz, _>(fetched_at)
        .bind::<Timestamptz, _>(expires_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "INSERT INTO webvh_log_events \
             (id, did, sequence, operation, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&event.event_digest)
        .bind::<Text, _>(&event.did)
        .bind::<BigInt, _>(event.sequence as i64)
        .bind::<Jsonb, _>(&event.operation)
        .bind::<Timestamptz, _>(event.created_at)
        .execute(&mut conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT id AS event_digest, did, sequence, operation, created_at \
             FROM webvh_log_events WHERE (did = $1 OR (did LIKE 'did:webvh:%' AND $1 LIKE 'did:webvh:%' AND split_part(did, ':', 3) = split_part($1, ':', 3))) ORDER BY sequence ASC, id ASC",
        )
        .bind::<Text, _>(did)
        .load::<WebvhLogRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(WebvhLogRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn ingest_verified_history(
        &self,
        expected_current_head: Option<String>,
        document: WebvhDocumentRecord,
    ) -> PersistenceResult<WebvhLogCommitOutcome> {
        self.ingest_complete_history(expected_current_head, document)
            .await
    }

    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
        service_identity: Option<ServiceIdentitySuccessor>,
    ) -> PersistenceResult<WebvhLogCommitOutcome> {
        if document.did != event.did
            || document.sequence != event.sequence
            || document.key_log_head.as_deref() != Some(event.event_digest.as_str())
        {
            return Ok(WebvhLogCommitOutcome::Conflict);
        }
        let native_did = arkret_wire::Did::new(event.did.clone())
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        let core = arkret_wire::project_did_to_core_id(&native_did)
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        if event.operation.pointer("/state/id").and_then(Value::as_str) != Some(event.did.as_str())
        {
            return Ok(WebvhLogCommitOutcome::Conflict);
        }
        let identity_values = if let Some(transition) = service_identity {
            transition
                .expected
                .validate()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            transition
                .next
                .validate()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if arkret_wire::project_did_to_core_id(&transition.expected.identity.did).ok()
                != arkret_wire::project_did_to_core_id(&transition.next.identity.did).ok()
                || transition.next.identity.did.as_str() != event.did
                || transition.expected.identity.service_id != transition.next.identity.service_id
                || transition.next.identity.version_id
                    != event
                        .operation
                        .get("versionId")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                || transition.next.registration_receipt.log_head_digest != event.event_digest
                || serde_json::to_value(&transition.next.did_document)
                    .map_err(PersistenceError::database)?
                    != document.did_document
            {
                return Ok(WebvhLogCommitOutcome::Conflict);
            }
            Some((
                serde_json::to_value(&transition.expected).map_err(PersistenceError::database)?,
                serde_json::to_value(&transition.next).map_err(PersistenceError::database)?,
            ))
        } else {
            None
        };
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<WebvhLogCommitOutcome, PgTransactionError, _>(async move |conn| {
                let lock = sql_query(
                    "SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(hashtextextended($1, 0))) AS held",
                )
                .bind::<Text, _>(core.as_str())
                .get_result::<WebvhCommitLockRow>(&mut *conn)
                .await.map_err(PersistenceError::database)?;
                let _ = lock.ok;

                let current = sql_query(
                    "WITH head AS (SELECT operation #>> '{state,id}' AS did FROM webvh_log_events \
                     WHERE (did=$1 OR (did LIKE 'did:webvh:%' AND $1 LIKE 'did:webvh:%' AND split_part(did, ':', 3)=split_part($1, ':', 3))) ORDER BY sequence DESC LIMIT 1) \
                     SELECT id AS did, did_document, key_log_head, sequence, method_evidence, \
                     fetched_at, expires_at, updated_at \
                     FROM webvh_documents WHERE id=COALESCE((SELECT did FROM head),$1) FOR UPDATE",
                )
                .bind::<Text, _>(&event.did)
                .get_result::<WebvhDocumentRow>(&mut *conn)
                .await
                .optional().map_err(PersistenceError::database)?;
                let existing_events = sql_query(
                    "SELECT id AS event_digest, did, sequence, operation, created_at \
                     FROM webvh_log_events WHERE (did = $1 OR (did LIKE 'did:webvh:%' AND $1 LIKE 'did:webvh:%' AND split_part(did, ':', 3) = split_part($1, ':', 3))) ORDER BY sequence ASC, id ASC FOR UPDATE",
                )
                .bind::<Text, _>(&event.did)
                .load::<WebvhLogRow>(&mut *conn)
                .await.map_err(PersistenceError::database)?;
                let identity_current = if let Some((expected, next)) = &identity_values {
                    let row = sql_query("SELECT identity FROM service_identity WHERE id='self' FOR UPDATE")
                        .get_result::<ServiceIdentityJsonRow>(&mut *conn)
                        .await.optional().map_err(PersistenceError::database)?;
                    match row.map(|row| row.identity) {
                        Some(value) if value == *expected => Some(false),
                        Some(value) if value == *next => Some(true),
                        _ => return Ok(WebvhLogCommitOutcome::Conflict),
                    }
                } else { None };
                let version_id = event
                    .operation
                    .get("versionId")
                    .and_then(Value::as_str);
                if let Some(existing) = existing_events.iter().find(|existing| {
                    existing.sequence.max(0) as u64 == event.sequence
                        || version_id.is_some_and(|version_id| {
                            existing
                                .operation
                                .get("versionId")
                                .and_then(Value::as_str)
                                == Some(version_id)
                        })
                }) {
                    return Ok(if existing.event_digest == event.event_digest
                        && existing.operation == event.operation
                        && identity_current.is_none_or(|already_next| already_next)
                    {
                        WebvhLogCommitOutcome::Duplicate
                    } else {
                        WebvhLogCommitOutcome::Conflict
                    });
                }
                let Some(expected_seq) = current.as_ref().map_or(Some(1), |record| {
                    (record.sequence.max(0) as u64).checked_add(1)
                }) else {
                    return Ok(WebvhLogCommitOutcome::Conflict);
                };
                let stored_state_matches_log = match (current.as_ref(), existing_events.last()) {
                    (None, None) => true,
                    (Some(document), Some(head)) => {
                        document.sequence.max(0) as u64 == head.sequence.max(0) as u64
                            && document.key_log_head.as_deref()
                                == Some(head.event_digest.as_str())
                            && head.operation.get("state") == Some(&document.did_document)
                    }
                    _ => false,
                };
                if current.as_ref().is_some_and(|row|row.did!=event.did) {
                    let mut chain=existing_events.iter().map(|row|row.operation.clone()).collect::<Vec<_>>();chain.push(event.operation.clone());
                    if arkret_identity::verify_did_webvh_v1_chain(&native_did,&chain).is_err(){return Ok(WebvhLogCommitOutcome::Conflict);}
                }
                let current_head = current.and_then(|record| record.key_log_head);
                if !stored_state_matches_log
                    || current_head != expected_current_head
                    || event.sequence != expected_seq
                    || identity_current == Some(true)
                {
                    return Ok(WebvhLogCommitOutcome::Conflict);
                }

                sql_query(
                    "INSERT INTO webvh_log_events \
                     (id, did, sequence, operation, created_at) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind::<Text, _>(&event.event_digest)
                .bind::<Text, _>(&event.did)
                .bind::<BigInt, _>(event.sequence as i64)
                .bind::<Jsonb, _>(&event.operation)
                .bind::<Timestamptz, _>(event.created_at)
                .execute(&mut *conn)
                .await.map_err(PersistenceError::database)?;
                let (fetched_at, expires_at) = webvh_freshness_on_put();
                sql_query(
                    "INSERT INTO webvh_documents \
                     (id, did_document, key_log_head, sequence, method_evidence, \
                      fetched_at, expires_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (id) DO UPDATE SET \
                        did_document = EXCLUDED.did_document, \
                        key_log_head = EXCLUDED.key_log_head, \
                        sequence = EXCLUDED.sequence, \
                        method_evidence = EXCLUDED.method_evidence, \
                        fetched_at = EXCLUDED.fetched_at, \
                        expires_at = EXCLUDED.expires_at, \
                        updated_at = EXCLUDED.updated_at",
                )
                .bind::<Text, _>(&document.did)
                .bind::<Jsonb, _>(&document.did_document)
                .bind::<Nullable<Text>, _>(&document.key_log_head)
                .bind::<BigInt, _>(document.sequence as i64)
                .bind::<Jsonb, _>(&document.method_evidence)
                .bind::<Timestamptz, _>(fetched_at)
                .bind::<Timestamptz, _>(expires_at)
                .bind::<Timestamptz, _>(document.updated_at)
                .execute(&mut *conn)
                .await.map_err(PersistenceError::database)?;
                if let Some((expected, next)) = identity_values {
                    let before: arkret_identity::service_identity::StoredDidCoreIdentity=serde_json::from_value(expected.clone()).map_err(PersistenceError::database)?;
                    let after: arkret_identity::service_identity::StoredDidCoreIdentity=serde_json::from_value(next.clone()).map_err(PersistenceError::database)?;
                    retain_service_receipt_in_connection(conn,&after.registration_receipt).await?;
                    if before.identity.registration_key!=after.identity.registration_key {
                        commit_service_mapping_in_connection(conn,&after,true).await?;
                    }

                    let updated = sql_query("UPDATE service_identity SET identity=$2 WHERE id='self' AND identity=$1")
                        .bind::<Jsonb, _>(expected)
                        .bind::<Jsonb, _>(next)
                        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
                    if updated != 1 {
                        return Err(PersistenceError::Conflict("service identity CAS failed after WebVH successor".to_owned()).into());
                    }
                }
                Ok(WebvhLogCommitOutcome::Accepted)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get_service_registration(
        &self,
        key: &arkret_models_identity::service_identity::ServiceRegistrationKey,
    ) -> PersistenceResult<
        Option<arkret_models_identity::service_identity::ServiceRegistrationResponseBody>,
    > {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT outcome FROM service_identity_registrations \
             WHERE service_kind = $1 AND public_base_url = $2",
        )
        .bind::<Text, _>(key.service_kind().as_str())
        .bind::<Text, _>(key.public_base_url().as_str())
        .get_result::<ServiceRegistrationRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_registration_outcome(row.outcome).map(registration_as_existing))
        .transpose()
    }

    async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationResponseBody,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<ServiceRegistrationCommitOutcome> {
        if !valid_new_service_registration_records(&outcome, &document, &event) {
            return Ok(ServiceRegistrationCommitOutcome::Conflict);
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<ServiceRegistrationCommitOutcome, PgTransactionError, _>(
            async move |conn| {
                let service_kind = key.service_kind().as_str();
                let public_base_url = key.public_base_url().as_str();
                let lock_key = format!("service-registration:{service_kind}:{public_base_url}");
                let lock = sql_query(
                    "SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(hashtextextended($1, 0))) AS held",
                )
                .bind::<Text, _>(&lock_key)
                .get_result::<WebvhCommitLockRow>(&mut *conn)
                .await.map_err(PersistenceError::database)?;
                let _ = lock.ok;

                // A registration key is unique, but the same signed inception
                // may declare more than one ArkretService entry. Serialize on
                // the DID as well so concurrent requests through different
                // registration keys deterministically observe the existing
                // binding instead of surfacing a database unique violation.
                let did_lock_key = format!("service-registration-did:{}", document.did);
                let did_lock = sql_query(
                    "SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(hashtextextended($1, 0))) AS held",
                )
                .bind::<Text, _>(&did_lock_key)
                .get_result::<WebvhCommitLockRow>(&mut *conn)
                .await.map_err(PersistenceError::database)?;
                let _ = did_lock.ok;

                let existing = sql_query(
                    "SELECT outcome FROM service_identity_registrations \
                     WHERE service_kind = $1 AND public_base_url = $2 FOR UPDATE",
                )
                .bind::<Text, _>(service_kind)
                .bind::<Text, _>(public_base_url)
                .get_result::<ServiceRegistrationRow>(&mut *conn)
                .await
                .optional().map_err(PersistenceError::database)?;
                if let Some(existing) = existing {
                    let existing = decode_registration_outcome(existing.outcome)?;
                    return Ok(if registrations_match(&existing, &outcome) {
                        ServiceRegistrationCommitOutcome::Existing(registration_as_existing(
                            existing,
                        ))
                    } else {
                        ServiceRegistrationCommitOutcome::Conflict
                    });
                }

                let hosted_binding = sql_query(
                    "SELECT id AS did FROM webvh_documents \
                     WHERE EXISTS ( \
                       SELECT 1 FROM jsonb_array_elements( \
                         CASE WHEN jsonb_typeof(did_document->'service') = 'array' \
                              THEN did_document->'service' ELSE '[]'::jsonb END \
                       ) AS entry \
                       WHERE entry->>'type' = 'ArkretService' \
                         AND entry->>'serviceKind' = $1 \
                         AND entry->>'serviceEndpoint' = $2 \
                     ) LIMIT 1 FOR UPDATE",
                )
                .bind::<Text, _>(service_kind)
                .bind::<Text, _>(public_base_url)
                .get_result::<ExistingDidRow>(&mut *conn)
                .await
                .optional().map_err(PersistenceError::database)?;
                if let Some(hosted_binding) = hosted_binding {
                    tracing::warn!(
                        existing_did = %hosted_binding.did,
                        service_kind,
                        public_base_url,
                        "refusing service registration because a hosted document already declares the key",
                    );
                    return Ok(ServiceRegistrationCommitOutcome::Conflict);
                }

                let existing_did = sql_query(
                    "SELECT id AS did FROM webvh_documents WHERE id = $1 FOR UPDATE",
                )
                .bind::<Text, _>(&document.did)
                .get_result::<ExistingDidRow>(&mut *conn)
                .await
                .optional().map_err(PersistenceError::database)?;
                if existing_did.is_some() {
                    return Ok(ServiceRegistrationCommitOutcome::Conflict);
                }

                sql_query(
                    "INSERT INTO webvh_log_events \
                     (id, did, sequence, operation, created_at) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind::<Text, _>(&event.event_digest)
                .bind::<Text, _>(&event.did)
                .bind::<BigInt, _>(event.sequence as i64)
                .bind::<Jsonb, _>(&event.operation)
                .bind::<Timestamptz, _>(event.created_at)
                .execute(&mut *conn)
                .await.map_err(PersistenceError::database)?;

                let (fetched_at, expires_at) = webvh_freshness_on_put();
                sql_query(
                    "INSERT INTO webvh_documents \
                     (id, did_document, key_log_head, sequence, method_evidence, \
                      fetched_at, expires_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind::<Text, _>(&document.did)
                .bind::<Jsonb, _>(&document.did_document)
                .bind::<Nullable<Text>, _>(&document.key_log_head)
                .bind::<BigInt, _>(document.sequence as i64)
                .bind::<Jsonb, _>(&document.method_evidence)
                .bind::<Timestamptz, _>(fetched_at)
                .bind::<Timestamptz, _>(expires_at)
                .bind::<Timestamptz, _>(document.updated_at)
                .execute(&mut *conn)
                .await.map_err(PersistenceError::database)?;

                let outcome_json = serde_json::to_value(&outcome).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "service registration outcome serialization failed: {error}"
                    ))
                })?;
                sql_query(
                    "INSERT INTO service_identity_registrations \
                     (service_kind, public_base_url, service_id, version_id, inception_digest, outcome, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
                )
                .bind::<Text, _>(service_kind)
                .bind::<Text, _>(public_base_url)
                .bind::<Text, _>(outcome.registration_receipt.service_id.as_str())
                .bind::<Text, _>(&outcome.registration_receipt.version_id)
                .bind::<Text, _>(&outcome.registration_receipt.log_head_digest)
                .bind::<Jsonb, _>(&outcome_json)
                .bind::<Timestamptz, _>(event.created_at)
                .execute(&mut *conn)
                .await.map_err(PersistenceError::database)?;

                retain_service_receipt_in_connection(conn,&outcome.registration_receipt).await?;
                Ok(ServiceRegistrationCommitOutcome::Created(outcome))
            },
        )
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

impl PgWebvhStore {
    async fn ingest_complete_history(
        &self,
        expected_current_head: Option<String>,
        document: WebvhDocumentRecord,
    ) -> PersistenceResult<WebvhLogCommitOutcome> {
        let invalid = |error: String| PersistenceError::SchemaViolation(error);
        let did = arkret_wire::Did::new(&document.did).map_err(|e| invalid(e.to_string()))?;
        let core = arkret_wire::project_did_to_core_id(&did).map_err(|e| invalid(e.to_string()))?;
        let evidence: arkret_models_identity::ResolutionMethodHistoryEvidence =
            serde_json::from_value(document.method_evidence.clone())
                .map_err(|e| invalid(e.to_string()))?;
        evidence
            .validate_shape()
            .map_err(|e| invalid(e.to_string()))?;
        let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            log_entries,
            witness_records,
            ..
        } = evidence
        else {
            return Err(invalid(
                "native history ingestion requires WebVH log evidence".into(),
            ));
        };
        let mut bytes = Vec::new();
        for entry in &log_entries {
            bytes.extend(
                arkret_canonical::canonical_json_bytes(entry)
                    .map_err(|e| invalid(e.to_string()))?,
            );
            bytes.push(b'\n');
        }
        let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
            &did,
            &bytes,
            Some(&serde_json::to_vec(&witness_records).map_err(|e| invalid(e.to_string()))?),
        )
        .map_err(|e| invalid(e.to_string()))?;
        let mut events = Vec::new();
        for (index, (raw, entry)) in verified
            .log
            .raw_entries
            .iter()
            .zip(&verified.log.entries)
            .enumerate()
        {
            events.push(WebvhLogRecord {
                event_digest: arkret_canonical::canonical_sha256(raw)
                    .map_err(|e| invalid(e.to_string()))?,
                did: entry
                    .state
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("native entry omits its original DID".into()))?
                    .to_owned(),
                sequence: index as u64 + 1,
                operation: raw.clone(),
                created_at: entry.version_created_at,
            });
        }
        if events.is_empty()
            || document.sequence != events.len() as u64
            || document.key_log_head.as_deref() != events.last().map(|e| e.event_digest.as_str())
            || document.did_document != verified.log.head_state
        {
            return Err(invalid(
                "native ingestion document differs from verified complete history".into(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<WebvhLogCommitOutcome, PgTransactionError, _>(async move |conn| {
            let lock = sql_query("SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(hashtextextended($1, 0))) AS held")
                .bind::<Text,_>(core.as_str()).get_result::<WebvhCommitLockRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            let _ = lock.ok;
            let current = sql_query("WITH head AS (SELECT operation #>> '{state,id}' AS did FROM webvh_log_events WHERE (did=$1 OR (did LIKE 'did:webvh:%' AND split_part(did, ':', 3)=split_part($1, ':', 3))) ORDER BY sequence DESC LIMIT 1) SELECT id AS did,did_document,key_log_head,sequence,method_evidence,fetched_at,expires_at,updated_at FROM webvh_documents WHERE id=COALESCE((SELECT did FROM head),$1) FOR UPDATE")
                .bind::<Text,_>(&document.did).get_result::<WebvhDocumentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            if current.as_ref().and_then(|row|row.key_log_head.as_ref()) != expected_current_head.as_ref()
                || current.as_ref().is_some_and(|row| {
                    let prior = usize::try_from(row.sequence).ok().and_then(|sequence|sequence.checked_sub(1)).and_then(|index|events.get(index));
                    !prior.is_some_and(|prior|prior.event_digest.as_str()==row.key_log_head.as_deref().unwrap_or_default() && prior.operation.get("state")==Some(&row.did_document))
                }) {
                return Ok(WebvhLogCommitOutcome::Conflict);
            }
            let existing = sql_query("SELECT id AS event_digest,did,sequence,operation,created_at FROM webvh_log_events WHERE (did=$1 OR (did LIKE 'did:webvh:%' AND split_part(did, ':', 3)=split_part($1, ':', 3))) ORDER BY sequence ASC,id ASC FOR UPDATE")
                .bind::<Text,_>(&document.did).load::<WebvhLogRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            if existing.len() > events.len() || existing.iter().zip(&events).any(|(old,new)|old.sequence != new.sequence as i64 || old.event_digest != new.event_digest || old.operation != new.operation) {
                return Ok(WebvhLogCommitOutcome::Conflict);
            }
            for event in events.iter().skip(existing.len()) {
                let count = sql_query("INSERT INTO webvh_log_events(id,did,sequence,operation,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE webvh_log_events.did=EXCLUDED.did AND webvh_log_events.sequence=EXCLUDED.sequence AND webvh_log_events.operation=EXCLUDED.operation")
                    .bind::<Text,_>(&event.event_digest).bind::<Text,_>(&event.did).bind::<BigInt,_>(event.sequence as i64).bind::<Jsonb,_>(&event.operation).bind::<Timestamptz,_>(event.created_at)
                    .execute(&mut *conn).await.map_err(PersistenceError::database)?;
                if count != 1 { return Err(PersistenceError::Conflict("native history ingestion collided with another original".into()).into()); }
            }
            let (fetched_at,expires_at) = webvh_freshness_on_put();
            sql_query("INSERT INTO webvh_documents(id,did_document,key_log_head,sequence,method_evidence,fetched_at,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET did_document=EXCLUDED.did_document,key_log_head=EXCLUDED.key_log_head,sequence=EXCLUDED.sequence,method_evidence=EXCLUDED.method_evidence,fetched_at=EXCLUDED.fetched_at,expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at")
                .bind::<Text,_>(&document.did).bind::<Jsonb,_>(&document.did_document).bind::<Nullable<Text>,_>(&document.key_log_head).bind::<BigInt,_>(document.sequence as i64).bind::<Jsonb,_>(&document.method_evidence).bind::<Timestamptz,_>(fetched_at).bind::<Timestamptz,_>(expires_at).bind::<Timestamptz,_>(fetched_at)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            Ok(WebvhLogCommitOutcome::Accepted)
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
