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
#[derive(QueryableByName)]
struct WebvhDocumentRow {
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Jsonb)]
    did_document: Value,
    #[diesel(sql_type = Nullable<Text>)]
    key_log_head: Option<String>,
    #[diesel(sql_type = BigInt)]
    seq: i64,
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
            seq: row.seq.max(0) as u64,
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
    seq: i64,
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
            seq: row.seq.max(0) as u64,
            operation: row.operation,
            created_at: row.created_at,
        }
    }
}
#[async_trait]
impl WebvhStore for PgWebvhStore {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS did, did_document, key_log_head, seq, method_evidence, \
             fetched_at, expires_at, updated_at \
             FROM webvh_documents WHERE id = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<WebvhDocumentRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS did, did_document, key_log_head, seq, method_evidence, \
             fetched_at, expires_at, updated_at \
             FROM webvh_documents \
             WHERE right(id, char_length($1) + 7) = ':webvh:' || $1 \
             ORDER BY updated_at DESC \
             LIMIT 1",
        )
        .bind::<Text, _>(local_id)
        .get_result::<WebvhDocumentRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Writes are ingestion: stamp freshness evidence with "now"
        // (`fetched_at = now`, `expires_at = now + high-risk baseline TTL`).
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        sql_query(
            "INSERT INTO webvh_documents \
             (id, did_document, key_log_head, seq, method_evidence, \
              fetched_at, expires_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO UPDATE SET \
                did_document = EXCLUDED.did_document, \
                key_log_head = EXCLUDED.key_log_head, \
                seq = EXCLUDED.seq, \
                method_evidence = EXCLUDED.method_evidence, \
                fetched_at = EXCLUDED.fetched_at, \
                expires_at = EXCLUDED.expires_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.did)
        .bind::<Jsonb, _>(&record.did_document)
        .bind::<Nullable<Text>, _>(&record.key_log_head)
        .bind::<BigInt, _>(record.seq as i64)
        .bind::<Jsonb, _>(&record.method_evidence)
        .bind::<Timestamptz, _>(fetched_at)
        .bind::<Timestamptz, _>(expires_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO webvh_log_events \
             (id, did, seq, operation, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&event.event_digest)
        .bind::<Text, _>(&event.did)
        .bind::<BigInt, _>(event.seq as i64)
        .bind::<Jsonb, _>(&event.operation)
        .bind::<Timestamptz, _>(event.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS event_digest, did, seq, operation, created_at \
             FROM webvh_log_events WHERE (did = $1 OR (did LIKE 'did:webvh:%' AND $1 LIKE 'did:webvh:%' AND split_part(did, ':', 3) = split_part($1, ':', 3))) ORDER BY seq ASC, id ASC",
        )
        .bind::<Text, _>(did)
        .load::<WebvhLogRow>(&mut *conn)
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
            || document.seq != event.seq
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
            if transition.expected.identity.did.as_str() != event.did
                || transition.next.identity.did.as_str() != event.did
                || transition.expected.identity.service_id != transition.next.identity.service_id
                || transition.expected.identity.registration_key
                    != transition.next.identity.registration_key
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
                    "SELECT id AS did, did_document, key_log_head, seq, method_evidence, \
                     fetched_at, expires_at, updated_at \
                     FROM webvh_documents WHERE (id = $1 OR (id LIKE 'did:webvh:%' AND $1 LIKE 'did:webvh:%' AND split_part(id, ':', 3) = split_part($1, ':', 3))) ORDER BY seq DESC LIMIT 1 FOR UPDATE",
                )
                .bind::<Text, _>(&event.did)
                .get_result::<WebvhDocumentRow>(&mut *conn)
                .await
                .optional().map_err(PersistenceError::database)?;
                let existing_events = sql_query(
                    "SELECT id AS event_digest, did, seq, operation, created_at \
                     FROM webvh_log_events WHERE (did = $1 OR (did LIKE 'did:webvh:%' AND $1 LIKE 'did:webvh:%' AND split_part(did, ':', 3) = split_part($1, ':', 3))) ORDER BY seq ASC, id ASC FOR UPDATE",
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
                    existing.seq.max(0) as u64 == event.seq
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
                    (record.seq.max(0) as u64).checked_add(1)
                }) else {
                    return Ok(WebvhLogCommitOutcome::Conflict);
                };
                let stored_state_matches_log = match (current.as_ref(), existing_events.last()) {
                    (None, None) => true,
                    (Some(document), Some(head)) => {
                        document.seq.max(0) as u64 == head.seq.max(0) as u64
                            && document.key_log_head.as_deref()
                                == Some(head.event_digest.as_str())
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
                    || event.seq != expected_seq
                    || identity_current == Some(true)
                {
                    return Ok(WebvhLogCommitOutcome::Conflict);
                }

                sql_query(
                    "INSERT INTO webvh_log_events \
                     (id, did, seq, operation, created_at) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind::<Text, _>(&event.event_digest)
                .bind::<Text, _>(&event.did)
                .bind::<BigInt, _>(event.seq as i64)
                .bind::<Jsonb, _>(&event.operation)
                .bind::<Timestamptz, _>(event.created_at)
                .execute(&mut *conn)
                .await.map_err(PersistenceError::database)?;
                let (fetched_at, expires_at) = webvh_freshness_on_put();
                sql_query(
                    "INSERT INTO webvh_documents \
                     (id, did_document, key_log_head, seq, method_evidence, \
                      fetched_at, expires_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (id) DO UPDATE SET \
                        did_document = EXCLUDED.did_document, \
                        key_log_head = EXCLUDED.key_log_head, \
                        seq = EXCLUDED.seq, \
                        method_evidence = EXCLUDED.method_evidence, \
                        fetched_at = EXCLUDED.fetched_at, \
                        expires_at = EXCLUDED.expires_at, \
                        updated_at = EXCLUDED.updated_at",
                )
                .bind::<Text, _>(&document.did)
                .bind::<Jsonb, _>(&document.did_document)
                .bind::<Nullable<Text>, _>(&document.key_log_head)
                .bind::<BigInt, _>(document.seq as i64)
                .bind::<Jsonb, _>(&document.method_evidence)
                .bind::<Timestamptz, _>(fetched_at)
                .bind::<Timestamptz, _>(expires_at)
                .bind::<Timestamptz, _>(document.updated_at)
                .execute(&mut *conn)
                .await.map_err(PersistenceError::database)?;
                if let Some((expected, next)) = identity_values {
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
        Option<arkret_models_identity::service_identity::ServiceRegistrationOutcome>,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT outcome FROM service_identity_registrations \
             WHERE service_kind = $1 AND public_base_url = $2",
        )
        .bind::<Text, _>(key.service_kind().as_str())
        .bind::<Text, _>(key.public_base_url().as_str())
        .get_result::<ServiceRegistrationRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_registration_outcome(row.outcome).map(registration_as_existing))
        .transpose()
    }

    async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
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
                     (id, did, seq, operation, created_at) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind::<Text, _>(&event.event_digest)
                .bind::<Text, _>(&event.did)
                .bind::<BigInt, _>(event.seq as i64)
                .bind::<Jsonb, _>(&event.operation)
                .bind::<Timestamptz, _>(event.created_at)
                .execute(&mut *conn)
                .await.map_err(PersistenceError::database)?;

                let (fetched_at, expires_at) = webvh_freshness_on_put();
                sql_query(
                    "INSERT INTO webvh_documents \
                     (id, did_document, key_log_head, seq, method_evidence, \
                      fetched_at, expires_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind::<Text, _>(&document.did)
                .bind::<Jsonb, _>(&document.did_document)
                .bind::<Nullable<Text>, _>(&document.key_log_head)
                .bind::<BigInt, _>(document.seq as i64)
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
                did: document.did.clone(),
                seq: index as u64 + 1,
                operation: raw.clone(),
                created_at: entry.version_time,
            });
        }
        if events.is_empty()
            || document.seq != events.len() as u64
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
            let current = sql_query("SELECT id AS did,did_document,key_log_head,seq,method_evidence,fetched_at,expires_at,updated_at FROM webvh_documents WHERE (id=$1 OR (id LIKE 'did:webvh:%' AND split_part(id, ':', 3)=split_part($1, ':', 3))) ORDER BY seq DESC LIMIT 1 FOR UPDATE")
                .bind::<Text,_>(&document.did).get_result::<WebvhDocumentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            if current.as_ref().and_then(|row|row.key_log_head.as_ref()) != expected_current_head.as_ref()
                || current.as_ref().is_some_and(|row| {
                    let prior = usize::try_from(row.seq).ok().and_then(|seq|seq.checked_sub(1)).and_then(|index|events.get(index));
                    row.did != document.did || !prior.is_some_and(|prior|prior.event_digest.as_str()==row.key_log_head.as_deref().unwrap_or_default() && prior.operation.get("state")==Some(&row.did_document))
                }) {
                return Ok(WebvhLogCommitOutcome::Conflict);
            }
            let existing = sql_query("SELECT id AS event_digest,did,seq,operation,created_at FROM webvh_log_events WHERE did=$1 ORDER BY seq ASC,id ASC FOR UPDATE")
                .bind::<Text,_>(&document.did).load::<WebvhLogRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            if existing.len() > events.len() || existing.iter().zip(&events).any(|(old,new)|old.seq != new.seq as i64 || old.event_digest != new.event_digest || old.operation != new.operation) {
                return Ok(WebvhLogCommitOutcome::Conflict);
            }
            for event in events.iter().skip(existing.len()) {
                let count = sql_query("INSERT INTO webvh_log_events(id,did,seq,operation,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE webvh_log_events.did=EXCLUDED.did AND webvh_log_events.seq=EXCLUDED.seq AND webvh_log_events.operation=EXCLUDED.operation")
                    .bind::<Text,_>(&event.event_digest).bind::<Text,_>(&event.did).bind::<BigInt,_>(event.seq as i64).bind::<Jsonb,_>(&event.operation).bind::<Timestamptz,_>(event.created_at)
                    .execute(&mut *conn).await.map_err(PersistenceError::database)?;
                if count != 1 { return Err(PersistenceError::Conflict("native history ingestion collided with another original".into()).into()); }
            }
            let (fetched_at,expires_at) = webvh_freshness_on_put();
            sql_query("INSERT INTO webvh_documents(id,did_document,key_log_head,seq,method_evidence,fetched_at,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET did_document=EXCLUDED.did_document,key_log_head=EXCLUDED.key_log_head,seq=EXCLUDED.seq,method_evidence=EXCLUDED.method_evidence,fetched_at=EXCLUDED.fetched_at,expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at")
                .bind::<Text,_>(&document.did).bind::<Jsonb,_>(&document.did_document).bind::<Nullable<Text>,_>(&document.key_log_head).bind::<BigInt,_>(document.seq as i64).bind::<Jsonb,_>(&document.method_evidence).bind::<Timestamptz,_>(fetched_at).bind::<Timestamptz,_>(expires_at).bind::<Timestamptz,_>(fetched_at)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            Ok(WebvhLogCommitOutcome::Accepted)
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
