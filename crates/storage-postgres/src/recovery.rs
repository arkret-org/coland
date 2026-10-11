use diesel_async::AsyncConnection;

use super::{
    Integer, Jsonb, Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RecoveryPolicyRecord, RecoveryPolicyStore, RecoverySessionLifecycle,
    RecoverySessionRecord, RecoverySessionStore, RunQueryDsl, Text, Timestamptz, Uuid, Value,
    async_trait, ids, pg_conn, sql_query, sql_types,
};
// ── Phase 2 in-memory sub-stores ────────────────────────────────────────────

pub struct PgRecoveryPolicyStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
pub(crate) struct RecoveryPolicyRow {
    #[diesel(sql_type = sql_types::Uuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Integer)]
    version: i32,
    #[diesel(sql_type = Jsonb)]
    acceptance_basis: Value,
    #[diesel(sql_type = Text)]
    trust_domain: String,

    #[diesel(sql_type = Nullable<sql_types::Uuid>)]
    supersedes: Option<Uuid>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    verification_method: String,
    #[diesel(sql_type = Jsonb)]
    raw_payload: Value,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}
impl TryFrom<RecoveryPolicyRow> for RecoveryPolicyRecord {
    type Error = PersistenceError;

    fn try_from(row: RecoveryPolicyRow) -> Result<Self, Self::Error> {
        let version = u32::try_from(row.version).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery policy `{}` has invalid version {}",
                row.policy_id, row.version
            ))
        })?;
        let acceptance_basis = serde_json::from_value(row.acceptance_basis).map_err(|error| {
            PersistenceError::Internal(format!(
                "recovery policy `{}` has invalid acceptance_basis: {error}",
                row.policy_id
            ))
        })?;
        Ok(Self {
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            account_id: arkret_wire::AccountId::new(row.principal_id, row.station_id),
            version,
            acceptance_basis,
            trust_domain: row.trust_domain,
            supersedes: row.supersedes.map(|u| ids::format_typed_uuid("policy", &u)),
            expires_at: row.expires_at,
            issued_at: row.issued_at,
            raw_payload: row.raw_payload,
            accepted_at: row.accepted_at,
            verification_method: row.verification_method,
        })
    }
}
#[async_trait]
impl RecoveryPolicyStore for PgRecoveryPolicyStore {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS policy_id, principal_id, station_id, version, acceptance_basis, trust_domain, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies p JOIN policy_current_results c \
               ON c.policy_id=('ak:policy:' || p.id::text) \
              AND c.current_commit_id=(p.acceptance_basis #>> '{}') \
              AND c.value=p.raw_payload \
             WHERE p.id = $1",
        )
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(policy_id))
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional().map_err(PersistenceError::database)?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }

    async fn get_active_for_account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS policy_id, principal_id, station_id, version, acceptance_basis, trust_domain, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies p JOIN policy_current_results c \
               ON c.policy_id=('ak:policy:' || p.id::text) \
              AND c.current_commit_id=(p.acceptance_basis #>> '{}') \
              AND c.value=p.raw_payload \
             WHERE p.principal_id = $1 AND p.station_id = $2 \
             ORDER BY p.version DESC, p.accepted_at DESC LIMIT 1",
        )
        .bind::<Text, _>(&account_id.principal_id)
        .bind::<Text, _>(&account_id.station_id)
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional().map_err(PersistenceError::database)?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }

    async fn list_for_account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT id AS policy_id, principal_id, station_id, version, acceptance_basis, trust_domain, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 AND station_id = $2 \
             ORDER BY version DESC, accepted_at DESC",
        )
        .bind::<Text, _>(&account_id.principal_id)
        .bind::<Text, _>(&account_id.station_id)
        .get_results::<RecoveryPolicyRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(RecoveryPolicyRecord::try_from)
            .collect()
    }

    async fn commit_publication(
        &self,
        write: coland_storage::RecoveryPolicyPublicationWrite,
    ) -> PersistenceResult<coland_storage::RecoveryPolicyPublicationOutcome> {
        write.commit.validate().map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "invalid recovery policy authority transaction: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async move |conn| {
            crate::pcr_recovery_policy_unit::commit_recovery_policy_unit_in_connection(conn, &write)
                .await
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }
}
pub struct PgRecoverySessionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct RecoverySessionRow {
    #[diesel(sql_type = sql_types::Uuid)]
    recovery_session_id: Uuid,
    #[diesel(sql_type = Text)]
    request_id: String,
    #[diesel(sql_type = Text)]
    create_intent_digest: String,
    #[diesel(sql_type = Text)]
    session_grant_id: String,
    #[diesel(sql_type = Text)]
    session_grant_cnf_jkt: String,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    requesting_device_id: String,
    #[diesel(sql_type = Text)]
    requesting_device_public_key_did: String,
    #[diesel(sql_type = Text)]
    trust_domain: String,
    #[diesel(sql_type = sql_types::Uuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Integer)]
    policy_version: i32,
    #[diesel(sql_type = Text)]
    identity_model: String,
    #[diesel(sql_type = sql_types::BigInt)]
    current_device_generation_ref: i64,
    #[diesel(sql_type = Jsonb)]
    accepted_stream_head: Value,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
    #[diesel(sql_type = Jsonb)]
    authority_context: Value,
    #[diesel(sql_type = Jsonb)]
    publication_authority_context: Value,
    #[diesel(sql_type = Text)]
    publication_authority_context_digest: String,
    #[diesel(sql_type = Text)]
    challenge: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    proof_payload: Option<Value>,
    #[diesel(sql_type = Nullable<sql_types::Uuid>)]
    transaction_id: Option<Uuid>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
impl TryFrom<RecoverySessionRow> for RecoverySessionRecord {
    type Error = PersistenceError;

    fn try_from(row: RecoverySessionRow) -> Result<Self, Self::Error> {
        let policy_version = u32::try_from(row.policy_version).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid policy_version {}",
                row.recovery_session_id, row.policy_version
            ))
        })?;
        let identity_model =
            serde_json::from_value(Value::String(row.identity_model)).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has invalid identity_model: {error}",
                    row.recovery_session_id
                ))
            })?;
        let current_device_generation_ref = u64::try_from(row.current_device_generation_ref)
            .ok()
            .filter(|generation| *generation > 0)
            .ok_or_else(|| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has no positive current_device_generation_ref",
                    row.recovery_session_id
                ))
            })?;
        let accepted_stream_head =
            serde_json::from_value(row.accepted_stream_head).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has invalid accepted_stream_head: {error}",
                    row.recovery_session_id
                ))
            })?;
        let authority_context = serde_json::from_value(row.authority_context).map_err(|error| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid authority_context: {error}",
                row.recovery_session_id
            ))
        })?;
        let publication_authority_context =
            serde_json::from_value(row.publication_authority_context).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session `{}` has invalid publication_authority_context: {error}",
                    row.recovery_session_id
                ))
            })?;
        let publication_authority_context_digest = arkret_identifiers::Hash::new(
            row.publication_authority_context_digest,
        )
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid publication_authority_context_digest: {error}",
                row.recovery_session_id
            ))
        })?;
        let actual_context_digest = arkret_canonical::canonical_sha256(
            &publication_authority_context,
        )
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "recovery session `{}` publication authority context is not canonical: {error}",
                row.recovery_session_id
            ))
        })?;
        if actual_context_digest != publication_authority_context_digest.as_str() {
            return Err(PersistenceError::Internal(format!(
                "recovery session `{}` publication authority context digest mismatch",
                row.recovery_session_id
            )));
        }
        let state = serde_json::from_value(Value::String(row.state)).map_err(|error| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid state: {error}",
                row.recovery_session_id
            ))
        })?;
        Ok(Self {
            request_id: row.request_id,
            create_intent_digest: row.create_intent_digest,
            recovery_session_id: ids::format_typed_uuid(
                "recovery_session",
                &row.recovery_session_id,
            ),
            session_grant_id: row.session_grant_id,
            session_grant_cnf_jkt: row.session_grant_cnf_jkt,
            principal_id: row.principal_id,
            station_id: row.station_id,
            requesting_device_id: row.requesting_device_id,
            requesting_device_public_key_did: row.requesting_device_public_key_did,
            trust_domain: row.trust_domain,
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            policy_version,
            identity_model,
            current_device_generation_ref,
            accepted_stream_head,
            policy_payload: row.policy_payload,
            authority_context,
            publication_authority_context,
            publication_authority_context_digest,
            challenge: row.challenge,
            state,
            proof_payload: row.proof_payload,
            transaction_id: row
                .transaction_id
                .map(|id| ids::format_typed_uuid("transaction", &id)),
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
        })
    }
}
const RECOVERY_SESSION_COLUMNS: &str = "id AS recovery_session_id, request_id, create_intent_digest, session_grant_id, session_grant_cnf_jkt, principal_id, station_id, requesting_device_id, requesting_device_public_key_did, \
     trust_domain, policy_id, policy_version, identity_model, \
     current_device_generation_ref, accepted_stream_head, \
     policy_payload, authority_context, publication_authority_context, publication_authority_context_digest, \
     challenge, state, proof_payload, transaction_id, created_at, updated_at, expires_at";

/// Snake_case wire name of the canonical SDK `SessionState`, matching the
/// `identity_model` text-column encoding above.
fn session_state_label(state: RecoverySessionLifecycle) -> &'static str {
    match state {
        RecoverySessionLifecycle::Pending => "pending",
        RecoverySessionLifecycle::Verified => "verified",
        RecoverySessionLifecycle::Completed => "completed",
        RecoverySessionLifecycle::Rejected => "rejected",
        RecoverySessionLifecycle::Expired => "expired",
    }
}
#[async_trait]
impl RecoverySessionStore for PgRecoverySessionStore {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {RECOVERY_SESSION_COLUMNS} FROM recovery_sessions \
             WHERE id = $1"
        ))
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(recovery_session_id))
        .get_result::<RecoverySessionRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(RecoverySessionRecord::try_from)
        .transpose()
    }

    async fn get_by_grant_id(
        &self,
        session_grant_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {RECOVERY_SESSION_COLUMNS} FROM recovery_sessions \
             WHERE session_grant_id = $1 ORDER BY created_at DESC LIMIT 1"
        ))
        .bind::<Text, _>(session_grant_id)
        .get_result::<RecoverySessionRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(RecoverySessionRecord::try_from)
        .transpose()
    }

    async fn get_by_grant_request(
        &self,
        session_grant_id: &str,
        request_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {RECOVERY_SESSION_COLUMNS} FROM recovery_sessions \
             WHERE session_grant_id = $1 AND request_id = $2 LIMIT 1"
        ))
        .bind::<Text, _>(session_grant_id)
        .bind::<Text, _>(request_id)
        .get_result::<RecoverySessionRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(RecoverySessionRecord::try_from)
        .transpose()
    }

    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async move |conn| {
        crate::key_backup_unlock::validate_recovery_unlock_policy(conn, &recovery_policy_session_value(&record), chrono::Utc::now()).await?;
        #[derive(QueryableByName)]
        struct PolicyVersion { #[diesel(sql_type=Integer)] version:i32 }
        let head=sql_query("SELECT version FROM recovery_policies WHERE principal_id=$1 AND station_id=$2 ORDER BY version DESC LIMIT 1")
            .bind::<Text,_>(&record.principal_id).bind::<Text,_>(&record.station_id)
            .get_result::<PolicyVersion>(&mut *conn).await.map_err(PersistenceError::database)?;
        if i64::from(head.version)!=i64::from(record.policy_version) {
            return Err(PersistenceError::Conflict("recovery policy changed before session creation".to_owned()).into());
        }
        sql_query(
            "INSERT INTO recovery_sessions \
             (id, request_id, create_intent_digest, session_grant_id, session_grant_cnf_jkt, principal_id, station_id, requesting_device_id, requesting_device_public_key_did, trust_domain, policy_id, \
              policy_version, identity_model, current_device_generation_ref, \
              accepted_stream_head, policy_payload, \
              authority_context, publication_authority_context, publication_authority_context_digest, challenge, \
              state, proof_payload, transaction_id, created_at, updated_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)",
        )
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
            &record.recovery_session_id,
        ))
        .bind::<Text, _>(&record.request_id)
        .bind::<Text, _>(&record.create_intent_digest)
        .bind::<Text, _>(&record.session_grant_id)
        .bind::<Text, _>(&record.session_grant_cnf_jkt)
        .bind::<Text, _>(&record.principal_id)
        .bind::<Text, _>(&record.station_id)
        .bind::<Text, _>(&record.requesting_device_id)
        .bind::<Text, _>(&record.requesting_device_public_key_did)
        .bind::<Text, _>(&record.trust_domain)
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&record.policy_id))
        .bind::<Integer, _>(record.policy_version as i32)
        .bind::<Text, _>(match record.identity_model {
            arkret_models_crypto::RecoveryIdentityModel::PcrPolicy => "pcr_policy",
        })
        .bind::<Nullable<sql_types::BigInt>, _>(Some(i64::try_from(
            record.current_device_generation_ref,
        )
        .map_err(|_| {
            PersistenceError::Internal(
                "recovery session current_device_generation_ref exceeds PostgreSQL bigint"
                    .to_owned(),
            )
        })?))
        .bind::<Nullable<Jsonb>, _>(Some(
            serde_json::to_value(&record.accepted_stream_head).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session accepted_stream_head encode failed: {error}"
                ))
            })?,
        ))
        .bind::<Jsonb, _>(&record.policy_payload)
        .bind::<Jsonb, _>(
            serde_json::to_value(&record.authority_context).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session authority_context encode failed: {error}"
                ))
            })?,
        )
        .bind::<Jsonb, _>(
            serde_json::to_value(&record.publication_authority_context).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recovery session publication_authority_context encode failed: {error}"
                ))
            })?,
        )
        .bind::<Text, _>(record.publication_authority_context_digest.as_str())
        .bind::<Text, _>(&record.challenge)
        .bind::<Text, _>(session_state_label(record.state))
        .bind::<Nullable<Jsonb>, _>(record.proof_payload.as_ref())
        .bind::<Nullable<sql_types::Uuid>, _>(
            record
                .transaction_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await.map_err(PersistenceError::database)?;
        Ok(())
        }).await.map_err(crate::PgTransactionError::into_persistence)
    }

    async fn save_verified_with_unlock_manifest(
        &self,
        record: RecoverySessionRecord,
        manifest: Value,
    ) -> PersistenceResult<()> {
        if record.state != RecoverySessionLifecycle::Verified {
            return Err(PersistenceError::Conflict(
                "unlock manifest requires verified transition".to_owned(),
            ));
        }
        let seconds = (record.expires_at - record.updated_at).num_seconds() - 60;
        if seconds <= 0 {
            return Err(PersistenceError::Conflict(
                "insufficient recovery completion window".to_owned(),
            ));
        }
        let mut total = 0u64;
        let mut entries = Vec::new();
        let snapshot = manifest.clone();
        for backup in manifest
            .get("backups")
            .and_then(Value::as_array)
            .ok_or_else(|| PersistenceError::Conflict("unlock manifest incomplete".to_owned()))?
            .iter()
            .cloned()
        {
            let (digest, charge) = crate::key_backup_unlock::object_charge(&backup)?;
            total = total.checked_add(charge as u64).ok_or_else(|| {
                PersistenceError::Conflict("recovery unlock budget overflow".to_owned())
            })?;
            entries.push((backup, digest, charge));
        }
        // Admission capacity bounds are conservative, and checked before verified is durable.
        if total > (seconds as u64).saturating_mul(16 * 1024 * 1024)
            || entries.len() as u64 > (seconds as u64).saturating_mul(4)
        {
            return Err(PersistenceError::Conflict(
                "recovery manifest exceeds delivery capacity".to_owned(),
            ));
        }
        let rate = ((entries.len() as u64)
            .saturating_mul(60)
            .div_ceil(seconds as u64))
        .max(1) as i64;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,crate::PgTransactionError,_>(async move |conn| {
            #[derive(QueryableByName)]
            struct SnapshotRevision { #[diesel(sql_type=sql_types::BigInt)] revision:i64 }
            crate::key_backup_unlock::validate_active_basis(conn,&snapshot).await?;
            crate::key_backup_unlock::validate_recovery_unlock_policy(conn,&recovery_policy_session_value(&record),chrono::Utc::now()).await?;
            let realm=snapshot["realm_id"].as_str().ok_or_else(||PersistenceError::Conflict("manifest Realm missing".to_owned()))?;
            // The same Realm advisory lock is held by authority-commit append; the table
            // lock also excludes backup insert/delete phantoms while the frozen manifest commits.
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(realm).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            sql_query("LOCK TABLE key_backups IN SHARE MODE").execute(&mut *conn).await.map_err(PersistenceError::database)?;
            let revision=sql_query("SELECT COALESCE((SELECT revision FROM key_backup_list_revisions WHERE actor_id=$1),0)::bigint AS revision")
                .bind::<Text,_>(snapshot["actor_id"].as_str().ok_or_else(||PersistenceError::Conflict("manifest actor missing".to_owned()))?).get_result::<SnapshotRevision>(&mut *conn).await.map_err(PersistenceError::database)?.revision;
            if Some(revision)!=snapshot["revision"].as_i64(){return Err(PersistenceError::Conflict("backup manifest changed before verification".to_owned()).into());}
            let updated=sql_query("UPDATE recovery_sessions SET state='verified',proof_payload=$2,updated_at=$3 WHERE id=$1 AND state='pending' AND expires_at>$3")
                .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(&record.recovery_session_id))
                .bind::<Nullable<Jsonb>,_>(record.proof_payload.as_ref()).bind::<Timestamptz,_>(record.updated_at)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if updated!=1 {return Err(PersistenceError::Conflict("recovery session verification raced or expired".to_owned()).into());}
            let account=arkret_wire::AccountId::new(record.principal_id.clone(),record.station_id.clone());
            let canonical_account=arkret_canonical::canonical_json_string(&account).map_err(PersistenceError::database)?;
            let challenge=serde_json::json!({"account_id":account,"requesting_device_id":record.requesting_device_id,"challenge":record.challenge,"recovery_session_id":record.recovery_session_id});
            sql_query("INSERT INTO key_backup_unlock_authorities(authority_id,identity_key,account_id,device_id,kind,challenge,expires_at,remaining_bytes,verified_at,rate_per_minute) VALUES($1,$1,$2,$3,'recovery_session',$4,$5,$6::numeric,$7,$8)")
                .bind::<Text,_>(&record.recovery_session_id).bind::<Text,_>(&canonical_account).bind::<Text,_>(&record.requesting_device_id)
                .bind::<Jsonb,_>(&challenge).bind::<Timestamptz,_>(record.expires_at).bind::<Text,_>(total.to_string())
                .bind::<Timestamptz,_>(record.updated_at).bind::<sql_types::BigInt,_>(rate)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            for (backup,digest,charge) in entries {
                let backup_id=backup["backup_id"].as_str().ok_or_else(||PersistenceError::Conflict("backup id missing".to_owned()))?;
                let current=sql_query("SELECT payload FROM key_backups WHERE id=$1 FOR SHARE")
                    .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(backup_id)).get_result::<crate::JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?.payload;
                if current!=backup || backup["actor_id"]["account_id"]!=serde_json::to_value(&account).map_err(PersistenceError::database)? {
                    return Err(PersistenceError::Conflict("backup manifest changed before verification".to_owned()).into());
                }
                sql_query("INSERT INTO key_backup_unlock_entries(authority_id,backup_id,object_digest,charge) VALUES($1,$2,$3,$4)")
                    .bind::<Text,_>(&record.recovery_session_id).bind::<Text,_>(backup_id).bind::<Text,_>(&digest).bind::<sql_types::BigInt,_>(charge)
                    .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            }
            Ok(())
        }).await.map_err(crate::PgTransactionError::into_persistence)
    }

    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let affected = sql_query(
            "UPDATE recovery_sessions SET \
                state = $2, proof_payload = $3, transaction_id = $4, updated_at = $5, expires_at = $6 \
             WHERE id = $1",
        )
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
            &record.recovery_session_id,
        ))
        .bind::<Text, _>(session_state_label(record.state))
        .bind::<Nullable<Jsonb>, _>(record.proof_payload.as_ref())
        .bind::<Nullable<sql_types::Uuid>, _>(
            record
                .transaction_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if affected == 0 {
            return Err(PersistenceError::NotFound(format!(
                "recovery_session_id `{}` not found",
                record.recovery_session_id
            )));
        }
        Ok(())
    }
}

fn recovery_policy_session_value(record: &RecoverySessionRecord) -> Value {
    serde_json::json!({
        "principal_id": record.principal_id,
        "station_id": record.station_id,
        "policy_payload": record.policy_payload,
        "proof_payload": record.proof_payload,
    })
}

/// Lock policy authority before the session row, shared by every recovery consumer.
pub(crate) async fn lock_recovery_session_authority(
    conn: &mut crate::AsyncPgConnection,
    session_id: &str,
) -> Result<Value, crate::PgTransactionError> {
    let id = ids::parse_typed_uuid(session_id, "recovery_session").ok_or_else(|| {
        PersistenceError::SchemaViolation("invalid recovery session id".to_owned())
    })?;
    let before = sql_query("SELECT to_jsonb(s) AS payload FROM recovery_sessions s WHERE id=$1")
        .bind::<sql_types::Uuid, _>(id)
        .get_result::<crate::JsonPayloadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::Conflict("recovery session missing".to_owned()))?
        .payload;
    crate::key_backup_unlock::validate_recovery_unlock_policy(conn, &before, chrono::Utc::now())
        .await?;
    let locked = sql_query("SELECT to_jsonb(s) AS payload FROM recovery_sessions s WHERE id=$1 AND state='verified' AND expires_at>clock_timestamp() FOR SHARE")
        .bind::<sql_types::Uuid,_>(id).get_result::<crate::JsonPayloadRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::Conflict("recovery session no longer verified or current".to_owned()))?.payload;
    if locked["policy_payload"] != before["policy_payload"]
        || locked["proof_payload"] != before["proof_payload"]
    {
        return Err(
            PersistenceError::Conflict("recovery session authority changed".to_owned()).into(),
        );
    }
    Ok(locked)
}
