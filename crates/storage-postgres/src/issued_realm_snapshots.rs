//! Exact signed Realm snapshots issued to one authenticated Account.
//!
//! Issuance is separate from handoff snapshots: a handoff's private full
//! manifest must never become readable merely because its ID is known.
//! The caller must prove same-cut account disclosure before calling `issue`.

use super::{
    AsyncConnection, AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz,
    Value, pg_conn, sql_query,
};

/// SQLSTATE 40001 aborts the whole snapshot-cut transaction. It can arise
/// from a governing-row change or concurrent refresh of an unchanged issued
/// object, so it does not establish that a handoff occurred.
pub(crate) fn snapshot_cut_error(error: diesel::result::Error) -> PersistenceError {
    use diesel::result::{DatabaseErrorKind, Error};
    match error {
        Error::DatabaseError(DatabaseErrorKind::SerializationFailure, info) => {
            PersistenceError::Conflict(format!(
                "{}: the snapshot transaction lost a concurrent write race: {}",
                coland_storage::ConflictCode::TemporarilyUnavailable.as_str(),
                info.message(),
            ))
        }
        other => PersistenceError::database(other),
    }
}

fn snapshot_write_error(stage: &'static str, error: diesel::result::Error) -> PersistenceError {
    if matches!(
        &error,
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::SerializationFailure,
            _,
        )
    ) {
        tracing::warn!(
            operation_stage = stage,
            database_error_kind = "serialization_failure",
            "snapshot issuance write lost a concurrent transaction race",
        );
    }
    snapshot_cut_error(error)
}

/// [`snapshot_cut_error`] for a whole snapshot-cut transaction.
pub(crate) fn snapshot_transaction_error(error: PgTransactionError) -> PersistenceError {
    match error {
        PgTransactionError::Diesel(error) => snapshot_cut_error(error),
        PgTransactionError::Storage(error) => error,
    }
}

/// Session locks precede BEGIN so a waiting issuer establishes a fresh MVCC
/// cut. Cancellation must discard the connection, never pool a locked session.
pub(crate) struct SnapshotIssuanceConnection {
    connection: Option<diesel_async::pooled_connection::deadpool::Object<AsyncPgConnection>>,
    realm_lock: String,
    runtime: tokio::runtime::Handle,
}

#[derive(QueryableByName)]
struct SessionUnlockRow {
    #[diesel(sql_type = super::Bool)]
    released: bool,
}

impl SnapshotIssuanceConnection {
    pub(crate) async fn acquire(
        pool: &PgPool,
        realm: &arkret_wire::RealmId,
    ) -> PersistenceResult<Self> {
        let mut guard = Self {
            connection: Some(pg_conn(pool).await?),
            realm_lock: format!("coland-snapshot-issuance:{}", realm.as_str()),
            runtime: tokio::runtime::Handle::current(),
        };
        sql_query("SELECT pg_advisory_lock_shared($1)")
            .bind::<super::BigInt, _>(crate::sync_cursor::retention::LOCK_KEY)
            .execute(&mut *guard)
            .await
            .map_err(PersistenceError::database)?;
        let key = guard.realm_lock.clone();
        sql_query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(key)
            .execute(&mut *guard)
            .await
            .map_err(PersistenceError::database)?;
        Ok(guard)
    }

    pub(crate) async fn finish<T>(mut self, result: PersistenceResult<T>) -> PersistenceResult<T> {
        let key = self.realm_lock.clone();
        let realm = sql_query("SELECT pg_advisory_unlock(hashtextextended($1, 0)) AS released")
            .bind::<Text, _>(key)
            .get_result::<SessionUnlockRow>(&mut *self)
            .await
            .map_err(PersistenceError::database)?;
        let retention = sql_query("SELECT pg_advisory_unlock_shared($1) AS released")
            .bind::<super::BigInt, _>(crate::sync_cursor::retention::LOCK_KEY)
            .get_result::<SessionUnlockRow>(&mut *self)
            .await
            .map_err(PersistenceError::database)?;
        if !realm.released || !retention.released {
            return Err(PersistenceError::Internal(
                "snapshot issuance session lock was lost".into(),
            ));
        }
        // Only a fully unlocked session may return to the pool.
        drop(self.connection.take());
        result
    }
}

impl std::ops::Deref for SnapshotIssuanceConnection {
    type Target = AsyncPgConnection;
    fn deref(&self) -> &Self::Target {
        self.connection
            .as_ref()
            .expect("issuance connection is held")
    }
}

impl std::ops::DerefMut for SnapshotIssuanceConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection
            .as_mut()
            .expect("issuance connection is held")
    }
}

impl Drop for SnapshotIssuanceConnection {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            let connection = diesel_async::pooled_connection::deadpool::Object::take(connection);
            let cancel = connection.cancel_token();
            // A backend waiting on a lock need not observe TCP EOF yet. Send
            // PostgreSQL's cancellation request as well as closing the detached
            // session. The pool establishes these connections with NoTls.
            drop(connection);
            self.runtime.spawn(async move {
                let _ = cancel.cancel_query(tokio_postgres::NoTls).await;
            });
        }
    }
}

#[derive(Clone)]
pub struct PgIssuedRealmSnapshotArchive {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct SnapshotJsonRow {
    #[diesel(sql_type = Jsonb)]
    snapshot_json: Value,
}

impl PgIssuedRealmSnapshotArchive {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Preserve one previously signed object and its exact Account grant in
    /// one transaction. A repeated issue is idempotent only for the same body.
    /// Production issuance goes through the same-cut `/head` unit instead.
    pub async fn issue(
        &self,
        account: &arkret_wire::AccountId,
        snapshot: &arkret_wire::RealmStateSnapshot,
    ) -> PersistenceResult<()> {
        let mut conn = SnapshotIssuanceConnection::acquire(&self.pool, &snapshot.realm_id).await?;
        let result = conn
            .transaction::<_, PgTransactionError, _>(async move |conn| {
                issue_in_connection(conn, account, snapshot)
                    .await
                    .map_err(Into::into)
            })
            .await
            .map_err(PgTransactionError::into_persistence);
        conn.finish(result).await
    }

    /// Read only the object previously issued to this exact Account, then
    /// re-prove at the same read cut that it is still disclosable to it.
    pub async fn by_ref(
        &self,
        account: &arkret_wire::AccountId,
        realm_id: &arkret_wire::RealmId,
        snapshot_id: &arkret_wire::RealmSnapshotId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        let account_key = account_key(account)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            let Some(row) = sql_query(
                "SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot \
                 JOIN realm_state_snapshot_issuances issued \
                   ON issued.snapshot_id = snapshot.snapshot_id \
                 WHERE snapshot.snapshot_id = $1 AND snapshot.realm_id = $2 \
                   AND issued.account_id = $3",
            )
            .bind::<Text, _>(snapshot_id.as_str())
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(&account_key)
            .get_result::<SnapshotJsonRow>(&mut *conn)
            .await
            .optional()?
            else {
                return Ok(None);
            };
            let snapshot: arkret_wire::RealmStateSnapshot =
                serde_json::from_value(row.snapshot_json).map_err(PersistenceError::database)?;
            if snapshot.snapshot_id != *snapshot_id
                || snapshot.realm_id != *realm_id
                || derived_snapshot_id(&snapshot)? != *snapshot_id
            {
                return Err(PersistenceError::Internal(
                    "issued snapshot identity differs from stored index".to_owned(),
                )
                .into());
            }
            recheck_disclosure_in_connection(conn, account, issuer, &snapshot).await?;
            Ok(Some(snapshot))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

/// Persist the exact signed object and the Account issuance on the caller's
/// transaction, so issuance commits or rolls back with its proving cut.
pub(crate) async fn issue_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<()> {
    let account_key = account_key(account)?;
    let body = serde_json::to_value(snapshot).map_err(PersistenceError::database)?;
    let generation = i64::try_from(snapshot.governance_generation).map_err(|_| {
        PersistenceError::SchemaViolation("snapshot generation exceeds storage range".to_owned())
    })?;
    sql_query(
        "INSERT INTO realm_state_snapshots \
         (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (snapshot_id) DO NOTHING",
    )
    .bind::<Text, _>(snapshot.snapshot_id.as_str())
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .bind::<super::BigInt, _>(generation)
    .bind::<Jsonb, _>(&body)
    .bind::<Timestamptz, _>(snapshot.created_at)
    .execute(&mut *conn)
    .await
    .map_err(snapshot_cut_error)?;
    let existing = sql_query(
        "SELECT snapshot_json FROM realm_state_snapshots \
         WHERE snapshot_id = $1 AND realm_id = $2 FOR SHARE",
    )
    .bind::<Text, _>(snapshot.snapshot_id.as_str())
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .get_result::<SnapshotJsonRow>(&mut *conn)
    .await
    .optional()
    .map_err(snapshot_cut_error)?;
    if existing.is_none_or(|row| row.snapshot_json != body) {
        return Err(PersistenceError::Conflict(
            "snapshot_ref_conflicts_with_issued_object".to_owned(),
        ));
    }
    sql_query(
        "INSERT INTO realm_state_snapshot_issuances (snapshot_id, account_id) \
         VALUES ($1,$2) ON CONFLICT (snapshot_id, account_id) DO NOTHING",
    )
    .bind::<Text, _>(snapshot.snapshot_id.as_str())
    .bind::<Text, _>(&account_key)
    .execute(&mut *conn)
    .await
    .map_err(snapshot_cut_error)?;
    Ok(())
}

#[derive(QueryableByName)]
struct IssuedCandidateRow {
    #[diesel(sql_type = Jsonb)]
    snapshot_json: Value,
}

/// Issue the signed object of one proved cut to `account`, bounded (0441).
///
/// An object already issued to the Account for exactly this cut (same
/// generation, heads, rows and floors, signed with the same verification
/// method) is reissued instead of archiving `signed`: retries and repeated
/// freezes at one head add no object. The Account's unreserved issuances in
/// this Realm are then trimmed to
/// [`coland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM`],
/// never touching a reserved one or a never-issued handoff object. The
/// caller holds the shared retention lock, so GC cannot interleave.
pub(crate) async fn issue_head_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    material: &coland_storage::RealmStateSnapshotMaterial,
    signed: arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<arkret_wire::RealmStateSnapshot> {
    let account_key = account_key(account)?;
    let generation = i64::try_from(material.governance_generation).map_err(|_| {
        PersistenceError::SchemaViolation("snapshot generation exceeds storage range".to_owned())
    })?;
    let heads =
        serde_json::to_value(&material.visible_stream_heads).map_err(PersistenceError::database)?;
    let candidates = sql_query(
        "SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot \
         JOIN realm_state_snapshot_issuances issued ON issued.snapshot_id = snapshot.snapshot_id \
         WHERE issued.account_id=$1 AND snapshot.realm_id=$2 \
           AND snapshot.governance_generation=$3 \
           AND snapshot.snapshot_json->'visible_stream_heads' = $4 \
         ORDER BY issued.issued_at DESC, snapshot.snapshot_id \
         LIMIT $5",
    )
    .bind::<Text, _>(&account_key)
    .bind::<Text, _>(material.realm_id.as_str())
    .bind::<super::BigInt, _>(generation)
    .bind::<Jsonb, _>(&heads)
    .bind::<super::BigInt, _>(coland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM)
    .load::<IssuedCandidateRow>(&mut *conn)
    .await
    .map_err(snapshot_cut_error)?;
    let mut issued = None;
    for candidate in candidates {
        let existing: arkret_wire::RealmStateSnapshot =
            serde_json::from_value(candidate.snapshot_json).map_err(PersistenceError::database)?;
        if !coland_storage::signed_snapshot_matches_material(&existing, material)
            || existing.signature.verification_method != signed.signature.verification_method
            || derived_snapshot_id(&existing)? != existing.snapshot_id
        {
            continue;
        }
        let touched = sql_query(
            "UPDATE realm_state_snapshot_issuances SET issued_at = now() \
             WHERE snapshot_id=$1 AND account_id=$2",
        )
        .bind::<Text, _>(existing.snapshot_id.as_str())
        .bind::<Text, _>(&account_key)
        .execute(&mut *conn)
        .await
        .map_err(|error| snapshot_write_error("reissue_recency", error))?;
        if touched == 1 {
            issued = Some(existing);
            break;
        }
    }
    let issued = match issued {
        Some(existing) => existing,
        None => {
            issue_in_connection(conn, account, &signed).await?;
            signed
        }
    };
    sql_query(
        "WITH doomed AS ( \
           SELECT issued.snapshot_id, issued.account_id \
           FROM realm_state_snapshot_issuances issued \
           JOIN realm_state_snapshots snapshot ON snapshot.snapshot_id = issued.snapshot_id \
           WHERE issued.account_id=$1 AND snapshot.realm_id=$2 AND issued.snapshot_id <> $3 \
             AND NOT EXISTS (SELECT 1 FROM realm_state_snapshot_window_reservations reserved \
                             WHERE reserved.snapshot_id = issued.snapshot_id \
                               AND reserved.account_id = issued.account_id) \
           ORDER BY issued.issued_at DESC, issued.snapshot_id DESC \
           OFFSET $4 \
         ), removed AS ( \
           DELETE FROM realm_state_snapshot_issuances issued USING doomed \
           WHERE issued.snapshot_id = doomed.snapshot_id \
             AND issued.account_id = doomed.account_id \
           RETURNING issued.snapshot_id, issued.account_id \
         ) \
         DELETE FROM realm_state_snapshots snapshot \
         WHERE snapshot.snapshot_id IN (SELECT snapshot_id FROM removed) \
           AND NOT EXISTS ( \
             SELECT 1 FROM realm_state_snapshot_issuances remaining \
             WHERE remaining.snapshot_id = snapshot.snapshot_id \
               AND NOT EXISTS (SELECT 1 FROM removed \
                               WHERE removed.snapshot_id = remaining.snapshot_id \
                                 AND removed.account_id = remaining.account_id))",
    )
    .bind::<Text, _>(&account_key)
    .bind::<Text, _>(material.realm_id.as_str())
    .bind::<Text, _>(issued.snapshot_id.as_str())
    .bind::<super::BigInt, _>(coland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM - 1)
    .execute(&mut *conn)
    .await
    .map_err(|error| snapshot_write_error("unreserved_issuance_prune", error))?;
    Ok(issued)
}

fn derived_snapshot_id(
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<arkret_wire::RealmSnapshotId> {
    let mut identity = serde_json::to_value(snapshot).map_err(PersistenceError::database)?;
    let object = identity
        .as_object_mut()
        .ok_or_else(|| PersistenceError::Internal("snapshot is not an object".to_owned()))?;
    object.remove("signature");
    object.remove("snapshot_id");
    let bytes =
        arkret_canonical::canonical_json_bytes(&identity).map_err(PersistenceError::database)?;
    Ok(arkret_wire::RealmSnapshotId::from_digest(
        arkret_canonical::sha256_bytes(&bytes),
    ))
}

#[derive(QueryableByName)]
struct ReadTenureRow {
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = super::BigInt)]
    generation: i64,
}

#[derive(QueryableByName)]
struct MemberRevisionRow {
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = super::BigInt)]
    current_stream_position: i64,
}

#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = super::Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = super::BigInt)]
    present: i64,
}

fn undisclosable(reason: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(format!(
        "issued snapshot is no longer provably disclosable: {reason}"
    ))
}

/// Preserve a verified original object only when every disclosed stream and
/// current row equals the hosted Account's complete durable replica cut.
pub(crate) async fn install_verified_account_snapshot(
    pool: &PgPool,
    account: &arkret_wire::AccountId,
    issuer: &arkret_wire::DidCoreId,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<()> {
    let mut conn = SnapshotIssuanceConnection::acquire(pool, &snapshot.realm_id).await?;
    let result = conn
        .transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *conn)
                .await?;
            crate::sync_cursor::retention::lock(conn, false).await?;
            let tenure = sql_query(
                "SELECT service_id, generation FROM realm_authorities WHERE realm_id=$1 FOR SHARE",
            )
            .bind::<Text, _>(snapshot.realm_id.as_str())
            .get_result::<ReadTenureRow>(&mut *conn)
            .await
            .optional()?
            .ok_or_else(|| undisclosable("the Realm has no governing authority"))?;
            let material =
                crate::snapshot_disclosure_gate::account_snapshot_material_in_connection(
                    conn,
                    &snapshot.realm_id,
                    account,
                )
                .await?
                .ok_or_else(|| undisclosable("the Account has no disclosed current cut"))?;
            require_snapshot_serving_cut(conn, account, issuer, &tenure.service_id, &material)
                .await?;
            if i64::try_from(snapshot.governance_generation).ok() != Some(tenure.generation)
                || !coland_storage::signed_snapshot_matches_material(snapshot, &material)
                || derived_snapshot_id(snapshot)? != snapshot.snapshot_id
            {
                return Err(undisclosable(
                    "the governing Snapshot differs from the complete current cut",
                )
                .into());
            }
            let signer = arkret_identity::verification_method_did(
                snapshot.signature.verification_method.as_str(),
            )
            .map_err(PersistenceError::database)?;
            if arkret_wire::project_did_to_core_id(&signer)
                .map_err(PersistenceError::database)?
                .as_str()
                != tenure.service_id
                || snapshot.signature.context
                    != arkret_wire::DetachedSignatureContext::RealmSnapshot
            {
                return Err(
                    undisclosable("the Snapshot signer is not the governing Station").into(),
                );
            }
            coland_storage::enforce_inline_realm_state_snapshot_capacity(snapshot)?;
            issue_head_in_connection(conn, account, &material, snapshot.clone()).await?;
            Ok(())
        })
        .await
        .map_err(snapshot_transaction_error);
    conn.finish(result).await
}

/// A member Station serves only its hosted Account and an exact verified
/// replica cut. It never gains the governing Station's signing authority.
pub(crate) async fn require_snapshot_serving_cut(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    issuer: &arkret_wire::DidCoreId,
    governance: &str,
    material: &coland_storage::RealmStateSnapshotMaterial,
) -> PersistenceResult<()> {
    if governance == issuer.as_str() {
        return Ok(());
    }
    if &account.station_id != issuer {
        return Err(undisclosable(
            "the Account is not hosted by this member Station",
        ));
    }
    for head in &material.visible_stream_heads {
        if crate::replica_authorization::verified_head(conn, &head.stream_ref)
            .await?
            .as_ref()
            != Some(head)
        {
            return Err(undisclosable(
                "the member Station has no exact verified current cut",
            ));
        }
    }
    Ok(())
}

/// Return the original governance-signed object already verified and archived
/// for this Account, only when it describes the complete current disclosure.
pub(crate) async fn served_current_snapshot(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    issuer: &arkret_wire::DidCoreId,
    material: &coland_storage::RealmStateSnapshotMaterial,
) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
    let rows = sql_query(
        "SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot \
         JOIN realm_state_snapshot_issuances issued ON issued.snapshot_id=snapshot.snapshot_id \
         WHERE snapshot.realm_id=$1 AND snapshot.governance_generation=$2 AND issued.account_id=$3 \
         ORDER BY issued.issued_at DESC, snapshot.snapshot_id",
    )
    .bind::<Text, _>(material.realm_id.as_str())
    .bind::<super::BigInt, _>(
        i64::try_from(material.governance_generation).map_err(PersistenceError::database)?,
    )
    .bind::<Text, _>(account_key(account)?)
    .load::<SnapshotJsonRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    for row in rows {
        let snapshot: arkret_wire::RealmStateSnapshot =
            serde_json::from_value(row.snapshot_json).map_err(PersistenceError::database)?;
        if coland_storage::signed_snapshot_matches_material(&snapshot, material) {
            if derived_snapshot_id(&snapshot)? != snapshot.snapshot_id {
                return Err(undisclosable("the stored snapshot identity changed"));
            }
            recheck_disclosure_in_connection(conn, account, issuer, &snapshot).await?;
            return Ok(Some(snapshot));
        }
    }
    Ok(None)
}

/// Re-prove, per row, head, and floor, that the issued object may still be
/// returned. Only the joined-member Realm-stream shape admitted by the
/// issuance gate is re-provable: the Account's `join` row in the object must
/// still be its unchanged current membership revision, the object's floor
/// must still be the Account's readable floor, no Message row may lie below
/// it, every head must still be the accepted Commit it names, and this
/// Station must still hold the object's governing term. Anything else is
/// unavailable, never substituted.
async fn recheck_disclosure_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    issuer: &arkret_wire::DidCoreId,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<()> {
    use arkret_wire::{CommitStreamRef, CurrentSelector, TypedCurrentRow};

    let tenure =
        sql_query("SELECT service_id, generation FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(snapshot.realm_id.as_str())
            .get_result::<ReadTenureRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| undisclosable("the Realm has no governing authority"))?;
    if i64::try_from(snapshot.governance_generation).ok() != Some(tenure.generation) {
        return Err(undisclosable(
            "a later or different governing term cannot re-prove this object",
        ));
    }
    let realm_stream = CommitStreamRef::Realm {
        realm_id: snapshot.realm_id.clone(),
    };
    // Recompute the Account's complete disclosure at this read cut. A signed
    // historical object is still readable only while every one of its streams
    // and rows remains disclosed to this Account. New visible streams may have
    // appeared since issuance; they do not invalidate the older exact slice.
    let current_material =
        crate::snapshot_disclosure_gate::account_snapshot_material_in_connection(
            conn,
            &snapshot.realm_id,
            account,
        )
        .await?
        .ok_or_else(|| undisclosable("the Account has no current disclosed cut"))?;
    require_snapshot_serving_cut(conn, account, issuer, &tenure.service_id, &current_material)
        .await?;
    let signer =
        arkret_identity::verification_method_did(snapshot.signature.verification_method.as_str())
            .map_err(PersistenceError::database)?;
    if arkret_wire::project_did_to_core_id(&signer)
        .map_err(PersistenceError::database)?
        .as_str()
        != tenure.service_id
        || snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
    {
        return Err(undisclosable(
            "the archived snapshot signer is not the governing Station",
        ));
    }
    for head in &snapshot.visible_stream_heads {
        if !current_material.visible_stream_heads.iter().any(|current| {
            current.stream_ref == head.stream_ref
                && (current.stream_position > head.stream_position
                    || (current.stream_position == head.stream_position
                        && current.commit_id == head.commit_id))
        }) {
            return Err(undisclosable("a signed stream is no longer disclosed"));
        }
        let old_floor = snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .find(|floor| floor.stream_ref == head.stream_ref)
            .ok_or_else(|| undisclosable("a signed stream has no floor"))?;
        let current_floor = current_material
            .retention_and_history_floor
            .stream_floors
            .iter()
            .find(|floor| floor.stream_ref == head.stream_ref)
            .ok_or_else(|| undisclosable("a signed stream has no current floor"))?;
        if old_floor.oldest_position < current_floor.oldest_position {
            return Err(undisclosable("a signed stream's readable floor advanced"));
        }
    }
    let actor = arkret_wire::ActorId::account(account.clone());
    let current_floor = crate::account_stream_scan::snapshot_realm_floor_in_connection(
        conn,
        &snapshot.realm_id,
        &actor,
    )
    .await?
    .ok_or_else(|| undisclosable("the Account's readable floor is not provable"))?;
    if snapshot
        .retention_and_history_floor
        .stream_floors
        .iter()
        .find(|floor| floor.stream_ref == realm_stream)
        .is_none_or(|floor| floor.oldest_position != current_floor.oldest_position)
    {
        return Err(undisclosable(
            "the object's floor is not the Account's current readable floor",
        ));
    }
    let mut own_membership = None;
    let mut message_targets = Vec::new();
    for row in &snapshot.current_state_entries {
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row;
        if !current_material.current_state_entries.contains(row) {
            return Err(undisclosable("a signed row is no longer disclosed"));
        }
        if source_stream_ref != &realm_stream {
            // The current disclosure gate proved this exact row and stream;
            // the historical snapshot's own signature binds its old cut.
            if !current_material
                .visible_stream_heads
                .iter()
                .any(|head| &head.stream_ref == source_stream_ref)
            {
                return Err(undisclosable("a row source is no longer visible"));
            }
            continue;
        }
        match selector {
            CurrentSelector::RealmGenesis
            | CurrentSelector::RealmAuthorityRoot
            | CurrentSelector::RealmProfile
            | CurrentSelector::RealmPolicyBundle
            | CurrentSelector::RealmJoinRule
            | CurrentSelector::RealmHistoryAccess
            | CurrentSelector::RealmReadReceiptPolicy
            | CurrentSelector::RealmDiscovery
            | CurrentSelector::RealmAlias
            | CurrentSelector::RealmPlaintextVisibleServices
            | CurrentSelector::Circle { .. }
            | CurrentSelector::Strand { .. }
            | CurrentSelector::CalendarScheduleSource { .. }
            | CurrentSelector::Space { .. }
            | CurrentSelector::SpaceParent { .. }
            | CurrentSelector::SpaceChildScopePolicy { .. }
            | CurrentSelector::DirectConversationBinding { .. }
            | CurrentSelector::MlsGroup { .. }
            | CurrentSelector::RealmSetDefaultStrand
            | CurrentSelector::InviteLifecycle { .. }
            | CurrentSelector::InviteLiveTarget { .. }
            | CurrentSelector::InviteDirectedInvitee { .. }
            | CurrentSelector::CapabilityGrant { .. }
            | CurrentSelector::ObjectRedaction { .. } => {}
            CurrentSelector::Relation {
                primary_conflict_domain,
            } => {
                let relation: arkret_wire::relation::Relation =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                relation
                    .validate_current_for_domain(&snapshot.realm_id, primary_conflict_domain)
                    .map_err(PersistenceError::database)?;
                if !crate::relation_disclosure::relation_visible_in_connection(
                    conn, &relation, &actor,
                )
                .await?
                {
                    return Err(undisclosable("Relation references are no longer disclosed"));
                }
            }
            CurrentSelector::MessageRevision { .. }
                if revision.stream_position < current_floor.oldest_position =>
            {
                return Err(undisclosable("a Message row lies below the readable floor"));
            }
            CurrentSelector::MessageRevision { message_id } => {
                let message_id = message_id.as_str().to_owned();
                message_targets.push(message_id.replacen("ak:message:", "ak:event:", 1));
                message_targets.push(message_id);
            }
            CurrentSelector::MemberState { actor_id }
                if actor_id == &actor
                    && own_membership.is_none()
                    && serde_json::from_value::<arkret_wire::MemberStateCurrent>(value.clone())
                        .is_ok_and(|member| {
                            member.membership == arkret_wire::MembershipState::Join
                        }) =>
            {
                own_membership = Some(revision.clone());
            }
            CurrentSelector::MemberState { actor_id } if actor_id != &actor => {}
            _ => {
                return Err(undisclosable(
                    "a row selector is outside the re-provable subset",
                ));
            }
        }
    }
    let own_membership =
        own_membership.ok_or_else(|| undisclosable("the object has no Account join row"))?;
    let current = sql_query(
        "SELECT membership, current_commit_id, current_stream_position \
         FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .bind::<Text, _>(actor.to_string())
    .get_result::<MemberRevisionRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| undisclosable("the Account has no current membership"))?;
    if current.membership != "join"
        || current.current_commit_id != own_membership.commit_id.as_str()
        || u64::try_from(current.current_stream_position).ok()
            != Some(own_membership.stream_position)
    {
        return Err(undisclosable(
            "the Account membership changed after this object was issued",
        ));
    }
    // A Message row carries its content, so it stops being disclosable once
    // retention expires any Event of the Realm or an `object_redaction`
    // assertion names it: the same decision that withholds its committed Event.
    let withdrawn = sql_query(
        "SELECT (EXISTS(SELECT 1 FROM retention_tombstones WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM object_redaction_current_results redaction \
                      WHERE redaction.realm_id=$1 AND redaction.target_ref = ANY($2))) AS present",
    )
    .bind::<Text, _>(snapshot.realm_id.as_str())
    .bind::<super::Array<Text>, _>(&message_targets)
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if withdrawn.present {
        return Err(undisclosable(
            "retention or a redaction withdrew a disclosed row",
        ));
    }
    for head in &snapshot.visible_stream_heads {
        let present = sql_query(
            "SELECT count(*) AS present FROM realm_commits \
             WHERE realm_id=$1 AND commit_id=$2 AND stream_position=$3",
        )
        .bind::<Text, _>(snapshot.realm_id.as_str())
        .bind::<Text, _>(head.commit_id.as_str())
        .bind::<super::BigInt, _>(i64::try_from(head.stream_position).map_err(|_| {
            PersistenceError::SchemaViolation("snapshot head position exceeds storage".to_owned())
        })?)
        .get_result::<CountRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if present.present != 1 {
            return Err(undisclosable(
                "a signed head is no longer an accepted Commit",
            ));
        }
    }
    Ok(())
}

fn account_key(account: &arkret_wire::AccountId) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(account).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)
}

#[derive(QueryableByName)]
struct WindowCommitRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    envelope: Option<Value>,
}

#[derive(QueryableByName)]
struct CommitIdRow {
    #[diesel(sql_type = Text)]
    present: String,
}

#[derive(QueryableByName)]
struct ReservedSnapshotRow {
    #[diesel(sql_type = Jsonb)]
    snapshot_json: Value,
    #[diesel(sql_type = super::BigInt)]
    expires_at_ms: i64,
}

fn window_rejected(reason: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("Account window cannot be frozen: {reason}"))
}

fn select_window_heads(
    realm_id: &arkret_wire::RealmId,
    visible_heads: &[arkret_wire::CommitStreamHead],
    selected_refs: Option<&[arkret_wire::CommitStreamRef]>,
) -> PersistenceResult<(Vec<arkret_wire::CommitStreamHead>, bool)> {
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let mut selected = match selected_refs {
        Some(refs) => {
            if refs.len() > 64 {
                return Err(window_rejected(
                    "explicit stream selection exceeds 64 entries",
                ));
            }
            let mut heads = Vec::with_capacity(refs.len());
            for stream in refs {
                if heads
                    .iter()
                    .any(|head: &arkret_wire::CommitStreamHead| &head.stream_ref == stream)
                {
                    return Err(window_rejected(
                        "explicit stream selection repeats a stream",
                    ));
                }
                let head = visible_heads
                    .iter()
                    .find(|head| &head.stream_ref == stream)
                    .ok_or_else(|| window_rejected("selected stream is not disclosed"))?;
                heads.push(head.clone());
            }
            heads
        }
        None => visible_heads.to_vec(),
    };
    if selected.is_empty() {
        return Err(window_rejected(
            "the selected cut has no established stream",
        ));
    }
    selected.sort_by_key(|head| {
        arkret_canonical::canonical_json_bytes(&head.stream_ref).unwrap_or_default()
    });
    let streams_limited = selected.len() > 64;
    if streams_limited {
        let realm_head = selected
            .iter()
            .find(|head| head.stream_ref == realm_stream)
            .cloned()
            .ok_or_else(|| window_rejected("default cut has no Realm stream"))?;
        selected.retain(|head| head.stream_ref != realm_stream);
        selected.truncate(63);
        selected.push(realm_head);
        selected.sort_by_key(|head| {
            arkret_canonical::canonical_json_bytes(&head.stream_ref).unwrap_or_default()
        });
    }
    Ok((selected, streams_limited))
}

/// The basis an exact issued snapshot gives a window whose first row is the
/// Commit after `anchor`: the state after this stream's committed prefix
/// through `anchor`. The signed snapshot can cover other visible streams,
/// but this stream's head and readable floor must match the exact anchor.
fn basis_from_snapshot(
    snapshot: &arkret_wire::RealmStateSnapshot,
    stream_ref: &arkret_wire::CommitStreamRef,
    anchor: &arkret_wire::CommitStreamHead,
    floor: u64,
) -> Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis> {
    use arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis;
    let exact_head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| &head.stream_ref == stream_ref)
        == Some(anchor);
    let exact_floor = snapshot
        .retention_and_history_floor
        .stream_floors
        .iter()
        .find(|entry| &entry.stream_ref == stream_ref)
        .is_some_and(|entry| entry.oldest_position == floor);
    (exact_head
        && exact_floor
        && floor <= anchor.stream_position
        && &anchor.stream_ref == stream_ref)
        .then(|| StreamWindowStartBasis {
            anchor_position: anchor.stream_position,
            anchor_commit_ref: anchor.commit_id.clone(),
            snapshot_ref: snapshot.snapshot_id.clone(),
            governance_generation: snapshot.governance_generation,
            accepted_dependency_refs: None,
        })
}

/// Re-prove an issued object for a basis at the caller's cut. Only a
/// disclosure failure means "not guaranteed"; any other error is a fault.
async fn still_disclosable(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    issuer: &arkret_wire::DidCoreId,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<bool> {
    match recheck_disclosure_in_connection(conn, account, issuer, snapshot).await {
        Ok(()) => Ok(true),
        Err(PersistenceError::SchemaViolation(reason)) => {
            tracing::debug!(%reason, snapshot_id=%snapshot.snapshot_id, "issued snapshot cannot back a window basis");
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// See [`coland_storage::AuthorityCommitStore::freeze_account_realm_window`].
///
/// One `REPEATABLE READ` cut holds, in order: the shared retention lock that
/// excludes issued-snapshot GC, the share-locked governing tenure, the
/// complete joined-member disclosure proof, the delivered rows, and the
/// basis reservation. The window's rows are the live delta after the
/// Account's delivered head when that head is still an accepted ancestor
/// within `window_limit`, otherwise the last `window_limit` Commits of the
/// Realm stream, never below the Account's readable floor. A caller with an
/// already-issued exact current head can instead start with an empty tail
/// immediately after that head. `limited` states whether readable history
/// lies below the window. A window above the floor names
/// the committed prefix through its anchor, backed by a snapshot already
/// issued to the Account at that anchor. A window starting exactly at a
/// floor above genesis has no issuable prefix state inside the Account's
/// readable range, so it is `preview_only` without a basis
/// (`sync/client-sync.md` §5.2, decision 0113).
/// The frozen head is issued to the Account in the same cut, so the next
/// delta can name it as its exact basis. Rows are served through the shared
/// committed-event disclosure decision. Issuance reuses the object already
/// issued for an unchanged cut and keeps the Account's unreserved issuances
/// capped; at the live-reservation cap a limited window is preview only.
pub(crate) async fn freeze_account_realm_window(
    pool: &PgPool,
    request: &coland_storage::AccountRealmWindowRequest,
    sign: coland_storage::RealmStateSnapshotSigner<'_>,
) -> PersistenceResult<Option<coland_storage::AccountRealmWindow>> {
    use arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow;

    if !(1..=100).contains(&request.window_limit) {
        return Err(window_rejected("window_limit must be in 1..=100"));
    }
    if request.expires_at_ms <= request.now_ms
        || request.expires_at_ms - request.now_ms
            > coland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS
    {
        return Err(window_rejected(
            "the consumable deadline is outside the cursor lifetime",
        ));
    }
    arkret_wire::Cursor::new(request.window_cursor.clone())
        .map_err(|_| window_rejected("the window identity is not a cursor value"))?;
    let account_key = account_key(&request.account)?;
    let mut conn = SnapshotIssuanceConnection::acquire(pool, &request.realm_id).await?;
    let result = conn
        .transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *conn)
                .await?;
            // Reservations and issued-snapshot GC exclude each other exactly like
            // Account sync reservations and version GC (0441).
            crate::sync_cursor::retention::lock(conn, false).await?;
            let Some(tenure) = sql_query(
                "SELECT service_id, generation FROM realm_authorities \
             WHERE realm_id=$1 FOR SHARE",
            )
            .bind::<Text, _>(request.realm_id.as_str())
            .get_result::<ReadTenureRow>(&mut *conn)
            .await
            .optional()?
            else {
                return Ok(None);
            };
            let Some(material) =
                crate::snapshot_disclosure_gate::account_snapshot_material_in_connection(
                    conn,
                    &request.realm_id,
                    &request.account,
                )
                .await?
            else {
                return Ok(None);
            };
            let generation = material.governance_generation;
            if i64::try_from(generation).ok() != Some(tenure.generation) {
                return Err(
                    window_rejected("material generation differs from the locked tenure").into(),
                );
            }
            require_snapshot_serving_cut(
                conn,
                &request.account,
                &request.issuer,
                &tenure.service_id,
                &material,
            )
            .await?;
            let (selected_heads, streams_limited) = select_window_heads(
                &request.realm_id,
                &material.visible_stream_heads,
                request.selected_stream_refs.as_deref(),
            )?;
            let minimum_heads = request
                .delivered_heads
                .iter()
                .filter(|required| {
                    selected_heads
                        .iter()
                        .any(|head| head.stream_ref == required.stream_ref)
                })
                .cloned()
                .collect::<Vec<_>>();
            if !crate::snapshot_disclosure_gate::continuation_heads_covered_in_material(
                conn,
                &request.realm_id,
                &material,
                &minimum_heads,
            )
            .await?
            {
                return Err(PersistenceError::Internal(
                    "Account continuation minimum head is not covered at the frozen cut".into(),
                )
                .into());
            }
            let per_stream_limit = request
                .window_limit
                .min((100 / selected_heads.len()) as u32)
                .max(1);
            let mut windows = Vec::with_capacity(selected_heads.len());
            let mut committed_events = Vec::new();
            for head in &selected_heads {
                let stream_ref = head.stream_ref.clone();
                let stream_key = crate::authority_commit::stream_key(&stream_ref)?;
                let floor = material
                    .retention_and_history_floor
                    .stream_floors
                    .iter()
                    .find(|floor| floor.stream_ref == stream_ref)
                    .ok_or_else(|| window_rejected("the proved cut has no Realm stream floor"))?;
                let floor = floor.oldest_position;
                let delivered_head = request
                    .delivered_heads
                    .iter()
                    .find(|delivered| delivered.stream_ref == stream_ref);
                let live_reservations = sql_query(
                    "SELECT count(*) AS present FROM realm_state_snapshot_window_reservations \
             WHERE account_id=$1 AND stream_key=$2 AND expires_at_ms > $3",
                )
                .bind::<Text, _>(&account_key)
                .bind::<Text, _>(&stream_key)
                .bind::<super::BigInt, _>(request.now_ms)
                .get_result::<CountRow>(&mut *conn)
                .await?
                .present;
                // A member whose readable floor is above genesis can bootstrap at an
                // already-issued current head without waiting for another Event. The
                // empty tail is still a bounded stream window, with the signed head
                // reserved as its exact start basis below.
                let mut head_basis_available = false;
                if floor > 0
                    && delivered_head.is_none_or(|delivered| delivered == head)
                    && live_reservations
                        < coland_storage::MAX_LIVE_WINDOW_RESERVATIONS_PER_ACCOUNT_STREAM
                {
                    let candidates = sql_query(
                        "SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot \
                 JOIN realm_state_snapshot_issuances issued \
                   ON issued.snapshot_id = snapshot.snapshot_id \
                 WHERE snapshot.realm_id=$1 AND snapshot.governance_generation=$2 \
                   AND issued.account_id=$3 \
                   AND snapshot.snapshot_json->'visible_stream_heads' @> $4 \
                 ORDER BY issued.issued_at DESC, snapshot.snapshot_id \
                 LIMIT $5 FOR KEY SHARE OF issued",
                    )
                    .bind::<Text, _>(request.realm_id.as_str())
                    .bind::<super::BigInt, _>(tenure.generation)
                    .bind::<Text, _>(&account_key)
                    .bind::<Jsonb, _>(
                        serde_json::to_value(std::slice::from_ref(head))
                            .map_err(PersistenceError::database)?,
                    )
                    .bind::<super::BigInt, _>(
                        coland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM,
                    )
                    .load::<SnapshotJsonRow>(&mut *conn)
                    .await?;
                    for candidate in candidates {
                        let snapshot: arkret_wire::RealmStateSnapshot =
                            serde_json::from_value(candidate.snapshot_json)
                                .map_err(PersistenceError::database)?;
                        if basis_from_snapshot(&snapshot, &stream_ref, head, floor).is_some()
                            && derived_snapshot_id(&snapshot)? == snapshot.snapshot_id
                            && still_disclosable(conn, &request.account, &request.issuer, &snapshot)
                                .await?
                        {
                            head_basis_available = true;
                            break;
                        }
                    }
                }
                let tail_start = (head.stream_position + 1)
                    .saturating_sub(u64::from(per_stream_limit))
                    .max(floor);
                let position = |value: u64| {
                    i64::try_from(value)
                        .map_err(|_| window_rejected("stream position exceeds storage"))
                };
                let delivered_is_ancestor = match delivered_head {
                    Some(delivered)
                        if delivered.stream_ref == stream_ref
                            && delivered.stream_position < head.stream_position
                            && delivered.stream_position + 1 >= tail_start =>
                    {
                        sql_query(
                            "SELECT commit_id AS present FROM realm_commits \
                     WHERE realm_id=$1 AND stream_key=$2 AND stream_position=$3",
                        )
                        .bind::<Text, _>(request.realm_id.as_str())
                        .bind::<Text, _>(&stream_key)
                        .bind::<super::BigInt, _>(position(delivered.stream_position)?)
                        .get_result::<CommitIdRow>(&mut *conn)
                        .await
                        .optional()?
                        .is_some_and(|row| row.present == delivered.commit_id.as_str())
                    }
                    _ => false,
                };
                let start = if head_basis_available && !delivered_is_ancestor {
                    head.stream_position + 1
                } else {
                    match delivered_head {
                        Some(delivered) if delivered_is_ancestor => delivered.stream_position + 1,
                        _ => tail_start,
                    }
                };
                // Load only the delivered rows and, for a start above genesis, the
                // anchor Commit just below them: never the whole stream history.
                let lowest = start.saturating_sub(1).max(floor);
                let rows = sql_query(
                    "SELECT commit_row.commit_json, event_row.envelope \
             FROM realm_commits commit_row \
             LEFT JOIN canonical_events event_row ON event_row.pk=commit_row.event_pk \
             WHERE commit_row.realm_id=$1 AND commit_row.stream_key=$2 \
               AND commit_row.stream_position >= $3 \
             ORDER BY commit_row.stream_position",
                )
                .bind::<Text, _>(request.realm_id.as_str())
                .bind::<Text, _>(&stream_key)
                .bind::<super::BigInt, _>(position(lowest)?)
                .load::<WindowCommitRow>(&mut *conn)
                .await?;
                let mut chain = Vec::with_capacity(rows.len());
                for row in rows {
                    let commit: arkret_wire::RealmCommit = serde_json::from_value(row.commit_json)
                        .map_err(PersistenceError::database)?;
                    chain.push(match row.envelope {
                        Some(envelope) => arkret_wire::CommittedEventView::Full(
                            arkret_wire::CommittedEventFullView {
                                commit,
                                event: serde_json::from_value(envelope)
                                    .map_err(PersistenceError::database)?,
                            },
                        ),
                        None => arkret_wire::CommittedEventView::Withheld(
                            arkret_wire::CommittedEventWithheldView {
                                commit,
                                event_disclosure: arkret_wire::EventDisclosure {
                                    status: arkret_wire::EventDisclosureStatus::Withheld,
                                },
                            },
                        ),
                    });
                }
                let contiguous = chain.iter().enumerate().all(|(offset, view)| {
                    view.commit().stream_position == lowest + offset as u64
                        && (offset == 0
                            || view.commit().previous_commit_ref.as_ref()
                                == Some(&chain[offset - 1].commit().commit_id))
                });
                let tip = chain
                    .last()
                    .ok_or_else(|| window_rejected("the proved stream has no Commit"))?;
                if !contiguous
                    || tip.commit().stream_position != head.stream_position
                    || tip.commit().commit_id != head.commit_id
                {
                    return Err(window_rejected(
                        "the delivered chain differs from the proved head",
                    )
                    .into());
                }
                let start_index =
                    usize::try_from(start - lowest).map_err(|_| window_rejected("window start"))?;
                let full_rows = chain[start_index..]
                    .iter()
                    .filter_map(|view| match view {
                        arkret_wire::CommittedEventView::Full(row) => Some(row.clone()),
                        arkret_wire::CommittedEventView::Withheld(_) => None,
                    })
                    .collect();
                let disclosed = crate::committed_disclosure::disclose_to_member_in_connection(
                    conn,
                    full_rows,
                    &arkret_wire::ActorId::account(request.account.clone()),
                )
                .await?;
                let mut disclosed = disclosed.into_iter();
                let delivered: Vec<_> = chain[start_index..]
                    .iter()
                    .map(|view| match view {
                        arkret_wire::CommittedEventView::Full(_) => {
                            disclosed.next().ok_or_else(|| {
                                window_rejected("the disclosure result omitted a Commit")
                            })
                        }
                        arkret_wire::CommittedEventView::Withheld(_) => Ok(view.clone()),
                    })
                    .collect::<PersistenceResult<_>>()?;
                let encoded = arkret_canonical::canonical_json_bytes(&delivered)
                    .map_err(PersistenceError::database)?;
                let used_bytes = arkret_canonical::canonical_json_bytes(&committed_events)
                    .map_err(PersistenceError::database)?
                    .len();
                if used_bytes + encoded.len() > request.byte_budget {
                    return Err(window_rejected("the atomic window exceeds its byte budget").into());
                }
                committed_events.extend(delivered);
                // Readable history lies below the window only above the proved floor.
                let limited = start > floor;
                let mut basis = None;
                // At the cap no further reservation is taken, so a limited window
                // names no basis and is preview only (0441).
                if start > floor
                    && live_reservations
                        < coland_storage::MAX_LIVE_WINDOW_RESERVATIONS_PER_ACCOUNT_STREAM
                {
                    let anchor_view = &chain[0];
                    let anchor = arkret_wire::CommitStreamHead {
                        stream_ref: stream_ref.clone(),
                        stream_position: anchor_view.commit().stream_position,
                        commit_id: anchor_view.commit().commit_id.clone(),
                    };
                    let candidates = sql_query(
                        "SELECT snapshot.snapshot_json FROM realm_state_snapshots snapshot \
                 JOIN realm_state_snapshot_issuances issued \
                   ON issued.snapshot_id = snapshot.snapshot_id \
                 WHERE snapshot.realm_id=$1 AND snapshot.governance_generation=$2 \
                   AND issued.account_id=$3 \
                   AND snapshot.snapshot_json->'visible_stream_heads' @> $4 \
                 ORDER BY issued.issued_at DESC, snapshot.snapshot_id \
                 LIMIT $5 FOR KEY SHARE OF issued",
                    )
                    .bind::<Text, _>(request.realm_id.as_str())
                    .bind::<super::BigInt, _>(tenure.generation)
                    .bind::<Text, _>(&account_key)
                    .bind::<Jsonb, _>(
                        serde_json::to_value(std::slice::from_ref(&anchor))
                            .map_err(PersistenceError::database)?,
                    )
                    .bind::<super::BigInt, _>(
                        coland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM,
                    )
                    .load::<SnapshotJsonRow>(&mut *conn)
                    .await?;
                    for candidate in candidates {
                        let snapshot: arkret_wire::RealmStateSnapshot =
                            serde_json::from_value(candidate.snapshot_json)
                                .map_err(PersistenceError::database)?;
                        let Some(candidate_basis) =
                            basis_from_snapshot(&snapshot, &stream_ref, &anchor, floor)
                        else {
                            continue;
                        };
                        if derived_snapshot_id(&snapshot)? != snapshot.snapshot_id
                            || !still_disclosable(
                                conn,
                                &request.account,
                                &request.issuer,
                                &snapshot,
                            )
                            .await?
                        {
                            continue;
                        }
                        sql_query(
                            "INSERT INTO realm_state_snapshot_window_reservations \
                     (window_cursor, account_id, stream_key, snapshot_id, expires_at_ms) \
                     VALUES ($1,$2,$3,$4,$5)",
                        )
                        .bind::<Text, _>(&request.window_cursor)
                        .bind::<Text, _>(&account_key)
                        .bind::<Text, _>(&stream_key)
                        .bind::<Text, _>(snapshot.snapshot_id.as_str())
                        .bind::<super::BigInt, _>(request.expires_at_ms)
                        .execute(&mut *conn)
                        .await?;
                        basis = Some(candidate_basis);
                        break;
                    }
                }
                let window = RealmStreamWindow {
                    stream_ref: stream_ref.clone(),
                    head_commit_ref: head.commit_id.clone(),
                    next_position: head.stream_position + 1,
                    limited,
                    window_limit: per_stream_limit,
                    complete: true,
                    preview_only: (start > 0 && basis.is_none()).then_some(true),
                    window_start_basis: basis,
                    e2ee_epoch: None,
                };
                window.validate().map_err(PersistenceError::database)?;
                windows.push(window);
            }
            // Issue the complete signed cut once, after all per-stream basis
            // reservations have been proved in this same transaction.
            if tenure.service_id == request.issuer.as_str() {
                let head_snapshot = sign(&material)?;
                if !coland_storage::signed_snapshot_matches_material(&head_snapshot, &material) {
                    return Err(PersistenceError::Internal(
                        "snapshot signer changed the proved disclosure material".to_owned(),
                    )
                    .into());
                }
                if coland_storage::enforce_inline_realm_state_snapshot_capacity(&head_snapshot)
                    .is_ok()
                {
                    issue_head_in_connection(conn, &request.account, &material, head_snapshot)
                        .await?;
                }
            }
            let mut windows = windows.into_iter();
            let window = windows
                .next()
                .ok_or_else(|| window_rejected("no selected window"))?;
            Ok(Some(coland_storage::AccountRealmWindow {
                governance_generation: generation,
                window,
                additional_windows: windows.collect(),
                streams_limited,
                committed_events,
                current_stream_heads: material.visible_stream_heads.clone(),
                current_state_entries: material.current_state_entries.clone(),
            }))
        })
        .await
        .map_err(snapshot_transaction_error);
    conn.finish(result).await
}

/// See [`coland_storage::AuthorityCommitStore::account_window_basis`].
pub(crate) async fn account_window_basis(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    account: &arkret_wire::AccountId,
    window_cursor: &str,
    stream_ref: &arkret_wire::CommitStreamRef,
    issuer: &arkret_wire::DidCoreId,
    now_ms: i64,
) -> PersistenceResult<
    Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis>,
> {
    let account_key = account_key(account)?;
    let stream_key = crate::authority_commit::stream_key(stream_ref)?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(row) = sql_query(
            "SELECT snapshot.snapshot_json, reserved.expires_at_ms \
             FROM realm_state_snapshot_window_reservations reserved \
             JOIN realm_state_snapshots snapshot ON snapshot.snapshot_id = reserved.snapshot_id \
             WHERE reserved.window_cursor=$1 AND reserved.account_id=$2 \
               AND reserved.stream_key=$3 AND snapshot.realm_id=$4",
        )
        .bind::<Text, _>(window_cursor)
        .bind::<Text, _>(&account_key)
        .bind::<Text, _>(&stream_key)
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<ReservedSnapshotRow>(&mut *conn)
        .await
        .optional()?
        else {
            return Ok(None);
        };
        if row.expires_at_ms <= now_ms {
            return Ok(None);
        }
        let snapshot: arkret_wire::RealmStateSnapshot =
            serde_json::from_value(row.snapshot_json).map_err(PersistenceError::database)?;
        let Some(anchor) = snapshot
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == stream_ref)
        else {
            return Ok(None);
        };
        let Some(floor) = snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .find(|floor| &floor.stream_ref == stream_ref)
        else {
            return Ok(None);
        };
        // The recheck below proves this floor is still the Account's own.
        let Some(basis) = basis_from_snapshot(&snapshot, stream_ref, anchor, floor.oldest_position)
        else {
            return Ok(None);
        };
        if !still_disclosable(conn, account, issuer, &snapshot).await? {
            return Ok(None);
        }
        Ok(Some(basis))
    })
    .await
    .map_err(snapshot_transaction_error)
}

/// Reclaim issued snapshots on the retention sweep's exclusive lock (0441).
///
/// Expired window reservations go first. An issuance is then reclaimable only
/// when no live reservation names it and it is older than
/// [`coland_storage::UNRESERVED_ISSUED_SNAPSHOT_RETENTION_MS`]; the signed
/// object goes with its last issuance. A snapshot that was never issued (a
/// private handoff anchor) is never a candidate. Each class is bounded to
/// `batch` rows; the result says whether either class filled its batch.
pub(crate) async fn prune_in_connection(
    conn: &mut AsyncPgConnection,
    now_ms: i64,
    batch: i64,
) -> Result<bool, PgTransactionError> {
    let reservations = sql_query(
        "DELETE FROM realm_state_snapshot_window_reservations WHERE ctid IN \
         (SELECT ctid FROM realm_state_snapshot_window_reservations \
          WHERE expires_at_ms <= $1 ORDER BY expires_at_ms LIMIT $2)",
    )
    .bind::<super::BigInt, _>(now_ms)
    .bind::<super::BigInt, _>(batch)
    .execute(&mut *conn)
    .await?;
    let issuances = sql_query(
        "WITH doomed AS ( \
           SELECT issued.snapshot_id, issued.account_id \
           FROM realm_state_snapshot_issuances issued \
           WHERE issued.issued_at <= to_timestamp(($1 - $2)::double precision / 1000) \
             AND NOT EXISTS (SELECT 1 FROM realm_state_snapshot_window_reservations reserved \
                             WHERE reserved.snapshot_id = issued.snapshot_id \
                               AND reserved.account_id = issued.account_id) \
           ORDER BY issued.issued_at LIMIT $3 \
         ), removed AS ( \
           DELETE FROM realm_state_snapshot_issuances issued USING doomed \
           WHERE issued.snapshot_id = doomed.snapshot_id \
             AND issued.account_id = doomed.account_id \
           RETURNING issued.snapshot_id, issued.account_id \
         ), orphaned AS ( \
           DELETE FROM realm_state_snapshots snapshot \
           WHERE snapshot.snapshot_id IN (SELECT snapshot_id FROM removed) \
             AND NOT EXISTS ( \
               SELECT 1 FROM realm_state_snapshot_issuances remaining \
               WHERE remaining.snapshot_id = snapshot.snapshot_id \
                 AND NOT EXISTS (SELECT 1 FROM removed \
                                 WHERE removed.snapshot_id = remaining.snapshot_id \
                                   AND removed.account_id = remaining.account_id)) \
           RETURNING 1 \
         ) \
         SELECT count(*) AS present FROM removed",
    )
    .bind::<super::BigInt, _>(now_ms)
    .bind::<super::BigInt, _>(coland_storage::UNRESERVED_ISSUED_SNAPSHOT_RETENTION_MS)
    .bind::<super::BigInt, _>(batch)
    .get_result::<CountRow>(&mut *conn)
    .await?
    .present;
    Ok(i64::try_from(reservations).is_ok_and(|rows| rows >= batch) || issuances >= batch)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AccountId, CommitStreamHead, CommitStreamRef, DidCoreId, DidUrl, EventId, HistoryAccess,
        RealmCommitId, RealmId, RealmSnapshotId, RetentionAndHistoryFloor, StreamHistoryFloor,
    };

    use super::*;

    fn account(principal: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn signed_snapshot() -> arkret_wire::RealmStateSnapshot {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x51; 32],
        ));
        let stream_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let material = coland_storage::RealmStateSnapshotMaterial {
            realm_id,
            governance_generation: 0,
            visible_stream_heads: vec![CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 0,
                commit_id: RealmCommitId::from_digest([0x52; 32]),
            }],
            current_state_entries: Vec::new(),
            retention_and_history_floor: RetentionAndHistoryFloor {
                history_access: HistoryAccess::SinceJoin,
                stream_floors: vec![StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 0,
                }],
            },
        };
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            &material,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &ed25519_dalek::SigningKey::from_bytes(&[0x73; 32]),
            chrono::Utc::now(),
        )
        .unwrap()
    }

    #[test]
    fn account_window_stream_cap_keeps_realm_and_explicit_batches_are_exact() {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x51; 32],
        ));
        let realm_ref = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let mut heads = vec![CommitStreamHead {
            stream_ref: realm_ref.clone(),
            stream_position: 0,
            commit_id: RealmCommitId::from_digest([0x52; 32]),
        }];
        for i in 0..65u8 {
            heads.push(CommitStreamHead {
                stream_ref: CommitStreamRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: arkret_wire::CircleId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [i; 32],
                    )),
                },
                stream_position: 0,
                commit_id: RealmCommitId::from_digest([i; 32]),
            });
        }
        let (at_limit, limited) = select_window_heads(&realm_id, &heads[..64], None).unwrap();
        assert_eq!(at_limit.len(), 64);
        assert!(!limited);
        let (default, limited) = select_window_heads(&realm_id, &heads, None).unwrap();
        assert_eq!(default.len(), 64);
        assert!(limited);
        assert!(default.iter().any(|head| head.stream_ref == realm_ref));
        let mut expected_circles = heads[1..].to_vec();
        expected_circles
            .sort_by_key(|head| arkret_canonical::canonical_json_bytes(&head.stream_ref).unwrap());
        assert_eq!(
            default
                .iter()
                .filter(|head| head.stream_ref != realm_ref)
                .cloned()
                .collect::<Vec<_>>(),
            expected_circles[..63],
        );
        let omitted = expected_circles[63].stream_ref.clone();
        let (explicit, limited) =
            select_window_heads(&realm_id, &heads, Some(&[omitted.clone()])).unwrap();
        assert_eq!(explicit.len(), 1);
        assert_eq!(explicit[0].stream_ref, omitted);
        assert!(!limited);
        assert!(select_window_heads(&realm_id, &heads, Some(&[omitted.clone(), omitted])).is_err());
        let too_many = heads[1..66]
            .iter()
            .map(|head| head.stream_ref.clone())
            .collect::<Vec<_>>();
        assert!(select_window_heads(&realm_id, &heads, Some(&too_many)).is_err());
    }

    #[test]
    fn complete_signed_body_over_eight_mib_is_rejected_whole() {
        let base = signed_snapshot();
        let sized = |payload: usize| {
            let material = coland_storage::RealmStateSnapshotMaterial {
                realm_id: base.realm_id.clone(),
                governance_generation: 0,
                visible_stream_heads: base.visible_stream_heads.clone(),
                current_state_entries: vec![arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::RealmProfile,
                    source_stream_ref: base.visible_stream_heads[0].stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: base.visible_stream_heads[0].commit_id.clone(),
                        stream_position: 0,
                    },
                    value: serde_json::json!({"title": "x".repeat(payload)}),
                }],
                retention_and_history_floor: base.retention_and_history_floor.clone(),
            };
            coland_services::authority_commit::build_signed_realm_state_snapshot(
                &material,
                DidUrl::new("did:web:station.example#notary-key").unwrap(),
                &ed25519_dalek::SigningKey::from_bytes(&[0x73; 32]),
                base.created_at,
            )
            .unwrap()
        };
        let probe = sized(0);
        let overhead = arkret_canonical::canonical_json_bytes(&probe)
            .unwrap()
            .len();
        let exact = sized(coland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES - overhead);
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&exact)
                .unwrap()
                .len(),
            coland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES,
        );
        coland_storage::enforce_inline_realm_state_snapshot_capacity(&exact).unwrap();
        let over = sized(coland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES - overhead + 1);
        let error =
            coland_storage::enforce_inline_realm_state_snapshot_capacity(&over).unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::SnapshotCapacityExceeded),
        );
    }

    async fn wait_for_session_lock(
        conn: &mut AsyncPgConnection,
        key: &str,
        waiting: bool,
        expected: i64,
    ) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let row = sql_query(
                    "SELECT COUNT(*) AS present FROM pg_locks \
                     WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) \
                       AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid \
                       AND objid=(hashtextextended($1,0)&4294967295)::oid AND objsubid=1 \
                       AND granted=$2",
                ).bind::<Text, _>(key).bind::<super::super::Bool, _>(!waiting)
                    .get_result::<CountRow>(&mut *conn).await.unwrap();
                if row.present == expected { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("the database must expose the expected session-lock state");
    }

    #[tokio::test]
    async fn coordinated_reissue_waits_before_establishing_its_repeatable_read_cut() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let alice = account("ak:did_core:web:alice.example");
        let snapshot = signed_snapshot();
        let material = coland_storage::RealmStateSnapshotMaterial {
            realm_id: snapshot.realm_id.clone(),
            governance_generation: snapshot.governance_generation,
            visible_stream_heads: snapshot.visible_stream_heads.clone(),
            current_state_entries: snapshot.current_state_entries.clone(),
            retention_and_history_floor: snapshot.retention_and_history_floor.clone(),
        };
        PgIssuedRealmSnapshotArchive::new(pool.clone())
            .issue(&alice, &snapshot)
            .await
            .unwrap();
        let mut first = SnapshotIssuanceConnection::acquire(&pool, &snapshot.realm_id)
            .await
            .unwrap();
        let key = first.realm_lock.clone();
        let second = tokio::spawn({
            let (pool, alice, snapshot, material) = (
                pool.clone(),
                alice.clone(),
                snapshot.clone(),
                material.clone(),
            );
            async move {
                let mut conn = SnapshotIssuanceConnection::acquire(&pool, &snapshot.realm_id)
                    .await
                    .unwrap();
                let result = conn
                    .transaction::<_, PgTransactionError, _>(async |conn| {
                        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                            .execute(&mut *conn)
                            .await?;
                        crate::sync_cursor::retention::lock(conn, false).await?;
                        issue_head_in_connection(conn, &alice, &material, snapshot.clone())
                            .await
                            .map_err(Into::into)
                    })
                    .await
                    .map_err(snapshot_transaction_error);
                conn.finish(result).await
            }
        });
        let mut observer = pg_conn(&pool).await.unwrap();
        wait_for_session_lock(&mut observer, &key, true, 1).await;
        let result = first
            .transaction::<_, PgTransactionError, _>(async |conn| {
                sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                    .execute(&mut *conn)
                    .await?;
                crate::sync_cursor::retention::lock(conn, false).await?;
                issue_head_in_connection(conn, &alice, &material, snapshot.clone())
                    .await
                    .map_err(Into::into)
            })
            .await
            .map_err(snapshot_transaction_error);
        assert_eq!(first.finish(result).await.unwrap(), snapshot);
        assert_eq!(second.await.unwrap().unwrap(), snapshot);
        wait_for_session_lock(&mut observer, &key, false, 0).await;
        let count = sql_query(
            "SELECT COUNT(*) AS present FROM realm_state_snapshot_issuances WHERE snapshot_id=$1",
        )
        .bind::<Text, _>(snapshot.snapshot_id.as_str())
        .get_result::<CountRow>(&mut *observer)
        .await
        .unwrap();
        assert_eq!(count.present, 1);
    }

    #[tokio::test]
    async fn cancelled_issuance_lock_wait_discards_the_pooled_session() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let realm = signed_snapshot().realm_id;
        let held = SnapshotIssuanceConnection::acquire(&pool, &realm)
            .await
            .unwrap();
        let key = held.realm_lock.clone();
        let waiting = tokio::spawn({
            let (pool, realm) = (pool.clone(), realm.clone());
            async move { SnapshotIssuanceConnection::acquire(&pool, &realm).await }
        });
        let mut observer = pg_conn(&pool).await.unwrap();
        wait_for_session_lock(&mut observer, &key, true, 1).await;
        waiting.abort();
        assert!(
            waiting
                .await
                .err()
                .expect("waiting task was cancelled")
                .is_cancelled()
        );
        wait_for_session_lock(&mut observer, &key, true, 0).await;
        held.finish(Ok(())).await.unwrap();
        wait_for_session_lock(&mut observer, &key, false, 0).await;
        let next = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            SnapshotIssuanceConnection::acquire(&pool, &realm),
        )
        .await
        .unwrap()
        .unwrap();
        next.finish(Ok(())).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_issuance_transaction_rolls_back_and_releases_session_locks() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let realm = signed_snapshot().realm_id;
        let (started, ready) = tokio::sync::oneshot::channel();
        let pending = tokio::spawn({
            let (pool, realm) = (pool.clone(), realm.clone());
            async move {
                let mut conn = SnapshotIssuanceConnection::acquire(&pool, &realm)
                    .await
                    .unwrap();
                let result = conn
                    .transaction::<_, PgTransactionError, _>(async |conn| {
                        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                            .execute(&mut *conn)
                            .await?;
                        crate::sync_cursor::retention::lock(conn, false).await?;
                        started.send(()).unwrap();
                        std::future::pending::<()>().await;
                        Ok(())
                    })
                    .await
                    .map_err(snapshot_transaction_error);
                conn.finish(result).await
            }
        });
        ready.await.unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        let next = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            SnapshotIssuanceConnection::acquire(&pool, &realm),
        )
        .await
        .unwrap()
        .unwrap();
        next.finish(Ok(())).await.unwrap();
        let mut observer = pg_conn(&pool).await.unwrap();
        // The exclusive GC lock also proves cancellation left no shared
        // retention lock behind on an idle pooled session.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sql_query("SELECT pg_advisory_xact_lock($1)")
                .bind::<super::super::BigInt, _>(crate::sync_cursor::retention::LOCK_KEY)
                .execute(&mut *observer),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn unchanged_cut_reissue_can_serialize_without_a_handoff() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let alice = account("ak:did_core:web:alice.example");
        let snapshot = signed_snapshot();
        let material = coland_storage::RealmStateSnapshotMaterial {
            realm_id: snapshot.realm_id.clone(),
            governance_generation: snapshot.governance_generation,
            visible_stream_heads: snapshot.visible_stream_heads.clone(),
            current_state_entries: snapshot.current_state_entries.clone(),
            retention_and_history_floor: snapshot.retention_and_history_floor.clone(),
        };
        PgIssuedRealmSnapshotArchive::new(pool.clone())
            .issue(&alice, &snapshot)
            .await
            .unwrap();
        let mut stale = pg_conn(&pool).await.unwrap();
        let mut current = pg_conn(&pool).await.unwrap();
        let result = stale
            .transaction::<_, PgTransactionError, _>(async |conn| {
                sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                    .execute(&mut *conn)
                    .await?;
                // This SELECT establishes the old MVCC cut, just as the
                // production shared retention lock does before issuance.
                crate::sync_cursor::retention::lock(conn, false).await?;
                let reissued = current
                    .transaction::<_, PgTransactionError, _>(async |conn| {
                        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                            .execute(&mut *conn)
                            .await?;
                        crate::sync_cursor::retention::lock(conn, false).await?;
                        issue_head_in_connection(conn, &alice, &material, snapshot.clone())
                            .await
                            .map_err(Into::into)
                    })
                    .await?;
                assert_eq!(reissued, snapshot);
                issue_head_in_connection(conn, &alice, &material, snapshot.clone())
                    .await
                    .map_err(Into::into)
            })
            .await;
        let error = match result {
            Ok(_) => panic!("stale repeatable-read issuance must lose the row-update race"),
            Err(error) => snapshot_transaction_error(error),
        };
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::TemporarilyUnavailable),
        );
        // Match our SQLSTATE 40001 mapping, not PostgreSQL's localized text.
        assert!(
            error
                .to_string()
                .contains("the snapshot transaction lost a concurrent write race"),
            "expected serialization failure mapping: {error}",
        );
        let retained =
            sql_query("SELECT snapshot_json FROM realm_state_snapshots WHERE snapshot_id=$1")
                .bind::<Text, _>(snapshot.snapshot_id.as_str())
                .get_result::<SnapshotJsonRow>(&mut *stale)
                .await
                .unwrap();
        assert_eq!(
            retained.snapshot_json,
            serde_json::to_value(&snapshot).unwrap()
        );
        let count = sql_query(
            "SELECT COUNT(*) AS present FROM realm_state_snapshot_issuances WHERE snapshot_id=$1",
        )
        .bind::<Text, _>(snapshot.snapshot_id.as_str())
        .get_result::<CountRow>(&mut *stale)
        .await
        .unwrap();
        assert_eq!(
            count.present, 1,
            "failed issuance must create no duplicate row"
        );
        // A new transaction sees the unchanged object and safely reissues it.
        let reissued = stale
            .transaction::<_, PgTransactionError, _>(async |conn| {
                sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                    .execute(&mut *conn)
                    .await?;
                crate::sync_cursor::retention::lock(conn, false).await?;
                issue_head_in_connection(conn, &alice, &material, snapshot.clone())
                    .await
                    .map_err(Into::into)
            })
            .await
            .map_err(snapshot_transaction_error)
            .unwrap();
        assert_eq!(reissued, snapshot);
    }

    #[tokio::test]
    async fn issued_snapshot_is_exact_immutable_account_scoped_and_rechecked() {
        let database = crate::test_database::TestDatabase::lease().await;
        let archive = PgIssuedRealmSnapshotArchive::new(database.pool());
        let alice = account("ak:did_core:web:alice.example");
        let bob = account("ak:did_core:web:bob.example");
        let issuer = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let snapshot = signed_snapshot();
        let wrong_realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x54; 32],
        ));
        let wrong_ref = RealmSnapshotId::from_digest([0x55; 32]);
        let read = |account: &AccountId, realm: &RealmId, id: &RealmSnapshotId| {
            let (archive, account, realm, id, issuer) = (
                archive.clone(),
                account.clone(),
                realm.clone(),
                id.clone(),
                issuer.clone(),
            );
            async move { archive.by_ref(&account, &realm, &id, &issuer).await }
        };

        assert!(
            read(&alice, &snapshot.realm_id, &snapshot.snapshot_id)
                .await
                .unwrap()
                .is_none()
        );
        archive.issue(&alice, &snapshot).await.unwrap();
        archive.issue(&alice, &snapshot).await.unwrap();
        // Issuance alone is not disclosure: this Realm has no governing
        // authority or Account join row at the read cut, so the exact
        // issued object is withheld rather than returned.
        assert!(matches!(
            read(&alice, &snapshot.realm_id, &snapshot.snapshot_id).await,
            Err(PersistenceError::SchemaViolation(_)),
        ));
        for (account, realm, id) in [
            (&bob, &snapshot.realm_id, &snapshot.snapshot_id),
            (&alice, &wrong_realm, &snapshot.snapshot_id),
            (&alice, &snapshot.realm_id, &wrong_ref),
        ] {
            assert!(read(account, realm, id).await.unwrap().is_none());
        }

        let mut forged_same_ref = snapshot.clone();
        forged_same_ref.signature.sig = arkret_wire::Base64UrlString::new("AA").unwrap();
        assert!(matches!(
            archive.issue(&alice, &forged_same_ref).await,
            Err(PersistenceError::Conflict(_)),
        ));
        // A private handoff-style row with no issuance is never exposed.
        let handoff = {
            let mut other = snapshot.clone();
            other.created_at -= chrono::Duration::seconds(1);
            let material = coland_storage::RealmStateSnapshotMaterial {
                realm_id: other.realm_id.clone(),
                governance_generation: other.governance_generation,
                visible_stream_heads: other.visible_stream_heads.clone(),
                current_state_entries: other.current_state_entries.clone(),
                retention_and_history_floor: other.retention_and_history_floor.clone(),
            };
            coland_services::authority_commit::build_signed_realm_state_snapshot(
                &material,
                DidUrl::new("did:web:station.example#notary-key").unwrap(),
                &ed25519_dalek::SigningKey::from_bytes(&[0x73; 32]),
                other.created_at,
            )
            .unwrap()
        };
        let mut conn = pg_conn(&database.pool()).await.unwrap();
        sql_query(
            "INSERT INTO realm_state_snapshots \
             (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
             VALUES ($1,$2,0,$3,$4)",
        )
        .bind::<Text, _>(handoff.snapshot_id.as_str())
        .bind::<Text, _>(handoff.realm_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&handoff).unwrap())
        .bind::<Timestamptz, _>(handoff.created_at)
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(
            read(&alice, &handoff.realm_id, &handoff.snapshot_id)
                .await
                .unwrap()
                .is_none()
        );
        // The newer Account-issued object never becomes the Realm-wide anchor.
        let store = crate::PgAuthorityCommitStore {
            pool: database.pool(),
        };
        assert_eq!(
            coland_storage::AuthorityCommitStore::latest_snapshot(&store, &snapshot.realm_id)
                .await
                .unwrap(),
            Some(handoff),
        );
    }
}
