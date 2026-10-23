use diesel_async::AsyncConnection;

use super::{
    BigInt, JsonPayloadRow, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz, Utc,
    Value, ids, pg_conn, sql_query, sql_types,
};

#[derive(QueryableByName)]
struct AuthorityRow {
    #[diesel(sql_type=Text)]
    account_id: String,
    #[diesel(sql_type=Text)]
    kind: String,
    #[diesel(sql_type=Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
    #[diesel(sql_type=Text)]
    remaining: String,
    #[diesel(sql_type=BigInt)]
    rate_per_minute: i64,
}
#[derive(QueryableByName)]
struct EntryRow {
    #[diesel(sql_type=Text)]
    object_digest: String,
    #[diesel(sql_type=BigInt)]
    charge: i64,
    #[diesel(sql_type=Nullable<Text>)]
    request_digest: Option<String>,
    #[diesel(sql_type=Nullable<Text>)]
    holder: Option<String>,
}
#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type=BigInt)]
    count: i64,
}

fn rejected(message: &str) -> PersistenceError {
    PersistenceError::Conflict(message.to_owned())
}
fn field<'a>(value: &'a Value, name: &str) -> PersistenceResult<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| rejected("unlock ledger binding incomplete"))
}
pub(crate) fn object_charge(value: &Value) -> PersistenceResult<(String, i64)> {
    let bytes =
        arkret_canonical::canonical_json_bytes(value).map_err(PersistenceError::database)?;
    let size = i64::try_from(bytes.len()).map_err(PersistenceError::database)?;
    Ok((arkret_canonical::sha256_digest(&bytes), size))
}

impl crate::key_backup::PgKeyBackupStore {
    pub(crate) async fn issue_unlock(
        &self,
        challenge: Value,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Value> {
        let id = field(&challenge, "challenge_id")?.to_owned();
        let backup_id = field(&challenge, "backup_id")?.to_owned();
        let device = field(&challenge, "requesting_device_id")?.to_owned();
        let account = arkret_canonical::canonical_json_string(&challenge["account_id"])
            .map_err(PersistenceError::database)?;
        let identity = arkret_canonical::canonical_sha256(&serde_json::json!([
            challenge["account_id"],
            device,
            backup_id,
            challenge["request_id"]
        ]))
        .map_err(PersistenceError::database)?;
        let expires = chrono::DateTime::parse_from_rfc3339(field(&challenge, "expires_at")?)
            .map_err(PersistenceError::database)?
            .with_timezone(&Utc);
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(format!("backup-unlock:{account}")).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            let existing=sql_query("SELECT challenge AS payload FROM key_backup_unlock_authorities WHERE identity_key=$1 AND expires_at>$2 AND NOT EXISTS (SELECT 1 FROM key_backup_unlock_entries e WHERE e.authority_id=key_backup_unlock_authorities.authority_id AND consumed_at IS NOT NULL)")
                .bind::<Text,_>(&identity).bind::<Timestamptz,_>(now).get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            if let Some(row)=existing { return Ok(row.payload); }
            let pending=sql_query("SELECT count(*) AS count FROM key_backup_unlock_authorities a WHERE account_id=$1 AND kind='current_device' AND expires_at>$2 AND NOT EXISTS(SELECT 1 FROM key_backup_unlock_entries e WHERE e.authority_id=a.authority_id AND consumed_at IS NOT NULL)")
                .bind::<Text,_>(&account).bind::<Timestamptz,_>(now).get_result::<CountRow>(&mut *conn).await.map_err(PersistenceError::database)?.count;
            if pending>=64 {return Err(rejected("rate_limited: outstanding unlock challenges").into());}
            // Keep consumed identities and their results for exact replay; a new issuance gets a distinct row.
            sql_query("UPDATE key_backup_unlock_authorities SET identity_key=authority_id WHERE identity_key=$1")
                .bind::<Text,_>(&identity).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            let backup=sql_query("SELECT payload FROM key_backups WHERE id=$1 FOR SHARE")
                .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(&backup_id)).get_result::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?.payload;
            if backup["series_id"]!=challenge["series_id"] || backup["ciphertext_digest"]!=challenge["ciphertext_digest"] { return Err(rejected("backup_frontier_stale").into()); }
            let (digest,charge)=object_charge(&backup)?;
            sql_query("INSERT INTO key_backup_unlock_authorities(authority_id,identity_key,account_id,device_id,kind,challenge,expires_at,remaining_bytes,verified_at,rate_per_minute) VALUES($1,$2,$3,$4,'current_device',$5,$6,$7,$8,4)")
                .bind::<Text,_>(&id).bind::<Text,_>(&identity).bind::<Text,_>(&account).bind::<Text,_>(&device).bind::<Jsonb,_>(&challenge).bind::<Timestamptz,_>(expires).bind::<BigInt,_>(charge).bind::<Timestamptz,_>(now).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            sql_query("INSERT INTO key_backup_unlock_entries(authority_id,backup_id,object_digest,charge) VALUES($1,$2,$3,$4)")
                .bind::<Text,_>(&id).bind::<Text,_>(&backup_id).bind::<Text,_>(digest).bind::<BigInt,_>(charge).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            Ok(challenge)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    pub(crate) async fn reserve_recovery_attempt(
        &self,
        id: &str,
        holder: &str,
        request_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            lock_recovery_policy_for_session(conn,id,now).await?;
            let now=chrono::Utc::now();
            let authority=sql_query("SELECT account_id,kind,expires_at,remaining_bytes::text AS remaining,rate_per_minute FROM key_backup_unlock_authorities WHERE authority_id=$1 AND kind='recovery_session' FOR UPDATE")
                .bind::<Text,_>(id).get_result::<AuthorityRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("recovery_evidence_unbound"))?;
            let session=sql_query("SELECT to_jsonb(s) AS payload FROM recovery_sessions s WHERE id=$1 AND state='verified' AND expires_at>$2 FOR SHARE")
                .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(id)).bind::<Timestamptz,_>(now).get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("recovery_evidence_unbound"))?.payload;
            if authority.expires_at<=now || holder!=format!("{}:{}",field(&session,"session_grant_id")?,field(&session,"session_grant_cnf_jkt")?) {return Err(rejected("recovery_evidence_unbound").into());}
            let replay=sql_query("SELECT count(*) AS count FROM key_backup_unlock_entries WHERE authority_id=$1 AND request_digest=$2 AND holder=$3 AND consumed_at IS NOT NULL")
                .bind::<Text,_>(id).bind::<Text,_>(request_digest).bind::<Text,_>(holder).get_result::<CountRow>(&mut *conn).await.map_err(PersistenceError::database)?.count;
            if replay>0 {return Ok(true);}
            let row=sql_query("INSERT INTO key_backup_unlock_attempt_windows(authority_id,window_start,attempts,last_request_digest,last_attempt_at) VALUES($1,date_trunc('minute',$2::timestamptz),1,$3,$2) ON CONFLICT(authority_id,window_start) DO UPDATE SET attempts=LEAST(key_backup_unlock_attempt_windows.attempts+1,$4+1),last_request_digest=EXCLUDED.last_request_digest,last_attempt_at=EXCLUDED.last_attempt_at RETURNING attempts AS count")
                .bind::<Text,_>(id).bind::<Timestamptz,_>(now).bind::<Text,_>(request_digest).bind::<BigInt,_>(authority.rate_per_minute).get_result::<CountRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            // A denied attempt is committed too; no backup allowance is touched here.
            Ok(row.count<=authority.rate_per_minute)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    pub(crate) async fn read_unlock(&self, id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = crate::pg_db(&self.pool);
        Ok(sql_query(
            "SELECT challenge AS payload FROM key_backup_unlock_authorities WHERE authority_id=$1",
        )
        .bind::<Text, _>(id)
        .get_result::<JsonPayloadRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| row.payload))
    }

    pub(crate) async fn consume_unlock_entry(
        &self,
        command: coland_storage::KeyBackupUnlockCommand<'_>,
    ) -> PersistenceResult<Value> {
        let coland_storage::KeyBackupUnlockCommand {
            basis,
            authority_id: id,
            backup,
            request_digest,
            holder,
            ip,
            now,
            daily_limit,
        } = command;
        let id = id.to_owned();
        let request_digest = request_digest.to_owned();
        let holder = holder.to_owned();
        let ip = ip.to_owned();
        let backup_id = field(&backup, "backup_id")?.to_owned();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            let current_device = match basis {
                coland_storage::KeyBackupUnlockBasis::CurrentDevice { basis, device_id } => {
                    recheck_pointer_basis(conn, basis, std::slice::from_ref(device_id), Some(&backup)).await?;
                    true
                }
                coland_storage::KeyBackupUnlockBasis::RecoverySession => false,
            };
            // Shared lock order serializes account counters and each authority's byte budget.
            let account=arkret_canonical::canonical_json_string(&backup["actor_id"]["account_id"]).map_err(PersistenceError::database)?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(format!("backup-unlock:{account}")).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            // Current-device authorities carry an explicit device gate. A recovery
            // authority must acquire the same policy lock as every policy publication.
            if !current_device { lock_recovery_policy_for_session(conn,&id,now).await?; }
            let now=chrono::Utc::now();
            let authority=sql_query("SELECT account_id,kind,expires_at,remaining_bytes::text AS remaining,rate_per_minute FROM key_backup_unlock_authorities WHERE authority_id=$1 FOR UPDATE")
                .bind::<Text,_>(&id).get_result::<AuthorityRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            if authority.account_id!=account {return Err(rejected("unlock account mismatch").into());}
            match (authority.kind.as_str(),current_device) {
                ("current_device",true)|("recovery_session",false)=>{},
                _=>return Err(rejected("unlock authority and current gate mismatch").into()),
            }
            if authority.kind=="recovery_session" {
                let session=sql_query("SELECT to_jsonb(s) AS payload FROM recovery_sessions s WHERE id=$1 AND state='verified' AND expires_at>$2 FOR SHARE")
                    .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(&id)).bind::<Timestamptz,_>(now).get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("recovery_evidence_unbound"))?.payload;
                if holder!=format!("{}:{}",field(&session,"session_grant_id")?,field(&session,"session_grant_cnf_jkt")?) {return Err(rejected("recovery holder changed").into());}
            }
            let entry=sql_query("SELECT object_digest,charge,request_digest,holder FROM key_backup_unlock_entries WHERE authority_id=$1 AND backup_id=$2 FOR UPDATE")
                .bind::<Text,_>(&id).bind::<Text,_>(&backup_id).get_result::<EntryRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("backup outside frozen unlock manifest"))?;
            let current=sql_query("SELECT payload FROM key_backups WHERE id=$1 FOR SHARE")
                .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(&backup_id)).get_result::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?.payload;
            let (digest,charge)=object_charge(&current)?;
            if digest!=entry.object_digest || charge!=entry.charge || current!=backup {return Err(rejected("backup_frontier_stale").into());}
            if let Some(previous)=entry.request_digest {
                if previous==request_digest && entry.holder.as_deref()==Some(holder.as_str()) {return Ok(current);}
                return Err(rejected("duplicate_conflict").into());
            }
            if authority.expires_at<=now {return Err(rejected("unlock challenge expired").into());}
            let remaining=authority.remaining.parse::<u64>().map_err(PersistenceError::database)?;
            if remaining < u64::try_from(charge).map_err(PersistenceError::database)? {return Err(rejected("unlock byte budget exhausted").into());}
            let window=now-chrono::Duration::minutes(1);
            if authority.kind=="current_device" {
                let day=now-chrono::Duration::hours(24);
                let count=sql_query("SELECT count(*) AS count FROM key_backup_unlock_entries e JOIN key_backup_unlock_authorities a USING(authority_id) WHERE a.account_id=$1 AND a.kind='current_device' AND e.consumed_at>$2")
                    .bind::<Text,_>(&account).bind::<Timestamptz,_>(day).get_result::<CountRow>(&mut *conn).await.map_err(PersistenceError::database)?.count;
                if count>=i64::from(daily_limit.min(64)) {return Err(rejected("rate_limited: daily backup unlock quota").into());}
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(format!("backup-unlock-ip:{ip}")).execute(&mut *conn).await.map_err(PersistenceError::database)?;
                let count=sql_query("SELECT count(*) AS count FROM key_backup_unlock_entries WHERE ip=$1 AND consumed_at>$2")
                    .bind::<Text,_>(&ip).bind::<Timestamptz,_>(window).get_result::<CountRow>(&mut *conn).await.map_err(PersistenceError::database)?.count;
                if count>=4 {return Err(rejected("rate_limited: backup unlock IP quota").into());}
            } else {
                let count=sql_query("SELECT count(*) AS count FROM key_backup_unlock_entries WHERE authority_id=$1 AND consumed_at>$2")
                    .bind::<Text,_>(&id).bind::<Timestamptz,_>(window).get_result::<CountRow>(&mut *conn).await.map_err(PersistenceError::database)?.count;
                if count>=authority.rate_per_minute {return Err(rejected("rate_limited: recovery unlock quota").into());}
            }
            sql_query("UPDATE key_backup_unlock_authorities SET remaining_bytes=remaining_bytes-$2 WHERE authority_id=$1")
                .bind::<Text,_>(&id).bind::<BigInt,_>(charge).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            sql_query("UPDATE key_backup_unlock_entries SET request_digest=$3,holder=$4,consumed_at=$5,ip=$6 WHERE authority_id=$1 AND backup_id=$2")
                .bind::<Text,_>(&id).bind::<Text,_>(&backup_id).bind::<Text,_>(&request_digest).bind::<Text,_>(&holder).bind::<Timestamptz,_>(now).bind::<Text,_>(&ip).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            Ok(current)
        }).await.map_err(PgTransactionError::into_persistence)
    }
}

/// Serialize policy revocation and unlock consumption by exact Account, before
/// any authority/session row lock. Normal later policy replacement is not revocation.
pub(crate) async fn validate_recovery_unlock_policy(
    conn: &mut crate::AsyncPgConnection,
    session: &Value,
    now: chrono::DateTime<Utc>,
) -> Result<(), PgTransactionError> {
    let principal = arkret_wire::DidCoreId::new(field(session, "principal_id")?.to_owned())
        .map_err(PersistenceError::database)?;
    let station = arkret_wire::DidCoreId::new(field(session, "station_id")?.to_owned())
        .map_err(PersistenceError::database)?;
    let account = arkret_wire::AccountId::new(principal, station);
    let canonical =
        arkret_canonical::canonical_json_string(&account).map_err(PersistenceError::database)?;
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("recovery-policy:{canonical}"))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let now = now.max(chrono::Utc::now());
    let bound = session["policy_payload"].clone();
    let bound_account: arkret_wire::AccountId = serde_json::from_value(
        bound
            .get("account_id")
            .cloned()
            .ok_or_else(|| rejected("recovery policy account binding missing"))?,
    )
    .map_err(PersistenceError::database)?;
    let bound_version = bound
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| rejected("recovery policy version missing"))?;
    if bound_account != account
        || session
            .get("policy_version")
            .and_then(Value::as_u64)
            .is_some_and(|version| version != bound_version)
    {
        return Err(rejected("recovery policy snapshot binding mismatch").into());
    }
    let version = i32::try_from(bound_version).map_err(PersistenceError::database)?;
    let rows=sql_query("SELECT p.raw_payload AS payload FROM recovery_policies p JOIN policy_current_results c ON c.policy_id=('ak:policy:' || p.id::text) AND c.current_commit_id=(p.acceptance_basis #>> '{}') AND c.value=p.raw_payload WHERE p.principal_id=$1 AND p.station_id=$2 AND p.version>=$3 ORDER BY p.version ASC FOR SHARE OF p")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).bind::<crate::Integer,_>(version)
        .load::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if rows
        .as_slice()
        .first()
        .is_none_or(|row| row.payload != session["policy_payload"])
    {
        return Err(rejected("frozen recovery policy is not accepted").into());
    }
    let updates = rows.into_iter().map(|row| row.payload).collect::<Vec<_>>();
    let proof = session
        .get("proof_payload")
        .and_then(|payload| payload.get("proof"))
        .filter(|proof| !proof.is_null())
        .cloned();
    if session.get("state").and_then(Value::as_str) == Some("verified") && proof.is_none() {
        return Err(rejected("verified recovery session proof missing").into());
    }
    let proof = proof
        .map(serde_json::from_value::<arkret_models_crypto::RecoverySessionProof>)
        .transpose()
        .map_err(PersistenceError::database)?;
    for policy in &updates {
        ensure_policy_payload_active(policy, now)?;
        if let Some(proof) = &proof {
            ensure_selected_recovery_method_active(policy, proof, now)?;
        }
    }
    Ok(())
}

fn ensure_selected_recovery_method_active(
    payload: &Value,
    proof: &arkret_models_crypto::RecoverySessionProof,
    now: chrono::DateTime<Utc>,
) -> Result<(), PgTransactionError> {
    use arkret_models_crypto::{RecoveryMethod, RecoverySessionProof};

    let policy: arkret_models_crypto::RecoveryPolicy =
        serde_json::from_value(payload.clone()).map_err(PersistenceError::database)?;
    let active = policy.methods.iter().any(|method| match (method, proof) {
        (RecoveryMethod::DidRoot, RecoverySessionProof::DidRoot(_)) => true,
        (RecoveryMethod::RecoveryUnlock { keys }, RecoverySessionProof::RecoveryUnlock(proof)) => {
            keys.iter().any(|key| {
                key.verification_method == proof.verification_method
                    && key.not_before <= now
                    && now < key.expires_at
                    && key.revoked_at.is_none_or(|revoked_at| now < revoked_at)
            })
        }
        (
            RecoveryMethod::DeviceQuorum { k, member_ids },
            RecoverySessionProof::DeviceQuorum(proof),
        ) => {
            *k <= proof
                .signatures
                .iter()
                .map(|signature| &signature.device_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len() as u32
                && proof
                    .signatures
                    .iter()
                    .all(|signature| member_ids.contains(&signature.device_id))
        }
        (
            RecoveryMethod::TrustedRecoveryService { services },
            RecoverySessionProof::TrustedRecoveryService(proof),
        ) => services.iter().any(|entry| {
            entry.service_id == proof.service_id
                && entry.audience == proof.audience
                && entry.authorization_verification_method == proof.verification_method
        }),
        _ => false,
    });
    if !active {
        return Err(rejected("selected recovery method or key was revoked").into());
    }
    Ok(())
}

pub(crate) fn ensure_policy_payload_active(
    policy: &Value,
    now: chrono::DateTime<Utc>,
) -> Result<(), PgTransactionError> {
    let methods = policy
        .get("methods")
        .and_then(Value::as_array)
        .ok_or_else(|| rejected("recovery policy methods missing"))?;
    if methods.is_empty() {
        return Err(rejected("recovery policy is revoked").into());
    }
    if let Some(not_before) = policy.get("not_before").and_then(Value::as_str) {
        let not_before = chrono::DateTime::parse_from_rfc3339(not_before)
            .map_err(PersistenceError::database)?
            .with_timezone(&chrono::Utc);
        if now < not_before {
            return Err(rejected("recovery policy is not yet active").into());
        }
    }
    if let Some(expires_at) = policy.get("expires_at").and_then(Value::as_str) {
        let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map_err(PersistenceError::database)?
            .with_timezone(&chrono::Utc);
        if expires_at <= now {
            return Err(rejected("recovery policy expired").into());
        }
    }
    Ok(())
}

pub(crate) async fn lock_recovery_policy_for_session(
    conn: &mut crate::AsyncPgConnection,
    id: &str,
    now: chrono::DateTime<Utc>,
) -> Result<(), PgTransactionError> {
    let session=sql_query("SELECT to_jsonb(s) AS payload FROM recovery_sessions s WHERE id=$1 AND state='verified' AND expires_at>$2")
        .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(id)).bind::<Timestamptz,_>(now)
        .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("recovery_evidence_unbound"))?;
    validate_recovery_unlock_policy(conn, &session.payload, now).await
}

/// The commit a frozen backup manifest was measured against.
fn basis_committed_ref(basis: &Value) -> PersistenceResult<arkret_wire::CommittedEventRef> {
    serde_json::from_value(
        basis
            .get("committed_ref")
            .cloned()
            .ok_or_else(|| rejected("backup authority committed_ref missing"))?,
    )
    .map_err(PersistenceError::database)
}

pub(crate) async fn validate_active_basis(
    conn: &mut crate::AsyncPgConnection,
    basis: &Value,
) -> Result<(), PgTransactionError> {
    #[derive(QueryableByName)]
    struct PresentRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        present: bool,
    }
    let reference = basis_committed_ref(basis)?;
    let present = sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.commit_id=$1 AND e.id=$2 AND c.stream_ref=$3 AND c.stream_position=$4 \
           AND e.state='committed') AS present",
    )
    .bind::<Text, _>(reference.commit_id.as_str())
    .bind::<diesel::sql_types::Binary, _>(
        ids::event_token_part_or_schema_violation(reference.event_id.as_str(), "event")?.to_vec(),
    )
    .bind::<Jsonb, _>(
        serde_json::to_value(&reference.stream_ref).map_err(PersistenceError::database)?,
    )
    .bind::<BigInt, _>(
        i64::try_from(reference.stream_position).map_err(PersistenceError::database)?,
    )
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    if !present {
        return Err(rejected("backup authority commit is not current").into());
    }
    Ok(())
}

#[derive(QueryableByName)]
struct GenerationRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

/// Recheck, at this transaction's PCR cut, the confirmed pointer a request
/// was authorized against (key-management.md §7.6): the `secret_storage`
/// pointer must be unchanged, every named device must be active in the
/// current generation at the same PCR head, and a released envelope must
/// belong to the active series and, when it names a generation, to the
/// current one. A later unrelated PCR Commit does not by itself stale it.
pub(crate) async fn recheck_pointer_basis(
    conn: &mut crate::AsyncPgConnection,
    basis: &coland_storage::KeyBackupPointerBasis,
    devices: &[arkret_wire::DeviceId],
    released: Option<&Value>,
) -> Result<(), PgTransactionError> {
    use arkret_models_crypto::BackupActiveSeriesPointer;
    use coland_storage::ConflictCode;

    let refused = |code: ConflictCode, reason: &str| -> PgTransactionError {
        PersistenceError::Conflict(format!("{code}: {reason}")).into()
    };
    let pointer = crate::key_backup_current_results::confirmed_key_backup_pointer_in_connection(
        conn,
        &basis.account_id,
    )
    .await?
    .ok_or_else(|| {
        refused(
            ConflictCode::TemporarilyUnavailable,
            "the confirmed KeyBackup pointer is absent",
        )
    })?;
    if pointer.secret_storage != basis.secret_storage {
        return Err(refused(
            ConflictCode::BackupRevisionStale,
            "the secret_storage pointer changed after authorization",
        ));
    }
    let now = Utc::now();
    for device in devices {
        let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
            conn,
            &basis.account_id,
            device,
            now,
        )
        .await?
        .ok_or_else(|| {
            refused(
                ConflictCode::DeviceUnauthorized,
                "device has no confirmed PCR cut",
            )
        })?;
        if cut.authority.authority_commit_id != pointer.authority_commit_id {
            return Err(refused(
                ConflictCode::TemporarilyUnavailable,
                "device status and pointer were read at different PCR heads",
            ));
        }
        if let Some(code) = cut.admission().error_code() {
            return Err(refused(
                ConflictCode::from_detail(code.as_str())
                    .unwrap_or(ConflictCode::DeviceUnauthorized),
                "device is not active in the current generation at the PCR cut",
            ));
        }
    }
    let Some(released) = released else {
        return Ok(());
    };
    let BackupActiveSeriesPointer::Active {
        active_series_id, ..
    } = &pointer.secret_storage
    else {
        return Err(refused(
            ConflictCode::BackupRevisionStale,
            "no active series is selected",
        ));
    };
    let envelope: arkret_models_crypto::KeyBackup = serde_json::from_value(released.clone())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if &envelope.series_id != active_series_id {
        return Err(refused(
            ConflictCode::BackupRevisionStale,
            "the envelope is outside the active series",
        ));
    }
    if let Some(source) = &envelope.source_commit_ref {
        let generation =
            sql_query("SELECT value FROM pcr_device_generation_current_results WHERE realm_id=$1")
                .bind::<Text, _>(pointer.control_realm_id.as_str())
                .get_result::<GenerationRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .and_then(|row| row.value["current_device_generation_ref"].as_u64());
        if generation != Some(source.device_generation_ref) {
            return Err(refused(
                ConflictCode::BackupRevisionStale,
                "the envelope names a device generation that is not current",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod pg_tests;
