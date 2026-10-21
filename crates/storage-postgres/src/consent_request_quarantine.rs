//! One holder-private Consent request admission cut. The public route remains
//! closed until this cut has a verified caller and post-commit device fanout.

use arkret_models_collaboration::governance::holder_quarantine::{
    HolderQuarantine, HolderQuarantineEntry, HolderQuarantineSurface,
};
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_wire::{AccountDataKey, ActorId, Hash};
use chrono::{DateTime, Duration, Utc};
use coland_storage::{
    AccountDataCasResult, AccountDataRecord, ConsentRequestQuarantineInput,
    ConsentRequestQuarantineOutcome, ConsentRequestQuarantineStore, PersistenceError,
    PersistenceResult,
};
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::{Value, json};

use crate::accounts::compare_account_data_in_transaction;
use crate::{PgPool, PgTransactionError, pg_conn};

const MAX_ENTRIES: usize = 200;
const ENTRY_TTL_DAYS: i64 = 7;

pub struct PgConsentRequestQuarantineStore {
    pub pool: PgPool,
}

#[derive(diesel::QueryableByName)]
struct HolderRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    disabled_at: Option<DateTime<Utc>>,
}

#[derive(diesel::QueryableByName)]
struct LifecycleRow {
    #[diesel(sql_type = Text)]
    state: String,
}

#[derive(diesel::QueryableByName)]
struct PolicyRow {
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
}

#[derive(diesel::QueryableByName)]
struct CellRow {
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Bool)]
    tombstone: bool,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct QuotaCountRow {
    #[diesel(sql_type = BigInt)]
    window_count: i64,
    #[diesel(sql_type = BigInt)]
    retention_count: i64,
}

fn invalid(detail: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_owned())
}

#[async_trait::async_trait]
impl ConsentRequestQuarantineStore for PgConsentRequestQuarantineStore {
    async fn admit(
        &self,
        input: ConsentRequestQuarantineInput,
    ) -> PersistenceResult<ConsentRequestQuarantineOutcome> {
        input
            .holder
            .validate()
            .map_err(|_| invalid("invalid Consent holder"))?;
        input
            .requester
            .validate()
            .map_err(|_| invalid("invalid Consent requester"))?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            admit_in_connection(conn, &input).await.map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

pub(crate) async fn admit_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    input: &ConsentRequestQuarantineInput,
) -> PersistenceResult<ConsentRequestQuarantineOutcome> {
    #[derive(diesel::QueryableByName)]
    struct Present {
        #[diesel(sql_type=Bool)]
        present: bool,
    }
    let present = sql_query(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE principal_id=$1 AND station_id=$2) AS present",
    )
    .bind::<Text, _>(input.holder.principal_id.as_str())
    .bind::<Text, _>(input.holder.station_id.as_str())
    .get_result::<Present>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !present.present {
        return Ok(ConsentRequestQuarantineOutcome::Dropped);
    }
    let authority = crate::pcr_private_authority::lock_holder(
        conn,
        &input.holder,
        Some(&input.acceptor_service_id),
    )
    .await?;
    // The Invite and Contact surfaces acquire this lock before touching their
    // account-backed ledger. Keep the same order to avoid a lock cycle with
    // their account foreign-key checks.
    let ledger_lock = format!(
        "invite-new-source-ledger:{}:{}",
        input.holder.principal_id, input.holder.station_id
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(&ledger_lock)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let holder = sql_query(
        "SELECT pk,disabled_at FROM accounts \
         WHERE principal_id=$1 AND station_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(input.holder.principal_id.as_str())
    .bind::<Text, _>(input.holder.station_id.as_str())
    .get_result::<HolderRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(holder) = holder else {
        return Ok(ConsentRequestQuarantineOutcome::Dropped);
    };
    let lifecycle = sql_query("SELECT state FROM account_lifecycle WHERE account_pk=$1 FOR SHARE")
        .bind::<BigInt, _>(holder.pk)
        .get_result::<LifecycleRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    if holder.disabled_at.is_some()
        || matches!(
            lifecycle.as_ref().map(|row| row.state.as_str()),
            Some("deactivated" | "erasure_pending")
        )
    {
        return Ok(ConsentRequestQuarantineOutcome::Dropped);
    }
    let policy = sql_query(
        "SELECT policy_payload FROM invite_receive_policies WHERE account_pk=$1 FOR SHARE",
    )
    .bind::<BigInt, _>(holder.pk)
    .get_result::<PolicyRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let policy = match policy {
        Some(row) => serde_json::from_value::<InviteReceivePolicy>(row.policy_payload)
            .map_err(|_| invalid("holder receive policy is invalid"))?,
        None => InviteReceivePolicy::spec_default(input.holder.clone()),
    };
    if policy.account_id != input.holder {
        return Err(invalid("holder receive policy belongs to another Account"));
    }
    let requester_actor = ActorId::account(input.requester.clone());
    if policy.consent_profile.requires_explicit_consent()
        || policy.denied_actor_ids.contains(&requester_actor)
        || policy
            .denied_source_ids
            .contains(&input.requester.station_id)
    {
        return Ok(ConsentRequestQuarantineOutcome::Dropped);
    }
    let quota = input
        .quota_constraints
        .effective(policy.new_source_quota.as_ref())
        .map_err(|_| invalid("holder new-source quota is invalid"))?;
    let actor = ActorId::account(input.holder.clone()).to_string();
    let key = AccountDataKey::ACCOUNT_HOLDER_QUARANTINE;
    let current = sql_query(
        "SELECT revision,payload,tombstone FROM account_datas \
         WHERE actor_id=$1 AND account_data_key=$2 \
         AND account_data_source_current(actor_id,account_data_key) FOR UPDATE",
    )
    .bind::<Text, _>(&actor)
    .bind::<Text, _>(key)
    .get_result::<CellRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let mut cell = match &current {
        Some(row) if !row.tombstone => {
            let cell: HolderQuarantine = serde_json::from_value(row.payload.clone())
                .map_err(|_| invalid("holder quarantine cell is invalid"))?;
            cell.validate_holder(&input.holder)
                .map_err(|_| invalid("holder quarantine cell owner or entry is invalid"))?;
            cell
        }
        _ => HolderQuarantine::new(input.received_at),
    };
    if cell
        .live_consent_request(
            &arkret_wire::ActorId::account(input.requester.clone()),
            input.consent_scope,
        )
        .is_some_and(|entry| entry.expires_at > input.received_at)
    {
        return Ok(ConsentRequestQuarantineOutcome::AlreadyPending);
    }

    let source_digest = crate::invite_new_source_ledger::source_digest_in_connection(
        conn,
        &input.holder,
        &input.requester.principal_id,
    )
    .await?;

    // The same holder lock also keeps the policy and the queue decision on
    // one stable admission cut while the source quota is checked below.
    let retention_floor = input.received_at - Duration::seconds(quota.retention_seconds as i64);
    let window_floor = input.received_at - Duration::seconds(quota.window_seconds as i64);
    let seen = sql_query(
        "SELECT count(*) AS count FROM invite_new_source_ledgers \
         WHERE account_pk=$1 AND source_digest=$2 AND first_admitted_at>$3",
    )
    .bind::<BigInt, _>(holder.pk)
    .bind::<Text, _>(&source_digest)
    .bind::<Timestamptz, _>(retention_floor)
    .get_result::<CountRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if seen.count == 0 {
        let counts = sql_query(
            "SELECT count(*) FILTER (WHERE first_admitted_at>$2) AS window_count, \
             count(*) AS retention_count FROM invite_new_source_ledgers \
             WHERE account_pk=$1 AND first_admitted_at>$3",
        )
        .bind::<BigInt, _>(holder.pk)
        .bind::<Timestamptz, _>(window_floor)
        .bind::<Timestamptz, _>(retention_floor)
        .get_result::<QuotaCountRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if u64::try_from(counts.window_count).unwrap_or(u64::MAX) >= quota.new_sources_per_window
            || u64::try_from(counts.retention_count).unwrap_or(u64::MAX)
                >= quota.new_sources_per_retention
        {
            return Ok(ConsentRequestQuarantineOutcome::Dropped);
        }
    }

    let digest = arkret_canonical::canonical_sha256(&json!({
        "holder": input.holder,
        "requester": input.requester,
        "consent_scope": input.consent_scope,
        "received_at": input.received_at,
    }))
    .map_err(PersistenceError::database)?;
    let entry = HolderQuarantineEntry {
        entry_digest: Hash::new(digest)
            .map_err(|_| invalid("Consent request digest is invalid"))?,
        account_id: input.holder.clone(),
        source_peer_principal_id: input.requester.principal_id.clone(),
        source_peer_actor_id: arkret_wire::ActorId::account(input.requester.clone()),
        source_id: input.requester.station_id.clone(),
        surface: HolderQuarantineSurface::ConsentRequest {
            consent_scope: input.consent_scope,
        },
        received_at: input.received_at,
        expires_at: input.received_at + Duration::days(ENTRY_TTL_DAYS),
    };
    cell.updated_at = cell.updated_at.max(input.received_at);
    cell.quarantine_entries
        .retain(|candidate| candidate.expires_at > cell.updated_at);
    cell.quarantine_entries.push(entry);
    cell.quarantine_entries.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.entry_digest.as_str().cmp(right.entry_digest.as_str()))
    });
    if cell.quarantine_entries.len() > MAX_ENTRIES {
        let excess = cell.quarantine_entries.len() - MAX_ENTRIES;
        cell.quarantine_entries.drain(0..excess);
    }
    cell.validate_holder(&input.holder)
        .map_err(|_| invalid("Consent request quarantine entry is invalid"))?;
    let expected_revision = current
        .as_ref()
        .map(|row| u64::try_from(row.revision).map_err(|_| invalid("negative quarantine revision")))
        .transpose()?
        .unwrap_or(0);
    let updated_at = cell.updated_at;
    let revision = expected_revision
        .checked_add(1)
        .ok_or_else(|| invalid("quarantine revision exhausted"))?;
    let record = AccountDataRecord {
        actor,
        account_data_key: key.to_owned(),
        revision,
        payload: serde_json::to_value(cell).map_err(PersistenceError::database)?,
        tombstone: false,
        updated_at,
    };
    let applied =
        compare_account_data_in_transaction(conn, &record, expected_revision, None).await?;
    let AccountDataCasResult::Applied(record) = applied else {
        return Err(PersistenceError::Conflict(
            "cas_conflict: quarantine changed".to_owned(),
        ));
    };
    if seen.count == 0 {
        sql_query(
            "DELETE FROM invite_new_source_ledgers WHERE account_pk=$1 AND first_admitted_at<=$2",
        )
        .bind::<BigInt, _>(holder.pk)
        .bind::<Timestamptz, _>(retention_floor)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let inserted = sql_query(
            "INSERT INTO invite_new_source_ledgers(account_pk,source_digest,first_admitted_at) \
             VALUES($1,$2,$3) ON CONFLICT(account_pk,source_digest) DO NOTHING",
        )
        .bind::<BigInt, _>(holder.pk)
        .bind::<Text, _>(&source_digest)
        .bind::<Timestamptz, _>(input.received_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if inserted != 1 {
            return Err(PersistenceError::Conflict(
                "cas_conflict: Consent source ledger changed".to_owned(),
            ));
        }
    }
    crate::consent_private_effects::mark_pending(conn, &input.holder, &authority.realm_id).await?;
    Ok(ConsentRequestQuarantineOutcome::Queued(record))
}
