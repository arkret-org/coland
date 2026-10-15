//! One repeatable-read PCR cut for the device lifecycle inputs. No caller may
//! infer `active` from an absent transaction result.

use arkret_models_crypto::{SecurityRotationRevokeCommandDecision, SecurityTransactionStep};
use arkret_wire::{AccountId, DeviceId};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;

use crate::pcr_device_revocation_proposals::{
    ConfirmedPcrDeviceCut, confirmed_pcr_device_cut_in_connection,
};
use crate::pcr_device_status_fold::{
    PcrDeviceLifecycle, RevokeCommandDecision, fold_confirmed_device_status,
};
use crate::{
    AsyncPgConnection, PersistenceError, PersistenceResult, PgPool, PgTransactionError, pg_conn,
};

#[derive(QueryableByName)]
struct StatusInputsRow {
    #[diesel(sql_type = BigInt)]
    proposal_count: i64,
    #[diesel(sql_type = BigInt)]
    bound_transaction_count: i64,
    #[diesel(sql_type = Jsonb)]
    transaction_rows: Value,
}

pub(crate) struct ConfirmedPcrDeviceStatusCut {
    pub authority: ConfirmedPcrDeviceCut,
    pub lifecycle: PcrDeviceLifecycle,
}

impl ConfirmedPcrDeviceStatusCut {
    /// Fold this cut into the current-device admission decision shared by
    /// every human-device producer gate; an instant outside the accepted
    /// authorization window has no complete current authorization.
    pub(crate) fn admission(&self) -> arkret_wire::DeviceRevocationAdmissionDecision {
        use arkret_wire::DeviceRevocationAdmissionDecision as Decision;
        match self.lifecycle {
            PcrDeviceLifecycle::Active => Decision::Allow,
            PcrDeviceLifecycle::Revoked => Decision::Revoked,
            PcrDeviceLifecycle::RevocationPending => Decision::RevocationPending,
            PcrDeviceLifecycle::GenerationFenced => Decision::GenerationMismatch,
            PcrDeviceLifecycle::Expired | PcrDeviceLifecycle::NotYetEffective => {
                Decision::AuthorityMismatch
            }
        }
    }
}

fn incomplete(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

/// Read all inputs under a single PostgreSQL REPEATABLE READ snapshot. The
/// transaction-local isolation setting is the first statement after BEGIN.
pub(crate) async fn confirmed_pcr_device_status_cut(
    pool: &PgPool,
    account: &AccountId,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<ConfirmedPcrDeviceStatusCut>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<Option<ConfirmedPcrDeviceStatusCut>, PgTransactionError, _>(async |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *conn)
            .await?;
        confirmed_pcr_device_status_cut_in_connection(conn, account, device_id, now).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Use only while the caller owns one PCR authority transaction. Reads every
/// device input from that same connection; the caller must serialize writers
/// before using this result for admission.
pub(crate) async fn confirmed_pcr_device_status_cut_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<ConfirmedPcrDeviceStatusCut>, PgTransactionError> {
    let Some(authority) = confirmed_pcr_device_cut_in_connection(conn, account, device_id).await?
    else {
        return Ok(None);
    };
    confirmed_pcr_device_status_from_authority(conn, account, device_id, authority, now)
        .await
        .map(Some)
}

/// Fold a cut already read on this connection, without querying a second
/// authorization. The caller must preserve the same snapshot or writer lock.
pub(crate) async fn confirmed_pcr_device_status_from_authority(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    device_id: &DeviceId,
    authority: ConfirmedPcrDeviceCut,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ConfirmedPcrDeviceStatusCut, PgTransactionError> {
    let row = sql_query(
            "SELECT \
               (SELECT count(*) FROM pcr_device_revocation_proposals r WHERE r.realm_id=$1 AND r.device_id=$2) AS proposal_count, \
               (SELECT count(*) FROM pcr_device_revocation_proposals r JOIN security_transactions t \
                  ON t.revoke_proposal->>'proposal_event_id'=r.event_id \
                 AND t.revoke_proposal->>'covering_commit_id'=r.commit_id \
                 AND t.kind='security_rotation' AND t.principal_id=$3 AND t.station_id=$4 \
                 AND t.prepared_plan->'revoke_unit'->'request'->'events'->0->>'event_id'=r.event_id \
                WHERE r.realm_id=$1 AND r.device_id=$2) AS bound_transaction_count, \
               (SELECT coalesce(jsonb_agg(jsonb_build_object( \
                    'event_id',r.event_id,'commit_id',r.commit_id,'tag_id',r.tag_id, \
                    'transaction_id',t.id::text, \
                    'proposal',t.revoke_proposal,'outcome',t.revoke_command_outcome, \
                    'terminal',t.terminal_outcome,'accepted_steps',t.accepted_steps) \
                    ORDER BY r.tag_id),'[]'::jsonb) \
                  FROM pcr_device_revocation_proposals r LEFT JOIN security_transactions t \
                    ON t.revoke_proposal->>'proposal_event_id'=r.event_id \
                   AND t.revoke_proposal->>'covering_commit_id'=r.commit_id \
                   AND t.kind='security_rotation' AND t.principal_id=$3 AND t.station_id=$4 \
                   AND t.prepared_plan->'revoke_unit'->'request'->'events'->0->>'event_id'=r.event_id \
                 WHERE r.realm_id=$1 AND r.device_id=$2) AS transaction_rows",
        )
        .bind::<Text, _>(authority.realm_id.as_str())
        .bind::<Text, _>(device_id.as_str())
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .get_result::<StatusInputsRow>(&mut *conn)
        .await?;
    if row.proposal_count != authority.proposals.len() as i64
        || row.bound_transaction_count != row.proposal_count
    {
        return Err(incomplete("PCR device status inputs are incomplete").into());
    }
    let rows = row
        .transaction_rows
        .as_array()
        .ok_or_else(|| incomplete("PCR revoke transaction rows are not an array"))?;
    if rows.len() != authority.proposals.len() {
        return Err(incomplete("PCR revoke transaction rows are incomplete").into());
    }
    let mut decisions = Vec::with_capacity(rows.len());
    for (source, record) in authority.proposals.iter().zip(rows) {
        let tag_id = record["tag_id"].as_str();
        let event_id = record["event_id"].as_str();
        let commit_id = record["commit_id"].as_str();
        if tag_id != Some(source.tag_id.as_str())
            || event_id != source.tag_id.strip_suffix(":0")
            || record["proposal"]["proposal_event_id"].as_str() != event_id
            || record["proposal"]["covering_commit_id"].as_str() != commit_id
        {
            return Err(incomplete("PCR revoke transaction provenance differs").into());
        }
        let transaction_uuid = record["transaction_id"]
            .as_str()
            .ok_or_else(|| incomplete("PCR revoke transaction id is absent"))?;
        let transaction_id = format!("ak:transaction:{transaction_uuid}");
        let stored = crate::security_transactions::load_one(conn, &transaction_id, false)
            .await?
            .ok_or_else(|| incomplete("PCR revoke transaction is absent"))?;
        let resource = stored.resource;
        let plan = resource
            .security_rotation_plan()
            .ok_or_else(|| incomplete("PCR revoke transaction is not SecurityRotation"))?;
        let durable_step = crate::security_transactions::load_step_outcome(
            conn,
            &transaction_id,
            SecurityTransactionStep::Revoke,
        )
        .await?;
        if resource.revoke_proposal.as_ref().is_none_or(|proposal| {
            Some(proposal.proposal_event_id.as_str()) != event_id
                || Some(proposal.covering_commit_id.as_str()) != commit_id
        }) || plan
            .revoke_unit
            .request
            .events
            .as_slice()
            .first()
            .is_none_or(|event| Some(event.event_id.as_str()) != event_id)
        {
            return Err(incomplete("PCR revoke typed transaction changed its proposal").into());
        }
        let decision = match resource.revoke_command_outcome.as_ref() {
            Some(outcome) if outcome.result == SecurityRotationRevokeCommandDecision::Accepted => {
                if durable_step.is_none() || resource.accepted_steps.is_empty() {
                    return Err(incomplete(
                        "PCR revoke accepted step is absent from the durable terminal outcome",
                    )
                    .into());
                }
                RevokeCommandDecision::Accepted
            }
            Some(outcome) if outcome.result == SecurityRotationRevokeCommandDecision::Rejected => {
                if durable_step.is_some() {
                    return Err(
                        incomplete("PCR rejected revoke has an accepted step outcome").into(),
                    );
                }
                RevokeCommandDecision::Rejected
            }
            None if durable_step.is_none() => RevokeCommandDecision::Pending,
            _ => return Err(incomplete("PCR revoke command outcome is invalid").into()),
        };
        if !record["outcome"].is_null()
            && (record["outcome"]["proposal_event_id"].as_str() != event_id
                || record["outcome"]["covering_commit_id"].as_str() != commit_id)
        {
            return Err(incomplete("PCR revoke outcome changed its proposal").into());
        }
        decisions.push(decision);
    }
    let authorization = authority
        .authorization
        .as_ref()
        .ok_or_else(|| incomplete("PCR device has no current authorization"))?;
    let generation = authority
        .current_generation
        .ok_or_else(|| incomplete("PCR device has no current generation"))?;
    let lifecycle =
        fold_confirmed_device_status(&authorization.payload, generation, &decisions, now);
    Ok(ConfirmedPcrDeviceStatusCut {
        authority,
        lifecycle,
    })
}

#[derive(QueryableByName)]
struct GenerationCutRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    generation_commit_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<BigInt>)]
    generation_stream_position: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    generation_value: Option<Value>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    latest_generation_commit_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<BigInt>)]
    latest_generation_stream_position: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    expected_generation_value: Option<Value>,
}

/// The PCR `device_generation` typed current from one REPEATABLE READ
/// snapshot of an accepted PCR head. The projection must equal what its latest
/// accepted writer (a registration anchor, managed PCR genesis or reanchor) derives, or the
/// read fails closed.
pub(crate) async fn confirmed_pcr_generation(
    pool: &PgPool,
    account: &AccountId,
) -> PersistenceResult<Option<coland_storage::PcrDeviceGeneration>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *conn)
            .await?;
        let row = sql_query(
            "SELECT \
               g.current_commit_id AS generation_commit_id, \
               g.current_stream_position AS generation_stream_position, g.value AS generation_value, \
               (SELECT c.commit_id FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                WHERE c.realm_id=p.pcr_realm_id AND \
                  (e.kind='ak.device.reanchor' OR \
                   (e.kind='ak.device.authorize' AND \
                    e.envelope->'payload'->>'authorization_binding_kind'='registration_anchor') OR \
                   (e.kind='ak.realm.create' AND c.stream_position=0 AND \
                    e.envelope->>'event_id'=p.genesis_event_id AND \
                    e.envelope#>>'{payload,object,purpose}'='applet_managed_control')) \
                ORDER BY c.stream_position DESC LIMIT 1) AS latest_generation_commit_id, \
               (SELECT c.stream_position FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                WHERE c.realm_id=p.pcr_realm_id AND \
                  (e.kind='ak.device.reanchor' OR \
                   (e.kind='ak.device.authorize' AND \
                    e.envelope->'payload'->>'authorization_binding_kind'='registration_anchor') OR \
                   (e.kind='ak.realm.create' AND c.stream_position=0 AND \
                    e.envelope->>'event_id'=p.genesis_event_id AND \
                    e.envelope#>>'{payload,object,purpose}'='applet_managed_control')) \
                ORDER BY c.stream_position DESC LIMIT 1) AS latest_generation_stream_position, \
               (SELECT jsonb_build_object('current_device_generation_ref', \
                        CASE WHEN e.kind='ak.device.reanchor' \
                          THEN e.envelope->'payload'->'new_device_generation' \
                          WHEN e.kind='ak.realm.create' THEN '1'::jsonb \
                          ELSE e.envelope->'payload'->'authorized_generation_ref' END) \
                FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                WHERE c.realm_id=p.pcr_realm_id AND \
                  (e.kind='ak.device.reanchor' OR \
                   (e.kind='ak.device.authorize' AND \
                    e.envelope->'payload'->>'authorization_binding_kind'='registration_anchor') OR \
                   (e.kind='ak.realm.create' AND c.stream_position=0 AND \
                    e.envelope->>'event_id'=p.genesis_event_id AND \
                    e.envelope#>>'{payload,object,purpose}'='applet_managed_control')) \
                ORDER BY c.stream_position DESC LIMIT 1) AS expected_generation_value \
             FROM principal_resolutions p \
             JOIN LATERAL (SELECT commit_id FROM realm_commits \
                           WHERE realm_id=p.pcr_realm_id \
                             AND stream_ref=jsonb_build_object('kind','realm','realm_id',p.pcr_realm_id) \
                           ORDER BY stream_position DESC LIMIT 1) h ON TRUE \
             LEFT JOIN pcr_device_generation_current_results g ON g.realm_id=p.pcr_realm_id \
             WHERE p.principal_id=$1 AND p.station_id=$2",
        )
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .get_result::<GenerationCutRow>(&mut *conn)
        .await
        .optional()?;
        let Some(row) = row else { return Ok(None) };
        if row.generation_commit_id.is_none()
            || row.generation_commit_id != row.latest_generation_commit_id
            || row.generation_stream_position != row.latest_generation_stream_position
            || row.generation_value != row.expected_generation_value
        {
            return Err(incomplete("PCR device generation projection is behind accepted Commit").into());
        }
        let value = row.generation_value.expect("checked above");
        let object = value
            .as_object()
            .filter(|object| object.len() == 1)
            .ok_or_else(|| incomplete("PCR generation value is not closed"))?;
        let current = object["current_device_generation_ref"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or_else(|| incomplete("PCR generation value is invalid"))?;
        Ok(Some(coland_storage::PcrDeviceGeneration {
            current_device_generation_ref: current,
        }))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
