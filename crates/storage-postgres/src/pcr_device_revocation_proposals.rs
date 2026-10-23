//! Immutable accepted PCR revoke dots and a same-snapshot keyed-set reader.

use arkret_models_collaboration::events_payloads::DeviceRevokePayload;
use arkret_wire::{
    AccountId, CommitStreamRef, DeviceId, Event, EventKind, RealmCommit, RealmCommitId,
};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::PgPool;
#[cfg(test)]
use crate::pg_conn;
use crate::{AsyncPgConnection, PersistenceError, PersistenceResult};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationProposal {
    pub tag_id: String,
    pub value: DeviceRevokePayload,
}

#[cfg(test)]
pub(crate) struct ConfirmedRevocationProposals {
    pub authority_commit_id: RealmCommitId,
    pub proposals: Vec<RevocationProposal>,
}

/// All PCR device authority inputs that can be justified by one SQL snapshot.
/// Lifecycle `active` still requires the formally specified terminal-result
/// and verified-conflict carriers; this type deliberately has no status flag.
pub(crate) struct ConfirmedPcrDeviceCut {
    pub realm_id: arkret_wire::RealmId,
    pub authority_commit_id: RealmCommitId,
    pub current_generation: Option<u64>,
    pub authorization: Option<DeviceAuthorizationAtCut>,
    pub proposals: Vec<RevocationProposal>,
}

pub(crate) struct DeviceAuthorizationAtCut {
    pub source_commit_id: RealmCommitId,
    pub event_id: arkret_wire::EventId,
    pub payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload,
}

#[derive(QueryableByName)]
struct PrincipalRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

#[derive(QueryableByName)]
struct StoredProposalRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    tag_id: String,
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

#[derive(QueryableByName)]
struct SnapshotRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
    #[diesel(sql_type = Text)]
    head_commit_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    generation_commit_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<BigInt>)]
    generation_stream_position: Option<i64>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    generation_value: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    latest_generation_commit_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<BigInt>)]
    latest_generation_stream_position: Option<i64>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    expected_generation_value: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    authorization_commit_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    authorization_stream_position: Option<i64>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    authorization_value: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    latest_authorization_commit_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    latest_authorization_stream_position: Option<i64>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    expected_authorization_value: Option<Value>,
    #[diesel(sql_type = BigInt)]
    accepted_count: i64,
    #[diesel(sql_type = BigInt)]
    projected_count: i64,
    #[diesel(sql_type = BigInt)]
    matched_count: i64,
    #[diesel(sql_type = Jsonb)]
    proposals: Value,
}

fn invalid(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

/// Called only from a registered revoke UoW after producer, device and
/// command-result validation. It does not itself make a generic revoke safe.
pub(crate) async fn project_revoke_proposal_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::DeviceRevoke
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid(
            "revoke proposal Event and accepted PCR Commit differ",
        ));
    }
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("revoke proposal actor is not an Account"))?;
    let principal = sql_query(
        "SELECT realm_id AS pcr_realm_id FROM pcr_genesis_units WHERE principal_id=$1 AND station_id=$2 AND result_json<>'{}'::jsonb FOR SHARE",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<PrincipalRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("revoke proposal has no accepted PCR creation anchor"))?;
    if principal.pcr_realm_id != event.realm_id.as_str() {
        return Err(invalid("revoke proposal is outside its PCR"));
    }
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let typed: DeviceRevokePayload = serde_json::from_value(payload.clone())
        .map_err(|error| invalid(format!("invalid revoke payload: {error}")))?;
    typed
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let tag_id = format!("{}:0", event.event_id);
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("revoke proposal position overflow"))?;
    sql_query(
        "INSERT INTO pcr_device_revocation_proposals \
         (realm_id,device_id,tag_id,event_id,commit_id,stream_position,payload) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(typed.device_id.as_str())
    .bind::<Text, _>(&tag_id)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&payload)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let stored = sql_query(
        "SELECT realm_id,device_id,tag_id,commit_id,stream_position,payload \
         FROM pcr_device_revocation_proposals WHERE event_id=$1",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .get_result::<StoredProposalRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if stored.realm_id != event.realm_id.as_str()
        || stored.device_id != typed.device_id.as_str()
        || stored.tag_id != tag_id
        || stored.commit_id != commit.commit_id.as_str()
        || stored.stream_position != position
        || stored.payload != payload
    {
        return Err(PersistenceError::Conflict(
            "device_revocation_proposal_duplicate_conflict".to_owned(),
        ));
    }
    Ok(())
}

/// One SQL statement fixes the head, accepted revoke count and canonical dot
/// set at one MVCC snapshot. An accepted revoke without its dot is unavailable.
pub(crate) async fn confirmed_pcr_device_cut_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    device_id: &DeviceId,
) -> PersistenceResult<Option<ConfirmedPcrDeviceCut>> {
    let row = sql_query(
        "SELECT p.realm_id AS pcr_realm_id, h.commit_id AS head_commit_id, \
           g.current_commit_id AS generation_commit_id, \
               g.current_stream_position AS generation_stream_position, g.value AS generation_value, \
           (SELECT c.commit_id FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE c.realm_id=p.realm_id AND \
              (e.kind='ak.device.reanchor' OR \
               (e.kind='ak.device.authorize' AND \
                e.envelope->'payload'->>'authorization_binding_kind'='registration_anchor')) \
            ORDER BY c.stream_position DESC LIMIT 1) AS latest_generation_commit_id, \
               (SELECT c.stream_position FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE c.realm_id=p.realm_id AND \
              (e.kind='ak.device.reanchor' OR \
               (e.kind='ak.device.authorize' AND \
                e.envelope->'payload'->>'authorization_binding_kind'='registration_anchor')) \
            ORDER BY c.stream_position DESC LIMIT 1) AS latest_generation_stream_position, \
           (SELECT jsonb_build_object('current_device_generation_ref', \
                    CASE WHEN e.kind='ak.device.reanchor' \
                      THEN e.envelope->'payload'->'new_device_generation' \
                          ELSE e.envelope->'payload'->'authorized_generation_ref' END) \
            FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE c.realm_id=p.realm_id AND \
              (e.kind='ak.device.reanchor' OR \
               (e.kind='ak.device.authorize' AND \
                e.envelope->'payload'->>'authorization_binding_kind'='registration_anchor')) \
            ORDER BY c.stream_position DESC LIMIT 1) AS expected_generation_value, \
           a.current_commit_id AS authorization_commit_id, a.current_stream_position AS authorization_stream_position, a.value AS authorization_value, \
           (SELECT c.commit_id FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE c.realm_id=p.realm_id AND e.kind='ak.device.authorize' \
              AND e.envelope->'payload'->>'device_id'=$3 \
            ORDER BY c.stream_position DESC LIMIT 1) AS latest_authorization_commit_id, \
           (SELECT c.stream_position FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE c.realm_id=p.realm_id AND e.kind='ak.device.authorize' \
              AND e.envelope->'payload'->>'device_id'=$3 \
            ORDER BY c.stream_position DESC LIMIT 1) AS latest_authorization_stream_position, \
           (SELECT ((e.envelope->'payload') - 'device_id'::text) || \
                    jsonb_build_object('device_authorize_event_id',e.envelope->>'event_id') \
            FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE c.realm_id=p.realm_id AND e.kind='ak.device.authorize' \
              AND e.envelope->'payload'->>'device_id'=$3 \
            ORDER BY c.stream_position DESC LIMIT 1) AS expected_authorization_value, \
           (SELECT count(*) FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE c.realm_id=p.realm_id AND e.kind='ak.device.revoke' \
              AND e.envelope->'payload'->>'device_id'=$3) AS accepted_count, \
           (SELECT count(*) FROM pcr_device_revocation_proposals r \
            WHERE r.realm_id=p.realm_id AND r.device_id=$3) AS projected_count, \
           (SELECT count(*) FROM pcr_device_revocation_proposals r \
            JOIN realm_commits c ON c.commit_id=r.commit_id \
            JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE r.realm_id=p.realm_id AND r.device_id=$3 \
              AND c.realm_id=r.realm_id AND c.stream_position=r.stream_position \
              AND e.kind='ak.device.revoke' AND e.envelope->>'event_id'=r.event_id \
              AND e.envelope->'payload'=r.payload) AS matched_count, \
           (SELECT coalesce(jsonb_agg(jsonb_build_object('tag_id',r.tag_id,'value',r.payload) \
                   ORDER BY r.tag_id),'[]'::jsonb) \
            FROM pcr_device_revocation_proposals r \
            WHERE r.realm_id=p.realm_id AND r.device_id=$3) AS proposals \
         FROM pcr_genesis_units p \
         JOIN LATERAL (SELECT commit_id FROM realm_commits \
                       WHERE realm_id=p.realm_id \
                         AND stream_ref=jsonb_build_object('kind','realm','realm_id',p.realm_id) \
                       ORDER BY stream_position DESC LIMIT 1) h ON TRUE \
         LEFT JOIN pcr_device_generation_current_results g ON g.realm_id=p.realm_id \
         LEFT JOIN pcr_device_authorization_current_results a \
           ON a.realm_id=p.realm_id AND a.device_id=$3 \
         WHERE p.principal_id=$1 AND p.station_id=$2 AND p.result_json<>'{}'::jsonb",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .bind::<Text, _>(device_id.as_str())
    .get_result::<SnapshotRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(None) };
    let realm =
        arkret_wire::RealmId::new(row.pcr_realm_id.clone()).map_err(|e| invalid(e.to_string()))?;
    if let arkret_wire::GenesisGovernance::Human(holder) =
        crate::pcr_private_authority::accepted_governance(conn, &realm).await?
    {
        if holder != *account {
            return Err(invalid("Human device cut belongs to another full Account"));
        }
        #[derive(diesel::QueryableByName)]
        struct Governor {
            #[diesel(sql_type=Text)]
            service_id: String,
            #[diesel(sql_type=diesel::sql_types::BigInt)]
            generation: i64,
        }
        let current =
            sql_query("SELECT service_id,generation FROM realm_authorities WHERE realm_id=$1")
                .bind::<Text, _>(realm.as_str())
                .get_result::<Governor>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
        arkret_wire::GenesisGovernance::Human(holder)
            .validate_current(
                &arkret_wire::DidCoreId::new(current.service_id)
                    .map_err(|e| invalid(e.to_string()))?,
                u64::try_from(current.generation).map_err(|e| invalid(e.to_string()))?,
            )
            .map_err(|e| invalid(e.to_string()))?;
    }
    if row.generation_commit_id != row.latest_generation_commit_id
        || row.authorization_commit_id != row.latest_authorization_commit_id
        || row.authorization_stream_position != row.latest_authorization_stream_position
        || row.generation_stream_position != row.latest_generation_stream_position
        || row.generation_value != row.expected_generation_value
        || row.authorization_value != row.expected_authorization_value
    {
        return Err(invalid(
            "PCR device authority projection is behind accepted Commit",
        ));
    }
    if row.accepted_count != row.projected_count || row.projected_count != row.matched_count {
        return Err(invalid(
            "accepted PCR revoke proposals are not fully projected",
        ));
    }
    let proposals: Vec<RevocationProposal> = serde_json::from_value(row.proposals)
        .map_err(|error| invalid(format!("stored revoke proposals are invalid: {error}")))?;
    for proposal in &proposals {
        if proposal.value.device_id != *device_id || !proposal.tag_id.ends_with(":0") {
            return Err(invalid("stored revoke proposal selector differs"));
        }
    }
    let current_generation = row
        .generation_value
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid("PCR generation value is not an object"))?;
            if object.len() != 1 {
                return Err(invalid("PCR generation value is not closed"));
            }
            value["current_device_generation_ref"]
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or_else(|| invalid("PCR generation value is invalid"))
        })
        .transpose()?;
    let authorization = match (row.authorization_commit_id, row.authorization_value) {
        (None, None) => None,
        (Some(source), Some(mut value)) => {
            let object = value
                .as_object_mut()
                .ok_or_else(|| invalid("PCR device authorization value is not an object"))?;
            let event_id: arkret_wire::EventId = serde_json::from_value(
                object
                    .remove("device_authorize_event_id")
                    .ok_or_else(|| invalid("PCR device authorization event id is absent"))?,
            )
            .map_err(|error| invalid(error.to_string()))?;
            object.insert(
                "device_id".to_owned(),
                serde_json::to_value(device_id).map_err(PersistenceError::database)?,
            );
            let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
                serde_json::from_value(value).map_err(|error| {
                    invalid(format!("PCR device authorization is invalid: {error}"))
                })?;
            Some(DeviceAuthorizationAtCut {
                source_commit_id: RealmCommitId::new(source)
                    .map_err(|error| invalid(error.to_string()))?,
                event_id,
                payload,
            })
        }
        _ => return Err(invalid("PCR device authorization provenance is incomplete")),
    };
    Ok(Some(ConfirmedPcrDeviceCut {
        realm_id: arkret_wire::RealmId::new(row.pcr_realm_id)
            .map_err(|error| invalid(error.to_string()))?,
        authority_commit_id: RealmCommitId::new(row.head_commit_id)
            .map_err(|error| invalid(error.to_string()))?,
        current_generation,
        authorization,
        proposals,
    }))
}

#[cfg(test)]
pub(crate) async fn confirmed_pcr_device_cut(
    pool: &PgPool,
    account: &AccountId,
    device_id: &DeviceId,
) -> PersistenceResult<Option<ConfirmedPcrDeviceCut>> {
    let mut conn = pg_conn(pool).await?;
    confirmed_pcr_device_cut_in_connection(&mut conn, account, device_id).await
}

#[cfg(test)]
pub(crate) async fn confirmed_revocation_proposals(
    pool: &PgPool,
    account: &AccountId,
    device_id: &DeviceId,
) -> PersistenceResult<Option<ConfirmedRevocationProposals>> {
    Ok(confirmed_pcr_device_cut(pool, account, device_id)
        .await?
        .map(|cut| ConfirmedRevocationProposals {
            authority_commit_id: cut.authority_commit_id,
            proposals: cut.proposals,
        }))
}
