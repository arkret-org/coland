//! Method-native resolution admission and current publication at one PCR cut.

use arkret_models_identity::{PrincipalResolutionProjection, PrincipalResolutionUpdatePayload};
use arkret_wire::{
    AccountId, AuthorityCommitStatus, AuthoritySubmitOutcome, Event, EventKind, RealmCommit,
};
use coland_storage::{
    AuthorityCommitWriteOutcome, ConflictCode, PrincipalResolutionRecord,
    PrincipalResolutionUpdateWrite,
};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};

use crate::actor_profiles::{
    PcrSelfEventCut, corrupt, rejected, verify_pcr_self_event_before_current_guard,
};
use crate::{AsyncPgConnection, PgTransactionError};

#[derive(QueryableByName)]
struct Current {
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    station_id: String,
    #[diesel(sql_type = Jsonb)]
    genesis_event: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    current_event: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// Reads exclusively from the typed current and its exact immutable source.
/// The replaceable principal_resolutions index cannot establish authority.
pub(crate) async fn current_in_connection(
    conn: &mut AsyncPgConnection,
    account: Option<&AccountId>,
    realm: Option<&arkret_wire::RealmId>,
) -> Result<Option<(PrincipalResolutionRecord, RealmCommit)>, PgTransactionError> {
    let row = sql_query(
        "SELECT r.principal_id,r.station_id,g.envelope AS genesis_event,e.envelope AS current_event,c.commit_json,r.value \
         FROM principal_resolution_current_results r \
         JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.pcr_realm_id AND c.stream_position=r.current_stream_position \
         JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         JOIN canonical_events g ON g.envelope->>'event_id'=r.genesis_event_id AND g.realm_id=r.pcr_realm_id AND g.state='committed' \
         JOIN realm_commits gc ON gc.event_pk=g.pk AND gc.stream_position=0 \
         WHERE ($1::text IS NULL OR r.principal_id=$1) AND ($2::text IS NULL OR r.station_id=$2) \
           AND ($3::text IS NULL OR r.pcr_realm_id=$3) \
           AND NOT EXISTS(SELECT 1 FROM realm_commits newer JOIN canonical_events ne ON ne.pk=newer.event_pk \
                          WHERE newer.realm_id=r.pcr_realm_id AND newer.stream_position>r.current_stream_position \
                            AND ne.kind='ak.identity.resolution.update' AND ne.state='committed')",
    )
    .bind::<Nullable<Text>, _>(account.map(|a| a.principal_id.as_str()))
    .bind::<Nullable<Text>, _>(account.map(|a| a.station_id.as_str()))
    .bind::<Nullable<Text>, _>(realm.map(|r| r.as_str()))
    .get_result::<Current>(&mut *conn).await.optional()?;
    let Some(row) = row else { return Ok(None) };
    let account = AccountId::new(
        row.principal_id.parse().map_err(corrupt)?,
        row.station_id.parse().map_err(corrupt)?,
    );
    let current: Event = serde_json::from_value(row.current_event).map_err(corrupt)?;
    let commit: RealmCommit = serde_json::from_value(row.commit_json).map_err(corrupt)?;
    let record = PrincipalResolutionRecord {
        account_id: account,
        pcr_realm_id: current.realm_id.clone(),
        genesis_event: serde_json::from_value(row.genesis_event).map_err(corrupt)?,
        current_event: current,
        projection: serde_json::from_value(row.value).map_err(corrupt)?,
    };
    coland_storage::validate_principal_resolution_record(&record)?;
    if record.current_event.event_id != commit.event_ref || commit.realm_id != record.pcr_realm_id {
        return Err(corrupt(
            "resolution current differs from its covering Commit",
        ));
    }
    let expected = if record.current_event.kind == EventKind::IdentityResolutionUpdate {
        let payload: PrincipalResolutionUpdatePayload = serde_json::from_value(
            serde_json::to_value(&record.current_event.payload).map_err(corrupt)?,
        )
        .map_err(corrupt)?;
        payload.next
    } else {
        serde_json::from_value(
            record
                .genesis_event
                .payload
                .get("object")
                .and_then(|o| o.get("initial_resolution"))
                .cloned()
                .ok_or_else(|| corrupt("resolution genesis omits initial_resolution"))?,
        )
        .map_err(corrupt)?
    };
    if record.projection.updated_at != record.current_event.created_at
        || record.projection.did != expected.did
        || record.projection.method_history_head != expected.method_history_head
        || record.projection.version_id != expected.version_id
    {
        return Err(corrupt(
            "resolution current value differs from its accepted Event",
        ));
    }
    Ok(Some((record, commit)))
}

pub(crate) async fn initialize_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    event: &Event,
    commit: &RealmCommit,
    projection: &PrincipalResolutionProjection,
) -> Result<(), PgTransactionError> {
    if event.kind != EventKind::RealmCreate
        || event.actor_id.as_account_id() != Some(account)
        || commit.event_ref != event.event_id
        || commit.stream_position != 0
        || projection.resolution_event_ref != event.event_id.as_str()
    {
        return Err(corrupt(
            "resolution initialization is not the exact Account genesis",
        ));
    }
    sql_query("INSERT INTO principal_resolution_current_results(principal_id,station_id,pcr_realm_id,genesis_event_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str())
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(corrupt)?)
        .bind::<Jsonb,_>(serde_json::to_value(projection).map_err(corrupt)?).bind::<Timestamptz,_>(commit.committed_at)
        .execute(conn).await?;
    Ok(())
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    write: &PrincipalResolutionUpdateWrite,
) -> Result<AuthoritySubmitOutcome, PgTransactionError> {
    let tx = &write.transaction;
    let event = &tx.event;
    if event.kind != EventKind::IdentityResolutionUpdate {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "not a resolution update",
        ));
    }
    arkret_schema::validate_event_for_submit(event).map_err(corrupt)?;
    let confirmed_head =
        match verify_pcr_self_event_before_current_guard(conn, tx, None, "identity resolution")
            .await?
        {
            PcrSelfEventCut::Known(commit) => {
                return Ok(AuthoritySubmitOutcome::Accepted {
                    status: AuthorityCommitStatus::Duplicate,
                    commit: *commit,
                });
            }
            PcrSelfEventCut::Fresh(signer) => signer.confirmed_head,
        };
    let (current, source) =
        current_in_connection(conn, event.actor_id.as_account_id(), Some(&event.realm_id))
            .await?
            .ok_or_else(|| {
                rejected(
                    ConflictCode::TemporarilyUnavailable,
                    "accepted resolution current unavailable",
                )
            })?;
    let payload: PrincipalResolutionUpdatePayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(corrupt)?)
            .map_err(corrupt)?;
    if payload.expected_revision.commit_id != source.commit_id
        || payload.expected_revision.stream_position != source.stream_position
    {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "identity resolution revision changed",
        ));
    }
    if tx.commit.previous_commit_ref.as_ref() != Some(&confirmed_head) {
        return Err(rejected(
            ConflictCode::TemporarilyUnavailable,
            "PCR head changed before resolution acceptance",
        ));
    }
    if payload.next.did.method() != "webvh"
        || current.projection.did.method() != "webvh"
        || arkret_wire::project_did_to_core_id(&payload.next.did).map_err(corrupt)?
            != current.account_id.principal_id
    {
        return Err(rejected(
            ConflictCode::DidMethodSuccessorInvalid,
            "resolution successor changes the principal core or method",
        ));
    }
    // Use the same native-core lock as the hosting writer. Its current head
    // cannot move between the evidence check and this PCR acceptance.
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(current.account_id.principal_id.as_str())
        .execute(&mut *conn)
        .await?;
    let mut bytes = Vec::new();
    for entry in &write.log_entries {
        bytes.extend(arkret_canonical::canonical_json_bytes(entry).map_err(corrupt)?);
        bytes.push(b'\n');
    }
    let witnesses =
        arkret_canonical::canonical_json_bytes(&write.witness_records).map_err(corrupt)?;
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &payload.next.did,
        &bytes,
        Some(&witnesses),
    )
    .map_err(|e| {
        rejected(
            ConflictCode::DidMethodSuccessorInvalid,
            &format!("resolution method history invalid: {e}"),
        )
    })?;
    let log = verified.log;
    if log.entries.last().is_none_or(|entry| {
        entry.version_time > tx.commit.committed_at
            || entry
                .parameters
                .get("deactivated")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
    }) {
        return Err(rejected(
            ConflictCode::DidMethodSuccessorInvalid,
            "resolution successor is future-dated or deactivated",
        ));
    }
    let terminal = log
        .raw_entries
        .last()
        .ok_or_else(|| corrupt("empty native resolution history"))?;
    let digest = arkret_canonical::canonical_sha256(terminal).map_err(corrupt)?;
    let previous = log.raw_entries.iter().position(|entry| {
        entry.get("versionId").and_then(serde_json::Value::as_str)
            == Some(current.projection.version_id.as_str())
            && entry
                .pointer("/state/id")
                .and_then(serde_json::Value::as_str)
                == Some(current.projection.did.as_str())
            && arkret_canonical::canonical_sha256(entry).ok().as_deref()
                == Some(current.projection.method_history_head.as_str())
    });
    if log.head_version_id != payload.next.version_id
        || digest != payload.next.method_history_head
        || !previous.is_some_and(|index| index + 1 < log.raw_entries.len())
    {
        return Err(rejected(
            ConflictCode::DidMethodSuccessorInvalid,
            "resolution history does not continuously advance the accepted boundary",
        ));
    }
    #[derive(QueryableByName)]
    struct Head {
        #[diesel(sql_type=Text)]
        id: String,
    }
    let head = sql_query("SELECT id FROM webvh_log_events WHERE split_part(did,':',3)=split_part($1,':',3) ORDER BY seq DESC LIMIT 1")
        .bind::<Text,_>(payload.next.did.as_str()).get_result::<Head>(&mut *conn).await.optional()?;
    if head.as_ref().is_none_or(|head| head.id != digest) {
        return Err(rejected(
            ConflictCode::TemporarilyUnavailable,
            "resolution method head is not the retained current native head",
        ));
    }
    let historical = crate::agent_producer_signer_keys::prepare_admitted_own_pcr_in_connection(
        conn, event, &tx.commit,
    )
    .await?;
    crate::authority_commit::queue_event_in_connection(conn, event, tx.commit.committed_at).await?;
    match crate::authority_commit::commit_verified_resolution_in_connection(conn, tx).await? {
        AuthorityCommitWriteOutcome::Committed => {}
        _ => {
            return Err(rejected(
                ConflictCode::TemporarilyUnavailable,
                "resolution accepting authority changed",
            ));
        }
    }
    crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
        conn, event, &tx.commit, historical,
    )
    .await?;
    let next = PrincipalResolutionProjection {
        did: payload.next.did,
        method_history_head: payload.next.method_history_head,
        version_id: payload.next.version_id,
        resolution_event_ref: event.event_id.to_string(),
        updated_at: event.created_at,
    };
    let changed = sql_query("UPDATE principal_resolution_current_results SET current_commit_id=$4,current_stream_position=$5,value=$6,updated_at=$7 WHERE principal_id=$1 AND station_id=$2 AND current_commit_id=$3")
        .bind::<Text,_>(current.account_id.principal_id.as_str()).bind::<Text,_>(current.account_id.station_id.as_str())
        .bind::<Text,_>(source.commit_id.as_str()).bind::<Text,_>(tx.commit.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(tx.commit.stream_position).map_err(corrupt)?)
        .bind::<Jsonb,_>(serde_json::to_value(&next).map_err(corrupt)?).bind::<Timestamptz,_>(tx.commit.committed_at)
        .execute(&mut *conn).await?;
    if changed != 1 {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "resolution current changed",
        ));
    }
    Ok(AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: tx.commit.clone(),
    })
}
