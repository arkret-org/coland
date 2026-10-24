//! List native stream heads from an anchored replica's single read cut.

use arkret_wire::{ActorId, CommitStreamRef, RealmId, RealmStreamView};
use coland_storage::AccountRealmStreamList;

use super::{
    AsyncPgConnection, BigInt, Jsonb, PersistenceError, PersistenceResult, QueryableByName,
    RunQueryDsl, Text, sql_query,
};

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    stream_ref: serde_json::Value,
}

/// The enclosing caller establishes repeatable-read isolation and current
/// parent membership before invoking this helper. A visible stream whose
/// anchor or history is unavailable refuses the entire list, preserving its
/// complete-at-cut contract instead of returning an incomplete enumeration.
pub(crate) async fn in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    caller: &ActorId,
) -> PersistenceResult<AccountRealmStreamList> {
    let realm_floor =
        match crate::account_stream_scan::replica_realm_floor_in_connection(conn, realm, caller)
            .await?
        {
            Ok(floor) => floor,
            Err(reason) => return Ok(AccountRealmStreamList::Unproved(reason)),
        };
    let heads = sql_query(crate::authority_commit::REALM_STREAM_HEADS_SQL)
        .bind::<Text, _>(realm.as_str())
        .load::<HeadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let mut rows = Vec::new();
    for head in heads {
        let stream: CommitStreamRef =
            serde_json::from_value(head.stream_ref).map_err(PersistenceError::database)?;
        if stream.realm_id() != realm {
            return Err(PersistenceError::SchemaViolation(
                "replica stream head belongs to a different Realm".into(),
            ));
        }
        let floor = match &stream {
            CommitStreamRef::Realm { .. } => realm_floor.clone(),
            CommitStreamRef::Circle { circle_id, .. } => {
                if crate::account_stream_scan::caller_circle_floor_in_connection(
                    conn, realm, circle_id, caller,
                )
                .await?
                .is_none()
                {
                    continue;
                }
                match crate::account_stream_scan::replica_circle_floor_in_connection(
                    conn, realm, circle_id, caller,
                )
                .await?
                {
                    Ok(floor) => floor,
                    Err(reason) => return Ok(AccountRealmStreamList::Unproved(reason)),
                }
            }
            CommitStreamRef::Sidecar { sidecar_id, .. } => {
                match crate::sidecar_replica_authority::floor_in_connection(
                    conn, realm, sidecar_id, caller,
                )
                .await?
                {
                    Ok(Some(floor)) => floor,
                    Ok(None) => continue,
                    Err(reason) => return Ok(AccountRealmStreamList::Unproved(reason)),
                }
            }
            _ => continue,
        };
        let position = u64::try_from(head.stream_position).map_err(|_| {
            PersistenceError::SchemaViolation("replica stream position is negative".into())
        })?;
        rows.push(RealmStreamView {
            stream_ref: stream,
            head_commit_ref: head.commit_id.parse().map_err(PersistenceError::database)?,
            next_position: position.checked_add(1).ok_or_else(|| {
                PersistenceError::SchemaViolation("replica stream position overflows".into())
            })?,
            readable_floor: Some(floor),
        });
    }
    if !rows
        .iter()
        .any(|row| matches!(row.stream_ref, CommitStreamRef::Realm { .. }))
    {
        return Ok(AccountRealmStreamList::Unproved(
            "the anchored Realm stream head is not held",
        ));
    }
    let mut keyed = rows
        .into_iter()
        .map(|row| {
            let key = arkret_canonical::canonical_json_bytes(&row.stream_ref)
                .map_err(PersistenceError::database)?;
            Ok((key, row))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(AccountRealmStreamList::Listed(
        keyed.into_iter().map(|(_, row)| row).collect(),
    ))
}
