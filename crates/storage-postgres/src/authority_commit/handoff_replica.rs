//! Keep the outgoing Station's fully verified frozen archive readable as a replica.

use super::*;

#[derive(QueryableByName)]
struct LocalStation {
    #[diesel(sql_type = Text)]
    station_id: String,
}

/// Called only after the complete imported originals, signer facts, native
/// current and every final head have matched the accepted handoff. These are
/// replica checkpoints of that same cut, not a new acceptance or signing right.
#[inline(never)]
pub(super) fn retain_outgoing_cut<'a>(
    conn: &'a mut AsyncPgConnection,
    handoff: &'a arkret_wire::RealmAuthorityHandoff,
    snapshot: &'a arkret_wire::RealmStateSnapshot,
    originals: &'a [arkret_wire::CommittedEventFullView],
) -> std::pin::Pin<Box<impl std::future::Future<Output = Result<(), PgTransactionError>> + Send + 'a>>
{
    Box::pin(async move {
        let local =
            sql_query("SELECT station_id FROM device_inventory_station WHERE singleton FOR SHARE")
                .get_result::<LocalStation>(&mut *conn)
                .await
                .optional()?;
        if local
            .as_ref()
            .is_none_or(|local| local.station_id != handoff.from_service_id.as_str())
        {
            return Ok(());
        }
        let at = chrono::Utc::now();
        let public_rows = snapshot
            .current_state_entries
            .iter()
            .filter(|row| {
                let arkret_wire::CurrentState::Value {
                    source_stream_ref, ..
                } = row;
                !matches!(
                    source_stream_ref,
                    arkret_wire::CommitStreamRef::RealmControl { .. }
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        crate::replica_authorization::guard_current_rows(conn, &handoff.realm_id, &public_rows)
            .await?;
        for head in &snapshot.visible_stream_heads {
            if matches!(
                head.stream_ref,
                arkret_wire::CommitStreamRef::RealmControl { .. }
            ) {
                continue;
            }
            crate::replica_authorization::install_verified_head(conn, head, at).await?;
        }
        // The full native handoff cut also retires stale rows retained from any
        // earlier member tenure. The revision guard above precedes this replacement.
        sql_query("DELETE FROM replica_authorization_rows WHERE realm_id=$1")
            .bind::<Text, _>(handoff.realm_id.as_str())
            .execute(&mut *conn)
            .await?;
        for row in &public_rows {
            crate::replica_authorization::save_row(conn, &handoff.realm_id, row, at).await?;
        }
        for head in &snapshot.visible_stream_heads {
            let reader = match &head.stream_ref {
                arkret_wire::CommitStreamRef::RealmControl { .. } => continue,
                arkret_wire::CommitStreamRef::Realm { .. }
                | arkret_wire::CommitStreamRef::Circle { .. } => {
                    super::replica::bootstrap_readers_in_connection(
                        conn,
                        &head.stream_ref,
                        &handoff.from_service_id,
                        true,
                    )
                    .await?
                    .into_iter()
                    .min_by_key(|(_, join)| join.stream_position)
                }
                arkret_wire::CommitStreamRef::Sidecar {
                    realm_id,
                    sidecar_id,
                } => {
                    if !crate::sidecar_replica_authority::holds_source_in_connection(
                        conn,
                        realm_id,
                        sidecar_id,
                        &handoff.from_service_id,
                    )
                    .await?
                    {
                        continue;
                    }
                    let owner = crate::sidecar_replica_authority::controller_in_connection(
                        conn,
                        &head.stream_ref,
                    )
                    .await?
                    .ok_or_else(|| invalid("outgoing Sidecar has no accepted controller"))?;
                    let account: arkret_wire::AccountId =
                        serde_json::from_value(owner).map_err(invalid)?;
                    let origin = originals
                        .iter()
                        .find(|full| {
                            full.commit.stream_ref == head.stream_ref
                                && crate::sidecar_replica_authority::is_native_origin(&full.commit)
                        })
                        .ok_or_else(|| {
                            invalid("outgoing Sidecar has no complete accepted origin")
                        })?;
                    Some((account, origin.commit.clone()))
                }
                _ => return Err(invalid("handoff replica stream is unsupported").into()),
            };
            let Some((account, opening)) = reader else {
                continue;
            };
            let changed = sql_query(
            "INSERT INTO replica_stream_anchors \
             (stream_key,realm_id,join_commit_id,member_account_id,anchor_commit_id,anchor_stream_position,anchored_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(stream_key) DO UPDATE SET \
             join_commit_id=EXCLUDED.join_commit_id,member_account_id=EXCLUDED.member_account_id, \
             anchor_commit_id=EXCLUDED.anchor_commit_id,anchor_stream_position=EXCLUDED.anchor_stream_position,anchored_at=EXCLUDED.anchored_at \
             WHERE replica_stream_anchors.realm_id=EXCLUDED.realm_id AND \
               (replica_stream_anchors.anchor_stream_position IS NULL \
                OR replica_stream_anchors.anchor_stream_position<EXCLUDED.anchor_stream_position \
                OR (replica_stream_anchors.anchor_stream_position=EXCLUDED.anchor_stream_position \
                    AND replica_stream_anchors.anchor_commit_id=EXCLUDED.anchor_commit_id))"
        ).bind::<Text,_>(stream_key(&head.stream_ref)?).bind::<Text,_>(handoff.realm_id.as_str())
            .bind::<Text,_>(opening.commit_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&account).map_err(invalid)?)
            .bind::<Text,_>(head.commit_id.as_str()).bind::<BigInt,_>(to_i64(head.stream_position,"handoff replica head")?)
            .bind::<Timestamptz,_>(at).execute(&mut *conn).await?;
            if changed != 1 {
                return Err(invalid("handoff regresses an existing hosted replica anchor").into());
            }
        }
        Ok(())
    })
}
