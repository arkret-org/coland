//! Frozen handoff verification uses accepted originals, not member replica rights.
use super::*;

#[derive(QueryableByName)]
struct HandoffMaterialRole {
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Nullable<Text>)]
    local_station: Option<String>,
}

fn canonical_rows(
    rows: Vec<arkret_wire::CurrentState>,
) -> PersistenceResult<Vec<arkret_wire::CurrentState>> {
    let mut keyed = rows
        .into_iter()
        .map(|row| {
            arkret_canonical::canonical_json_bytes(&row)
                .map(|key| (key, row))
                .map_err(PersistenceError::database)
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(keyed.into_iter().map(|(_, row)| row).collect())
}

/// Called only inside install_handoff_inner after its complete archive,
/// authority/CAS, final-head, private-state and historical signer checks.
/// Nothing here mutates a projection, a replica cut or the local Station.
pub(super) async fn frozen_material(
    conn: &mut AsyncPgConnection,
    handoff: &arkret_wire::RealmAuthorityHandoff,
    originals: &[arkret_wire::CommittedEventFullView],
) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
    let role = sql_query(
        "SELECT service_id,generation,current_device_inventory_station() AS local_station \
         FROM realm_authorities WHERE realm_id=$1",
    )
    .bind::<Text, _>(handoff.realm_id.as_str())
    .get_result::<HandoffMaterialRole>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if role.service_id != handoff.from_service_id.as_str()
        || to_u64(role.generation, "handoff source generation")? != handoff.from_generation
        || role.local_station.as_deref().is_none_or(|local| {
            local != handoff.from_service_id.as_str() && local != handoff.to_service_id.as_str()
        })
    {
        return Err(invalid(
            "frozen handoff material has no exact participating Station role",
        ));
    }
    let Some(mut material) =
        realm_state_snapshot_material_in_connection(conn, &handoff.realm_id).await?
    else {
        return Ok(None);
    };
    if originals.iter().any(|full| full.event.realm_id != handoff.realm_id
        || full.commit.stream_ref.realm_id() != &handoff.realm_id) {
        return Err(invalid("frozen handoff original belongs to another Realm"));
    }
    material.current_state_entries = canonical_rows(material.current_state_entries)?;
    Ok(Some(material))
}
