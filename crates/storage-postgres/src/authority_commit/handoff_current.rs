//! Frozen handoff verification uses accepted originals, not member replica rights.
use super::*;
use crate::circle_current_states::FrozenHandoffCurrentEffect;

#[derive(QueryableByName)]
struct HandoffMaterialRole {
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Nullable<Text>)]
    local_station: Option<String>,
}

#[derive(QueryableByName)]
struct CircleCurrent {
    #[diesel(sql_type = Jsonb)]
    entry: Value,
    #[diesel(sql_type = Nullable<Text>)]
    create_event_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    short_name_folded: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    membership: Option<String>,
}

fn is_circle(entry: &arkret_wire::CurrentState) -> bool {
    let arkret_wire::CurrentState::Value { selector, .. } = entry;
    matches!(
        selector,
        arkret_wire::CurrentSelector::Circle { .. }
            | arkret_wire::CurrentSelector::CircleMemberState { .. }
    )
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
    let mut expected = std::collections::BTreeMap::<Vec<u8>, FrozenHandoffCurrentEffect>::new();
    for full in originals {
        if full.event.realm_id != handoff.realm_id
            || full.commit.stream_ref.realm_id() != &handoff.realm_id
        {
            return Err(invalid("frozen handoff original belongs to another Realm"));
        }
        let Some(effect) = crate::circle_current_states::frozen_handoff_current_effect(full)?
        else {
            continue;
        };
        let arkret_wire::CurrentState::Value {
            selector,
            source_stream_ref,
            revision,
            ..
        } = &effect.current;
        let key =
            arkret_canonical::canonical_json_bytes(selector).map_err(PersistenceError::database)?;
        if let Some(prior) = expected.get(&key) {
            let arkret_wire::CurrentState::Value {
                source_stream_ref: prior_source,
                revision: prior_revision,
                ..
            } = &prior.current;
            if prior_source != source_stream_ref
                || prior_revision.stream_position >= revision.stream_position
            {
                return Err(invalid(
                    "frozen Circle current has a conflicting source or revision",
                ));
            }
        }
        expected.insert(key, effect);
    }
    // Read the complete retained typed rows. The public/member query must keep
    // its exact native/replica proof filter; no authorization is inferred here.
    let rows = sql_query(
        "SELECT jsonb_build_object('selector',jsonb_build_object('kind','circle','circle_id',circle_id), \
         'source_stream_ref',source_stream_ref,'revision',jsonb_build_object('commit_id',current_commit_id, \
         'stream_position',current_stream_position),'value',value) AS entry \
         ,create_event_id,short_name_folded,NULL::text AS membership \
         FROM circle_current_states WHERE realm_id=$1 \
         UNION ALL SELECT jsonb_build_object('selector',jsonb_build_object('kind','circle_member_state', \
         'circle_id',circle_id,'member_actor_id',member_id::jsonb),'source_stream_ref',source_stream_ref, \
         'revision',jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position), \
         'value',value) AS entry,NULL::text AS create_event_id,NULL::text AS short_name_folded,membership \
         FROM circle_member_state_current_states WHERE realm_id=$1",
    ).bind::<Text, _>(handoff.realm_id.as_str()).load::<CircleCurrent>(&mut *conn).await
        .map_err(PersistenceError::database)?;
    let mut actual = std::collections::BTreeMap::<Vec<u8>, FrozenHandoffCurrentEffect>::new();
    for row in rows {
        let current = serde_json::from_value::<arkret_wire::CurrentState>(row.entry)
            .map_err(|_| invalid("handoff Circle row is not a closed typed current"))?;
        let arkret_wire::CurrentState::Value { selector, .. } = &current;
        let key =
            arkret_canonical::canonical_json_bytes(selector).map_err(PersistenceError::database)?;
        let effect = FrozenHandoffCurrentEffect {
            current,
            create_event_id: row.create_event_id,
            short_name_folded: row.short_name_folded,
            membership: row.membership,
        };
        if actual.insert(key, effect).is_some() {
            return Err(invalid("handoff Circle current has duplicate selectors"));
        }
    }
    if actual != expected {
        return Err(invalid(
            "handoff Circle current differs from complete imported originals",
        ));
    }
    material.current_state_entries.retain(|row| !is_circle(row));
    material
        .current_state_entries
        .extend(expected.into_values().map(|effect| effect.current));
    material.current_state_entries = canonical_rows(material.current_state_entries)?;
    Ok(Some(material))
}
