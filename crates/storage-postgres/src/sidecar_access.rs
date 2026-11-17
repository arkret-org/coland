//! Native Sidecar membership is derived from its same-cut authority and MLS.

use arkret_wire::{AccountId, ActorId, RealmId, SidecarId};

use super::{
    AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};

#[derive(QueryableByName)]
struct ControllerRow {
    #[diesel(sql_type = Jsonb)]
    controller_account_id: serde_json::Value,
}

pub(crate) async fn controller_account_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
) -> PersistenceResult<Option<AccountId>> {
    let Some(controller) = sql_query(
        "SELECT s.controller_account_id FROM sidecar_current_states s \
        JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id \
          AND c.stream_position=s.current_stream_position \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
        WHERE s.realm_id=$1 AND s.sidecar_id=$2 AND s.value->>'state'='active'",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(sidecar.as_str())
    .get_result::<ControllerRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(None);
    };
    let controller: AccountId = serde_json::from_value(controller.controller_account_id)
        .map_err(PersistenceError::database)?;
    Ok(Some(controller))
}

/// H-only native authority collector. G callers use their resource/floor owner.
pub(crate) async fn cut_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
) -> PersistenceResult<Option<crate::sidecar_authority_cut::SidecarParticipantAuthorityCut>> {
    let Some(controller) = controller_account_in_connection(conn, realm, sidecar).await? else {
        return Ok(None);
    };
    if !crate::sidecar_replica_authority::is_owning_station_in_connection(conn, &controller).await?
    {
        return Err(PersistenceError::Conflict(format!(
            "{}: Sidecar native participant inputs belong to the owning Station",
            coland_storage::ConflictCode::TemporarilyUnavailable,
        )));
    }
    crate::sidecar_authority_cut::in_connection(conn, realm, sidecar, &controller).await
}

/// Desired authority permits only the restricted public handshake needed to
/// validate a recipient's Welcome. It is not application or delivery access.
pub(crate) fn desired_participant(
    cut: &crate::sidecar_authority_cut::SidecarParticipantAuthorityCut,
    actor: &ActorId,
) -> bool {
    actor.as_account_id().is_some_and(|account| {
        account == &cut.controller_account_id
            || (account.station_id == cut.controller_account_id.station_id
                && cut.desired_agent_ids.contains(&account.principal_id))
    })
}

/// Pending recipients may read a handshake only when its signed participant
/// binding equals the currently accepted cut. Content still requires consume.
pub(crate) async fn handshake_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    actor: &ActorId,
) -> PersistenceResult<bool> {
    let arkret_wire::ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = &event.scope_ref
    else {
        return Ok(false);
    };
    let binding = match event.kind {
        arkret_wire::EventKind::MlsGenesis => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::MlsGenesisPayload,
        >(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?
        .governance_binding,
        arkret_wire::EventKind::MlsCommit => {
            serde_json::from_value::<arkret_models_crypto::MlsCommitPayload>(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?
            .governance_binding()
            .clone()
        }
        _ => return Ok(false),
    };
    let Some(controller) = controller_account_in_connection(conn, realm_id, sidecar_id).await?
    else {
        return Ok(false);
    };
    if !crate::sidecar_replica_authority::is_owning_station_in_connection(conn, &controller).await?
    {
        let Some(floor) = crate::sidecar_authority_cut::public_material_floor_in_connection(
            conn, realm_id, sidecar_id, actor,
        )
        .await?
        else {
            return Ok(false);
        };
        let source = sql_query("SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
            WHERE e.state='committed' AND e.envelope->>'event_id'=$1 AND c.realm_id=$2 \
            AND c.stream_ref=$3 AND c.stream_position>=$4) AS present")
            .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(realm_id.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(&event.scope_ref).map_err(PersistenceError::database)?)
            .bind::<diesel::sql_types::BigInt,_>(i64::try_from(floor.oldest_position).map_err(PersistenceError::database)?)
            .get_result::<crate::ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        return Ok(source.present && binding.effective_scope() == &event.scope_ref);
    }
    let Some(cut) = cut_in_connection(conn, realm_id, sidecar_id).await? else {
        return Ok(false);
    };
    Ok(desired_participant(&cut, actor)
        && binding.effective_scope() == &event.scope_ref
        && binding.sidecar_binding().is_some_and(|binding| {
            binding.sidecar_id == cut.sidecar_id
                && binding.participant_authority_digest == cut.participant_authority_digest
        }))
}

/// Use only inside the caller's read/admission transaction. Realm membership,
/// a Circle capability and an Agent ownership projection cannot authorize
/// this scope; the exact controller or a currently effective owned Agent can.
pub(crate) async fn participant_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    actor: &ActorId,
) -> PersistenceResult<bool> {
    let Some(account) = actor.as_account_id() else {
        return Ok(false);
    };
    let Some(controller) = controller_account_in_connection(conn, realm, sidecar).await? else {
        return Ok(false);
    };
    if !crate::sidecar_replica_authority::is_owning_station_in_connection(conn, &controller).await?
    {
        return Ok(crate::sidecar_authority_cut::caller_floor_in_connection(
            conn, realm, sidecar, actor,
        )
        .await?
        .is_some());
    }
    let Some(cut) = cut_in_connection(conn, realm, sidecar).await? else {
        return Ok(false);
    };
    let controller = &cut.controller_account_id;
    if account == controller {
        return Ok(true);
    }
    if account.station_id != controller.station_id
        || !cut.desired_agent_ids.contains(&account.principal_id)
    {
        return Ok(false);
    }
    Ok(
        crate::sidecar_effective_access::effective_agents_in_connection(conn, &cut)
            .await?
            .contains(&account.principal_id),
    )
}

/// Every recipient comes from the exact native scope. Merely being joined to
/// the parent Realm never opens a private inbox or a peer delivery target.
pub(crate) async fn recipients_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
) -> PersistenceResult<Vec<AccountId>> {
    let Some(controller) = controller_account_in_connection(conn, realm, sidecar).await? else {
        return Ok(Vec::new());
    };
    if !crate::sidecar_replica_authority::is_owning_station_in_connection(conn, &controller).await?
    {
        // All recipients route to H. G creates one authority-bound H intent;
        // H selects native/effective endpoint deliveries at its own cut.
        let actor = ActorId::account(controller.clone());
        return Ok(
            if crate::sidecar_authority_cut::controller_floor_in_connection(
                conn, realm, sidecar, &actor,
            )
            .await?
            .is_some()
            {
                vec![controller]
            } else {
                Vec::new()
            },
        );
    }
    let Some(cut) = cut_in_connection(conn, realm, sidecar).await? else {
        return Ok(Vec::new());
    };
    let agents =
        crate::sidecar_effective_access::effective_agents_in_connection(conn, &cut).await?;
    let mut recipients = vec![cut.controller_account_id.clone()];
    recipients.extend(
        agents
            .into_iter()
            .map(|agent| AccountId::new(agent, cut.controller_account_id.station_id.clone())),
    );
    recipients.sort_by(|left, right| {
        left.principal_id
            .as_str()
            .as_bytes()
            .cmp(right.principal_id.as_str().as_bytes())
    });
    recipients.dedup();
    Ok(recipients)
}
