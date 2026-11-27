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
    if !is_owning_station_in_connection(conn, &controller).await? {
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
/// an Agent ownership projection cannot authorize
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

/// Check the explicit reply grant and exact consumed runtime leaf in the writer's transaction.
pub(crate) async fn can_reply_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    agent: &AccountId,
    method: &arkret_wire::DidUrl,
    key: Option<&arkret_wire::EventId>,
) -> PersistenceResult<bool> {
    let Some(owner) = controller_account_in_connection(conn, realm, sidecar).await? else {
        return Ok(false);
    };
    if owner.station_id != agent.station_id
        || !is_owning_station_in_connection(conn, &owner).await?
    {
        return Ok(false);
    }
    let Some(cut) =
        crate::sidecar_authority_cut::locked_in_connection(conn, realm, sidecar, &owner).await?
    else {
        return Ok(false);
    };
    if crate::sidecar_authority_cut::enrollment(conn, realm, sidecar, agent)
        .await?
        .is_none_or(|r| r.value["membership"] != "join" || r.value["private_reply_allowed"] != true)
    {
        return Ok(false);
    }
    Ok(
        crate::sidecar_effective_access::effective_agents_for_endpoint_in_connection(
            conn,
            &cut,
            Some((&agent.principal_id, method, key)),
        )
        .await?
        .contains(&agent.principal_id),
    )
}

/// Select the local native role from the configured Station identity, never
/// from missing PCR rows or the success of a native-authority query.
pub(crate) async fn is_owning_station_in_connection(
    conn: &mut crate::AsyncPgConnection,
    account: &arkret_wire::AccountId,
) -> PersistenceResult<bool> {
    Ok(account.station_id == local_station_in_connection(conn).await?)
}

async fn local_station_in_connection(
    conn: &mut crate::AsyncPgConnection,
) -> PersistenceResult<arkret_wire::DidCoreId> {
    let row = diesel::sql_query(
        "SELECT to_jsonb(station_id) AS payload FROM device_inventory_station WHERE singleton",
    )
    .get_result::<crate::JsonPayloadRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    serde_json::from_value(row.payload).map_err(PersistenceError::database)
}
