//! H-owned participant inputs from native state and its accepted Realm member view.

pub use arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityCut;
use arkret_wire::{
    AccountId, ActorId, CommitStreamHead, CommitStreamRef, DidCoreId, EventId, RealmId, SidecarId,
};
use serde_json::Value;

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn,
    sql_query,
};

#[derive(QueryableByName)]
struct OwnerRow {
    #[diesel(sql_type = Jsonb)]
    controller_account_id: Value,
    #[diesel(sql_type = Text)]
    create_event_id: String,
}

#[derive(QueryableByName)]
pub(crate) struct FactRow {
    #[diesel(sql_type = Text)]
    pub(crate) event_id: String,
    #[diesel(sql_type = Text)]
    pub(crate) commit_id: String,
    #[diesel(sql_type = BigInt)]
    pub(crate) stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    pub(crate) stream_ref: Value,
    #[diesel(sql_type = Jsonb)]
    pub(crate) value: Value,
}

#[derive(QueryableByName)]
struct AgentRow {
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    principal_control_realm_id: String,
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
}

fn invalid(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

fn remember(fact: &FactRow, streams: &mut Vec<CommitStreamRef>) -> PersistenceResult<()> {
    let _ = EventId::new(&fact.event_id).map_err(PersistenceError::database)?;
    let stream: CommitStreamRef =
        serde_json::from_value(fact.stream_ref.clone()).map_err(PersistenceError::database)?;
    let _ = arkret_wire::RealmCommitId::new(&fact.commit_id).map_err(PersistenceError::database)?;
    u64::try_from(fact.stream_position)
        .map_err(|_| invalid("negative Sidecar authority coordinate"))?;
    streams.push(stream);
    Ok(())
}

pub(crate) async fn member_fact(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    actor: &ActorId,
) -> PersistenceResult<Option<FactRow>> {
    sql_query("SELECT e.envelope->>'event_id' AS event_id,c.commit_id,c.stream_position,c.stream_ref, \
        m.value || jsonb_build_object('agent_controller_binding',e.envelope->'payload'->'agent_controller_binding') AS value \
        FROM member_state_current_states m JOIN realm_commits c \
          ON c.realm_id=m.realm_id AND c.commit_id=m.current_commit_id AND c.stream_position=m.current_stream_position \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
        WHERE m.realm_id=$1 AND m.member_id=$2 AND m.value->>'membership'=m.membership \
          AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND e.kind IN ('ak.member.state','ak.invite.accept','ak.realm_invite_link.accept')")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(actor.to_string())
        .get_result(&mut *conn).await.optional().map_err(PersistenceError::database)
}

/// The caller owns the already accepted Sidecar, and its parent membership,
/// ownership, lifecycle and runtime-key facts all come from this connection.
pub(crate) async fn in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    controller: &AccountId,
) -> PersistenceResult<Option<SidecarParticipantAuthorityCut>> {
    let owner = sql_query("SELECT s.controller_account_id,s.create_event_id FROM sidecar_current_states s \
        JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id \
          AND c.stream_position=s.current_stream_position AND c.stream_ref=s.source_stream_ref \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.kind='ak.sidecar.create' \
        WHERE s.realm_id=$1 AND s.sidecar_id=$2 AND s.value->>'state'='active'")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(sidecar.as_str())
        .get_result::<OwnerRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(owner) = owner else {
        return Ok(None);
    };
    if serde_json::from_value::<AccountId>(owner.controller_account_id)
        .map_err(PersistenceError::database)?
        != *controller
    {
        return Ok(None);
    }
    let Some(member) = member_fact(conn, realm, &ActorId::account(controller.clone())).await?
    else {
        return Ok(None);
    };
    if member.value.get("membership").and_then(Value::as_str) != Some("join") {
        return Ok(None);
    }
    if SidecarId::from_event_id(
        &EventId::new(owner.create_event_id).map_err(PersistenceError::database)?,
    ) != *sidecar
    {
        return Err(invalid(
            "Sidecar Create source differs from its immutable ID",
        ));
    }
    let mut streams = vec![CommitStreamRef::Realm {
        realm_id: realm.clone(),
    }];
    let member_controller_generation = member.event_id.clone();
    remember(&member, &mut streams)?;
    #[derive(QueryableByName)]
    struct ControllerPcr {
        #[diesel(sql_type = Text)]
        realm_id: String,
    }
    let controller_pcr =
        sql_query("SELECT realm_id FROM pcr_genesis_units WHERE principal_id=$1 AND station_id=$2")
            .bind::<Text, _>(controller.principal_id.as_str())
            .bind::<Text, _>(controller.station_id.as_str())
            .get_result::<ControllerPcr>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
    let Some(controller_pcr) = controller_pcr else {
        return Err(invalid(
            "Sidecar controller PCR ownership cut is not held here",
        ));
    };
    // The accepted controller PCR genesis fixes the complete Account identity;
    // a matching principal string in another Station's PCR is insufficient.
    let agents = sql_query("SELECT p.agent_id,p.value->>'principal_control_realm_id' AS principal_control_realm_id, \
        e.envelope->>'event_id' AS event_id,c.commit_id,c.stream_position,c.stream_ref \
        FROM agent_provisioning_current_states p JOIN pcr_genesis_units g ON g.realm_id=p.realm_id \
        JOIN realm_commits c ON c.realm_id=p.realm_id AND c.commit_id=p.current_commit_id AND c.stream_position=p.current_stream_position \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
        JOIN member_state_current_states m ON m.realm_id=$4 AND m.membership='join' \
          AND m.value->>'membership'='join' \
          AND m.member_id::jsonb=jsonb_build_object('kind','account','account_id', \
              jsonb_build_object('principal_id',p.agent_id,'station_id',$2::text)) \
        WHERE g.principal_id=$1 AND g.station_id=$2 AND p.value->>'controller_principal_id'=$1 AND p.realm_id=$3 \
        ORDER BY p.agent_id")
        .bind::<Text,_>(controller.principal_id.as_str()).bind::<Text,_>(controller.station_id.as_str())
        .bind::<Text,_>(&controller_pcr.realm_id).bind::<Text,_>(realm.as_str())
        .load::<AgentRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut desired = Vec::new();
    let at = chrono::Utc::now();
    for agent in agents {
        let agent_id = DidCoreId::new(&agent.agent_id).map_err(PersistenceError::database)?;
        let actor = ActorId::account(AccountId::new(
            agent_id.clone(),
            controller.station_id.clone(),
        ));
        let Some(member) = member_fact(conn, realm, &actor).await? else {
            return Err(invalid(
                "Sidecar joined Agent lacks its accepted membership source",
            ));
        };
        let binding = member
            .value
            .get("agent_controller_binding")
            .filter(|binding| binding.is_object())
            .ok_or_else(|| invalid("Sidecar Agent join lacks its controller binding"))?;
        let bound_controller: AccountId = serde_json::from_value(
            binding
                .get("controller_account_id")
                .cloned()
                .ok_or_else(|| invalid("Agent join lacks its complete controller"))?,
        )
        .map_err(PersistenceError::database)?;
        let controller_generation = binding
            .get("controller_membership_generation_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Agent join lacks its controller membership generation"))?;
        if bound_controller != *controller
            || controller_generation != member_controller_generation.as_str()
        {
            continue;
        }
        // Only exact Realm members with a current controller binding require
        // native provisioning/lifecycle/key inputs from H.
        let pcr =
            RealmId::new(&agent.principal_control_realm_id).map_err(PersistenceError::database)?;
        remember(&member, &mut streams)?;
        let ownership = FactRow {
            event_id: agent.event_id,
            commit_id: agent.commit_id,
            stream_position: agent.stream_position,
            stream_ref: agent.stream_ref,
            value: Value::Null,
        };
        remember(&ownership, &mut streams)?;
        let status = sql_query("SELECT e.envelope->>'event_id' AS event_id,c.commit_id,c.stream_position,c.stream_ref, \
            jsonb_build_object('state',s.value,'actor_id',s.actor_id) AS value \
            FROM agent_status_current_states s JOIN realm_commits c \
              ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id AND c.stream_position=s.current_stream_position \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
            WHERE s.realm_id=$1 AND s.agent_id=$2")
            .bind::<Text,_>(pcr.as_str()).bind::<Text,_>(agent_id.as_str())
            .get_result::<FactRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let Some(status) = status else {
            return Err(invalid(
                "owned joined Agent lacks accepted lifecycle current",
            ));
        };
        remember(&status, &mut streams)?;
        let status_actor: ActorId = serde_json::from_value(status.value["actor_id"].clone())
            .map_err(PersistenceError::database)?;
        if status_actor != actor {
            return Err(invalid(
                "Agent lifecycle current names another complete Account",
            ));
        }
        let keys = sql_query("SELECT e.envelope->>'event_id' AS event_id,c.commit_id,c.stream_position,c.stream_ref, \
            k.value || jsonb_build_object('key_id',k.agent_key_id) AS value \
            FROM agent_key_current_states k JOIN realm_commits c \
              ON c.realm_id=k.realm_id AND c.commit_id=k.current_commit_id AND c.stream_position=k.current_stream_position \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
            WHERE k.realm_id=$1 AND k.agent_id=$2 ORDER BY k.agent_key_id")
            .bind::<Text,_>(pcr.as_str()).bind::<Text,_>(agent_id.as_str())
            .load::<FactRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mut authorized = false;
        for key in keys {
            remember(&key, &mut streams)?;
            let entries = key
                .value
                .get("authorizations")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("Agent authorization current lacks its closed dot set"))?;
            for entry in entries {
                if entry
                    .get("value")
                    .and_then(|value| value.get("verification_method"))
                    .and_then(Value::as_str)
                    .is_none()
                {
                    continue;
                }
                let payload: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
                    serde_json::from_value(entry["value"].clone()).map_err(PersistenceError::database)?;
                if payload.agent_id != agent_id
                    || Some(payload.key_id.as_str())
                        != key.value.get("key_id").and_then(Value::as_str)
                {
                    return Err(invalid(
                        "Agent authorization payload differs from its current selector",
                    ));
                }
                arkret_signatures::agent::validate_agent_runtime_public_key(
                    &payload.public_key,
                    &payload.verification_method,
                )
                .map_err(PersistenceError::database)?;
                let dot = entry
                    .get("tag_id")
                    .and_then(Value::as_str)
                    .and_then(|tag| tag.strip_suffix(":1"))
                    .ok_or_else(|| invalid("invalid Agent authorization dot"))?;
                let _ = EventId::new(dot).map_err(PersistenceError::database)?;
                if !payload.expires_at.is_some_and(|expiry| expiry <= at) {
                    authorized = true;
                }
            }
        }
        if status.value.get("state").and_then(Value::as_str) == Some("active") && authorized {
            desired.push(
                arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityAgent {
                    agent_id,
                    join_event_ref: EventId::new(member.event_id)
                        .map_err(PersistenceError::database)?,
                },
            );
        }
    }
    let digest = arkret_models_collaboration::agent_sidecar::sidecar_participant_authority_digest(
        sidecar, realm, controller, &desired,
    )
    .map_err(PersistenceError::database)?;
    let desired = desired.into_iter().map(|pair| pair.agent_id).collect();
    streams.sort();
    streams.dedup();
    let mut heads = Vec::new();
    for stream in streams {
        let page = crate::authority_commit::stream_page_in_connection(
            conn,
            &arkret_wire::StreamScanRequestBody {
                realm_id: stream.realm_id().clone(),
                stream_ref: stream.clone(),
                direction: arkret_wire::StreamScanDirection::Before(None),
                limit: 1,
            },
        )
        .await?;
        let item = page
            .committed_events
            .as_slice()
            .first()
            .ok_or_else(|| invalid("Sidecar authority stream lacks its accepted head"))?;
        heads.push(CommitStreamHead {
            stream_ref: stream,
            commit_id: item.commit().commit_id.clone(),
            stream_position: item.commit().stream_position,
        });
    }
    Ok(Some(SidecarParticipantAuthorityCut {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
        controller_account_id: controller.clone(),
        desired_agent_ids: desired,
        participant_authority_digest: digest,
        visible_stream_heads: heads,
    }))
}

pub async fn read(
    pool: &PgPool,
    realm: &RealmId,
    sidecar: &SidecarId,
    controller: &AccountId,
) -> PersistenceResult<Option<SidecarParticipantAuthorityCut>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        in_connection(conn, realm, sidecar, controller)
            .await
            .map_err(PgTransactionError::from)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub async fn read_access(
    pool: &PgPool,
    realm: &RealmId,
    sidecar: &SidecarId,
    controller: &AccountId,
    device: &arkret_wire::DeviceId,
) -> PersistenceResult<
    Option<(
        SidecarParticipantAuthorityCut,
        Vec<DidCoreId>,
        Option<arkret_wire::MlsGroupValue>,
        bool,
    )>,
> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY").execute(&mut *conn).await?;
        let Some(cut) = in_connection(conn, realm, sidecar, controller).await? else { return Ok(None); };
        let effective = crate::sidecar_effective_access::effective_agents_in_connection(conn, &cut).await?;
        #[derive(QueryableByName)]
        struct GroupValue { #[diesel(sql_type = Jsonb)] value: Value }
        let scope = arkret_wire::ScopeRef::Sidecar { realm_id: realm.clone(), sidecar_id: sidecar.clone() };
        let key = crate::mls_group_current_states::scope_key(&scope)?;
        let group = sql_query("SELECT g.value FROM mls_group_current_states g JOIN realm_commits c ON c.realm_id=g.realm_id \
            AND c.commit_id=g.current_commit_id AND c.stream_position=g.current_stream_position \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE g.scope_key=$1")
            .bind::<Text,_>(key).get_result::<GroupValue>(&mut *conn).await.optional()?
            .map(|row| serde_json::from_value(row.value).map_err(PersistenceError::database)).transpose()?;
        let device_ready = match &group {
            Some(group) => crate::sidecar_mls_readiness::controller_device_ready_in_connection(conn,&cut,group,device).await?,
            None => false,
        };
        Ok(Some((cut, effective, group, device_ready)))
    }).await.map_err(PgTransactionError::into_persistence)
}

/// Private controller stream access is tied to the complete Account and its
/// accepted current parent membership. A Realm member is never sufficient.
pub(crate) async fn controller_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    caller: &ActorId,
) -> PersistenceResult<Option<arkret_wire::ReadableFloor>> {
    let Some(account) = caller.as_account_id() else {
        return Ok(None);
    };
    let owner = sql_query("SELECT s.controller_account_id,s.create_event_id FROM sidecar_current_states s \
        JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id \
        AND c.stream_position=s.current_stream_position AND c.stream_ref=s.source_stream_ref \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.kind='ak.sidecar.create' \
        WHERE s.realm_id=$1 AND s.sidecar_id=$2 AND s.value->>'state'='active'")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(sidecar.as_str())
        .get_result::<OwnerRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(owner) = owner else { return Ok(None) };
    if serde_json::from_value::<AccountId>(owner.controller_account_id)
        .map_err(PersistenceError::database)?
        != *account
    {
        return Ok(None);
    }
    if !member_fact(conn, realm, caller)
        .await?
        .is_some_and(|member| {
            member.value.get("membership").and_then(Value::as_str) == Some("join")
        })
    {
        return Ok(None);
    }
    let stream = CommitStreamRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let first = crate::authority_commit::stream_page_in_connection(
        conn,
        &arkret_wire::StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: stream,
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1,
        },
    )
    .await?;
    Ok(first
        .committed_events
        .as_slice()
        .first()
        .map(|first| arkret_wire::ReadableFloor {
            oldest_position: first.commit().stream_position,
            floor_commit_id: first.commit().commit_id.clone(),
            floor_reason: if first.commit().stream_position == 0 {
                arkret_wire::ReadableFloorReason::StreamStart
            } else {
                arkret_wire::ReadableFloorReason::HistoryAccessPolicy
            },
        }))
}

/// Hold the controller ownership stream before discovering its Agent PCRs.
pub(crate) async fn caller_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    caller: &ActorId,
) -> PersistenceResult<Option<arkret_wire::ReadableFloor>> {
    if let Some(floor) = controller_floor_in_connection(conn, realm, sidecar, caller).await? {
        return Ok(Some(floor));
    }
    let Some(account) = caller.as_account_id() else {
        return Ok(None);
    };
    let Some(controller) =
        crate::sidecar_access::controller_account_in_connection(conn, realm, sidecar).await?
    else {
        return Ok(None);
    };
    if !crate::sidecar_replica_authority::is_owning_station_in_connection(conn, &controller).await?
    {
        return crate::sidecar_replica_authority::agent_floor_in_connection(
            conn, realm, sidecar, caller,
        )
        .await;
    }
    let Some(cut) = crate::sidecar_access::cut_in_connection(conn, realm, sidecar).await? else {
        return Ok(None);
    };
    if account.station_id != cut.controller_account_id.station_id
        || !crate::sidecar_effective_access::effective_agents_in_connection(conn, &cut)
            .await?
            .contains(&account.principal_id)
    {
        return Ok(None);
    }
    crate::sidecar_replica_authority::agent_floor_in_connection(conn, realm, sidecar, caller).await
}

/// Preserve the ordinary effective interval, or prove the restricted public
/// material interval for a still pending desired recipient.
pub(crate) async fn public_material_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    caller: &ActorId,
) -> PersistenceResult<Option<arkret_wire::ReadableFloor>> {
    match caller_floor_in_connection(conn, realm, sidecar, caller).await? {
        Some(floor) => Ok(Some(floor)),
        None => handshake_floor_in_connection(conn, realm, sidecar, caller).await,
    }
}

/// A desired recipient must verify its accepted Add before it can consume
/// the Welcome. Only handshakes bound to this exact current authority cut
/// open this interval; ordinary content floors stay unchanged. Snapshot callers
/// may use it only for the public MLS current needed to verify the roster.
pub(crate) async fn handshake_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    caller: &ActorId,
) -> PersistenceResult<Option<arkret_wire::ReadableFloor>> {
    if let Some(floor) = controller_floor_in_connection(conn, realm, sidecar, caller).await? {
        return Ok(Some(floor));
    }
    let Some(controller) =
        crate::sidecar_access::controller_account_in_connection(conn, realm, sidecar).await?
    else {
        return Ok(None);
    };
    if !crate::sidecar_replica_authority::is_owning_station_in_connection(conn, &controller).await?
    {
        return crate::sidecar_replica_authority::agent_floor_in_connection(
            conn, realm, sidecar, caller,
        )
        .await;
    }
    let Some(cut) = crate::sidecar_access::cut_in_connection(conn, realm, sidecar).await? else {
        return Ok(None);
    };
    if !crate::sidecar_access::desired_participant(&cut, caller) {
        return Ok(None);
    }
    // Desired metadata is not a promise that this Agent has ever occupied a
    // Sidecar leaf. Do not require a remote G-issued floor for that known
    // absence, or block its otherwise valid parent Realm Snapshot.
    if !crate::sidecar_effective_access::accepted_tree_contains_actor_in_connection(
        conn, realm, sidecar, caller,
    )
    .await?
    {
        return Ok(None);
    }
    crate::sidecar_replica_authority::agent_floor_in_connection(conn, realm, sidecar, caller).await
}

/// H holds the controller ownership stream before discovering relevant Agent
/// PCRs. Only joined Agents are locked; unrelated provisioning does not become
/// a Sidecar dependency. Authority mutations hold these same source rows, so
/// the relevant inputs remain held through the enclosing Event transaction.
pub(crate) async fn locked_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    controller: &AccountId,
) -> PersistenceResult<Option<SidecarParticipantAuthorityCut>> {
    #[derive(QueryableByName)]
    struct RealmRow {
        #[diesel(sql_type = Text)]
        realm_id: String,
    }
    let pcr = sql_query("SELECT a.realm_id FROM realm_authorities a JOIN pcr_genesis_units g ON g.realm_id=a.realm_id \
        WHERE g.principal_id=$1 AND g.station_id=$2 FOR SHARE OF a")
        .bind::<Text,_>(controller.principal_id.as_str()).bind::<Text,_>(controller.station_id.as_str())
        .get_result::<RealmRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(pcr) = pcr else {
        return Err(invalid(
            "Sidecar controller ownership authority is not held here",
        ));
    };
    let _parents = sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR SHARE")
        .bind::<Text, _>(realm.as_str())
        .load::<RealmRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let owned = sql_query(
        "SELECT a.realm_id FROM realm_authorities a JOIN agent_provisioning_current_states p \
        ON a.realm_id=p.value->>'principal_control_realm_id' \
        JOIN member_state_current_states m ON m.realm_id=$2 AND m.membership='join' \
          AND m.value->>'membership'='join' AND m.member_id::jsonb=jsonb_build_object('kind','account', \
            'account_id',jsonb_build_object('principal_id',p.agent_id,'station_id',$3::text)) \
        WHERE p.realm_id=$1 ORDER BY a.realm_id FOR SHARE OF a",
    )
    .bind::<Text, _>(&pcr.realm_id)
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(controller.station_id.as_str())
    .load::<RealmRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let _ = owned;
    in_connection(conn, realm, sidecar, controller).await
}

/// H rechecks the signed desired/join digest after locking its relevant native
/// sources. G independently checks its own membership/RFC/fence cut.
pub(crate) async fn validate_mls_binding_in_connection(
    conn: &mut AsyncPgConnection,
    binding: &arkret_models_crypto::MlsGovernanceBindingPayload,
    controller: &AccountId,
) -> PersistenceResult<SidecarParticipantAuthorityCut> {
    let arkret_wire::ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = binding.effective_scope()
    else {
        return Err(invalid(
            "Sidecar authority verifier requires a native Sidecar scope",
        ));
    };
    let cut = locked_in_connection(conn, realm_id, sidecar_id, controller)
        .await?
        .ok_or_else(|| {
            PersistenceError::Conflict(format!(
                "{}: Sidecar controller or parent membership is not current",
                coland_storage::ConflictCode::CapabilityDenied
            ))
        })?;
    let supplied = binding
        .sidecar_binding()
        .ok_or_else(|| invalid("Sidecar MLS binding lacks its closed authority coordinates"))?;
    if supplied.participant_authority_digest != cut.participant_authority_digest {
        return Err(PersistenceError::Conflict(format!(
            "{}: Sidecar signed participant cut is stale",
            coland_storage::ConflictCode::FailedPrecondition
        )));
    }
    Ok(cut)
}

/// Check only H's native responsibility before its exact original is forwarded.
/// Claim originals and signatures are verified by the serving owner; G separately
/// decides the complete RFC transition and its own membership/fence cut.
pub(crate) async fn mls_authoring_is_current(
    pool: &PgPool,
    event: &arkret_wire::Event,
    actors: &std::collections::BTreeSet<ActorId>,
    endpoints: &[(AccountId, arkret_wire::MlsWelcomeRecipientEndpoint, EventId)],
) -> PersistenceResult<bool> {
    use arkret_event_draft::EventPayloadExt as _;

    let arkret_wire::ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = &event.scope_ref
    else {
        return Ok(false);
    };
    if realm_id != &event.realm_id || actors.is_empty() {
        return Ok(false);
    }
    let binding = match event.kind {
        arkret_wire::EventKind::MlsGenesis => {
            event
                .as_mls_genesis()
                .map_err(PersistenceError::database)?
                .governance_binding
        }
        arkret_wire::EventKind::MlsCommit => event
            .as_mls_commit()
            .map_err(PersistenceError::database)?
            .governance_binding()
            .clone(),
        _ => return Ok(false),
    };
    if binding.effective_scope() != &event.scope_ref {
        return Ok(false);
    }
    let Some(supplied) = binding.sidecar_binding() else {
        return Ok(false);
    };
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(controller) =
            crate::sidecar_access::controller_account_in_connection(conn, realm_id, sidecar_id)
                .await?
        else {
            return Ok(false);
        };
        if !crate::sidecar_replica_authority::is_owning_station_in_connection(conn, &controller)
            .await?
        {
            return Ok(false);
        }
        let Some(cut) = in_connection(conn, realm_id, sidecar_id, &controller).await? else {
            return Ok(false);
        };
        if supplied.participant_authority_digest != cut.participant_authority_digest
            || !crate::sidecar_access::desired_participant(&cut, &event.actor_id)
            || actors
                .iter()
                .any(|actor| !crate::sidecar_access::desired_participant(&cut, actor))
        {
            return Ok(false);
        }
        for (account, endpoint, authorization) in endpoints {
            let actor = ActorId::account(account.clone());
            if !actors.contains(&actor)
                || !crate::sidecar_access::desired_participant(&cut, &actor)
                || !crate::sidecar_mls_readiness::endpoint_current_in_connection(
                    conn,
                    account,
                    endpoint,
                    authorization,
                )
                .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
