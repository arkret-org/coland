//! The shared authority lock for native PCR state and its coupled private effects.

use arkret_wire::{AccountId, ActorId, CommitStreamHead, DidCoreId, RealmCommit, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

pub(crate) struct PrivateAuthorityCut {
    pub realm_id: RealmId,
    pub generation: u64,
    pub service_id: DidCoreId,
    pub head: CommitStreamHead,
}

/// Native PCR genesis does not use the ordinary bootstrap materializer.
/// Classify the actual accepted stream-zero original, never a missing projection.
pub(crate) async fn native_inception(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<bool> {
    #[derive(diesel::QueryableByName)]
    struct Genesis {
        #[diesel(sql_type=Jsonb)]
        envelope: serde_json::Value,
    }
    let row=sql_query("SELECT e.envelope FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text) AND c.stream_position=0 AND e.kind='ak.realm.create' AND e.state='committed'")
        .bind::<Text,_>(realm.as_str()).get_result::<Genesis>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||unavailable("accepted inception original is missing"))?;
    let event: arkret_wire::Event =
        serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
    let payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
    if event.realm_id != *realm {
        return Err(unavailable("inception belongs to another Realm"));
    }
    use arkret_models_collaboration::events_payloads::RealmPurpose;
    Ok(matches!(
        payload.object.purpose,
        RealmPurpose::PrincipalControl
            | RealmPurpose::AgentControl
            | RealmPurpose::AppletManagedControl
    ))
}

/// The supported native export is deliberately closed. A PCR with a domain
/// requiring an additional operational archive refuses before its change
/// freezes the old authority, rather than activating a partial private copy.
pub(crate) async fn ensure_export_supported(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Unsupported {
        #[diesel(sql_type=Bool)]
        unsupported: bool,
    }
    let row=sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events e WHERE e.realm_id=$1 AND (e.state<>'committed' OR e.kind NOT IN ('ak.realm.create','ak.device.authorize','ak.device.reanchor','ak.profile.create','ak.profile.update','ak.identity.resolution.update','ak.consent.grant','ak.consent.revoke','ak.realm.governance_station.change'))) AS unsupported")
        .bind::<Text,_>(realm.as_str()).get_result::<Unsupported>(conn).await.map_err(PersistenceError::database)?;
    if row.unsupported {
        return Err(unavailable(
            "native export contains an unsupported domain; migration must be prepared before freezing",
        ));
    }
    let private=sql_query("SELECT EXISTS(SELECT 1 FROM blobs WHERE realm_id=$1) OR EXISTS(SELECT 1 FROM principal_resolutions p JOIN security_transactions t ON t.principal_id=p.principal_id AND t.station_id=p.station_id WHERE p.pcr_realm_id=$1) OR EXISTS(SELECT 1 FROM principal_resolutions p JOIN accounts a ON a.principal_id=p.principal_id AND a.station_id=p.station_id JOIN key_backups b ON b.account_pk=a.pk WHERE p.pcr_realm_id=$1) AS unsupported")
        .bind::<Text,_>(realm.as_str()).get_result::<Unsupported>(&mut *conn).await.map_err(PersistenceError::database)?;
    let contacts=sql_query("SELECT EXISTS(SELECT 1 FROM principal_resolutions p JOIN contacts c ON c.requester_id::jsonb->'account_id'=jsonb_build_object('principal_id',p.principal_id,'station_id',p.station_id) OR c.target_id::jsonb->'account_id'=jsonb_build_object('principal_id',p.principal_id,'station_id',p.station_id) WHERE p.pcr_realm_id=$1) OR EXISTS(SELECT 1 FROM principal_resolutions p JOIN contact_verified_mirrors m ON m.target_holder_principal_id=p.principal_id WHERE p.pcr_realm_id=$1) AS unsupported")
        .bind::<Text,_>(realm.as_str()).get_result::<Unsupported>(&mut *conn).await.map_err(PersistenceError::database)?;
    if contacts.unsupported {
        return Err(unavailable(
            "native archive does not support an attached private Contact domain",
        ));
    }
    if private.unsupported {
        return Err(unavailable(
            "native archive does not support an attached blob, backup or security workflow",
        ));
    }
    Ok(())
}

pub(crate) async fn admit_governance_change(
    conn: &mut AsyncPgConnection,
    transaction: &coland_storage::AuthorityCommitTransaction,
) -> Result<coland_storage::AuthorityCommitWriteOutcome, crate::PgTransactionError> {
    use crate::actor_profiles::{PcrSelfEventCut, verify_pcr_self_event};
    let event = &transaction.event;
    if event.kind != arkret_wire::EventKind::RealmGovernanceStationChange
        || transaction.commit.producer_signer_fact_digest.is_some()
    {
        return Err(unavailable("change is not a native PCR unit").into());
    }
    let auth = event
        .authorization_ref
        .as_deref()
        .ok_or_else(|| unavailable("change lacks root authorization"))?;
    match verify_pcr_self_event(conn, transaction, Some(auth), "PCR planned handoff").await? {
        PcrSelfEventCut::Known(_) => {
            return Ok(coland_storage::AuthorityCommitWriteOutcome::Duplicate);
        }
        PcrSelfEventCut::Fresh(_) => {}
    }
    let holder = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| unavailable("change producer is not the holder Account"))?;
    let cut = lock_holder(
        conn,
        holder,
        Some(&transaction.expected_authority.service_id),
    )
    .await?;
    if cut.realm_id != event.realm_id {
        return Err(unavailable("change is outside the holder inception PCR").into());
    }
    #[derive(diesel::QueryableByName)]
    struct Root {
        #[diesel(sql_type=Text)]
        authority_event_ref: String,
    }
    let root = sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<Root>(&mut *conn)
    .await?;
    if root.authority_event_ref != auth {
        return Err(unavailable("change root reference is stale").into());
    }
    crate::pcr_private_archive::validate_export_ready(conn, holder, &event.realm_id).await?;
    let historical = crate::agent_producer_signer_keys::prepare_admitted_own_pcr_in_connection(
        conn,
        event,
        &transaction.commit,
    )
    .await?;
    crate::authority_commit::queue_event_in_connection(
        conn,
        event,
        transaction.commit.committed_at,
    )
    .await?;
    let result = crate::authority_commit::commit_verified_pcr_governance_change_in_connection(
        conn,
        transaction,
    )
    .await?;
    if result == coland_storage::AuthorityCommitWriteOutcome::Committed {
        crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
            conn,
            event,
            &transaction.commit,
            historical,
        )
        .await?;
    }
    Ok(result)
}

#[derive(diesel::QueryableByName)]
struct AuthorityRow {
    #[diesel(sql_type=Text)]
    realm_id: String,
    #[diesel(sql_type=BigInt)]
    generation: i64,
    #[diesel(sql_type=Text)]
    service_id: String,
}

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "temporarily_unavailable: holder private authority {detail}"
    ))
}

/// Acquire this before any holder account, policy, quota or private-cell lock.
/// The Account's hosting Station and its PCR governor are independent identities.
pub(crate) async fn lock_holder(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    expected_acceptor: Option<&DidCoreId>,
) -> PersistenceResult<PrivateAuthorityCut> {
    lock_holder_mode(conn, holder, expected_acceptor, false).await
}

/// Operational export requires the real terminal change at the locked head.
pub(crate) async fn lock_frozen_holder(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
) -> PersistenceResult<PrivateAuthorityCut> {
    lock_holder_mode(conn, holder, None, true).await
}

async fn lock_holder_mode(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    expected_acceptor: Option<&DidCoreId>,
    require_frozen: bool,
) -> PersistenceResult<PrivateAuthorityCut> {
    let authority=sql_query("SELECT a.realm_id,a.generation,a.service_id FROM principal_resolutions p JOIN realm_authorities a ON a.realm_id=p.pcr_realm_id JOIN realm_authority_root_current_results root ON root.realm_id=a.realm_id WHERE p.principal_id=$1 AND p.station_id=$2 AND root.controller_actor_id=$3 AND (EXISTS(SELECT 1 FROM pcr_genesis_units g WHERE g.realm_id=p.pcr_realm_id AND g.principal_id=p.principal_id AND g.station_id=p.station_id) OR EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk JOIN agent_producer_signer_keys s ON s.commit_id=c.commit_id WHERE e.envelope->>'event_id'=p.genesis_event_id AND e.state='committed' AND e.kind='ak.realm.create' AND e.envelope->'actor_id'=$3 AND e.envelope->'payload'->'object'->>'purpose'='agent_control' AND c.realm_id=p.pcr_realm_id AND c.stream_position=0 AND c.governance_generation=0 AND s.self_admission_kind='agent_pcr_genesis')) FOR UPDATE OF a")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(ActorId::account(holder.clone())).map_err(PersistenceError::database)?)
        .get_result::<AuthorityRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("has no complete accepted inception and root"))?;
    let service_id = DidCoreId::new(authority.service_id).map_err(unavailable)?;
    if expected_acceptor.is_some_and(|service| service != &service_id) {
        return Err(unavailable("is governed by another Station"));
    }
    #[derive(diesel::QueryableByName)]
    struct Frozen {
        #[diesel(sql_type=Bool)]
        frozen: bool,
    }
    let frozen=sql_query("SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.governance_generation=$2 AND e.kind='ak.realm.governance_station.change') AS frozen")
        .bind::<Text,_>(&authority.realm_id).bind::<BigInt,_>(authority.generation)
        .get_result::<Frozen>(&mut *conn).await.map_err(PersistenceError::database)?;
    if frozen.frozen != require_frozen {
        return Err(unavailable(if require_frozen {
            "is not frozen for operational export"
        } else {
            "is frozen for planned handoff"
        }));
    }
    #[derive(diesel::QueryableByName)]
    struct Head {
        #[diesel(sql_type=Jsonb)]
        commit_json: serde_json::Value,
    }
    let head=sql_query("SELECT commit_json FROM realm_commits WHERE realm_id=$1 AND stream_ref->>'kind'='realm' ORDER BY stream_position DESC LIMIT 1")
        .bind::<Text,_>(&authority.realm_id).get_result::<Head>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)?.ok_or_else(|| unavailable("head is missing"))?;
    let head: RealmCommit =
        serde_json::from_value(head.commit_json).map_err(PersistenceError::database)?;
    let realm_id = RealmId::new(authority.realm_id).map_err(unavailable)?;
    if head.realm_id != realm_id
        || head.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            })
    {
        return Err(unavailable("head belongs to another stream"));
    }
    Ok(PrivateAuthorityCut {
        realm_id,
        generation: u64::try_from(authority.generation).map_err(unavailable)?,
        service_id,
        head: CommitStreamHead {
            stream_ref: head.stream_ref,
            stream_position: head.stream_position,
            commit_id: head.commit_id,
        },
    })
}
