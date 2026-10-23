//! The shared authority lock for native PCR state and its coupled private effects.

use arkret_wire::{AccountId, ActorId, CommitStreamHead, DidCoreId, RealmCommit, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Jsonb, Text};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};

pub(crate) struct PrivateAuthorityCut {
    pub realm_id: RealmId,
    pub generation: u64,
    pub service_id: DidCoreId,
    pub head: CommitStreamHead,
}

/// Read the immutable accepted origin, including the complete Human unit and
/// receipt. Editable current/profile rows cannot reclassify a registered Human.
pub(crate) async fn accepted_governance(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<arkret_wire::GenesisGovernance> {
    #[derive(diesel::QueryableByName)]
    struct Genesis {
        #[diesel(sql_type=Jsonb)]
        envelope: serde_json::Value,
        #[diesel(sql_type=Jsonb)]
        commit_json: serde_json::Value,
        #[diesel(sql_type=diesel::sql_types::Nullable<diesel::sql_types::Binary>)]
        exact_request_body: Option<Vec<u8>>,
        #[diesel(sql_type=diesel::sql_types::Nullable<Jsonb>)]
        result_json: Option<serde_json::Value>,
    }
    let row = sql_query("SELECT e.envelope,c.commit_json,g.exact_request_body,g.result_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk LEFT JOIN pcr_genesis_units g ON g.realm_id=c.realm_id WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text) AND c.stream_position=0 AND e.kind='ak.realm.create' AND e.state='committed'")
        .bind::<Text,_>(realm.as_str()).get_result::<Genesis>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| refused("accepted inception original is missing"))?;
    let event: arkret_wire::Event =
        serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
    let commit: RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    if event.realm_id != *realm
        || commit.realm_id != *realm
        || commit.event_ref != event.event_id
        || RealmId::from_event_id(&event.event_id) != *realm
    {
        return Err(refused("inception original and covering Commit disagree"));
    }
    let governance = arkret_wire::GenesisGovernance::from_genesis(&event).map_err(refused)?;
    if let arkret_wire::GenesisGovernance::Human(account) = &governance {
        let input: arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput =
            serde_json::from_slice(
                row.exact_request_body
                    .as_deref()
                    .ok_or_else(|| refused("Human ordered genesis unit is missing"))?,
            )
            .map_err(refused)?;
        let outcome: arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome =
            serde_json::from_value(
                row.result_json
                    .ok_or_else(|| refused("Human accepted receipt is missing"))?,
            )
            .map_err(refused)?;
        outcome.validate_against(&input).map_err(refused)?;
        if input.genesis_unit.create() != &event
            || outcome.commits[0] != commit
            || account.station_id != input.account_authority_id
            || account.principal_id != input.principal_id
        {
            return Err(refused(
                "Human accepted unit, receipt and full Account differ",
            ));
        }
    }
    Ok(governance)
}

pub(crate) fn refused(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: PCR governance {detail}"))
}

pub(crate) async fn native_inception(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<bool> {
    Ok(accepted_governance(conn, realm)
        .await?
        .is_principal_control())
}

pub(crate) async fn require_transferable(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<()> {
    accepted_governance(conn, realm)
        .await?
        .require_transferable()
        .map_err(refused)
}

/// A stored current tuple cannot grant a managed Agent a foreign tenure.
/// Fresh genesis has no accepted original yet and is checked by its native unit.
pub(crate) async fn validate_agent_current(
    conn: &mut AsyncPgConnection,
    current: &coland_storage::CurrentRealmAuthority,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct AgentOrigin {
        #[diesel(sql_type = Bool)]
        present: bool,
    }
    let origin = sql_query("SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text) AND c.stream_position=0 AND e.kind='ak.realm.create' AND e.state='committed' AND e.envelope#>>'{payload,object,purpose}'='agent_control') AS present")
        .bind::<Text,_>(current.realm_id.as_str()).get_result::<AgentOrigin>(&mut *conn).await.map_err(PersistenceError::database)?;
    if origin.present {
        accepted_governance(conn, &current.realm_id)
            .await?
            .validate_current(&current.service_id, current.generation)
            .map_err(refused)?;
    }
    Ok(())
}

/// The supported native export is deliberately closed. A PCR with a domain
/// requiring an additional operational archive refuses before its change
/// freezes the old authority, rather than activating a partial private copy.
pub(crate) async fn ensure_export_supported(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<()> {
    require_transferable(conn, realm).await?;
    #[derive(diesel::QueryableByName)]
    struct Unsupported {
        #[diesel(sql_type=Bool)]
        unsupported: bool,
    }
    let row=sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events e WHERE e.realm_id=$1 AND (e.state<>'committed' OR e.kind NOT IN ('ak.realm.create','ak.device.authorize','ak.device.reanchor','ak.profile.create','ak.profile.update','ak.identity.resolution.update','ak.consent.replace','ak.realm.governance_station.change'))) AS unsupported")
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
    require_transferable(conn, &event.realm_id).await?;
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
/// Human and user-managed Agent PCRs stay at their original Account Station.
/// Only independently accepted Organization governance can split from hosting.
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
    let realm = RealmId::new(authority.realm_id.clone()).map_err(refused)?;
    let governance = accepted_governance(conn, &realm).await?;
    governance
        .validate_current(
            &service_id,
            u64::try_from(authority.generation).map_err(refused)?,
        )
        .map_err(refused)?;
    if require_frozen {
        governance.require_transferable().map_err(refused)?;
    }

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

/// Native Human private effects use the same current lifecycle boundary as
/// the hosting projection. The authority lock precedes the account row lock.
pub(crate) async fn require_active_human_account(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Active {
        #[diesel(sql_type=Bool)]
        active: bool,
    }
    let row=sql_query("SELECT TRUE AS active FROM accounts a LEFT JOIN account_lifecycle l ON l.account_pk=a.pk WHERE a.principal_id=$1 AND a.station_id=$2 AND a.disabled_at IS NULL AND COALESCE(l.state NOT IN ('deactivated','erasure_pending'),TRUE) FOR SHARE OF a").bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).get_result::<Active>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if !row.is_some_and(|r| r.active) {
        return Err(unavailable("holder account is no longer active"));
    }
    Ok(())
}

/// Recheck immutable genesis restrictions even when reading an installed tenure.
/// A persisted handoff is not evidence that a fixed-governor Realm could migrate.
pub(crate) async fn validate_installed_governance(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<arkret_wire::GenesisGovernance> {
    #[derive(diesel::QueryableByName)]
    struct Current {
        #[diesel(sql_type = BigInt)]
        generation: i64,
        #[diesel(sql_type = Text)]
        service_id: String,
        #[diesel(sql_type = Bool)]
        has_handoffs: bool,
        #[diesel(sql_type = Bool)]
        has_inception_original: bool,
    }
    let row = sql_query("SELECT a.generation,a.service_id,EXISTS(SELECT 1 FROM realm_authority_handoffs h WHERE h.realm_id=a.realm_id) AS has_handoffs,EXISTS(SELECT 1 FROM realm_commits c WHERE c.realm_id=a.realm_id AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',a.realm_id) AND c.stream_position=0 AND c.event_pk IS NOT NULL) AS has_inception_original FROM realm_authorities a WHERE a.realm_id=$1")
        .bind::<Text,_>(realm.as_str()).get_result::<Current>(&mut *conn).await.map_err(PersistenceError::database)?;
    // A withheld position-zero Commit contains no Genesis Event. If a Full
    // original is present, however, its corruption must never fall back to the
    // retained snapshot's genesis current.
    let governance = if row.has_inception_original {
        accepted_governance(conn, realm).await?
    } else {
        accepted_replica_governance(conn, realm).await?
    };
    governance
        .validate_current(
            &DidCoreId::new(row.service_id).map_err(refused)?,
            u64::try_from(row.generation).map_err(refused)?,
        )
        .map_err(refused)?;
    if row.has_handoffs {
        governance.require_transferable().map_err(refused)?;
    }
    Ok(governance)
}

/// A since-join replica retains the verified Snapshot's immutable genesis
/// current below its readable floor, without materializing the genesis Event.
/// Use the same anchor coverage as `accepted_ordinary_realm`; mutable profile
/// rows and an unanchored current never supply inception provenance.
async fn accepted_replica_governance(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<arkret_wire::GenesisGovernance> {
    use arkret_models_collaboration::events_payloads::realm::{RealmGenesis, RealmPurpose};
    #[derive(diesel::QueryableByName)]
    struct Genesis {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let row = sql_query("SELECT g.value FROM realm_bootstrap_current_results g WHERE g.realm_id=$1 AND g.result_family='realm_genesis' AND g.current_stream_position=0 AND EXISTS(SELECT 1 FROM replica_stream_anchors a WHERE a.realm_id=g.realm_id AND a.stream_key=$2 AND a.anchor_stream_position>=g.current_stream_position)")
        .bind::<Text,_>(realm.as_str())
        .bind::<Text,_>(crate::authority_commit::stream_key(&arkret_wire::CommitStreamRef::Realm { realm_id: realm.clone() })?)
        .get_result::<Genesis>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| refused("accepted inception original or verified replica genesis is missing"))?;
    let genesis: RealmGenesis = serde_json::from_value(row.value).map_err(refused)?;
    genesis.validate().map_err(refused)?;
    match genesis.purpose {
        RealmPurpose::Collaboration => Ok(arkret_wire::GenesisGovernance::Collaboration),
        RealmPurpose::DirectConversation => Ok(arkret_wire::GenesisGovernance::DirectConversation(
            genesis.governance_station_id,
        )),
        _ => Err(refused(
            "a replica anchor cannot establish native PCR provenance",
        )),
    }
}
