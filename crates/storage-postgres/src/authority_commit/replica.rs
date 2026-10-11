//! Remote current authority records and the Realm streams a non-governance
//! member Station holds as replicas (`federation.md` §3, §4.1.1).
//!
//! A replica never re-admits, re-signs or fans out: it stores the source Event
//! and the source RealmCommit exactly, only as the direct successor of the
//! stream this Station already holds. The one way to open a held stream is a
//! hosted member's own verified join (its `ak.member.state{join}` or its
//! `ak.invite.accept`) while no hosted member is joined -- on a stream this
//! Station does not hold yet or, after its last hosted member left, on the
//! stream it still holds, where continuity then restarts at the join; the
//! stream then stays pending anchor until the
//! governing Station's bootstrap snapshot is installed as its typed current.
//! Commits at or below that snapshot head are held for continuity only; each
//! later replica is re-verified against the hosted-member basis and the
//! Event's visibility at the local typed current, which it then advances in
//! the same transaction together with the hosted Accounts' summaries. A
//! Commit whose Event no hosted member may hold in full is kept as a
//! continuity-only chain node without Event bytes.

use arkret_models_crypto::MlsCommitPayload;
use coland_storage::{
    CommittedChainNode, CommittedReplica, CommittedReplicaOutcome, CommittedReplicaRole,
    ConflictCode, ReplicaAnchorInstall, ReplicaStreamAnchor,
};

use super::{
    AsyncPgConnection, BigInt, CommitRow, CurrentRealmAuthority, Jsonb, Nullable,
    OptionalExtension, PersistenceError, PgTransactionError, QueryableByName, RunQueryDsl, Text,
    Timestamptz, Value, decode_json, invalid, locked_authority, same_authority, sql_query,
    stream_key, to_i64,
};

#[derive(QueryableByName)]
struct HeldRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    envelope: Option<Value>,
}

#[derive(QueryableByName)]
struct EventPkOnlyRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

#[derive(QueryableByName)]
struct MemberIdRow {
    #[diesel(sql_type = Text)]
    member_id: String,
}

#[derive(QueryableByName)]
struct AnchorRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    join_commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    member_account_id: Value,
    #[diesel(sql_type = Nullable<Text>)]
    anchor_commit_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    anchor_stream_position: Option<i64>,
}

#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct MlsGenesisProvenanceRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    mls_group_id: String,
    #[diesel(sql_type = Text)]
    genesis_event_ref: String,
}

/// Freeze the governance-signed Genesis selector at the exact held Commit
/// cut. A held Full Genesis binds its own Event ID. A later MLS Commit needs
/// the separately signed replica carrier; its target never implies Genesis.
pub(super) async fn bind_mls_replica_genesis_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    genesis_event_ref: Option<&arkret_wire::EventId>,
    has_welcomes: bool,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    if !matches!(
        event.kind,
        arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
    ) {
        if genesis_event_ref.is_some() {
            return Err(invalid("non-MLS replica carries a Genesis selector").into());
        }
        return Ok(());
    }
    let mls_group_id = event.scope_ref.canonical_mls_group_id().map_err(invalid)?;
    let genesis_event_ref = match event.kind {
        arkret_wire::EventKind::MlsGenesis => {
            if genesis_event_ref.is_some() || has_welcomes {
                return Err(invalid("Genesis replica carries an extra selector or Welcome").into());
            }
            let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(invalid)?;
            payload.validate().map_err(invalid)?;
            if payload.effective_scope() != &event.scope_ref
                || payload.mls_group_id().map_err(invalid)? != mls_group_id
                || payload.created_at != event.created_at
            {
                return Err(
                    invalid("Genesis replica differs from its exact accepted scope").into(),
                );
            }
            &event.event_id
        }
        arkret_wire::EventKind::MlsCommit => {
            let Some(reference) = genesis_event_ref else {
                if has_welcomes {
                    return Err(invalid("MLS Welcome has no signed Genesis selector").into());
                }
                return Ok(());
            };
            let payload: MlsCommitPayload = serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(invalid)?;
            if payload.mls_group_id().map_err(invalid)? != mls_group_id
                || reference == &event.event_id
            {
                return Err(
                    invalid("MLS replica Genesis selector differs from its Commit group").into(),
                );
            }
            reference
        }
        _ => {
            if genesis_event_ref.is_some() {
                return Err(invalid("non-MLS replica carries a Genesis selector").into());
            }
            return Ok(());
        }
    };
    if commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref
            != arkret_wire::CommitStreamRef::from_scope(
                &event.scope_ref,
                Some(event.realm_id.clone()),
            )
            .map_err(invalid)?
        || held_duplicate(conn, commit, Some(event)).await?
            != Some(CommittedReplicaOutcome::Duplicate)
    {
        return Err(invalid("MLS Genesis provenance has no exact held source Full").into());
    }
    let scope_key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&event.scope_ref)
            .map_err(PersistenceError::database)?,
    )
    .map_err(invalid)?;
    sql_query(
        "INSERT INTO mls_replica_genesis_provenance \
         (realm_id,scope_key,mls_group_id,genesis_event_ref,first_carried_commit_event_ref,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (scope_key) DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&scope_key)
    .bind::<Text, _>(mls_group_id.as_str())
    .bind::<Text, _>(genesis_event_ref.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Timestamptz, _>(at)
    .execute(&mut *conn)
    .await?;
    let frozen = sql_query(
        "SELECT realm_id,mls_group_id,genesis_event_ref \
         FROM mls_replica_genesis_provenance WHERE scope_key=$1 FOR UPDATE",
    )
    .bind::<Text, _>(&scope_key)
    .get_result::<MlsGenesisProvenanceRow>(&mut *conn)
    .await?;
    if frozen.realm_id != event.realm_id.as_str()
        || frozen.mls_group_id != mls_group_id.as_str()
        || frozen.genesis_event_ref != genesis_event_ref.as_str()
    {
        return Err(conflict(
            ConflictCode::DuplicateConflict,
            "MLS replica changed its immutable Genesis selector",
        ));
    }
    Ok(())
}

fn conflict(code: ConflictCode, detail: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {detail}")).into()
}

fn validate_authority_shape(authority: &CurrentRealmAuthority) -> Result<(), PgTransactionError> {
    let consistent = match (&authority.authority_ref, &authority.last_handoff_ref) {
        (arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(_), None) => {
            authority.generation == 0
        }
        (arkret_wire::RealmCommitAuthorityRef::Handoff(handoff), Some(last)) => {
            authority.generation > 0 && handoff == last
        }
        _ => false,
    };
    if !consistent {
        return Err(invalid("remote authority generation and references disagree").into());
    }
    Ok(())
}

async fn require_current_replica_authority(
    conn: &mut AsyncPgConnection,
    authority: &CurrentRealmAuthority,
    commit: &arkret_wire::RealmCommit,
) -> Result<(), PgTransactionError> {
    let current = locked_authority(conn, &authority.realm_id)
        .await?
        .ok_or_else(|| PersistenceError::Internal("remote authority row disappeared".into()))?;
    if !same_authority(&current, authority)
        || commit.governance_generation != authority.generation
        || commit.authority_ref != authority.authority_ref
    {
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "replica Commit is outside the current governance tenure",
        ));
    }
    Ok(())
}

/// Upsert one verified remote authority under the Realm authority row lock.
pub(super) async fn record_remote_authority_in_connection(
    conn: &mut AsyncPgConnection,
    authority: &CurrentRealmAuthority,
    local_service_id: &arkret_wire::DidCoreId,
) -> Result<(), PgTransactionError> {
    validate_authority_shape(authority)?;
    if &authority.service_id == local_service_id {
        return Err(invalid("a remote authority record names this Station").into());
    }
    let authority_ref =
        serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?;
    let generation = to_i64(authority.generation, "remote authority generation")?;
    let last_handoff_ref = authority.last_handoff_ref.as_ref().map(|id| id.as_str());
    sql_query(
        "INSERT INTO realm_authorities \
         (realm_id, generation, service_id, authority_ref, last_handoff_ref) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (realm_id) DO NOTHING",
    )
    .bind::<Text, _>(authority.realm_id.as_str())
    .bind::<BigInt, _>(generation)
    .bind::<Text, _>(authority.service_id.as_str())
    .bind::<Jsonb, _>(&authority_ref)
    .bind::<Nullable<Text>, _>(last_handoff_ref)
    .execute(&mut *conn)
    .await?;
    let current = locked_authority(conn, &authority.realm_id)
        .await?
        .ok_or_else(|| PersistenceError::Internal("remote authority row disappeared".into()))?;
    if &current.service_id == local_service_id {
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "this Station holds the Realm's current authority",
        ));
    }
    if current.generation > authority.generation {
        return Ok(());
    }
    if current.generation == authority.generation {
        if same_authority(&current, authority) {
            return Ok(());
        }
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "two different verified authorities share one generation",
        ));
    }
    sql_query(
        "UPDATE realm_authorities SET generation = $2, service_id = $3, authority_ref = $4, \
         last_handoff_ref = $5, updated_at = now() WHERE realm_id = $1",
    )
    .bind::<Text, _>(authority.realm_id.as_str())
    .bind::<BigInt, _>(generation)
    .bind::<Text, _>(authority.service_id.as_str())
    .bind::<Jsonb, _>(&authority_ref)
    .bind::<Nullable<Text>, _>(last_handoff_ref)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The founding exception opens an already complete, anchored peer stream.
/// The caller has verified every source proof and its local founding
/// authority; all writes stay in the caller's transaction.
pub(crate) async fn materialize_founding_in_connection(
    conn: &mut AsyncPgConnection,
    unit: &coland_storage::DirectConversationFoundingCommitUnit,
    local_service_id: &arkret_wire::DidCoreId,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    let authority = &unit.transactions[0].expected_authority;
    record_remote_authority_in_connection(conn, authority, local_service_id).await?;
    let key = stream_key(&unit.transactions[0].commit.stream_ref)?;
    if locked_head(conn, &key).await?.is_some() {
        return Err(conflict(
            ConflictCode::DirectConversationSlotAlreadyCommitted,
            "the founding Realm stream already exists",
        ));
    }
    for transaction in &unit.transactions {
        let event = &transaction.event;
        let commit = &transaction.commit;
        crate::agent_producer_signer_keys::validate_producer_fact_binding(
            event,
            commit,
            transaction.producer_signer_fact.as_ref(),
        )?;
        store_replica_rows(conn, event, commit, &key, received_at).await?;
        if let Some(fact) = transaction.producer_signer_fact.as_ref() {
            crate::agent_producer_signer_keys::retain_prepared_producer_in_connection(
                conn, event, commit, fact,
            )
            .await?;
        }
        crate::capability_grant_current_results::commit_realm_authority_root_current_result_in_connection(
            conn, event, commit,
        )
        .await?;
        crate::realm_bootstrap_current_results::commit_ordinary_bootstrap_singleton_current_result_in_connection(
            conn, event, commit,
        )
        .await?;
        crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit).await?;
        // The replayed main Strand belongs to the validated four-Event
        // founding unit, exactly as at the source Station: it carries no
        // earlier capability basis for the per-Event authority path.
        if event.kind == arkret_wire::EventKind::StrandCreate {
            crate::strand_current_results::commit_direct_conversation_founding_strand_in_connection(
                conn, event, commit,
            )
            .await?;
        }
    }
    let facts = unit.facts().map_err(invalid)?;
    let member_account_id = facts.peer_id.as_account_id().ok_or_else(|| {
        invalid("a peer founding member must be an Account hosted by this Station")
    })?;
    let member = serde_json::to_value(member_account_id).map_err(PersistenceError::database)?;
    sql_query(
        "INSERT INTO replica_stream_anchors \
         (stream_key,realm_id,join_commit_id,member_account_id,anchor_commit_id,anchor_stream_position,anchored_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind::<Text, _>(&key)
    .bind::<Text, _>(facts.realm_id.as_str())
    .bind::<Text, _>(unit.transactions[2].commit.commit_id.as_str())
    .bind::<Jsonb, _>(&member)
    .bind::<Text, _>(unit.transactions[3].commit.commit_id.as_str())
    .bind::<BigInt, _>(i64::try_from(unit.transactions[3].commit.stream_position).map_err(invalid)?)
    .bind::<Timestamptz, _>(received_at)
    .execute(&mut *conn)
    .await?;
    // The registered unit has been verified and all four source-committed
    // reducers have run in this transaction. Retain their exact current rows
    // and head as the complete founding authorization cut, without a snapshot.
    let material = super::realm_state_snapshot_material_in_connection(conn, &facts.realm_id)
        .await?
        .ok_or_else(|| invalid("accepted founding unit has no reducer current"))?;
    let last = &unit.transactions[3].commit;
    let source_head = arkret_wire::CommitStreamHead {
        stream_ref: last.stream_ref.clone(),
        commit_id: last.commit_id.clone(),
        stream_position: last.stream_position,
    };
    if material.governance_generation != authority.generation
        || material.visible_stream_heads.as_slice() != std::slice::from_ref(&source_head)
        || material.current_state_entries.is_empty()
    {
        return Err(invalid("founding reducer cut differs from the accepted unit").into());
    }
    for entry in &material.current_state_entries {
        let arkret_wire::TypedCurrentRow::Value {
            source_stream_ref,
            revision,
            ..
        } = entry;
        if !unit.transactions.iter().any(|transaction| {
            source_stream_ref == &transaction.commit.stream_ref
                && revision.commit_id == transaction.commit.commit_id
                && revision.stream_position == transaction.commit.stream_position
        }) {
            return Err(invalid("founding current row has no exact accepted source").into());
        }
        crate::replica_authorization::save_row(conn, &facts.realm_id, entry, received_at).await?;
    }
    crate::replica_authorization::install_verified_head(conn, &source_head, received_at).await?;
    crate::account_summary::publish_realm_account_summary_in_connection(conn, &facts.realm_id)
        .await?;
    Ok(())
}

pub(super) async fn hosts_joined_member(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
    local_service_id: &arkret_wire::DidCoreId,
) -> Result<bool, PgTransactionError> {
    hosted_member_basis(conn, stream, local_service_id, true).await
}

/// Repeatable-read callers already own a consistent snapshot. Row locks here
/// would turn concurrent snapshot installation into a serialization failure.
pub(super) async fn hosts_joined_member_in_snapshot(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
    local_service_id: &arkret_wire::DidCoreId,
) -> Result<bool, PgTransactionError> {
    hosted_member_basis(conn, stream, local_service_id, false).await
}

async fn hosted_member_basis(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
    local_service_id: &arkret_wire::DidCoreId,
    lock_rows: bool,
) -> Result<bool, PgTransactionError> {
    let lock = if lock_rows { " FOR SHARE" } else { "" };
    let rows = match stream {
        arkret_wire::CommitStreamRef::Realm { realm_id } => sql_query(format!("SELECT member_id FROM member_state_current_results WHERE realm_id=$1 AND membership='join'{lock}"))
            .bind::<Text, _>(realm_id.as_str()).load::<MemberIdRow>(&mut *conn).await?,
        arkret_wire::CommitStreamRef::Circle { realm_id, circle_id } => sql_query(format!("SELECT cm.member_id FROM circle_member_state_current_results cm JOIN member_state_current_results rm ON rm.realm_id=cm.realm_id AND rm.member_id=cm.member_id JOIN circle_current_results circle ON circle.circle_id=cm.circle_id AND circle.realm_id=cm.realm_id WHERE cm.realm_id=$1 AND cm.circle_id=$2 AND cm.membership='join' AND rm.membership='join' AND circle_member_parent_join_current(cm.realm_id,cm.member_id,cm.value) AND circle.value->>'state'='active'{lock}"))
            .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(circle_id.as_str()).load::<MemberIdRow>(&mut *conn).await?,
        arkret_wire::CommitStreamRef::Sidecar {realm_id,sidecar_id} => return crate::sidecar_replica_authority::holds_source_at_cut(conn,realm_id,sidecar_id,local_service_id,lock_rows).await.map_err(Into::into),
        _ => return Ok(false),
    };
    for row in rows {
        let member: arkret_wire::ActorId =
            serde_json::from_str(&row.member_id).map_err(|error| {
                PersistenceError::Internal(format!("replica member identity is malformed: {error}"))
            })?;
        if member.route_service_id() == local_service_id {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Choose only exact accepted current joins. This read grants no authority:
/// the governing bootstrap must still prove complete disclosure and its cut.
pub(super) async fn bootstrap_readers_in_connection(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
    local_service: &arkret_wire::DidCoreId,
    lock_rows: bool,
) -> Result<Vec<(arkret_wire::AccountId, arkret_wire::RealmCommit)>, PgTransactionError> {
    #[derive(QueryableByName)]
    struct ReaderRow {
        #[diesel(sql_type = Text)]
        member_id: String,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
        #[diesel(sql_type = Jsonb)]
        envelope: Value,
    }
    let scope = serde_json::to_value(stream).map_err(PersistenceError::database)?;
    let lock = if lock_rows { " FOR SHARE OF m" } else { "" };
    let rows = match stream {
        arkret_wire::CommitStreamRef::Realm { realm_id } => sql_query(format!(
            "SELECT m.member_id,c.commit_json,e.envelope FROM member_state_current_results m \
             JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id \
                AND c.stream_position=m.current_stream_position AND c.stream_ref=$2 \
             JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
             WHERE m.realm_id=$1 AND m.membership='join' ORDER BY m.member_id{lock}"
        )).bind::<Text,_>(realm_id.as_str()).bind::<Jsonb,_>(&scope)
            .load::<ReaderRow>(&mut *conn).await?,
        arkret_wire::CommitStreamRef::Circle { realm_id, circle_id } => sql_query(format!(
            "SELECT m.member_id,c.commit_json,e.envelope FROM circle_member_state_current_results m \
             JOIN member_state_current_results rm ON rm.realm_id=m.realm_id AND rm.member_id=m.member_id \
             JOIN circle_current_results circle ON circle.circle_id=m.circle_id AND circle.realm_id=m.realm_id \
             JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id \
                AND c.stream_position=m.current_stream_position AND c.stream_ref=$2 \
             JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
             WHERE m.realm_id=$1 AND m.circle_id=$3 AND m.membership='join' AND rm.membership='join' \
                AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) \
                AND circle.value->>'state'='active' ORDER BY m.member_id{lock}"
        )).bind::<Text,_>(realm_id.as_str()).bind::<Jsonb,_>(&scope).bind::<Text,_>(circle_id.as_str())
            .load::<ReaderRow>(&mut *conn).await?,
        _ => return Ok(Vec::new()),
    };
    let mut readers = Vec::new();
    for row in rows {
        let actor: arkret_wire::ActorId = serde_json::from_str(&row.member_id).map_err(invalid)?;
        let Some(account) = actor
            .as_account_id()
            .filter(|account| &account.station_id == local_service)
        else {
            continue;
        };
        let event: arkret_wire::Event = serde_json::from_value(row.envelope).map_err(invalid)?;
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json).map_err(invalid)?;
        let own_join = event.actor_id == actor && match event.kind {
            arkret_wire::EventKind::InviteAccept => matches!(stream, arkret_wire::CommitStreamRef::Realm { .. }),
            arkret_wire::EventKind::MemberState => serde_json::from_value::<arkret_models_collaboration::governance::membership_invite::MembershipPayload>(serde_json::to_value(&event.payload).map_err(invalid)?)
                .map_err(invalid).map(|payload| payload.member_id == actor && payload.membership == arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join)?,
            arkret_wire::EventKind::CircleMemberState => event.payload.get("membership").and_then(Value::as_str) == Some("join")
                && event.payload.get("member_id").and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok()).as_ref() == Some(&actor),
            _ => false,
        };
        if !own_join
            || commit.event_ref != event.event_id
            || &commit.stream_ref != stream
            || &commit.realm_id != stream.realm_id()
            || event.realm_id != commit.realm_id
            || arkret_wire::CommitStreamRef::from_scope(
                &event.scope_ref,
                Some(event.realm_id.clone()),
            )
            .map_err(invalid)?
                != *stream
        {
            return Err(invalid("bootstrap reader has no exact accepted own join").into());
        }
        readers.push((account.clone(), commit));
    }
    Ok(readers)
}

#[cfg(test)]
mod hosted_basis_tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_basis_survives_concurrent_membership_update_without_row_locks() {
        let database = crate::TestDatabase::lease().await;
        let pool = database.pool();
        let mut reader = pool.get().await.unwrap();
        let mut writer = pool.get().await.unwrap();
        let realm: arkret_wire::RealmId = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"
            .parse()
            .unwrap();
        let station: arkret_wire::DidCoreId = "ak:did_core:web:holder.example".parse().unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:member.example".parse().unwrap(),
            station.clone(),
        ));
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        sql_query("INSERT INTO member_state_current_results(realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,'join','snapshot-read-fixture',0,'{\"membership\":\"join\"}',now())")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(actor.to_string())
            .execute(&mut *writer).await.unwrap();
        sql_query("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *reader)
            .await
            .unwrap();
        assert!(
            hosts_joined_member_in_snapshot(&mut reader, &stream, &station)
                .await
                .map_err(PgTransactionError::into_persistence)
                .unwrap()
        );
        sql_query("UPDATE member_state_current_results SET membership='leave',value='{\"membership\":\"leave\"}' WHERE realm_id=$1")
            .bind::<Text,_>(realm.as_str()).execute(&mut *writer).await.unwrap();
        assert!(
            hosts_joined_member_in_snapshot(&mut reader, &stream, &station)
                .await
                .map_err(PgTransactionError::into_persistence)
                .unwrap()
        );
        // The installing path retains its row-lock contract. Using that path
        // in this old snapshot reproduces the exact observed SQLSTATE 40001.
        assert!(matches!(
            hosts_joined_member(&mut reader, &stream, &station).await,
            Err(PgTransactionError::Diesel(
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::SerializationFailure,
                    _
                )
            ))
        ));
        sql_query("ROLLBACK").execute(&mut *reader).await.unwrap();
        assert!(
            !hosts_joined_member_in_snapshot(&mut reader, &stream, &station)
                .await
                .map_err(PgTransactionError::into_persistence)
                .unwrap()
        );
    }
}

/// The Commit held at the head of `key`, locked for this transaction.
async fn locked_head(
    conn: &mut AsyncPgConnection,
    key: &str,
) -> Result<Option<arkret_wire::RealmCommit>, PgTransactionError> {
    sql_query(
        "SELECT commit_json FROM realm_commits \
         WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1 FOR UPDATE",
    )
    .bind::<Text, _>(key)
    .get_result::<CommitRow>(&mut *conn)
    .await
    .optional()?
    .map(|row| decode_json(row.commit_json, "held head").map_err(Into::into))
    .transpose()
}

const ANCHOR_SELECT: &str = "SELECT a.realm_id, c.commit_json AS join_commit_json, \
     a.member_account_id, a.anchor_commit_id, a.anchor_stream_position \
     FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id = a.join_commit_id";

async fn locked_anchor(
    conn: &mut AsyncPgConnection,
    key: &str,
) -> Result<Option<AnchorRow>, PgTransactionError> {
    Ok(sql_query(format!(
        "{ANCHOR_SELECT} WHERE a.stream_key = $1 FOR UPDATE OF a"
    ))
    .bind::<Text, _>(key)
    .get_result::<AnchorRow>(&mut *conn)
    .await
    .optional()?)
}

fn anchor_from_row(row: AnchorRow) -> Result<ReplicaStreamAnchor, PgTransactionError> {
    let join_commit: arkret_wire::RealmCommit =
        decode_json(row.join_commit_json, "replica join Commit")?;
    let anchored_head = match (row.anchor_commit_id, row.anchor_stream_position) {
        (Some(commit_id), Some(position)) => Some(arkret_wire::CommitStreamHead {
            stream_ref: join_commit.stream_ref.clone(),
            stream_position: u64::try_from(position).map_err(|_| {
                PersistenceError::Internal("stored anchor position is negative".to_owned())
            })?,
            commit_id: decode_json(Value::String(commit_id), "replica anchor Commit id")?,
        }),
        (None, None) => None,
        _ => {
            return Err(PersistenceError::Internal("replica anchor row is torn".to_owned()).into());
        }
    };
    Ok(ReplicaStreamAnchor {
        realm_id: decode_json(Value::String(row.realm_id), "replica anchor Realm id")?,
        join_commit,
        member_account_id: decode_json(row.member_account_id, "replica anchor member Account")?,
        anchored_head,
    })
}

/// The anchored head of a held stream, or the refusal of a stream that is
/// not held or not anchored yet.
fn anchored_head(
    anchor: Option<AnchorRow>,
) -> Result<arkret_wire::CommitStreamHead, PgTransactionError> {
    let Some(anchor) = anchor else {
        return Err(conflict(
            ConflictCode::DependencyMissing,
            "this Station holds no anchored replica of the Commit's stream",
        ));
    };
    anchor_from_row(anchor)?.anchored_head.ok_or_else(|| {
        conflict(
            ConflictCode::DependencyMissing,
            "the held stream is pending its bootstrap anchor",
        )
    })
}

/// The held head must be the Commit's direct predecessor.
fn require_direct_successor(
    head: Option<&arkret_wire::RealmCommit>,
    commit: &arkret_wire::RealmCommit,
) -> Result<(), PgTransactionError> {
    let Some(head) = head else {
        return Err(conflict(
            ConflictCode::DependencyMissing,
            "this Station holds no predecessor on the Commit's stream",
        ));
    };
    if commit.stream_position <= head.stream_position {
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "a different Commit is held at or after this stream position",
        ));
    }
    if commit.stream_position > head.stream_position.saturating_add(1) {
        return Err(conflict(
            ConflictCode::DependencyMissing,
            "the Commits between the held head and this one are not held",
        ));
    }
    commit
        .validate_successor_of(head)
        .map_err(|error| conflict(ConflictCode::ForkQuarantine, &error.to_string()))
}

/// The same held Commit, or the refusal of a Commit id held with other
/// content. A chain node answers an exact replay of its Commit as held.
async fn held_duplicate(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommit,
    event: Option<&arkret_wire::Event>,
) -> Result<Option<CommittedReplicaOutcome>, PgTransactionError> {
    let Some(existing) = sql_query(
        "SELECT c.commit_json, e.envelope FROM realm_commits c \
         LEFT JOIN canonical_events e ON e.pk = c.event_pk WHERE c.commit_id = $1",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .get_result::<HeldRow>(&mut *conn)
    .await
    .optional()?
    else {
        return Ok(None);
    };
    let commit_json = serde_json::to_value(commit).map_err(PersistenceError::database)?;
    let same_event = match (&existing.envelope, event) {
        (Some(envelope), Some(event)) => {
            *envelope == serde_json::to_value(event).map_err(PersistenceError::database)?
        }
        _ => true,
    };
    if existing.commit_json == commit_json && same_event {
        // A previously withheld row has no Event or original Human fact yet.
        // Its first permitted Full import is an atomic upgrade, not a replay.
        if existing.envelope.is_none() && event.is_some() {
            return Ok(None);
        }
        return Ok(Some(CommittedReplicaOutcome::Duplicate));
    }
    Err(conflict(
        ConflictCode::DuplicateConflict,
        "the Commit id is held with different content",
    ))
}

/// Recipient visibility re-verification against the local typed current
/// (`federation.md` §4.1.1): this Station must be allowed to hold the
/// Event's complete canonical bytes.
async fn require_visible(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    local_service_id: &arkret_wire::DidCoreId,
) -> Result<(), PgTransactionError> {
    if let arkret_wire::ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = &event.scope_ref
        && !crate::sidecar_replica_authority::holds_source_in_connection(
            conn,
            realm_id,
            sidecar_id,
            local_service_id,
        )
        .await?
    {
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "private Sidecar source is not held by this exact controller Station",
        ));
    }
    if event.kind == arkret_wire::EventKind::SidecarCreate
        && event
            .actor_id
            .as_account_id()
            .is_none_or(|owner| &owner.station_id != local_service_id)
    {
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "Sidecar creation is private to its exact controller Station",
        ));
    }
    if crate::realm_fanout::plaintext_message(event) {
        let services = sql_query(
            "SELECT value FROM realm_bootstrap_current_results \
             WHERE realm_id=$1 AND result_family='realm_plaintext_visible_services'",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()?
        .map(|row| crate::realm_fanout::plaintext_message_service_ids(&row.value))
        .unwrap_or_default();
        if !services
            .iter()
            .any(|service| service == local_service_id.as_str())
        {
            return Err(conflict(
                ConflictCode::CapabilityDenied,
                "the Realm does not list this Station as a plaintext message service",
            ));
        }
    }
    if matches!(
        event.kind,
        arkret_wire::EventKind::SelfModerationReport
            | arkret_wire::EventKind::ModerationFrankingProof
    ) {
        let scope = if event.kind == arkret_wire::EventKind::ModerationFrankingProof {
            let proof: arkret_models_collaboration::events_payloads::moderation::FrankingProof =
                serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(PersistenceError::database)?;
            crate::moderation_franking_proof_current_results::franking_target_scope_in_connection(
                conn,
                &event.realm_id,
                &proof.event_id,
            )
            .await?
        } else {
            event.scope_ref.clone()
        };
        let rows = sql_query("SELECT member_id FROM member_state_current_results WHERE realm_id=$1 AND membership='join'").bind::<Text, _>(event.realm_id.as_str()).load::<MemberIdRow>(&mut *conn).await?;
        for row in rows {
            let member: arkret_wire::ActorId =
                serde_json::from_str(&row.member_id).map_err(PersistenceError::database)?;
            if member.route_service_id() == local_service_id
                && crate::replica_authorization::scope_moderator(
                    conn,
                    &event.realm_id,
                    &member,
                    &scope,
                    &[
                        arkret_wire::CapabilityActionId::POLICY_MANAGE,
                        arkret_wire::CapabilityActionId::MODERATION_DECISION,
                    ],
                    chrono::Utc::now(),
                )
                .await?
            {
                return Ok(());
            }
        }
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "no hosted exact-scope moderator is proved at the verified replica cut",
        ));
    }
    Ok(())
}

/// Write the exact Event and its Commit as committed in the caller's
/// transaction.
async fn store_replica_rows(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    key: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    if event.kind == arkret_wire::EventKind::RealmDestroy {
        return Err(PersistenceError::Conflict(
            "failed_precondition: v1 does not admit Realm destruction".to_owned(),
        )
        .into());
    }
    super::queue_event_in_connection(conn, event, received_at).await?;
    let token = super::ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id = $1 FOR UPDATE")
        .bind::<super::Binary, _>(token.to_vec())
        .get_result::<EventPkOnlyRow>(&mut *conn)
        .await?
        .pk;
    insert_commit_row(conn, commit, key, Some(event_pk)).await?;
    let settled = sql_query(
        "UPDATE canonical_events SET state = 'committed', committed_at = $2, \
         rejection_reason = NULL WHERE pk = $1 AND state = 'queued'",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    if settled != 1 {
        return Err(PersistenceError::Conflict(
            "replica acceptance conflicts with the Event terminal state".into(),
        )
        .into());
    }
    Ok(())
}

async fn insert_commit_row(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommit,
    key: &str,
    event_pk: Option<i64>,
) -> Result<(), PgTransactionError> {
    sql_query(
        "INSERT INTO realm_commits \
         (commit_id, realm_id, stream_key, stream_ref, stream_position, previous_commit_ref, \
          event_pk, governance_generation, commit_json, committed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(commit.realm_id.as_str())
    .bind::<Text, _>(key)
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(to_i64(commit.stream_position, "stream position")?)
    .bind::<Nullable<Text>, _>(commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
    .bind::<Nullable<BigInt>, _>(event_pk)
    .bind::<BigInt, _>(to_i64(
        commit.governance_generation,
        "governance generation",
    )?)
    .bind::<Jsonb, _>(serde_json::to_value(commit).map_err(PersistenceError::database)?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn require_realm_stream(commit: &arkret_wire::RealmCommit) -> Result<(), PgTransactionError> {
    if !matches!(&commit.stream_ref, arkret_wire::CommitStreamRef::Realm { realm_id } | arkret_wire::CommitStreamRef::Circle { realm_id, .. } | arkret_wire::CommitStreamRef::Sidecar{realm_id,..} if realm_id == &commit.realm_id)
    {
        return Err(invalid("replica stream has no supported scope membership basis").into());
    }
    Ok(())
}

/// Store one verified replica in the caller's transaction.
/// Store one replica and, in the same transaction, queue the re-verified
/// Welcomes it carried (encryption-and-audit.md §2.2 "跨站 recipient"): a
/// Welcome that fails its own checks is not queued and never blocks the
/// replica, and a replay of an already held Commit still queues the Welcomes
/// that are not queued yet.
pub(super) async fn install_committed_replica_in_connection(
    conn: &mut AsyncPgConnection,
    replica: &CommittedReplica,
) -> Result<CommittedReplicaOutcome, PgTransactionError> {
    crate::agent_producer_signer_keys::validate_producer_fact_binding(
        &replica.event,
        &replica.commit,
        replica.producer_signer_fact.as_ref(),
    )?;
    let outcome = install_replica_commit_in_connection(conn, replica).await?;
    match outcome {
        CommittedReplicaOutcome::Stored => {
            if let Some(fact) = replica.producer_signer_fact.as_ref() {
                crate::agent_producer_signer_keys::retain_prepared_producer_in_connection(
                    conn,
                    &replica.event,
                    &replica.commit,
                    fact,
                )
                .await?;
            }
        }
        CommittedReplicaOutcome::Duplicate => {
            let original =
                crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
                    conn,
                    &replica.event,
                    &replica.commit,
                )
                .await?;
            if original != replica.producer_signer_fact {
                return Err(PersistenceError::Conflict(
                    "replicated producer source differs from frozen original".into(),
                )
                .into());
            }
        }
    }
    bind_mls_replica_genesis_in_connection(
        conn,
        &replica.event,
        &replica.commit,
        replica.genesis_event_ref.as_ref(),
        !replica.welcomes.is_empty(),
        replica.received_at,
    )
    .await?;
    crate::mls_group_current_results::queue_replicated_welcomes_in_connection(
        conn,
        &replica.event,
        &replica.commit,
        &replica.welcomes,
        replica.received_at,
    )
    .await?;
    Ok(outcome)
}

/// Queue the re-verified Welcomes of a Commit this Station already holds as
/// the exact replica, and answer `duplicate`.
pub(super) async fn queue_welcomes_of_held_replica_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    genesis_event_ref: Option<&arkret_wire::EventId>,
    welcomes: &[coland_storage::VerifiedMlsWelcome],
    at: chrono::DateTime<chrono::Utc>,
) -> Result<CommittedReplicaOutcome, PgTransactionError> {
    if held_duplicate(conn, commit, Some(event)).await? != Some(CommittedReplicaOutcome::Duplicate)
    {
        return Err(conflict(
            ConflictCode::DependencyMissing,
            "the replicated Commit is not held",
        ));
    }
    bind_mls_replica_genesis_in_connection(
        conn,
        event,
        commit,
        genesis_event_ref,
        !welcomes.is_empty(),
        at,
    )
    .await?;
    crate::mls_group_current_results::queue_replicated_welcomes_in_connection(
        conn, event, commit, welcomes, at,
    )
    .await?;
    Ok(CommittedReplicaOutcome::Duplicate)
}

/// Materialize the body of a held withheld Commit only after a verified
/// snapshot covers its effect and the existing current disclosure gate allows
/// Full. Preserve the exact signed Commit, current projection and stream head.
async fn upgrade_held_full_in_connection(
    conn: &mut AsyncPgConnection,
    replica: &CommittedReplica,
) -> Result<Option<CommittedReplicaOutcome>, PgTransactionError> {
    let commit = &replica.commit;
    let existing = sql_query("SELECT c.commit_json,e.envelope FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1")
        .bind::<Text,_>(commit.commit_id.as_str()).get_result::<HeldRow>(&mut *conn).await.optional()?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.envelope.is_some() {
        return Ok(None);
    }
    if existing.commit_json != serde_json::to_value(commit).map_err(PersistenceError::database)? {
        return Err(conflict(
            ConflictCode::DuplicateConflict,
            "held withheld Commit differs from Full source",
        ));
    }
    let key = stream_key(&commit.stream_ref)?;
    let head = locked_head(conn, &key).await?.ok_or_else(|| {
        conflict(
            ConflictCode::DependencyMissing,
            "held Full upgrade lacks stream head",
        )
    })?;
    let anchor = anchored_head(locked_anchor(conn, &key).await?)?;
    if commit.stream_position > anchor.stream_position
        || commit.stream_position > head.stream_position
    {
        return Err(conflict(
            ConflictCode::DependencyMissing,
            "Full upgrade requires a verified snapshot covering the held Commit effect",
        ));
    }
    if !hosts_joined_member(conn, &commit.stream_ref, &replica.local_service_id).await? {
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "Full upgrade has no hosted exact-scope reader",
        ));
    }
    require_visible(conn, &replica.event, &replica.local_service_id).await?;
    super::queue_event_in_connection(conn, &replica.event, replica.received_at).await?;
    let token = super::ids::parse_event_id(replica.event.event_id.as_str())
        .ok_or_else(|| invalid("Full upgrade Event token is invalid"))?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id=$1 FOR UPDATE")
        .bind::<super::Binary, _>(token.to_vec())
        .get_result::<EventPkOnlyRow>(&mut *conn)
        .await?
        .pk;
    let written = sql_query("UPDATE realm_commits SET event_pk=$2 WHERE commit_id=$1 AND event_pk IS NULL AND commit_json=$3")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(event_pk)
        .bind::<Jsonb,_>(serde_json::to_value(commit).map_err(PersistenceError::database)?)
        .execute(&mut *conn).await?;
    if written != 1 {
        return Err(conflict(
            ConflictCode::DuplicateConflict,
            "Full upgrade source changed",
        ));
    }
    sql_query("UPDATE canonical_events SET state='committed',committed_at=$2,rejection_reason=NULL WHERE pk=$1 AND state='queued'")
        .bind::<BigInt,_>(event_pk).bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await?;
    Ok(Some(CommittedReplicaOutcome::Stored))
}

async fn install_replica_commit_in_connection(
    conn: &mut AsyncPgConnection,
    replica: &CommittedReplica,
) -> Result<CommittedReplicaOutcome, PgTransactionError> {
    let event = &replica.event;
    let commit = &replica.commit;
    if commit.realm_id != replica.authority.realm_id
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
    {
        return Err(invalid("replica Commit does not bind its Event and Realm").into());
    }
    if arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None).map_err(invalid)?
        != commit.stream_ref
    {
        return Err(
            invalid("replica Event source scope differs from its covering Commit stream").into(),
        );
    }
    require_realm_stream(commit)?;
    record_remote_authority_in_connection(conn, &replica.authority, &replica.local_service_id)
        .await?;
    if let Some(outcome) = held_duplicate(conn, commit, Some(event)).await? {
        return Ok(outcome);
    }
    if let Some(upgraded) = upgrade_held_full_in_connection(conn, replica).await? {
        return Ok(upgraded);
    }
    require_current_replica_authority(conn, &replica.authority, commit).await?;
    let key = stream_key(&commit.stream_ref)?;
    let head = locked_head(conn, &key).await?;
    let anchor = locked_anchor(conn, &key).await?;
    if matches!(
        commit.stream_ref,
        arkret_wire::CommitStreamRef::Sidecar { .. }
    ) && head.is_none()
    {
        if anchor.is_some() || !crate::sidecar_replica_authority::is_native_origin(commit) {
            return Err(conflict(
                ConflictCode::DependencyMissing,
                "private Sidecar origin is not held",
            ));
        }
        if !crate::sidecar_replica_authority::permits_in_connection(
            conn,
            commit,
            &replica.local_service_id,
        )
        .await?
        {
            return Err(conflict(
                ConflictCode::CapabilityDenied,
                "private Sidecar source authority is unproved",
            ));
        }
        require_visible(conn, event, &replica.local_service_id).await?;
        crate::realm_lifecycle_current_results::require_replica_live_in_connection(conn, event)
            .await?;
        store_replica_rows(conn, event, commit, &key, replica.received_at).await?;
        crate::replica_current::advance_in_connection(conn, event, commit).await?;
        sql_query("INSERT INTO replica_stream_anchors (stream_key,realm_id,join_commit_id,member_account_id,anchor_commit_id,anchor_stream_position,anchored_at) VALUES($1,$2,$3,$4,$3,0,$5)")
            .bind::<Text,_>(&key).bind::<Text,_>(commit.realm_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
            .bind::<Jsonb,_>(crate::sidecar_replica_authority::controller_in_connection(conn,&commit.stream_ref).await?.ok_or_else(||invalid("private Sidecar owner vanished"))?)
            .bind::<Timestamptz,_>(replica.received_at).execute(&mut *conn).await?;
        return Ok(CommittedReplicaOutcome::Stored);
    }
    // A hosted member's own join opens the stream -- or, once no hosted
    // member is joined any more, re-opens it at the join (decision 0122).
    let opening = match &replica.role {
        CommittedReplicaRole::OpeningJoin { member_account_id }
            if head.is_none()
                || !hosts_joined_member(conn, &commit.stream_ref, &replica.local_service_id)
                    .await? =>
        {
            Some(member_account_id)
        }
        _ => None,
    };
    let Some(member_account_id) = opening else {
        return store_held_successor(conn, replica, &key, head.as_ref(), anchor).await;
    };
    // federation.md section 4.1.1: a Circle join opens the held stream only
    // while the local parent Realm current is join at exactly the revision
    // the join signed. A lagging Realm replica or a superseded parent join
    // writes nothing and stays retryable.
    if matches!(
        commit.stream_ref,
        arkret_wire::CommitStreamRef::Circle { .. }
    ) {
        let payload: arkret_models_collaboration::events_payloads::circle::CircleMemberStatePayload =
            serde_json::from_value(serde_json::json!(&event.payload))
                .map_err(|error| invalid(format!("Circle opening join payload: {error}")))?;
        let bound = payload
            .parent_membership_revision
            .as_ref()
            .ok_or_else(|| invalid("Circle opening join names no parent membership revision"))?;
        if !super::parent_join_at_revision_in_connection(
            conn,
            &event.realm_id,
            &arkret_wire::ActorId::account(member_account_id.clone()),
            bound,
        )
        .await?
        {
            return Err(conflict(
                ConflictCode::DependencyMissing,
                "Circle opening join names a parent Realm join this Station does not hold as current",
            ));
        }
    }
    let member_account_id =
        serde_json::to_value(member_account_id).map_err(PersistenceError::database)?;
    match (&head, anchor) {
        (None, None) => {
            store_replica_rows(conn, event, commit, &key, replica.received_at).await?;
            sql_query(
                "INSERT INTO replica_stream_anchors \
                 (stream_key, realm_id, join_commit_id, member_account_id) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind::<Text, _>(&key)
            .bind::<Text, _>(commit.realm_id.as_str())
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<Jsonb, _>(&member_account_id)
            .execute(&mut *conn)
            .await?;
        }
        // The rows held so far stay canonical only; continuity restarts at
        // this join and the positions before it are not pulled.
        (Some(head), Some(_)) => {
            if commit.stream_position <= head.stream_position {
                return Err(conflict(
                    ConflictCode::ForkQuarantine,
                    "a different Commit is held at or after this stream position",
                ));
            }
            store_replica_rows(conn, event, commit, &key, replica.received_at).await?;
            sql_query(
                "UPDATE replica_stream_anchors SET join_commit_id = $2, member_account_id = $3, \
                 anchor_commit_id = NULL, anchor_stream_position = NULL, anchored_at = NULL \
                 WHERE stream_key = $1",
            )
            .bind::<Text, _>(&key)
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<Jsonb, _>(&member_account_id)
            .execute(&mut *conn)
            .await?;
        }
        _ => {
            return Err(PersistenceError::Internal(
                "the held stream and its replica anchor disagree".to_owned(),
            )
            .into());
        }
    }
    crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit).await?;
    crate::account_summary::publish_realm_account_summary_in_connection(conn, &event.realm_id)
        .await?;
    Ok(CommittedReplicaOutcome::Stored)
}

/// Store a direct successor of an anchored held stream. At or below the
/// installed snapshot head it is held for continuity only; after it, the
/// hosted-member basis and visibility are re-verified at local typed current,
/// which the Event then advances.
async fn store_held_successor(
    conn: &mut AsyncPgConnection,
    replica: &CommittedReplica,
    key: &str,
    head: Option<&arkret_wire::RealmCommit>,
    anchor: Option<AnchorRow>,
) -> Result<CommittedReplicaOutcome, PgTransactionError> {
    let event = &replica.event;
    let commit = &replica.commit;
    let anchored = anchored_head(anchor)?;
    require_direct_successor(head, commit)?;
    if !hosts_joined_member(conn, &commit.stream_ref, &replica.local_service_id).await?
        && !accepted_own_circle_cleanup_in_connection(conn, replica).await?
    {
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "no hosted member has the exact replica scope",
        ));
    }
    require_visible(conn, event, &replica.local_service_id).await?;
    if commit.stream_position <= anchored.stream_position {
        // The installed snapshot already carries this Commit's effect.
        store_replica_rows(conn, event, commit, key, replica.received_at).await?;
        return Ok(CommittedReplicaOutcome::Stored);
    }
    crate::realm_lifecycle_current_results::require_replica_live_in_connection(conn, event).await?;
    store_replica_rows(conn, event, commit, key, replica.received_at).await?;
    crate::replica_current::advance_in_connection(conn, event, commit).await?;
    if crate::account_summary::changes_account_summary_inputs(&event.kind) {
        crate::account_summary::publish_realm_account_summary_in_connection(conn, &event.realm_id)
            .await?;
    }
    Ok(CommittedReplicaOutcome::Stored)
}

/// The original self-submission may explicitly clear an old Circle join that
/// a parent Realm rejoin invalidated (circle.md section 9.1). Only its exact
/// accepted result can use this path; it grants no ordinary replica basis.
async fn accepted_own_circle_cleanup_in_connection(
    conn: &mut AsyncPgConnection,
    replica: &CommittedReplica,
) -> Result<bool, PgTransactionError> {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    use arkret_models_collaboration::events_payloads::CircleMemberStatePayload;
    use arkret_models_collaboration::governance::circle::CircleMembership;

    let CommittedReplicaRole::AcceptedOwnCircleLeave { member_account_id } = &replica.role else {
        return Ok(false);
    };
    let event = &replica.event;
    let commit = &replica.commit;
    let actor = arkret_wire::ActorId::account(member_account_id.clone());
    let arkret_wire::ScopeRef::Circle {
        realm_id,
        circle_id,
    } = &event.scope_ref
    else {
        return Ok(false);
    };
    if event.kind != arkret_wire::EventKind::CircleMemberState
        || event.actor_id != actor
        || event.executed_by.is_some()
        || realm_id != &event.realm_id
        || member_account_id.station_id != replica.local_service_id
        || event.human_device_producer().map_err(invalid)?.is_none()
        || replica
            .producer_signer_fact
            .as_ref()
            .and_then(|fact| fact.as_human())
            .is_none()
    {
        return Ok(false);
    }
    let payload: CircleMemberStatePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(invalid)?;
    payload.validate().map_err(invalid)?;
    if payload.membership != CircleMembership::Leave
        || payload.member_id != actor
        || &payload.circle_id != circle_id
    {
        return Ok(false);
    }
    #[derive(QueryableByName)]
    struct OriginalResultRow {
        #[diesel(sql_type=Jsonb)]
        submission_json: Value,
        #[diesel(sql_type=Jsonb)]
        accepted_json: Value,
        #[diesel(sql_type=Jsonb)]
        parent_revision: Value,
        #[diesel(sql_type=Jsonb)]
        join_envelope: Value,
        #[diesel(sql_type=Jsonb)]
        join_commit_json: Value,
        #[diesel(sql_type=Jsonb)]
        member_value: Value,
    }
    let row = sql_query(
        "SELECT f.original_submission_json AS submission_json,f.accepted_commit_json AS accepted_json, \
            f.circle_leave_parent_revision AS parent_revision,j.envelope AS join_envelope, \
            jc.commit_json AS join_commit_json,m.value AS member_value \
         FROM canonical_events e JOIN authority_forward_attempts f ON f.event_pk=e.pk \
         JOIN replica_stream_anchors a ON a.realm_id=$2 AND a.stream_key=$3 \
         JOIN realm_commits jc ON jc.commit_id=a.join_commit_id \
         JOIN canonical_events j ON j.pk=jc.event_pk \
         JOIN circle_member_state_current_results m ON m.realm_id=a.realm_id AND m.circle_id=$4 AND m.member_id=$5 \
         WHERE e.id=$1 AND e.envelope=$6 AND e.state='queued' AND j.state='committed' \
           AND f.original_submission_json IS NOT NULL AND f.accepted_commit_json=$7 \
           AND f.circle_leave_parent_revision IS NOT NULL AND a.anchor_commit_id IS NOT NULL \
           AND a.member_account_id=$8 AND jc.stream_ref=$9 AND jc.stream_position<$10 \
           AND m.membership='join' AND m.source_stream_ref=jc.stream_ref \
           AND m.current_commit_id=jc.commit_id AND m.current_stream_position=jc.stream_position"
    ).bind::<super::Binary,_>(event.event_id.token_bytes().to_vec())
     .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(stream_key(&commit.stream_ref)?)
     .bind::<Text,_>(circle_id.as_str()).bind::<Text,_>(actor.to_string())
     .bind::<Jsonb,_>(serde_json::to_value(event).map_err(PersistenceError::database)?)
     .bind::<Jsonb,_>(serde_json::to_value(commit).map_err(PersistenceError::database)?)
     .bind::<Jsonb,_>(serde_json::to_value(member_account_id).map_err(PersistenceError::database)?)
     .bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
     .bind::<BigInt,_>(to_i64(commit.stream_position,"Circle cleanup position")?)
     .get_result::<OriginalResultRow>(&mut *conn).await.optional()?;
    let Some(row) = row else {
        return Ok(false);
    };
    let submission: SelfAuthoritySubmitRequest =
        decode_json(row.submission_json, "Circle cleanup original submission")?;
    let SelfAuthoritySubmitRequest::Event(original) = submission else {
        return Ok(false);
    };
    let accepted: arkret_wire::RealmCommit =
        decode_json(row.accepted_json, "Circle cleanup accepted result")?;
    let parent: arkret_wire::CurrentRevision =
        decode_json(row.parent_revision, "Circle cleanup parent cut")?;
    let join: arkret_wire::Event =
        decode_json(row.join_envelope, "Circle cleanup canonical opening")?;
    let join_commit: arkret_wire::RealmCommit =
        decode_json(row.join_commit_json, "Circle cleanup opening Commit")?;
    let member: arkret_wire::CircleMemberStateCurrent =
        decode_json(row.member_value, "Circle cleanup canonical member")?;
    if original.event != *event
        || accepted != *commit
        || join.actor_id != actor
        || join.kind != arkret_wire::EventKind::CircleMemberState
        || join.scope_ref != event.scope_ref
        || join.realm_id != event.realm_id
        || join_commit.event_ref != join.event_id
        || join_commit.stream_ref != commit.stream_ref
        || member.membership != arkret_wire::MembershipState::Join
    {
        return Ok(false);
    }
    let opening: CircleMemberStatePayload = serde_json::from_value(
        serde_json::to_value(&join.payload).map_err(PersistenceError::database)?,
    )
    .map_err(invalid)?;
    opening.validate().map_err(invalid)?;
    if opening.membership != CircleMembership::Join
        || opening.member_id != actor
        || &opening.circle_id != circle_id
        || opening.parent_membership_revision.is_none()
        || member.parent_membership_revision != opening.parent_membership_revision
    {
        return Ok(false);
    }
    join.verify_event_id_matches_content_with_digest_suite(
        join.event_id.digest_suite_code().digest_suite(),
    )
    .map_err(invalid)?;
    join_commit.validate_shape().map_err(invalid)?;
    join_commit
        .verify_commit_id_matches_content()
        .map_err(invalid)?;
    super::parent_join_at_revision_in_connection(conn, &event.realm_id, &actor, &parent)
        .await
        .map_err(Into::into)
}

/// Store one verified withheld Commit as a chain node that directly follows
/// the anchored held head.
pub(super) async fn install_committed_chain_node_in_connection(
    conn: &mut AsyncPgConnection,
    node: &CommittedChainNode,
) -> Result<CommittedReplicaOutcome, PgTransactionError> {
    let commit = &node.commit;
    if commit.realm_id != node.authority.realm_id {
        return Err(invalid("chain node Commit names another Realm").into());
    }
    require_realm_stream(commit)?;
    record_remote_authority_in_connection(conn, &node.authority, &node.local_service_id).await?;
    if let Some(outcome) = held_duplicate(conn, commit, None).await? {
        return Ok(outcome);
    }
    require_current_replica_authority(conn, &node.authority, commit).await?;
    let key = stream_key(&commit.stream_ref)?;
    let head = locked_head(conn, &key).await?;
    anchored_head(locked_anchor(conn, &key).await?)?;
    require_direct_successor(head.as_ref(), commit)?;
    insert_commit_row(conn, commit, &key, None).await?;
    // A withheld Event may have changed authorization on either held stream.
    // Its Commit advances continuity, but its undisclosed body cannot advance
    // the verified authorization cut. Reusing the old cut would also reject
    // the next full successor as non-contiguous after this chain node.
    let source = serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
    sql_query("DELETE FROM replica_authorization_cuts WHERE realm_id=$1 AND source_stream_ref=$2 AND head_stream_position<$3")
        .bind::<Text, _>(commit.realm_id.as_str()).bind::<Jsonb, _>(source).bind::<BigInt, _>(to_i64(commit.stream_position,"withheld authorization cut")?).execute(&mut *conn).await?;

    Ok(CommittedReplicaOutcome::Stored)
}

pub(super) async fn replica_stream_anchor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> Result<Option<ReplicaStreamAnchor>, PgTransactionError> {
    replica_anchor_for_stream_in_connection(
        conn,
        &arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
    )
    .await
}

pub(super) async fn replica_anchor_for_stream_in_connection(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
) -> Result<Option<ReplicaStreamAnchor>, PgTransactionError> {
    sql_query(format!("{ANCHOR_SELECT} WHERE a.stream_key=$1"))
        .bind::<Text, _>(stream_key(stream)?)
        .get_result::<AnchorRow>(&mut *conn)
        .await
        .optional()?
        .map(anchor_from_row)
        .transpose()
}

/// Install a verified bootstrap snapshot and its typed current atomically.
/// A pending stream requires its original opening join. An anchored refresh
/// may use another exact current hosted join, preserving the opening prefix.
pub(super) async fn install_replica_anchor_in_connection(
    conn: &mut AsyncPgConnection,
    install: &ReplicaAnchorInstall,
) -> Result<(), PgTransactionError> {
    crate::sync_cursor::retention::lock(conn, false).await?;
    let realm_stream = install.snapshot_head.stream_ref.clone();
    let key = stream_key(&realm_stream)?;
    let anchor = locked_anchor(conn, &key)
        .await?
        .map(anchor_from_row)
        .transpose()?
        .ok_or_else(|| {
            conflict(
                ConflictCode::DependencyMissing,
                "this Station holds no replica of the Realm stream",
            )
        })?;
    let current = locked_authority(conn, &install.realm_id)
        .await?
        .ok_or_else(|| {
            conflict(
                ConflictCode::DependencyMissing,
                "replica authority is absent",
            )
        })?;
    if current.generation != install.governance_generation {
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "bootstrap snapshot is outside the current governance tenure",
        ));
    }
    let refresh = if anchor.join_commit.commit_id == install.join_commit_id {
        None
    } else {
        if anchor.anchored_head.is_none() {
            return Err(invalid("a pending anchor names another opening join").into());
        }
        Some(
            bootstrap_readers_in_connection(
                conn,
                &realm_stream,
                &anchor.member_account_id.station_id,
                true,
            )
            .await?
            .into_iter()
            .find(|(_, join)| join.commit_id == install.join_commit_id)
            .ok_or_else(|| invalid("bootstrap refresh has no current hosted opening join"))?,
        )
    };
    let (member_account_id, join) = refresh
        .as_ref()
        .map(|(member, join)| (member, join))
        .unwrap_or((&anchor.member_account_id, &anchor.join_commit));
    if join.commit_id != install.join_commit_id {
        return Err(invalid("the anchor names another opening join").into());
    }
    let head = locked_head(conn, &key).await?;
    if anchor.anchored_head.is_none()
        && head.as_ref().map(|head| &head.commit_id) != Some(&join.commit_id)
    {
        return Err(PersistenceError::Internal(
            "a pending replica stream holds a Commit after its join".to_owned(),
        )
        .into());
    }
    let snapshot_head = &install.snapshot_head;
    if snapshot_head.stream_ref != realm_stream
        || snapshot_head.stream_position < join.stream_position
        || (snapshot_head.stream_position == join.stream_position
            && snapshot_head.commit_id != join.commit_id)
    {
        return Err(invalid("the bootstrap snapshot head does not cover the join").into());
    }
    if let Some(held) = &head
        && (snapshot_head.stream_position < held.stream_position
            || (snapshot_head.stream_position == held.stream_position
                && snapshot_head.commit_id != held.commit_id))
    {
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "a refreshed snapshot does not cover the verified held head",
        ));
    }
    if let Some(previous) = &anchor.anchored_head
        && (snapshot_head.stream_position < previous.stream_position
            || (snapshot_head.stream_position == previous.stream_position
                && snapshot_head.commit_id != previous.commit_id))
    {
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "a refreshed snapshot regresses its verified anchor",
        ));
    }
    let member = arkret_wire::ActorId::account(member_account_id.clone());
    let opening_selector = match &realm_stream {
        arkret_wire::CommitStreamRef::Realm { .. } => arkret_wire::CurrentSelector::MemberState {
            actor_id: member.clone(),
        },
        arkret_wire::CommitStreamRef::Circle { circle_id, .. } => {
            arkret_wire::CurrentSelector::CircleMemberState {
                circle_id: circle_id.clone(),
                member_actor_id: member.clone(),
            }
        }
        _ => return Err(invalid("bootstrap has no supported stream").into()),
    };
    let current_opening = install.current_state_entries.iter().any(|entry| matches!(entry, arkret_wire::TypedCurrentRow::Value { selector, source_stream_ref, revision, value } if selector == &opening_selector && source_stream_ref == &realm_stream && revision.commit_id == join.commit_id && revision.stream_position == join.stream_position && value.get("membership").and_then(Value::as_str) == Some("join")));
    if !current_opening {
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "bootstrap does not prove its exact opening join is still current",
        ));
    }
    if matches!(realm_stream, arkret_wire::CommitStreamRef::Circle { .. }) {
        // circle.md section 9.1: the snapshot's two typed currents of one cut
        // must agree -- the parent join is current at the revision the
        // opening Circle join bound.
        let opening = install
            .current_state_entries
            .iter()
            .find_map(|entry| match entry {
                arkret_wire::TypedCurrentRow::Value {
                    selector, value, ..
                } if selector == &opening_selector => Some(value),
                _ => None,
            })
            .map(|value| {
                serde_json::from_value::<arkret_wire::CircleMemberStateCurrent>(value.clone())
            })
            .transpose()
            .map_err(|error| invalid(format!("bootstrap Circle join current: {error}")))?;
        let parent_joined = opening.is_some_and(|circle| {
            install
                .current_state_entries
                .iter()
                .any(|entry| match entry {
                    arkret_wire::TypedCurrentRow::Value {
                        selector: arkret_wire::CurrentSelector::MemberState { actor_id },
                        source_stream_ref,
                        revision,
                        value,
                    } if actor_id == &member => {
                        serde_json::from_value::<arkret_wire::MemberStateCurrent>(value.clone())
                            .is_ok_and(|parent| {
                                circle.is_effective_under_parent(
                                    &install.realm_id,
                                    source_stream_ref,
                                    revision,
                                    parent.membership,
                                )
                            })
                    }
                    _ => false,
                })
        });
        if !parent_joined {
            return Err(conflict(
                ConflictCode::CapabilityDenied,
                "Circle bootstrap has no current parent Realm join",
            ));
        }
    }
    let installed_at = chrono::Utc::now();
    let snapshot = &install.verified_snapshot;
    if snapshot.realm_id != install.realm_id
        || snapshot.governance_generation != install.governance_generation
        || snapshot.visible_stream_heads != install.visible_stream_heads
        || snapshot.current_state_entries != install.current_state_entries
        || !snapshot.visible_stream_heads.contains(snapshot_head)
        || snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
    {
        return Err(invalid("verified bootstrap differs from its installed material").into());
    }
    crate::issued_realm_snapshots::issue_head_in_connection(
        conn,
        member_account_id,
        &coland_storage::RealmStateSnapshotMaterial {
            realm_id: snapshot.realm_id.clone(),
            governance_generation: snapshot.governance_generation,
            visible_stream_heads: snapshot.visible_stream_heads.clone(),
            current_state_entries: snapshot.current_state_entries.clone(),
            retention_and_history_floor: snapshot.retention_and_history_floor.clone(),
        },
        snapshot.clone(),
    )
    .await?;
    crate::replica_current::install_snapshot_at_heads_in_connection(
        conn,
        &install.realm_id,
        snapshot_head,
        &install.visible_stream_heads,
        &install.current_state_entries,
        installed_at,
    )
    .await?;
    sql_query(
        "UPDATE replica_stream_anchors SET anchor_commit_id = $2, \
         anchor_stream_position = $3, anchored_at = $4 WHERE stream_key = $1",
    )
    .bind::<Text, _>(&key)
    .bind::<Text, _>(snapshot_head.commit_id.as_str())
    .bind::<BigInt, _>(to_i64(snapshot_head.stream_position, "anchor position")?)
    .bind::<Timestamptz, _>(installed_at)
    .execute(&mut *conn)
    .await?;
    crate::account_summary::publish_realm_account_summary_in_connection(conn, &install.realm_id)
        .await?;
    Ok(())
}
