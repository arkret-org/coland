//! Foreign Direct read facts derived from a verified public MLS replay.
//! Neither the public cache nor snapshot rows are governing admission inputs.
use arkret_wire::{
    ActorId, CommitStreamHead, CommitStreamRef, CurrentSelector, Event, MlsGroupCurrent,
    RealmCommit, RealmId, TypedCurrentRow,
};
use coland_storage::{
    DirectConversationDurableState, ForeignDirectMlsInput, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{OptionalExtension, QueryableByName};

const MAX_REPLAY_ROWS: usize = 256;
const MAX_REPLAY_BYTES: i64 = 16 * 1024 * 1024;
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("foreign Direct MLS: {error}"))
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Cut {
    service_id: arkret_wire::DidCoreId,
    generation: u64,
    head: CommitStreamHead,
    current: TypedCurrentRow,
    // Include Binding and roster evidence in the cache publication fence.
    // Legacy local cache entries must be rebound to this stronger native cut.
    #[serde(default)]
    current_state_entries: Vec<TypedCurrentRow>,
    participants: std::collections::BTreeSet<ActorId>,
}
#[derive(QueryableByName)]
struct AuthorityRow {
    #[diesel(sql_type=Text)]
    service_id: String,
    #[diesel(sql_type=BigInt)]
    generation: i64,
    #[diesel(sql_type=Jsonb)]
    member_account_id: serde_json::Value,
    #[diesel(sql_type=Nullable<BigInt>)]
    anchor_stream_position: Option<i64>,
    #[diesel(sql_type=Nullable<Text>)]
    anchor_commit_id: Option<String>,
}
#[derive(QueryableByName)]
struct HistoryRow {
    #[diesel(sql_type=Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    envelope: Option<serde_json::Value>,
}
#[derive(QueryableByName)]
struct CacheRow {
    #[diesel(sql_type=Jsonb)]
    cut: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    replay_base: serde_json::Value,
    #[diesel(sql_type=Bool)]
    complete: bool,
    #[diesel(sql_type=Bool)]
    exact_pair: bool,
}
async fn cache_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<Option<CacheRow>> {
    diesel::sql_query("SELECT cut,replay_base,complete,exact_pair FROM replica_direct_mls_public_states WHERE realm_id=$1").bind::<Text,_>(realm.as_str()).get_result::<CacheRow>(conn).await.optional().map_err(PersistenceError::database)
}

async fn cut_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    caller: Option<&ActorId>,
) -> PersistenceResult<Option<Cut>> {
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let key = crate::authority_commit::stream_key(&stream)?;
    let authority = diesel::sql_query("SELECT a.service_id,a.generation,r.member_account_id,r.anchor_stream_position,r.anchor_commit_id FROM realm_authorities a JOIN replica_stream_anchors r ON r.realm_id=a.realm_id AND r.stream_key=$2 WHERE a.realm_id=$1")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&key).get_result::<AuthorityRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(authority) = authority else {
        return Ok(None);
    };
    let hosted: arkret_wire::AccountId =
        serde_json::from_value(authority.member_account_id).map_err(invalid)?;
    let service_id = authority.service_id.parse().map_err(invalid)?;
    if service_id == hosted.station_id
        || caller.is_some_and(|actor| actor.fixed_route_service_id() != Some(&hosted.station_id))
    {
        return Ok(None);
    }
    let Some(head) = crate::replica_authorization::verified_head(conn, &stream).await? else {
        return Ok(None);
    };
    if authority.anchor_stream_position.is_none_or(|position| {
        position < 0
            || position as u64 > head.stream_position
            || (position as u64 == head.stream_position
                && authority.anchor_commit_id.as_deref() != Some(head.commit_id.as_str()))
    }) {
        return Ok(None);
    }
    let latest = diesel::sql_query("SELECT commit_json,NULL::jsonb AS envelope FROM realm_commits WHERE stream_key=$1 ORDER BY stream_position DESC LIMIT 1")
        .bind::<Text,_>(&key).get_result::<HistoryRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(latest) = latest {
        let commit: RealmCommit = serde_json::from_value(latest.commit_json).map_err(invalid)?;
        if commit.stream_position > head.stream_position
            || (commit.stream_position == head.stream_position
                && commit.commit_id != head.commit_id)
        {
            return Ok(None);
        }
    }
    let Some(binding) =
        crate::direct_conversation_admission::binding_current_snapshot_in_connection(conn, realm)
            .await?
    else {
        return Ok(None);
    };
    binding.validate().map_err(invalid)?;
    let participants = binding
        .binding
        .unordered_participant_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if participants.len() != 2 || caller.is_some_and(|actor| !participants.contains(actor)) {
        return Ok(None);
    }
    let pair: [ActorId; 2] = participants
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| invalid("participant cardinality"))?;
    let pair_key = &binding.binding.pair_key;
    let Some((verified_head, entries)) =
        crate::replica_authorization::direct_current_evidence(conn, realm, pair_key, &pair).await?
    else {
        return Ok(None);
    };
    if verified_head != head || !entries.iter().any(|entry| {
        let TypedCurrentRow::Value { selector, source_stream_ref, value, .. } = entry;
        matches!(selector, CurrentSelector::DirectConversationBinding { pair_key: found } if found == pair_key)
            && source_stream_ref == &stream
            && serde_json::to_value(&binding).is_ok_and(|expected| expected == *value)
    }) {
        return Ok(None);
    }
    if let Some(caller) = caller
        && !entries
            .iter()
            .any(|row| row.parent_membership_revision(realm, caller).is_some())
    {
        return Ok(None);
    }
    let Some(current) = entries.iter().find(|entry| matches!(entry, TypedCurrentRow::Value { selector: CurrentSelector::MlsGroup { scope_ref }, source_stream_ref, .. } if scope_ref == &arkret_wire::ScopeRef::Realm { realm_id: realm.clone() } && source_stream_ref == &stream)).cloned() else { return Ok(None) };
    Ok(Some(Cut {
        service_id,
        generation: u64::try_from(authority.generation).map_err(invalid)?,
        head,
        current,
        current_state_entries: entries,
        participants,
    }))
}

pub(crate) async fn input_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    caller: &ActorId,
) -> PersistenceResult<Option<ForeignDirectMlsInput>> {
    let Some(cut) = cut_in_connection(conn, realm, Some(caller)).await? else {
        return Ok(None);
    };
    let Ok(floor) =
        crate::account_stream_scan::replica_realm_floor_in_connection(conn, realm, caller).await?
    else {
        return Ok(None);
    };
    let TypedCurrentRow::Value { value, .. } = &cut.current;
    let group: MlsGroupCurrent = serde_json::from_value(value.clone()).map_err(invalid)?;
    let binding =
        crate::direct_conversation_admission::binding_current_snapshot_in_connection(conn, realm)
            .await?
            .ok_or_else(|| invalid("binding disappeared"))?;
    let expected_initial_pair_ref = binding.binding.initial_exact_pair_group_state_ref.clone();
    let mut base = None;
    if let Some(cache) = cache_in_connection(conn, realm).await? {
        let cached: Cut = serde_json::from_value(cache.cut).map_err(invalid)?;
        let candidate: coland_storage::ForeignDirectMlsBase =
            serde_json::from_value(cache.replay_base).map_err(invalid)?;
        let TypedCurrentRow::Value {
            value: cached_value,
            ..
        } = &cached.current;
        let cached_group: MlsGroupCurrent =
            serde_json::from_value(cached_value.clone()).map_err(invalid)?;
        if cached.service_id == cut.service_id
            && cached.generation == cut.generation
            && cached.participants == cut.participants
            && cached_group.genesis_event_ref == group.genesis_event_ref
            && cached_group.effective_scope == group.effective_scope
            && cached_group.cipher_suite == group.cipher_suite
            && candidate.epoch <= group.epoch
            && candidate.head.stream_ref == cut.head.stream_ref
            && candidate.head.stream_position <= cut.head.stream_position
            && (candidate.head.stream_position < cut.head.stream_position
                || candidate.head.commit_id == cut.head.commit_id)
        {
            // v1 forbids ProposalOrRef::Reference. An unchanged signed winning MLS
            // row needs no replay of intervening ordinary Events or separate proposals.
            if cache.complete && cached.current == cut.current {
                let replay_head = cut.head.clone();
                return Ok(Some(ForeignDirectMlsInput {
                    realm_id: realm.clone(),
                    caller: caller.clone(),
                    service_id: cut.service_id,
                    generation: cut.generation,
                    head: cut.head,
                    current: cut.current,
                    current_state_entries: cut.current_state_entries,
                    participants: cut.participants,
                    history: vec![],
                    base: Some(candidate),
                    replay_head,
                    complete: true,
                    expected_initial_pair_ref,
                }));
            }
            if candidate.head.stream_position.saturating_add(1) >= floor.oldest_position {
                base = Some(candidate)
            }
        }
    }
    let key = crate::authority_commit::stream_key(&cut.head.stream_ref)?;
    let start = if let Some(base) = &base {
        base.head.stream_position.saturating_add(1)
    } else {
        let genesis=diesel::sql_query("SELECT c.commit_json,e.envelope FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.stream_key=$1 AND c.commit_json->>'event_ref'=$2")
   .bind::<Text,_>(&key).bind::<Text,_>(group.genesis_event_ref.as_str()).get_result::<HistoryRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let Some(genesis) = genesis else {
            return Ok(None);
        };
        let commit: RealmCommit = serde_json::from_value(genesis.commit_json).map_err(invalid)?;
        if commit.stream_position < floor.oldest_position {
            return Ok(None);
        }
        commit.stream_position
    };
    let end = cut.head.stream_position;
    if start > end {
        return Ok(None);
    }
    // Headers prove a complete accepted span before filtering to MLS Events.
    // Any withheld/unknown Event is fail-closed, not guessed to be non-MLS.
    #[derive(QueryableByName)]
    struct Span {
        #[diesel(sql_type=Bool)]
        valid: bool,
    }
    let span=diesel::sql_query("SELECT COALESCE(COUNT(*)=$3-$2+1 AND bool_and(event_pk IS NOT NULL AND (stream_position=$2 OR previous_commit_ref=prior_commit)),false) AS valid FROM (SELECT event_pk,stream_position,previous_commit_ref,lag(commit_id) OVER(ORDER BY stream_position) AS prior_commit FROM realm_commits WHERE stream_key=$1 AND stream_position BETWEEN $2 AND $3) s")
  .bind::<Text,_>(&key).bind::<BigInt,_>(i64::try_from(start).map_err(invalid)?).bind::<BigInt,_>(i64::try_from(end).map_err(invalid)?).get_result::<Span>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !span.valid {
        return Ok(None);
    }
    if let Some(base) = &base {
        let first=diesel::sql_query("SELECT commit_json,NULL::jsonb AS envelope FROM realm_commits WHERE stream_key=$1 AND stream_position=$2").bind::<Text,_>(&key).bind::<BigInt,_>(i64::try_from(start).map_err(invalid)?).get_result::<HistoryRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let first: RealmCommit = serde_json::from_value(first.commit_json).map_err(invalid)?;
        if first.previous_commit_ref.as_ref() != Some(&base.head.commit_id) {
            return Ok(None);
        }
    }
    let rows=diesel::sql_query("WITH candidates AS (SELECT c.commit_json,c.stream_position,e.envelope,pg_column_size(e.envelope)::bigint AS bytes FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.stream_key=$1 AND c.stream_position BETWEEN $2 AND $3 AND e.kind IN ('ak.mls.genesis','ak.mls.commit') ORDER BY c.stream_position LIMIT 257), sized AS (SELECT commit_json,envelope,stream_position,SUM(bytes) OVER(ORDER BY stream_position) AS total_bytes FROM candidates) SELECT commit_json,envelope FROM sized WHERE total_bytes<=16777216 ORDER BY stream_position")
  .bind::<Text,_>(&key).bind::<BigInt,_>(i64::try_from(start).map_err(invalid)?).bind::<BigInt,_>(i64::try_from(end).map_err(invalid)?).load::<HistoryRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut bytes = 0usize;
    let mut history = Vec::new();
    for row in rows.into_iter().take(MAX_REPLAY_ROWS) {
        let Some(envelope) = row.envelope else {
            return Ok(None);
        };
        bytes += serde_json::to_vec(&envelope).map_err(invalid)?.len();
        if bytes > MAX_REPLAY_BYTES as usize {
            break;
        }
        history.push((
            serde_json::from_value::<RealmCommit>(row.commit_json).map_err(invalid)?,
            serde_json::from_value::<Event>(envelope).map_err(invalid)?,
        ));
    }
    if history.is_empty() && base.is_none() {
        return Ok(None);
    }
    let last_position = history
        .last()
        .map(|(commit, _)| commit.stream_position)
        .unwrap_or_else(|| base.as_ref().unwrap().head.stream_position);
    let remaining=diesel::sql_query("SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.stream_key=$1 AND c.stream_position>$2 AND c.stream_position<=$3 AND e.kind IN ('ak.mls.genesis','ak.mls.commit')) AS present")
      .bind::<Text,_>(&key).bind::<BigInt,_>(i64::try_from(last_position).map_err(invalid)?).bind::<BigInt,_>(i64::try_from(end).map_err(invalid)?).get_result::<crate::query_rows::ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if remaining && history.is_empty() {
        return Ok(None);
    }
    let complete = !remaining;
    let replay_head = if complete {
        cut.head.clone()
    } else {
        CommitStreamHead {
            stream_ref: history.last().unwrap().0.stream_ref.clone(),
            commit_id: history.last().unwrap().0.commit_id.clone(),
            stream_position: last_position,
        }
    };
    Ok(Some(ForeignDirectMlsInput {
        realm_id: realm.clone(),
        caller: caller.clone(),
        service_id: cut.service_id,
        generation: cut.generation,
        head: cut.head,
        current: cut.current,
        current_state_entries: cut.current_state_entries,
        participants: cut.participants,
        history,
        base,
        replay_head,
        complete,
        expected_initial_pair_ref,
    }))
}

fn input_cut(input: &ForeignDirectMlsInput) -> Cut {
    Cut {
        service_id: input.service_id.clone(),
        generation: input.generation,
        head: input.head.clone(),
        current: input.current.clone(),
        current_state_entries: input.current_state_entries.clone(),
        participants: input.participants.clone(),
    }
}
pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    input: &ForeignDirectMlsInput,
    result: &coland_storage::ForeignDirectMlsBase,
    exact_pair: bool,
) -> PersistenceResult<bool> {
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &input.realm_id).await?;
    let Some(current) = input_in_connection(conn, &input.realm_id, &input.caller).await? else {
        return Ok(false);
    };
    if current != *input
        || result.head != input.replay_head
        || result.public_state.len() > MAX_REPLAY_BYTES as usize
    {
        return Ok(false);
    }
    diesel::sql_query("INSERT INTO replica_direct_mls_public_states(realm_id,cut,replay_base,complete,exact_pair) VALUES($1,$2,$3,$4,$5) ON CONFLICT(realm_id) DO UPDATE SET cut=EXCLUDED.cut,replay_base=EXCLUDED.replay_base,complete=EXCLUDED.complete,exact_pair=EXCLUDED.exact_pair")
  .bind::<Text,_>(input.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(input_cut(input)).map_err(invalid)?).bind::<Jsonb,_>(serde_json::to_value(result).map_err(invalid)?).bind::<Bool,_>(input.complete).bind::<Bool,_>(exact_pair).execute(conn).await.map_err(PersistenceError::database)?;
    Ok(true)
}
pub(crate) async fn apply_in_connection(
    conn: &mut AsyncPgConnection,
    facts: &mut DirectConversationDurableState,
) -> PersistenceResult<()> {
    let realm = RealmId::new(facts.founding_slot.realm_id.clone()).map_err(invalid)?;
    let foreign = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM replica_stream_anchors WHERE realm_id=$1) AS present",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<crate::query_rows::ExistsRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    if !foreign {
        return Ok(());
    }
    facts.group_state_ref = None;
    facts.group_current_exact_pair = None;
    facts.initial_exact_pair_group_state_ref = None;
    let Some(cut) = cut_in_connection(conn, &realm, None).await? else {
        return Ok(());
    };
    let TypedCurrentRow::Value { value, .. } = &cut.current;
    let group: MlsGroupCurrent = serde_json::from_value(value.clone()).map_err(invalid)?;
    facts.group_state_ref = Some(group.current_mls_commit_event_ref.clone());
    let cache = cache_in_connection(conn, &realm).await?;
    if let Some(cache) = cache {
        let cached: Cut = serde_json::from_value(cache.cut).map_err(invalid)?;
        if cache.complete && cached == cut {
            let TypedCurrentRow::Value { value, .. } = &cut.current;
            let group: MlsGroupCurrent = serde_json::from_value(value.clone()).map_err(invalid)?;
            let base: coland_storage::ForeignDirectMlsBase =
                serde_json::from_value(cache.replay_base).map_err(invalid)?;
            facts.group_state_ref = Some(group.current_mls_commit_event_ref);
            facts.group_current_exact_pair = Some(cache.exact_pair);
            facts.initial_exact_pair_group_state_ref = base.initial_pair_ref;
        }
    }
    Ok(())
}
