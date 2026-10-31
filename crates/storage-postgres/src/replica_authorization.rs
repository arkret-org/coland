//! Read-only authorization from the governing Station's signed typed rows.
//!
//! These rows retain the existing SDK values and source coordinates. They do
//! not manufacture the private admission provenance omitted by snapshots.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, CapabilitySubject, IssuerAuthorityRef,
};
use arkret_wire::{ActorId, CurrentSelector, CurrentState, GrantId, RealmId, ScopeRef};
use coland_storage::{AuthorizationOperation, OperationFacts, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("replica authorization row: {detail}"))
}

pub(crate) fn keeps(_selector: &CurrentSelector) -> bool {
    true
}

pub(crate) const CURRENT_REVISION_GUARD_SQL: &str = "SELECT EXISTS(SELECT 1 FROM jsonb_array_elements($2) incoming \
     JOIN LATERAL (SELECT current_commit_id,current_stream_position,source_stream_ref,value \
       FROM replica_authorization_rows WHERE realm_id=$1 AND selector=incoming->'selector' \
       LIMIT 1) stored ON TRUE \
     WHERE stored.current_commit_id=incoming->'revision'->>'commit_id' \
       AND stored.current_stream_position::text=incoming->'revision'->>'stream_position' \
       AND (stored.source_stream_ref IS DISTINCT FROM incoming->'source_stream_ref' \
         OR stored.value IS DISTINCT FROM incoming->'value')) AS present";

/// Compare the complete incoming cut before a snapshot retires old rows.
/// A verified signature does not permit rewriting an already observed revision.
pub(crate) async fn guard_current_rows(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    entries: &[CurrentState],
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Conflict {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        present: bool,
    }
    let conflict = diesel::sql_query(CURRENT_REVISION_GUARD_SQL)
        .bind::<Text, _>(realm.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(entries).map_err(invalid)?)
        .get_result::<Conflict>(conn)
        .await
        .map_err(PersistenceError::database)?;
    if conflict.present {
        return Err(PersistenceError::Conflict(
            "failed_precondition: current revision has conflicting canonical bytes".into(),
        ));
    }
    Ok(())
}

/// Save only a verified snapshot or source-committed reducer result. The
/// enclosing replica transaction installs the rows and its anchor together.
pub(crate) async fn save_row(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    entry: &CurrentState,
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    save_row_with_observation(conn, realm, entry, installed_at, false).await
}

/// A reducer can observe only the effect it just materialized, never a
/// future qualified snapshot's cut for an omitted historical selector.
pub(crate) async fn save_effect_row(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    entry: &CurrentState,
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    save_row_with_observation(conn, realm, entry, installed_at, true).await
}

async fn save_row_with_observation(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    entry: &CurrentState,
    installed_at: chrono::DateTime<chrono::Utc>,
    effect_only: bool,
) -> PersistenceResult<()> {
    let CurrentState::Value {
        selector,
        source_stream_ref,
        revision,
        value,
    } = entry;
    if !keeps(selector) {
        return Ok(());
    }
    if source_stream_ref.realm_id() != realm {
        return Err(invalid("source stream is outside the Realm"));
    }
    let position = i64::try_from(revision.stream_position)
        .map_err(|_| invalid("source position exceeds PostgreSQL BIGINT"))?;
    let changed = diesel::sql_query(
        "INSERT INTO replica_authorization_rows \
         (realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at, \
          observed_anchor_commit_id,observed_anchor_stream_position,circle_continuation_id) \
         SELECT $1,$2,$3,$4,$5,$6,$7,h.head_commit_id,h.head_stream_position,h.circle_continuation_id \
         FROM (SELECT 1) seed LEFT JOIN replica_authorization_cuts h \
           ON h.realm_id=$1 AND h.source_stream_ref=$3 AND h.circle_continuation_id IS NOT NULL \
             AND $2->>'kind' IN ('circle','circle_member_state') \
             AND ($5<h.head_stream_position OR ($5=h.head_stream_position AND $4=h.head_commit_id)) \
             AND (NOT $8 OR ($5=h.head_stream_position AND $4=h.head_commit_id)) \
         ON CONFLICT(realm_id,selector) DO UPDATE SET \
         source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value, \
         observed_anchor_commit_id=EXCLUDED.observed_anchor_commit_id, \
         observed_anchor_stream_position=EXCLUDED.observed_anchor_stream_position, \
         circle_continuation_id=EXCLUDED.circle_continuation_id, \
         updated_at=EXCLUDED.updated_at \
         WHERE replica_authorization_rows.current_commit_id<>EXCLUDED.current_commit_id \
           OR replica_authorization_rows.current_stream_position<>EXCLUDED.current_stream_position \
           OR (replica_authorization_rows.source_stream_ref=EXCLUDED.source_stream_ref \
             AND replica_authorization_rows.value=EXCLUDED.value)",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(selector).map_err(invalid)?)
    .bind::<Jsonb, _>(serde_json::to_value(source_stream_ref).map_err(invalid)?)
    .bind::<Text, _>(revision.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(installed_at)
    .bind::<diesel::sql_types::Bool, _>(effect_only)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: current revision has conflicting canonical bytes".into(),
        ));
    }
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct StoredRow {
    #[diesel(sql_type = Jsonb)]
    selector: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// The Station signature establishes each grant's reducer-derived root refs.
/// The member Station checks their Realm/generation and every live parent,
/// without guessing a root Event ref not disclosed by the root value.
pub(crate) fn intact_chain(
    id: &GrantId,
    grants: &BTreeMap<GrantId, CapabilityGrant>,
    realm: &RealmId,
    generation: u64,
    at: chrono::DateTime<chrono::Utc>,
    visiting: &mut BTreeSet<GrantId>,
    depth: usize,
) -> bool {
    if depth > 4 || !visiting.insert(id.clone()) {
        return false;
    }
    let valid = grants.get(id).is_some_and(|grant| {
        grant.realm_id.as_ref() == Some(realm)
            && crate::capability_grant_current_states::grant_is_active_at(grant, at)
            && !grant.issuer_authority_refs.is_empty()
            && !grant.authority_root_refs.is_empty()
            && grant.authority_root_refs.iter().all(|root| {
                matches!(root, AuthorityRootRef::RealmRoot { realm_id, authority_generation, .. }
                    if realm_id == realm && *authority_generation == generation)
            })
            && grant.issuer_authority_refs.iter().all(|reference| match reference {
                IssuerAuthorityRef::OwnedAgent { .. } => false,
                IssuerAuthorityRef::RealmRoot {
                    realm_id,
                    authority_event_ref,
                    authority_generation,
                } => {
                    realm_id == realm
                        && *authority_generation == generation
                        && grant.authority_root_refs.iter().any(|root| {
                            matches!(root, AuthorityRootRef::RealmRoot { realm_id: root_realm,
                                authority_event_ref: root_event, authority_generation: root_generation }
                                if root_realm == realm && root_event == authority_event_ref
                                    && *root_generation == generation)
                        })
                }
                IssuerAuthorityRef::Grant { grant_id } => {
                    grants.get(grant_id).is_some_and(|parent| {
                        matches!(&parent.subject, CapabilitySubject::Actor(subject) if subject == &grant.issuer_id)
                    }) && intact_chain(
                        grant_id,
                        grants,
                        realm,
                        generation,
                        at,
                        visiting,
                        depth + 1,
                    )
                }
            })
    });
    visiting.remove(id);
    valid
}

/// This is a governance metadata read, not ordinary Circle content access.
/// The caller separately proves its hosted membership and anchored stream.
pub(crate) async fn scope_moderator(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    actor: &ActorId,
    scope: &ScopeRef,
    actions: &[&str],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let Some(cut) = verified_head(conn, &realm_stream).await? else {
        return Ok(false);
    };
    let key = crate::authority_commit::stream_key(&realm_stream)?;
    let known = diesel::sql_query(
        "SELECT commit_id AS head_commit_id,stream_position AS head_stream_position FROM realm_commits WHERE stream_key=$1 \
         UNION ALL SELECT anchor_commit_id AS head_commit_id,anchor_stream_position AS head_stream_position FROM replica_stream_anchors \
         WHERE stream_key=$1 AND anchor_commit_id IS NOT NULL ORDER BY head_stream_position DESC LIMIT 1",
    ).bind::<Text, _>(&key).get_result::<CutRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if known.is_some_and(|head| {
        u64::try_from(head.head_stream_position).map_or(true, |position| {
            position > cut.stream_position
                || (position == cut.stream_position
                    && head.head_commit_id != cut.commit_id.as_str())
        })
    }) {
        return Ok(false);
    }
    let rows = diesel::sql_query(
        "SELECT selector,value FROM replica_authorization_rows WHERE realm_id=$1 ORDER BY selector::text",
    )
    .bind::<Text, _>(realm.as_str())
    .load::<StoredRow>(conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut root = None;
    let mut policy_present = false;
    let mut grants = BTreeMap::new();
    for row in rows {
        let selector: CurrentSelector = serde_json::from_value(row.selector).map_err(invalid)?;
        match selector {
            CurrentSelector::RealmAuthorityRoot => root = Some(row.value),
            CurrentSelector::RealmPolicyBundle => {
                serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload,
                >(row.value)
                .map_err(invalid)?;
                policy_present = true;
            }
            CurrentSelector::CapabilityGrant { grant_id } => {
                let grant: CapabilityGrant = serde_json::from_value(row.value).map_err(invalid)?;
                if grant.id != grant_id || grant.realm_id.as_ref() != Some(realm) {
                    return Err(invalid("grant identity differs from its selector"));
                }
                grants.insert(grant_id, grant);
            }
            CurrentSelector::MemberState { .. } => {}
            _ => {}
        }
    }
    let Some(root) = root.filter(|_| policy_present) else {
        return Ok(false);
    };
    let controller: ActorId = serde_json::from_value(
        root.get("controller_actor_id")
            .cloned()
            .ok_or_else(|| invalid("root controller is absent"))?,
    )
    .map_err(invalid)?;
    root.get("controller_epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("root controller epoch is absent"))?;
    let generation = root
        .get("authority_generation")
        .and_then(arkret_canonical::serde_helpers::parse_uint64_decimal_value)
        .ok_or_else(|| invalid("root generation is absent"))?;
    let target = match scope {
        ScopeRef::Realm { realm_id } if realm_id == realm => {
            if controller == *actor {
                return Ok(true);
            }
            arkret_wire::WireResourceSelector::realm(realm.clone())
        }
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == realm => {
            arkret_wire::WireResourceSelector::circle(realm.clone(), circle_id.clone())
        }
        _ => return Ok(false),
    };
    let effective = grants.iter().filter_map(|(id, grant)| {
        (matches!(&grant.subject, CapabilitySubject::Actor(subject) if subject == actor)
            && intact_chain(id, &grants, realm, generation, at, &mut BTreeSet::new(), 0))
        .then_some(grant)
    });
    let facts = OperationFacts::default();
    Ok(!coland_storage::evaluate_grants(
        &AuthorizationOperation {
            actor,
            actions,
            target: &target,
            at,
            facts: &facts,
        },
        effective,
    )
    .unreserved()
    .is_empty())
}

#[derive(diesel::QueryableByName)]
struct CutRow {
    #[diesel(sql_type=Text)]
    head_commit_id: String,
    #[diesel(sql_type=BigInt)]
    head_stream_position: i64,
}

pub(crate) async fn verified_head(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
) -> PersistenceResult<Option<arkret_wire::CommitStreamHead>> {
    use horme::OptionalExtension as _;
    diesel::sql_query("SELECT head_commit_id,head_stream_position FROM replica_authorization_cuts WHERE realm_id=$1 AND source_stream_ref=$2")
        .bind::<Text, _>(stream.realm_id().as_str()).bind::<Jsonb, _>(serde_json::to_value(stream).map_err(invalid)?)
        .get_result::<CutRow>(conn).await.optional().map_err(PersistenceError::database)?.map(|row| Ok(arkret_wire::CommitStreamHead { stream_ref:stream.clone(), commit_id:row.head_commit_id.parse().map_err(invalid)?, stream_position:u64::try_from(row.head_stream_position).map_err(invalid)? })).transpose()
}

/// A qualified Circle-domain source cut already materialized this prefix.
/// Such Full originals are continuity only, including extra snapshot heads
/// whose transport anchor has not caught up yet.
pub(crate) async fn circle_effect_covered(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<bool> {
    if !matches!(
        commit.stream_ref,
        arkret_wire::CommitStreamRef::Circle { .. }
    ) {
        return Ok(false);
    }
    let covered = diesel::sql_query("SELECT head_commit_id,head_stream_position FROM replica_authorization_cuts WHERE realm_id=$1 AND source_stream_ref=$2 AND circle_continuation_id IS NOT NULL AND circle_effect_base_commit_id IS NOT NULL")
        .bind::<Text,_>(commit.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).map_err(invalid)?)
        .get_result::<CutRow>(conn).await.optional().map_err(PersistenceError::database)?;
    let Some(covered) = covered else {
        return Ok(false);
    };
    let position = i64::try_from(commit.stream_position).map_err(invalid)?;
    if position == covered.head_stream_position
        && commit.commit_id.as_str() != covered.head_commit_id
    {
        return Err(PersistenceError::Conflict(format!(
            "{}: Circle effect differs from the exact qualified source endpoint",
            coland_storage::ConflictCode::ForkQuarantine
        )));
    }
    Ok(position <= covered.head_stream_position)
}

#[derive(diesel::QueryableByName)]
struct CurrentEvidenceRow {
    #[diesel(sql_type = Jsonb)]
    entry_json: serde_json::Value,
}

#[derive(diesel::QueryableByName)]
struct MemberEvidenceRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// Exact selector evidence at the verified held replica cut. Point probes
/// exclude unrelated Realm rows and stale bootstrap receipts.
pub(crate) async fn exact_current_evidence(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
    selectors: &[CurrentSelector],
) -> PersistenceResult<Option<(arkret_wire::CommitStreamHead, Vec<CurrentState>)>> {
    let realm = stream.realm_id();
    let Some(head) = verified_head(conn, stream).await? else {
        return Ok(None);
    };
    let known = diesel::sql_query(
        "SELECT commit_id AS head_commit_id,stream_position AS head_stream_position \
         FROM realm_commits WHERE stream_key=$1 \
         UNION ALL SELECT anchor_commit_id AS head_commit_id,anchor_stream_position AS head_stream_position \
         FROM replica_stream_anchors WHERE stream_key=$1 AND anchor_commit_id IS NOT NULL \
         ORDER BY head_stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(crate::authority_commit::stream_key(stream)?)
    .get_result::<CutRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if known.is_none_or(|known| {
        known.head_stream_position != i64::try_from(head.stream_position).unwrap_or(-1)
            || known.head_commit_id != head.commit_id.as_str()
    }) {
        return Ok(None);
    }
    let mut entries = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let Some(row) = diesel::sql_query(
            "SELECT jsonb_build_object('selector',selector,'source_stream_ref',source_stream_ref, \
             'revision',jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position), \
             'value',value) AS entry_json FROM replica_authorization_rows WHERE realm_id=$1 AND selector=$2",
        )
        .bind::<Text, _>(realm.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(selector).map_err(invalid)?)
        .get_result::<CurrentEvidenceRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        else {
            return Ok(None);
        };
        let entry: CurrentState = serde_json::from_value(row.entry_json).map_err(invalid)?;
        let CurrentState::Value {
            selector: found,
            source_stream_ref,
            revision,
            ..
        } = &entry;
        if found != selector
            || source_stream_ref != stream
            || revision.stream_position > head.stream_position
            || (revision.stream_position == head.stream_position
                && revision.commit_id != head.commit_id)
        {
            return Ok(None);
        }
        if circle_selector(selector) && !circle_entry_proved(conn, realm, &entry).await? {
            return Ok(None);
        }
        entries.push(entry);
    }
    Ok(Some((head, entries)))
}

/// Complete authorization inputs at the latest verified held Realm cut.
/// Unknown coverage is unavailable, never an empty grant set.
pub(crate) async fn authorization_evidence(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<Option<Vec<CurrentState>>> {
    let rows = diesel::sql_query(
        "SELECT selector,value FROM replica_authorization_rows WHERE realm_id=$1 \
         AND selector->>'kind' IN ('realm_authority_root','realm_policy_bundle','capability_grant') \
         ORDER BY selector::text",
    )
    .bind::<Text, _>(realm.as_str())
    .load::<StoredRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let selectors = rows
        .into_iter()
        .map(|row| serde_json::from_value::<CurrentSelector>(row.selector).map_err(invalid))
        .collect::<PersistenceResult<Vec<_>>>()?;
    if !selectors.contains(&CurrentSelector::RealmAuthorityRoot)
        || !selectors.contains(&CurrentSelector::RealmPolicyBundle)
    {
        return Ok(None);
    }
    Ok(exact_current_evidence(
        conn,
        &arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        },
        &selectors,
    )
    .await?
    .map(|(_, rows)| rows))
}

/// Point reads from the verified native prefix; unrelated object and message
/// rows are neither loaded nor included in the resolver's change fence.
pub(crate) async fn direct_current_evidence(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    pair_key: &arkret_wire::Hash,
    participants: &[ActorId; 2],
) -> PersistenceResult<Option<(arkret_wire::CommitStreamHead, Vec<CurrentState>)>> {
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let mut members = diesel::sql_query(
        "SELECT member_id,current_commit_id,current_stream_position,value \
         FROM member_state_current_states WHERE realm_id=$1 AND member_id IN ($2,$3) \
         ORDER BY member_id",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(participants[0].to_string())
    .bind::<Text, _>(participants[1].to_string())
    .load::<MemberEvidenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if members.len() != 2 {
        return Ok(None);
    }
    // One witness is enough to prove that the immutable pair is no longer
    // the complete joined roster. The existing membership index bounds it.
    let additional = diesel::sql_query(
        "SELECT member_id,current_commit_id,current_stream_position,value \
         FROM member_state_current_states WHERE realm_id=$1 AND membership='join' \
         AND member_id NOT IN ($2,$3) ORDER BY member_id LIMIT 1",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(participants[0].to_string())
    .bind::<Text, _>(participants[1].to_string())
    .get_result::<MemberEvidenceRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    members.extend(additional);
    members.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    let mut selectors = vec![
        CurrentSelector::DirectConversationBinding {
            pair_key: pair_key.clone(),
        },
        CurrentSelector::MlsGroup {
            scope_ref: ScopeRef::Realm {
                realm_id: realm.clone(),
            },
        },
    ];
    for member in &members {
        selectors.push(CurrentSelector::MemberState {
            actor_id: serde_json::from_str(&member.member_id).map_err(invalid)?,
        });
    }
    let Some((head, entries)) = exact_current_evidence(conn, &stream, &selectors).await? else {
        return Ok(None);
    };
    for entry in &entries {
        let CurrentState::Value {
            selector: found,
            revision,
            value,
            ..
        } = entry;
        if let CurrentSelector::MemberState { actor_id } = found {
            let member = members
                .iter()
                .find(|member| member.member_id == actor_id.to_string())
                .ok_or_else(|| invalid("selected member is outside the bounded roster"))?;
            let _: arkret_wire::MemberStateValue =
                serde_json::from_value(value.clone()).map_err(invalid)?;
            if member.current_commit_id != revision.commit_id.as_str()
                || u64::try_from(member.current_stream_position).ok()
                    != Some(revision.stream_position)
                || member.value != *value
            {
                return Ok(None);
            }
        }
    }
    Ok(Some((head, entries)))
}

#[cfg(test)]
mod direct_evidence_tests {
    use super::*;
    use crate::test_database::TestDatabase;
    use crate::{RunQueryDsl, pg_conn};

    #[tokio::test]
    async fn bounded_direct_cut_ignores_other_objects_and_detects_roster_and_prefix_changes() {
        let database = TestDatabase::lease().await;
        let mut conn = pg_conn(&database.pool()).await.unwrap();
        let genesis =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]);
        let realm = RealmId::from_event_id(&genesis);
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let key = crate::authority_commit::stream_key(&stream).unwrap();
        let commit = arkret_wire::RealmCommitId::from_digest([2; 32]);
        let next_commit = arkret_wire::RealmCommitId::from_digest([3; 32]);
        let pair_key =
            arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"bounded pair")).unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let actor = |name: &str| {
            ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
                station.clone(),
            ))
        };
        let pair = [actor("alice"), actor("bob")];
        let mut head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            commit_id: commit.clone(),
            stream_position: 0,
        };
        let at = chrono::Utc::now();
        // This is a storage read fixture, not a signed MLS/product fixture.
        diesel::sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,governance_generation,commit_json,committed_at) VALUES($1,$2,$3,$4,0,0,'{}',$5)")
            .bind::<Text,_>(commit.as_str()).bind::<Text,_>(realm.as_str()).bind::<Text,_>(&key)
            .bind::<Jsonb,_>(serde_json::to_value(&stream).unwrap()).bind::<Timestamptz,_>(at)
            .execute(&mut *conn).await.unwrap();
        let entry = |selector: CurrentSelector, value: serde_json::Value| CurrentState::Value {
            selector,
            source_stream_ref: stream.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: commit.clone(),
                stream_position: 0,
            },
            value,
        };
        for selector in [
            CurrentSelector::DirectConversationBinding {
                pair_key: pair_key.clone(),
            },
            CurrentSelector::MlsGroup {
                scope_ref: ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
            },
        ] {
            save_row(
                &mut conn,
                &realm,
                &entry(selector, serde_json::json!({})),
                at,
            )
            .await
            .unwrap();
        }
        for member in &pair {
            let value = serde_json::json!({"membership":"join"});
            save_row(
                &mut conn,
                &realm,
                &entry(
                    CurrentSelector::MemberState {
                        actor_id: member.clone(),
                    },
                    value.clone(),
                ),
                at,
            )
            .await
            .unwrap();
            diesel::sql_query("INSERT INTO member_state_current_states(realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,'join',$3,0,$4,$5)")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(member.to_string()).bind::<Text,_>(commit.as_str())
                .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(at).execute(&mut *conn).await.unwrap();
        }
        assert!(
            direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
                .await
                .unwrap()
                .is_none()
        );
        install_verified_head(&mut conn, &head, at).await.unwrap();
        let (_, original) = direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original.len(), 4);
        let original_cut = coland_storage::DirectConversationReplicaCut {
            authority: coland_storage::CurrentRealmAuthority {
                realm_id: realm.clone(),
                generation: 0,
                service_id: station.clone(),
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis),
                last_handoff_ref: None,
            },
            head: head.clone(),
            current_state_entries: original.clone(),
        };
        // A malformed unrelated selector/value must never be read or decoded.
        diesel::sql_query("INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) SELECT $1,jsonb_build_object('unrelated_topic',n),$2,$3,0,'null',$4 FROM generate_series(1,1000) n")
            .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(&stream).unwrap())
            .bind::<Text,_>(commit.as_str()).bind::<Timestamptz,_>(at).execute(&mut *conn).await.unwrap();
        assert_eq!(
            direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
                .await
                .unwrap()
                .unwrap()
                .1,
            original
        );
        diesel::sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,governance_generation,commit_json,committed_at) VALUES($1,$2,$3,$4,1,$5,0,'{}',$6)")
            .bind::<Text,_>(next_commit.as_str()).bind::<Text,_>(realm.as_str()).bind::<Text,_>(&key)
            .bind::<Jsonb,_>(serde_json::to_value(&stream).unwrap()).bind::<Text,_>(commit.as_str()).bind::<Timestamptz,_>(at)
            .execute(&mut *conn).await.unwrap();
        assert!(
            direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
                .await
                .unwrap()
                .is_none()
        );
        head.commit_id = next_commit;
        head.stream_position = 1;
        install_verified_head(&mut conn, &head, at).await.unwrap();
        let advanced_cut = coland_storage::DirectConversationReplicaCut {
            head: head.clone(),
            ..original_cut.clone()
        };
        assert!(advanced_cut.retains_resolver_facts(&original_cut));
        assert!(!original_cut.retains_resolver_facts(&advanced_cut));
        let mut replaced_cut = advanced_cut.clone();
        let CurrentState::Value { revision, .. } = &mut replaced_cut.current_state_entries[0];
        revision.commit_id = head.commit_id.clone();
        revision.stream_position = head.stream_position;
        assert!(!replaced_cut.retains_resolver_facts(&original_cut));
        replaced_cut = advanced_cut;
        replaced_cut.authority.generation += 1;
        assert!(!replaced_cut.retains_resolver_facts(&original_cut));
        assert_eq!(
            direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
                .await
                .unwrap()
                .unwrap()
                .1,
            original
        );
        let third = actor("charlie");
        let value = serde_json::json!({"membership":"join"});
        diesel::sql_query("INSERT INTO member_state_current_states(realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,'join',$3,0,$4,$5)")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(third.to_string()).bind::<Text,_>(commit.as_str())
            .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(at).execute(&mut *conn).await.unwrap();
        assert!(
            direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
                .await
                .unwrap()
                .is_none()
        );
        save_row(
            &mut conn,
            &realm,
            &entry(
                CurrentSelector::MemberState {
                    actor_id: third.clone(),
                },
                value,
            ),
            at,
        )
        .await
        .unwrap();
        let (_, extended) = direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(extended.len(), 5);
        assert!(extended.iter().any(|entry| matches!(entry,CurrentState::Value { selector:CurrentSelector::MemberState { actor_id },.. } if actor_id==&third)));
        let mut bad = entry(
            CurrentSelector::MemberState {
                actor_id: pair[0].clone(),
            },
            serde_json::json!({"membership":"leave"}),
        );
        // A real successor has its own revision, even when testing a bad roster.
        let CurrentState::Value { revision, .. } = &mut bad;
        revision.commit_id = head.commit_id.clone();
        revision.stream_position = 1;
        save_row(&mut conn, &realm, &bad, at).await.unwrap();
        assert!(
            direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
                .await
                .unwrap()
                .is_none()
        );
        let CurrentState::Value {
            source_stream_ref,
            value,
            ..
        } = &mut bad;
        *value = serde_json::json!({"membership":"join"});
        *source_stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [4; 32],
            )),
        };
        // Foreign source injection is refused by the verified installation boundary.
        assert!(save_row(&mut conn, &realm, &bad, at).await.is_err());
        let CurrentState::Value {
            source_stream_ref,
            revision,
            ..
        } = &mut bad;
        *source_stream_ref = stream;
        revision.stream_position = 2;
        save_row(&mut conn, &realm, &bad, at).await.unwrap();
        assert!(
            direct_current_evidence(&mut conn, &realm, &pair_key, &pair)
                .await
                .unwrap()
                .is_none()
        );
        let store = crate::authority_commit::PgAuthorityCommitStore {
            pool: database.pool(),
        };
        use coland_storage::AuthorityCommitStore as _;
        assert!(
            store
                .direct_conversation_replica_cut(
                    &realm,
                    actor("outsider").as_account_id().unwrap(),
                    &pair_key,
                    &pair
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .direct_conversation_replica_cut(
                    &realm,
                    pair[0].as_account_id().unwrap(),
                    &pair_key,
                    &pair
                )
                .await
                .is_err()
        );
    }
}

/// Exact current evidence retained by verified bootstrap and contiguous
/// replica folding. A stale or unverified stream cannot prove a missing
/// historical Commit, and its row is excluded rather than reconstructed.
pub(crate) async fn snapshot_current_evidence(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    heads: &[arkret_wire::CommitStreamHead],
) -> PersistenceResult<Vec<CurrentState>> {
    let rows = diesel::sql_query(
        "SELECT jsonb_build_object('selector',selector,'source_stream_ref',source_stream_ref, \
         'revision',jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position), \
         'value',value) AS entry_json FROM replica_authorization_rows WHERE realm_id=$1",
    ).bind::<Text, _>(realm.as_str()).load::<CurrentEvidenceRow>(conn)
        .await.map_err(PersistenceError::database)?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut verified = BTreeSet::new();
    for head in heads {
        if verified_head(conn, &head.stream_ref).await?.as_ref() == Some(head) {
            verified.insert(head.stream_ref.clone());
        }
    }
    let mut entries = Vec::new();
    for row in rows {
        let entry: CurrentState = serde_json::from_value(row.entry_json).map_err(invalid)?;
        let CurrentState::Value {
            source_stream_ref,
            revision,
            ..
        } = &entry;
        if source_stream_ref.realm_id() != realm {
            return Err(invalid("current evidence belongs to another Realm"));
        }
        let CurrentState::Value { selector, .. } = &entry;
        if verified.contains(source_stream_ref)
            && (!circle_selector(selector) || circle_entry_proved(conn, realm, &entry).await?)
            && heads.iter().any(|head| {
                &head.stream_ref == source_stream_ref
                    && (revision.stream_position < head.stream_position
                        || (revision.stream_position == head.stream_position
                            && revision.commit_id == head.commit_id))
            })
        {
            entries.push(entry);
        }
    }
    Ok(entries)
}

pub(crate) async fn install_verified_head(
    conn: &mut AsyncPgConnection,
    head: &arkret_wire::CommitStreamHead,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if let Some(previous) = verified_head(conn, &head.stream_ref).await?
        && (previous.stream_position > head.stream_position
            || (previous.stream_position == head.stream_position
                && previous.commit_id != head.commit_id))
    {
        return Err(invalid(
            "snapshot regresses an already verified authorization cut",
        ));
    }
    diesel::sql_query("INSERT INTO replica_authorization_cuts (realm_id,source_stream_ref,head_commit_id,head_stream_position,verified_at,circle_effect_base_commit_id,circle_effect_base_stream_position,circle_continuation_id) VALUES($1,$2,$3,$4,$5,$3,$4,$6::uuid) ON CONFLICT(realm_id,source_stream_ref) DO UPDATE SET head_commit_id=EXCLUDED.head_commit_id,head_stream_position=EXCLUDED.head_stream_position,verified_at=EXCLUDED.verified_at, circle_effect_base_commit_id=CASE WHEN replica_authorization_cuts.head_commit_id=EXCLUDED.head_commit_id AND replica_authorization_cuts.head_stream_position=EXCLUDED.head_stream_position AND replica_authorization_cuts.circle_continuation_id IS NOT NULL THEN replica_authorization_cuts.circle_effect_base_commit_id ELSE EXCLUDED.circle_effect_base_commit_id END, circle_effect_base_stream_position=CASE WHEN replica_authorization_cuts.head_commit_id=EXCLUDED.head_commit_id AND replica_authorization_cuts.head_stream_position=EXCLUDED.head_stream_position AND replica_authorization_cuts.circle_continuation_id IS NOT NULL THEN replica_authorization_cuts.circle_effect_base_stream_position ELSE EXCLUDED.circle_effect_base_stream_position END, circle_continuation_id=CASE WHEN replica_authorization_cuts.head_commit_id=EXCLUDED.head_commit_id AND replica_authorization_cuts.head_stream_position=EXCLUDED.head_stream_position AND replica_authorization_cuts.circle_continuation_id IS NOT NULL THEN replica_authorization_cuts.circle_continuation_id ELSE EXCLUDED.circle_continuation_id END")
        .bind::<Text, _>(head.stream_ref.realm_id().as_str()).bind::<Jsonb, _>(serde_json::to_value(&head.stream_ref).map_err(invalid)?).bind::<Text, _>(head.commit_id.as_str()).bind::<BigInt, _>(i64::try_from(head.stream_position).map_err(invalid)?).bind::<Timestamptz, _>(at).bind::<Text,_>(uuid::Uuid::new_v4().to_string()).execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn advance_verified_head(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Segment {
        #[diesel(sql_type=Text)]
        head_commit_id: String,
        #[diesel(sql_type=BigInt)]
        head_stream_position: i64,
        #[diesel(sql_type=diesel::sql_types::Nullable<Text>)]
        continuation_id: Option<String>,
    }
    let Some(segment) = diesel::sql_query("SELECT head_commit_id,head_stream_position,circle_continuation_id::text AS continuation_id FROM replica_authorization_cuts WHERE realm_id=$1 AND source_stream_ref=$2")
        .bind::<Text,_>(commit.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).map_err(invalid)?)
        .get_result::<Segment>(&mut *conn).await.optional().map_err(PersistenceError::database)? else {
        return Ok(());
    };
    let previous = arkret_wire::CommitStreamHead {
        stream_ref: commit.stream_ref.clone(),
        commit_id: segment.head_commit_id.parse().map_err(invalid)?,
        stream_position: u64::try_from(segment.head_stream_position).map_err(invalid)?,
    };
    if commit.stream_position <= previous.stream_position {
        return Ok(());
    }
    if commit.previous_commit_ref.as_ref() != Some(&previous.commit_id)
        || commit.stream_position != previous.stream_position + 1
    {
        return Err(invalid("authorization cut tail is not contiguous"));
    }
    // Advancing a materialized direct successor preserves its segment. It is
    // not a qualified snapshot and cannot create a new observation segment.
    let changed = diesel::sql_query("UPDATE replica_authorization_cuts SET head_commit_id=$3,head_stream_position=$4,verified_at=$5 WHERE realm_id=$1 AND source_stream_ref=$2 AND head_commit_id=$6 AND head_stream_position=$7 AND circle_continuation_id IS NOT DISTINCT FROM $8::uuid")
        .bind::<Text,_>(commit.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).map_err(invalid)?)
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(invalid)?)
        .bind::<Timestamptz,_>(commit.committed_at).bind::<Text,_>(previous.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(previous.stream_position).map_err(invalid)?)
        .bind::<diesel::sql_types::Nullable<Text>,_>(segment.continuation_id)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(invalid(
            "authorization cut changed during successor projection",
        ));
    }
    Ok(())
}

pub(crate) fn circle_selector(selector: &CurrentSelector) -> bool {
    matches!(
        selector,
        CurrentSelector::Circle { .. } | CurrentSelector::CircleMemberState { .. }
    )
}

/// Compare only two revisions of the same Realm parent stream. An older
/// cache cannot refute a newer signed parent binding; a same-position fork
/// is unavailable rather than a normal membership withdrawal.
pub(crate) async fn parent_binding_superseded(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    actor: &ActorId,
    bound: &arkret_wire::CurrentRevision,
) -> PersistenceResult<Option<bool>> {
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let selector = CurrentSelector::MemberState {
        actor_id: actor.clone(),
    };
    #[derive(diesel::QueryableByName)]
    struct ActualRole {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        is_native: bool,
    }
    let role = diesel::sql_query("SELECT service_id=current_device_inventory_station() AS is_native FROM realm_authorities WHERE realm_id=$1 AND current_device_inventory_station() IS NOT NULL")
        .bind::<Text,_>(realm.as_str()).get_result::<ActualRole>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(role) = role else {
        return Ok(None);
    };
    let current = if role.is_native {
        diesel::sql_query("SELECT jsonb_build_object('selector',jsonb_build_object('kind','member_state','actor_id',$2::jsonb),'source_stream_ref',c.stream_ref,'revision',jsonb_build_object('commit_id',m.current_commit_id,'stream_position',m.current_stream_position),'value',m.value) AS entry_json FROM member_state_current_states m JOIN realm_authorities a ON a.realm_id=m.realm_id AND a.service_id=current_device_inventory_station() JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position AND c.stream_ref=$3 JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE m.realm_id=$1 AND m.member_id=$4")
            .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(actor).map_err(invalid)?)
            .bind::<Jsonb,_>(serde_json::to_value(&stream).map_err(invalid)?).bind::<Text,_>(actor.to_string())
            .get_result::<CurrentEvidenceRow>(conn).await.optional().map_err(PersistenceError::database)?
            .map(|row| serde_json::from_value(row.entry_json).map_err(invalid)).transpose()?
    } else {
        exact_current_evidence(conn, &stream, &[selector])
            .await?
            .and_then(|(_, parents)| parents.into_iter().next())
    };
    let Some(CurrentState::Value {
        revision, value, ..
    }) = current
    else {
        return Ok(None);
    };
    #[derive(diesel::QueryableByName)]
    struct ParentProjection {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        present: bool,
    }
    let agrees = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM member_state_current_states WHERE realm_id=$1 AND member_id=$2 AND current_commit_id=$3 AND current_stream_position=$4 AND value=$5) AS present")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(actor.to_string()).bind::<Text,_>(revision.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(revision.stream_position).map_err(invalid)?).bind::<Jsonb,_>(&value)
        .get_result::<ParentProjection>(conn).await.map_err(PersistenceError::database)?.present;
    if !agrees {
        return Ok(None);
    }
    let parent: arkret_wire::MemberStateValue = serde_json::from_value(value).map_err(invalid)?;
    if revision.stream_position < bound.stream_position {
        return Ok(None);
    }
    if revision.stream_position > bound.stream_position {
        return Ok(Some(true));
    }
    if revision.commit_id != bound.commit_id
        || parent.membership != arkret_wire::MembershipState::Join
    {
        return Err(PersistenceError::Conflict(format!(
            "{}: observed parent conflicts with the signed Circle binding",
            coland_storage::ConflictCode::TemporarilyUnavailable
        )));
    }
    Ok(Some(false))
}

pub(crate) async fn circle_entry_proved(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    entry: &CurrentState,
) -> PersistenceResult<bool> {
    #[derive(diesel::QueryableByName)]
    struct Proof {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        present: bool,
    }
    let CurrentState::Value {
        selector,
        source_stream_ref,
        revision,
        value,
    } = entry;
    Ok(
        diesel::sql_query("SELECT circle_current_row_proved($1,$2,$3,$4,$5,$6) AS present")
            .bind::<Text, _>(realm.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(selector).map_err(invalid)?)
            .bind::<Jsonb, _>(serde_json::to_value(source_stream_ref).map_err(invalid)?)
            .bind::<Text, _>(revision.commit_id.as_str())
            .bind::<BigInt, _>(i64::try_from(revision.stream_position).map_err(invalid)?)
            .bind::<Jsonb, _>(value)
            .get_result::<Proof>(conn)
            .await
            .map_err(PersistenceError::database)?
            .present,
    )
}

pub(crate) async fn invalidate_circle_continuation(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<()> {
    diesel::sql_query("UPDATE replica_authorization_cuts SET circle_effect_base_commit_id=NULL,circle_effect_base_stream_position=NULL,circle_continuation_id=NULL WHERE realm_id=$1 AND circle_continuation_id IS NOT NULL")
        .bind::<Text,_>(realm.as_str()).execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
