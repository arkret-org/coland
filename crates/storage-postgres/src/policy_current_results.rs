//! Same-cut semantic checks and RealmCommit-bound Policy current writers.
use arkret_models_collaboration::events_payloads::{PolicyActionStatePayload, PolicyActionSubject};
use arkret_models_collaboration::governance::operation_wire::{
    PolicySetStatePayload, PolicySetValue,
};
use arkret_wire::{
    CapabilityActionId, CommitStreamRef, CurrentRevision, Event, EventKind, PolicyKind,
    RealmCommit, WireResourceSelector,
};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

#[derive(QueryableByName)]
struct Stored {
    #[diesel(sql_type=Text)]
    realm_id: String,
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct PolicyRevisionRow {
    #[diesel(sql_type=Text)]
    realm_id: String,
    #[diesel(sql_type=Text)]
    current_commit_id: String,
    #[diesel(sql_type=BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type=Text)]
    current_event_id: String,
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct Present {
    #[diesel(sql_type=Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct ManagementPolicyRow {
    #[diesel(sql_type=Text)]
    policy_id: String,
    #[diesel(sql_type=Text)]
    realm_id: String,
    #[diesel(sql_type=Text)]
    current_commit_id: String,
    #[diesel(sql_type=BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type=Text)]
    current_event_id: String,
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct ManagementPolicyHistory {
    #[diesel(sql_type=Text)]
    policy_id: String,
    #[diesel(sql_type=Text)]
    realm_id: String,
    #[diesel(sql_type=Text)]
    current_commit_id: String,
    #[diesel(sql_type=BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type=Text)]
    current_event_id: String,
    #[diesel(sql_type=Jsonb)]
    source_stream: Value,
    #[diesel(sql_type=Jsonb)]
    event_scope: Value,
    #[diesel(sql_type=diesel::sql_types::Nullable<Jsonb>)]
    expected_revision: Option<Value>,
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

/// Governing admission only, under the shared Realm lock. Replica-held prefixes
/// cannot establish authoritative absence of a management Policy.
#[cfg(test)]
async fn read_agent_management_policies_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<Vec<arkret_models_collaboration::governance::operation_wire::Policy>> {
    read_scoped_agent_management_policies_in_connection(conn, realm, None).await
}

/// Parent Realm and the operation's actual Circle are applicable layers. Strand
/// selectors narrow their rules; they do not create a protocol ScopeRef.
pub(crate) async fn read_scoped_agent_management_policies_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    circle: Option<&arkret_wire::CircleId>,
) -> PersistenceResult<Vec<arkret_models_collaboration::governance::operation_wire::Policy>> {
    Box::pin(read_scoped_agent_management_policies_at_cut(
        conn, realm, circle, true,
    ))
    .await
}

/// Governing visibility from an enclosing repeatable-read transaction. This is
/// not an authorization result reusable at a later delivery point.
pub(crate) async fn read_scoped_agent_management_policy_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    circle: Option<&arkret_wire::CircleId>,
) -> PersistenceResult<Vec<arkret_models_collaboration::governance::operation_wire::Policy>> {
    read_scoped_agent_management_policies_at_cut(conn, realm, circle, false).await
}

fn management_source(
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
) -> PersistenceResult<CommitStreamRef> {
    let source = CommitStreamRef::from_scope(scope, None).map_err(schema)?;
    if source.realm_id() != realm
        || !matches!(
            source,
            CommitStreamRef::Realm { .. } | CommitStreamRef::Circle { .. }
        )
    {
        return Err(refused(
            "Management Policy has unresolved governance evidence",
        ));
    }
    Ok(source)
}

fn policy_revision(row: &ManagementPolicyHistory) -> PersistenceResult<CurrentRevision> {
    Ok(CurrentRevision {
        commit_id: row.current_commit_id.parse().map_err(schema)?,
        stream_position: u64::try_from(row.current_stream_position).map_err(schema)?,
    })
}

/// Accepted writes define a CAS chain, not a total order across streams. Every
/// accepted node must occur once in the unique chain ending at typed current.
fn management_chain<'a>(
    rows: &'a [ManagementPolicyHistory],
    realm: &arkret_wire::RealmId,
    kind: &PolicyKind,
) -> PersistenceResult<Vec<&'a ManagementPolicyHistory>> {
    use std::collections::{BTreeMap, BTreeSet};
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut by_revision = BTreeMap::new();
    let mut children = BTreeMap::new();
    let mut events = BTreeSet::new();
    let mut predecessors = Vec::new();
    let mut first = None;
    for (index, row) in rows.iter().enumerate() {
        let document: PolicySetValue = serde_json::from_value(row.value.clone()).map_err(schema)?;
        document.validate().map_err(schema)?;
        if !matches!(document, PolicySetValue::Governance(ref policy)
            if &policy.policy_kind == kind && policy.id.as_str() == row.policy_id
                && policy.realm_id.as_ref() == Some(realm))
            || row.realm_id != realm.as_str()
            || row.policy_id != rows[0].policy_id
        {
            return Err(refused("Management Policy id, Realm or family changed"));
        }
        let scope: arkret_wire::ScopeRef =
            serde_json::from_value(row.event_scope.clone()).map_err(schema)?;
        let source = management_source(realm, &scope)?;
        if serde_json::to_value(source).map_err(schema)? != row.source_stream {
            return Err(refused(
                "Management Policy has unresolved governance evidence",
            ));
        }
        let revision = policy_revision(row)?;
        let key = (revision.commit_id.to_string(), revision.stream_position);
        if by_revision.insert(key, index).is_some() || !events.insert(row.current_event_id.clone())
        {
            return Err(refused("Management Policy accepted pointer is duplicated"));
        }
        let expected: Option<CurrentRevision> = serde_json::from_value(
            row.expected_revision
                .clone()
                .ok_or_else(|| refused("Accepted management Policy omitted expected_revision"))?,
        )
        .map_err(schema)?;
        if let Some(previous) = expected {
            let key = (previous.commit_id.to_string(), previous.stream_position);
            if children.insert(key.clone(), index).is_some() {
                return Err(refused("Management Policy accepted CAS chain is forked"));
            }
            predecessors.push(Some(key));
        } else {
            if first.replace(index).is_some() {
                return Err(refused("Management Policy has multiple first writes"));
            }
            predecessors.push(None);
        }
    }
    let mut index =
        first.ok_or_else(|| refused("Management Policy first-write evidence is unavailable"))?;
    let mut visited = BTreeSet::new();
    let mut chain = Vec::new();
    loop {
        if !visited.insert(index) {
            return Err(refused("Management Policy accepted CAS chain is cyclic"));
        }
        let row = &rows[index];
        chain.push(row);
        let revision = policy_revision(row)?;
        let key = (revision.commit_id.to_string(), revision.stream_position);
        let Some(next) = children.get(&key) else {
            break;
        };
        index = *next;
    }
    if chain.len() != rows.len()
        || predecessors
            .iter()
            .flatten()
            .any(|key| !by_revision.contains_key(key))
    {
        return Err(refused(
            "Management Policy accepted CAS chain is incomplete",
        ));
    }
    let mut stream_positions = BTreeMap::new();
    for row in &chain {
        let source: CommitStreamRef =
            serde_json::from_value(row.source_stream.clone()).map_err(schema)?;
        if stream_positions
            .insert(source, row.current_stream_position)
            .is_some_and(|previous| previous >= row.current_stream_position)
        {
            return Err(refused(
                "Management Policy chain reverses an individual stream",
            ));
        }
    }
    Ok(chain)
}

fn current_matches_history(row: &ManagementPolicyRow, accepted: &ManagementPolicyHistory) -> bool {
    row.realm_id == accepted.realm_id
        && row.current_commit_id == accepted.current_commit_id
        && row.current_stream_position == accepted.current_stream_position
        && row.current_event_id == accepted.current_event_id
        && row.value == accepted.value
}

async fn require_complete_policy_stream(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    source: &CommitStreamRef,
    head: Option<&CurrentRevision>,
) -> PersistenceResult<()> {
    let source_json = serde_json::to_value(source).map_err(schema)?;
    let complete = sql_query(
        "WITH nodes AS (SELECT c.*,e.state,e.kind AS event_kind,e.realm_id AS event_realm,e.envelope, \
         ROW_NUMBER() OVER (ORDER BY c.stream_position)-1 AS expected_position, \
         LAG(c.commit_id) OVER (ORDER BY c.stream_position) AS predecessor \
         FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_ref=$2) \
         SELECT COALESCE(BOOL_AND(COALESCE(stream_position=expected_position \
         AND previous_commit_ref IS NOT DISTINCT FROM predecessor AND state='committed' \
         AND event_realm=$1 AND envelope->>'kind'=event_kind \
         AND commit_json->>'commit_id'=commit_id AND commit_json->>'realm_id'=$1 \
         AND commit_json->'stream_ref'=stream_ref \
         AND commit_json->>'stream_position'=stream_position::text \
         AND commit_json->>'previous_commit_ref' IS NOT DISTINCT FROM previous_commit_ref \
         AND commit_json->>'event_ref'=envelope->>'event_id' \
         AND ((stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND stream_position=0 \
               AND event_kind='ak.realm.create' AND NOT (envelope ? 'realm_id') \
               AND envelope->'scope_ref'=jsonb_build_object('kind','realm_genesis')) \
              OR (envelope->>'realm_id'=$1 AND envelope->'scope_ref'=stream_ref AND NOT \
                  (stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND stream_position=0))),false)) \
         AND MIN(stream_position)=0 AND ($3 IS NULL OR \
             (MAX(stream_position)=$3 AND BOOL_OR(stream_position=$3 AND commit_id=$4))),false) \
         OR (COUNT(*)=0 AND $3 IS NULL AND $2->>'kind'='circle' AND EXISTS(SELECT 1 \
             FROM circle_current_results cc JOIN realm_commits pc ON pc.realm_id=$1 \
             AND pc.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) \
             JOIN canonical_events pe ON pe.pk=pc.event_pk WHERE cc.circle_id=$2->>'circle_id' \
             AND cc.realm_id=$1 AND cc.value->>'id'=cc.circle_id \
             AND cc.create_event_id=pe.envelope->>'event_id' \
             AND pe.state='committed' AND pe.kind='ak.circle.create' \
             AND pe.envelope->>'event_id'=('ak:event:' || substring(cc.circle_id from 11)))) \
         AS present FROM nodes",
    )
    .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(source_json)
    .bind::<diesel::sql_types::Nullable<BigInt>,_>(head.map(|h| i64::try_from(h.stream_position)).transpose().map_err(schema)?)
    .bind::<diesel::sql_types::Nullable<Text>,_>(head.map(|h| h.commit_id.as_str()))
    .get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !complete {
        return Err(refused(
            "complete Agent management governance history is unavailable",
        ));
    }
    Ok(())
}

const MANAGEMENT_HISTORY_SELECT: &str = "SELECT e.envelope->'payload'->>'policy_id' AS policy_id,c.realm_id, \
    c.commit_id AS current_commit_id,c.stream_position AS current_stream_position, \
    e.envelope->>'event_id' AS current_event_id,c.stream_ref AS source_stream, \
    e.envelope->'scope_ref' AS event_scope,e.envelope->'payload'->'expected_revision' AS expected_revision, \
    e.envelope->'payload'->'value' AS value FROM realm_commits c \
    JOIN canonical_events e ON e.pk=c.event_pk WHERE e.kind='ak.policy.set' AND e.state='committed'";

async fn read_scoped_agent_management_policies_at_cut(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    circle: Option<&arkret_wire::CircleId>,
    lock: bool,
) -> PersistenceResult<Vec<arkret_models_collaboration::governance::operation_wire::Policy>> {
    Ok(
        read_agent_management_policy_domains_at_cut(conn, realm, circle, lock, false)
            .await?
            .into_iter()
            .map(|(policy, _)| policy)
            .collect(),
    )
}

/// Authorization covers future targets as well as current objects. Read every
/// accepted governance carrier at the same Realm cut before checking overlap.
/// The source tuple stays internal; a missing or forged current is never absence.
pub(crate) async fn read_agent_management_authorization_domains_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<
    Vec<(
        arkret_models_collaboration::governance::operation_wire::Policy,
        CommitStreamRef,
    )>,
> {
    read_agent_management_policy_domains_at_cut(conn, realm, None, true, true).await
}

async fn read_agent_management_policy_domains_at_cut(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    circle: Option<&arkret_wire::CircleId>,
    lock: bool,
    all_scopes: bool,
) -> PersistenceResult<
    Vec<(
        arkret_models_collaboration::governance::operation_wire::Policy,
        CommitStreamRef,
    )>,
> {
    use std::collections::{BTreeMap, BTreeSet};
    if lock {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
    } else if !sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_authorities WHERE realm_id=$1) AS present",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<Present>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present
    {
        return Err(refused("the Realm has no current governance authority"));
    }
    let realm_source = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let circle_source = circle.map(|circle_id| CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle_id.clone(),
    });
    require_complete_policy_stream(conn, realm, &realm_source, None).await?;
    if let Some(source) = &circle_source {
        require_complete_policy_stream(conn, realm, source, None).await?;
    }
    let history = sql_query(format!(
        "{MANAGEMENT_HISTORY_SELECT} AND e.envelope->'payload'->>'policy_id' IN \
         (SELECT pe.envelope->'payload'->>'policy_id' FROM realm_commits pc \
          JOIN canonical_events pe ON pe.pk=pc.event_pk WHERE pe.kind='ak.policy.set' AND pe.state='committed' \
          AND (pc.realm_id=$1 OR pe.envelope->'payload'->'value'->>'realm_id'=$1))"
    )).bind::<Text,_>(realm.as_str()).load::<ManagementPolicyHistory>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    let agent_value =
        |value: &Value| value.get("policy_kind").and_then(Value::as_str) == Some("agent");
    let mut ids = BTreeSet::new();
    let mut by_id: BTreeMap<String, Vec<ManagementPolicyHistory>> = BTreeMap::new();
    for row in history {
        if agent_value(&row.value) {
            ids.insert(row.policy_id.clone());
        }
        by_id.entry(row.policy_id.clone()).or_default().push(row);
    }
    let known = ids.iter().cloned().collect::<Vec<_>>();
    let rows = sql_query(format!(
        "SELECT policy_id,realm_id,current_commit_id,current_stream_position,current_event_id,value \
         FROM policy_current_results WHERE realm_id=$1 OR value->>'realm_id'=$1 OR policy_id=ANY($2) \
         ORDER BY policy_id{}", if lock { " FOR SHARE" } else { "" }
    )).bind::<Text,_>(realm.as_str()).bind::<diesel::sql_types::Array<Text>,_>(&known)
        .load::<ManagementPolicyRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut current = BTreeMap::new();
    for row in rows {
        if agent_value(&row.value) {
            ids.insert(row.policy_id.clone());
        }
        current.insert(row.policy_id.clone(), row);
    }
    let mut policies = Vec::new();
    let mut checked = BTreeSet::from([realm_source.clone()]);
    if let Some(source) = &circle_source {
        checked.insert(source.clone());
    }
    for id in ids {
        let chain = management_chain(
            by_id
                .get(&id)
                .ok_or_else(|| refused("Agent Policy current has no accepted history"))?,
            realm,
            &PolicyKind::Agent,
        )?;
        let accepted = chain
            .last()
            .ok_or_else(|| refused("Agent Policy history is unavailable"))?;
        let source: CommitStreamRef =
            serde_json::from_value(accepted.source_stream.clone()).map_err(schema)?;
        let row = current
            .get(&id)
            .ok_or_else(|| refused("accepted Agent Policy current is missing"))?;
        if !current_matches_history(row, accepted) {
            return Err(refused(
                "Agent Policy current differs from its last accepted write",
            ));
        }
        // A policy currently carried by another Circle is not a parent policy.
        if !all_scopes && source != realm_source && Some(&source) != circle_source.as_ref() {
            continue;
        }
        for node in &chain {
            let source: CommitStreamRef =
                serde_json::from_value(node.source_stream.clone()).map_err(schema)?;
            if checked.insert(source.clone()) {
                require_complete_policy_stream(conn, realm, &source, None).await?;
            }
        }
        let PolicySetValue::Governance(policy) =
            serde_json::from_value(row.value.clone()).map_err(schema)?
        else {
            return Err(refused("Agent Policy binding or family changed"));
        };
        policies.push((*policy, source));
    }
    Ok(policies)
}

/// Resolve immutable object governance scope from its accepted creation, not a
/// service-local hint. The current revision must still have a committed source;
/// the immutable Realm/Circle binding must equal the whole creation carrier.
pub(crate) async fn authorization_object_scope_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    selector: &WireResourceSelector,
) -> PersistenceResult<Option<arkret_wire::ScopeRef>> {
    let (table, column, id, event_id, kind) = match selector.kind {
        arkret_wire::ResourceSelectorKind::Strand => {
            let Some(id) = &selector.strand_id else {
                return Ok(None);
            };
            (
                "strand_current_results",
                "strand_id",
                id.to_string(),
                format!(
                    "ak:event:{}",
                    id.as_str()
                        .strip_prefix("ak:strand:")
                        .ok_or_else(|| schema("invalid Strand ref"))?
                ),
                EventKind::StrandCreate,
            )
        }
        arkret_wire::ResourceSelectorKind::Space => {
            let Some(id) = &selector.space_id else {
                return Ok(None);
            };
            (
                "space_current_results",
                "space_id",
                id.to_string(),
                format!(
                    "ak:event:{}",
                    id.as_str()
                        .strip_prefix("ak:space:")
                        .ok_or_else(|| schema("invalid Space ref"))?
                ),
                EventKind::SpaceCreate,
            )
        }
        _ => return Ok(None),
    };
    #[derive(QueryableByName)]
    struct ObjectBinding {
        #[diesel(sql_type=Jsonb)]
        value: Value,
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Jsonb)]
        stream: Value,
    }
    let row = sql_query(format!(
        "SELECT obj.value,creation.envelope,origin.stream_ref AS stream FROM {table} obj \
         JOIN realm_commits latest ON latest.realm_id=obj.realm_id AND latest.commit_id=obj.current_commit_id \
           AND latest.stream_position=obj.current_stream_position \
         JOIN canonical_events latest_event ON latest_event.pk=latest.event_pk AND latest_event.state='committed' \
         JOIN canonical_events creation ON creation.realm_id=obj.realm_id AND creation.envelope->>'event_id'=$3 \
           AND creation.kind=$4 AND creation.state='committed' \
         JOIN realm_commits origin ON origin.event_pk=creation.pk AND origin.realm_id=obj.realm_id \
           AND origin.commit_json->>'event_ref'=creation.envelope->>'event_id' \
           AND origin.stream_ref=creation.envelope->'scope_ref' \
         WHERE obj.realm_id=$1 AND obj.{column}=$2 FOR SHARE OF obj"
    )).bind::<Text,_>(realm.as_str()).bind::<Text,_>(&id).bind::<Text,_>(&event_id)
      .bind::<Text,_>(kind.as_str()).get_result::<ObjectBinding>(&mut *conn).await.optional()
      .map_err(PersistenceError::database)?
      .ok_or_else(|| refused("authorization object has no accepted immutable scope"))?;
    let event: Event = serde_json::from_value(row.envelope).map_err(schema)?;
    let scope: arkret_wire::ScopeRef = serde_json::from_value(row.stream).map_err(schema)?;
    let expected_id = match kind {
        EventKind::StrandCreate => {
            arkret_wire::StrandId::from_event_id(&event.event_id).to_string()
        }
        EventKind::SpaceCreate => arkret_wire::SpaceId::from_event_id(&event.event_id).to_string(),
        _ => return Err(schema("unknown creation carrier")),
    };
    let creation = event
        .payload
        .get("object")
        .ok_or_else(|| schema("creation object absent"))?;
    if event.kind != kind
        || event.realm_id != *realm
        || event.scope_ref != scope
        || scope.realm_id_opt() != Some(realm)
        || expected_id != id
        || creation.get("realm_id").and_then(Value::as_str) != Some(realm.as_str())
        || row.value.get("id").and_then(Value::as_str) != Some(id.as_str())
        || row.value.get("realm_id").and_then(Value::as_str) != Some(realm.as_str())
        || row.value.get("scope_circle_id").and_then(Value::as_str)
            != creation.get("scope_circle_id").and_then(Value::as_str)
        || match &scope {
            arkret_wire::ScopeRef::Realm { .. } => creation
                .get("scope_circle_id")
                .is_some_and(|value| !value.is_null()),
            arkret_wire::ScopeRef::Circle { circle_id, .. } => {
                creation.get("scope_circle_id").and_then(Value::as_str) != Some(circle_id.as_str())
            }
            _ => true,
        }
    {
        return Err(refused(
            "authorization object immutable scope differs from accepted source",
        ));
    }
    Ok(Some(scope))
}

pub(crate) enum ManagementPolicyCurrentRead {
    NotFound,
    NeverWritten,
    Present {
        source: CommitStreamRef,
        revision: CurrentRevision,
        payload: PolicySetStatePayload,
        head: Box<arkret_wire::CommitStreamHead>,
    },
}

pub(crate) fn management_policy_scope_target(
    realm: &arkret_wire::RealmId,
    source: &CommitStreamRef,
) -> PersistenceResult<WireResourceSelector> {
    match source {
        CommitStreamRef::Realm { realm_id } if realm_id == realm => {
            Ok(WireResourceSelector::realm(realm_id.clone()))
        }
        CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == realm => Ok(WireResourceSelector::circle(
            realm_id.clone(),
            circle_id.clone(),
        )),
        _ => Err(refused("Management Policy actual scope is unresolved")),
    }
}

/// The exact read and migration authorization share the admission reader's
/// accepted CAS chain. A private projection miss is never NeverWritten.
pub(crate) async fn read_management_policy_exact_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    id: &arkret_wire::PolicyId,
) -> PersistenceResult<ManagementPolicyCurrentRead> {
    let current=sql_query("SELECT realm_id,current_commit_id,current_stream_position,current_event_id,value FROM policy_current_results WHERE policy_id=$1")
        .bind::<Text,_>(id.as_str()).get_result::<PolicyRevisionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let history = sql_query(format!(
        "{MANAGEMENT_HISTORY_SELECT} AND e.envelope->'payload'->>'policy_id'=$1"
    ))
    .bind::<Text, _>(id.as_str())
    .load::<ManagementPolicyHistory>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if current
        .as_ref()
        .is_some_and(|row| row.realm_id != realm.as_str())
        || history.iter().any(|row| row.realm_id != realm.as_str())
    {
        return Ok(ManagementPolicyCurrentRead::NotFound);
    }
    let realm_source = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    if history.is_empty() && current.is_none() {
        let authority = sql_query(
            "SELECT EXISTS(SELECT 1 FROM realm_authorities WHERE realm_id=$1) AS present",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<Present>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present;
        if !authority {
            return Err(refused("Policy governance authority is unavailable"));
        }
        require_complete_policy_stream(conn, realm, &realm_source, None).await?;
        #[derive(QueryableByName)]
        struct Source {
            #[diesel(sql_type=Jsonb)]
            value: Value,
        }
        let sources =
            sql_query("SELECT DISTINCT stream_ref AS value FROM realm_commits WHERE realm_id=$1")
                .bind::<Text, _>(realm.as_str())
                .load::<Source>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
        for source in sources {
            let source: CommitStreamRef = serde_json::from_value(source.value).map_err(schema)?;
            if source.realm_id() != realm {
                return Err(refused("Policy absence has foreign stream evidence"));
            }
            if source != realm_source {
                require_complete_policy_stream(conn, realm, &source, None).await?;
            }
        }
        return Ok(ManagementPolicyCurrentRead::NeverWritten);
    }
    let management_kind = history
        .iter()
        .map(|row| &row.value)
        .chain(current.iter().map(|row| &row.value))
        .find_map(|value| {
            match (
                value.get("schema").and_then(Value::as_str),
                value.get("policy_kind").and_then(Value::as_str),
            ) {
                (Some(arkret_wire::SchemaId::POLICY_V1), Some("agent")) => Some(PolicyKind::Agent),
                (Some(arkret_wire::SchemaId::POLICY_V1), Some("applet")) => {
                    Some(PolicyKind::Applet)
                }
                _ => None,
            }
        });
    let Some(kind) = management_kind else {
        return Ok(ManagementPolicyCurrentRead::NotFound);
    };
    let chain = management_chain(&history, realm, &kind)?;
    let leaf = chain
        .last()
        .ok_or_else(|| refused("Policy current has no accepted history"))?;
    let row =
        current.ok_or_else(|| refused("Policy current is absent despite accepted history"))?;
    if row.realm_id != leaf.realm_id
        || row.current_commit_id != leaf.current_commit_id
        || row.current_stream_position != leaf.current_stream_position
        || row.current_event_id != leaf.current_event_id
        || row.value != leaf.value
    {
        return Err(refused("Policy current differs from accepted history"));
    }
    let mut checked = std::collections::BTreeSet::from([realm_source.clone()]);
    require_complete_policy_stream(conn, realm, &realm_source, None).await?;
    for node in &chain {
        let source: CommitStreamRef =
            serde_json::from_value(node.source_stream.clone()).map_err(schema)?;
        if checked.insert(source.clone()) {
            require_complete_policy_stream(conn, realm, &source, None).await?;
        }
    }
    let source: CommitStreamRef =
        serde_json::from_value(leaf.source_stream.clone()).map_err(schema)?;
    #[derive(QueryableByName)]
    struct Head {
        #[diesel(sql_type=Text)]
        commit_id: String,
        #[diesel(sql_type=BigInt)]
        stream_position: i64,
    }
    let head=sql_query("SELECT commit_id,stream_position FROM realm_commits WHERE realm_id=$1 AND stream_ref=$2 ORDER BY stream_position DESC LIMIT 1")
        .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(&source).map_err(schema)?)
        .get_result::<Head>(&mut *conn).await.map_err(PersistenceError::database)?;
    let payload = PolicySetStatePayload {
        policy_id: id.clone(),
        expected_revision: Some(
            serde_json::from_value(
                leaf.expected_revision
                    .clone()
                    .ok_or_else(|| refused("Policy expected revision is missing"))?,
            )
            .map_err(schema)?,
        ),
        value: serde_json::from_value(leaf.value.clone()).map_err(schema)?,
    };
    payload.validate().map_err(schema)?;
    Ok(ManagementPolicyCurrentRead::Present {
        head: Box::new(arkret_wire::CommitStreamHead {
            stream_ref: source.clone(),
            commit_id: head.commit_id.parse().map_err(schema)?,
            stream_position: u64::try_from(head.stream_position).map_err(schema)?,
        }),
        source,
        revision: policy_revision(leaf)?,
        payload,
    })
}

/// Admission only: replay reducers install accepted history without redoing CAS.
async fn check_policy_cas_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    payload: &PolicySetStatePayload,
) -> PersistenceResult<()> {
    payload.validate().map_err(schema)?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    // Policy ids are global even when two writers hold different Realm locks.
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("policy:{}", payload.policy_id))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    // An accepted byte-identical retry uses its durable result, not today's revision.
    let replay = sql_query("SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.commit_json->>'event_ref'=$2 AND e.state='committed' AND e.envelope=$3) AS present")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(schema)?)
        .get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if replay {
        return Ok(());
    }
    let management_kind = match &payload.value {
        PolicySetValue::Governance(p)
            if matches!(p.policy_kind, PolicyKind::Agent | PolicyKind::Applet) =>
        {
            Some(p.policy_kind.clone())
        }
        _ => None,
    };
    let current = sql_query("SELECT realm_id,current_commit_id,current_stream_position,current_event_id,value FROM policy_current_results WHERE policy_id=$1 FOR UPDATE")
        .bind::<Text,_>(payload.policy_id.as_str()).get_result::<PolicyRevisionRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?;
    if current
        .as_ref()
        .is_some_and(|row| row.realm_id != event.realm_id.as_str())
    {
        return Err(refused("Policy id belongs to another Realm"));
    }
    let was_management = sql_query("SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.state='committed' AND e.kind='ak.policy.set' AND e.envelope->'payload'->>'policy_id'=$1 AND e.envelope->'payload'->'value'->>'schema'='ak.schema.policy.v1' AND e.envelope->'payload'->'value'->>'policy_kind' IN ('agent','applet')) AS present")
        .bind::<Text,_>(payload.policy_id.as_str()).get_result::<Present>(&mut *conn)
        .await.map_err(PersistenceError::database)?.present;
    let current_kind = current.as_ref().and_then(|row| {
        if row.value.get("schema").and_then(Value::as_str) != Some(arkret_wire::SchemaId::POLICY_V1)
        {
            return None;
        }
        match row.value.get("policy_kind").and_then(Value::as_str) {
            Some("agent") => Some(PolicyKind::Agent),
            Some("applet") => Some(PolicyKind::Applet),
            _ => None,
        }
    });
    if management_kind.is_none() {
        return if was_management || current_kind.is_some() {
            Err(refused(
                "Management Policy id cannot change policy kind or family",
            ))
        } else {
            Ok(())
        };
    }
    if current.is_some() && current_kind != management_kind {
        return Err(refused("Management Policy id cannot change policy kind"));
    }
    let source = management_source(&event.realm_id, &event.scope_ref)?;
    if commit.realm_id != event.realm_id
        || commit.stream_ref != source
        || commit.event_ref != event.event_id
    {
        return Err(refused(
            "Management Policy CAS requires its actual governance stream",
        ));
    }
    let realm_source = CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if source != realm_source {
        require_complete_policy_stream(conn, &event.realm_id, &realm_source, None).await?;
    }
    if let Some(position) = commit.stream_position.checked_sub(1) {
        let head = CurrentRevision {
            commit_id: commit
                .previous_commit_ref
                .clone()
                .ok_or_else(|| refused("Management Policy predecessor is unavailable"))?,
            stream_position: position,
        };
        require_complete_policy_stream(conn, &event.realm_id, &source, Some(&head)).await?;
    } else {
        // A new Circle stream may be empty only when its creation is proved in
        // the complete parent Realm; it is not an arbitrary private cache miss.
        if !matches!(source, CommitStreamRef::Circle { .. }) || commit.previous_commit_ref.is_some()
        {
            return Err(refused(
                "Management Policy CAS needs an established governance prefix",
            ));
        }
        require_complete_policy_stream(conn, &event.realm_id, &source, None).await?;
        let occupied = sql_query("SELECT EXISTS(SELECT 1 FROM realm_commits WHERE realm_id=$1 AND stream_ref=$2) AS present")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&source).map_err(schema)?)
            .get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?.present;
        if occupied {
            return Err(refused(
                "Management Policy stream already has accepted history",
            ));
        }
    }
    let history = sql_query(format!(
        "{MANAGEMENT_HISTORY_SELECT} AND e.envelope->'payload'->>'policy_id'=$1"
    ))
    .bind::<Text, _>(payload.policy_id.as_str())
    .load::<ManagementPolicyHistory>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let chain = management_chain(&history, &event.realm_id, management_kind.as_ref().unwrap())?;
    for node in &chain {
        let ancestor_source: CommitStreamRef =
            serde_json::from_value(node.source_stream.clone()).map_err(schema)?;
        if ancestor_source != source && ancestor_source != realm_source {
            require_complete_policy_stream(conn, &event.realm_id, &ancestor_source, None).await?;
        }
    }
    if chain.is_empty() {
        // Known holes in other governing streams cannot prove global id absence.
        let unresolved = sql_query(
            "WITH nodes AS (SELECT c.*,e.state,e.realm_id AS event_realm,e.envelope, \
             ROW_NUMBER() OVER (PARTITION BY c.stream_key ORDER BY c.stream_position)-1 AS expected_position, \
             LAG(c.commit_id) OVER (PARTITION BY c.stream_key ORDER BY c.stream_position) AS predecessor \
             FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1) \
             SELECT EXISTS(SELECT 1 FROM nodes WHERE stream_position<>expected_position \
             OR previous_commit_ref IS DISTINCT FROM predecessor OR state IS DISTINCT FROM 'committed' \
             OR event_realm IS DISTINCT FROM $1 OR commit_json->>'event_ref' IS DISTINCT FROM envelope->>'event_id') AS present"
        ).bind::<Text,_>(event.realm_id.as_str()).get_result::<Present>(&mut *conn)
            .await.map_err(PersistenceError::database)?.present;
        if unresolved {
            return Err(refused(
                "Policy absence has unresolved sibling stream evidence",
            ));
        }
    }
    match (&current, chain.last()) {
        (None, None) => {}
        (Some(row), Some(accepted))
            if row.realm_id == accepted.realm_id
                && row.current_commit_id == accepted.current_commit_id
                && row.current_stream_position == accepted.current_stream_position
                && row.current_event_id == accepted.current_event_id
                && row.value == accepted.value => {}
        _ => {
            return Err(refused(
                "Policy current does not match its last accepted write",
            ));
        }
    }
    let revision = chain.last().map(|row| policy_revision(row)).transpose()?;
    if payload.expected_revision.as_ref() != Some(&revision) {
        return Err(refused(
            "Management Policy expected_revision differs from current",
        ));
    }
    Ok(())
}
fn schema(e: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(e.to_string())
}
fn refused(e: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {e}"))
}
fn require_supported_policy(
    document: &arkret_models_collaboration::governance::operation_wire::Policy,
    scope: &arkret_wire::ScopeRef,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::operation_wire::{
        AgentPolicyOperation, PolicyResourceKind, PolicyRuleKind,
    };
    use arkret_wire::PolicyEffect;

    if document.policy_kind == PolicyKind::Applet {
        return Err(refused(
            "Applet management execution and delivery gates are not established",
        ));
    }
    if document.policy_kind != PolicyKind::Agent {
        return Ok(());
    }
    document.validate().map_err(schema)?;
    if !matches!(scope,
        arkret_wire::ScopeRef::Realm { realm_id }
        | arkret_wire::ScopeRef::Circle { realm_id, .. }
        if document.realm_id.as_ref() == Some(realm_id))
    {
        return Err(refused(
            "Agent management Policy has no registered governance scope",
        ));
    }
    let circle = matches!(scope, arkret_wire::ScopeRef::Circle { .. });
    if (circle && document.default_effect == PolicyEffect::RequireReview)
        || document.rules.iter().any(|rule| {
            rule.kind != PolicyRuleKind::Agent
                || (circle && rule.effect == PolicyEffect::RequireReview)
                || rule.actions.as_ref().is_some_and(|actions| {
                    actions.iter().any(|action| {
                        arkret_schema::capability_action(action).is_none_or(|descriptor| {
                            descriptor.event_mapping_kind == "aggregate_admin"
                        }) || arkret_wire::ServiceOperationId::from_wire(action).is_some()
                    })
                })
                || (rule.actions.is_some()
                    && rule.agent_operations.as_ref().is_some_and(|ops| {
                        ops.iter().any(|op| {
                            matches!(
                                op,
                                AgentPolicyOperation::Join | AgentPolicyOperation::Publish
                            )
                        })
                    }))
                || rule.resources.as_ref().is_some_and(|resources| {
                    resources.iter().any(|resource| {
                        resource
                            .realm_id
                            .as_ref()
                            .is_some_and(|realm| document.realm_id.as_ref() != Some(realm))
                            || match resource.kind {
                                PolicyResourceKind::Realm => {
                                    resource.resource_ref.as_ref().is_some_and(|id| {
                                        document
                                            .realm_id
                                            .as_ref()
                                            .is_none_or(|realm| realm.as_str() != id)
                                    })
                                }
                                PolicyResourceKind::Strand => resource
                                    .resource_ref
                                    .as_ref()
                                    .is_some_and(|id| id.parse::<arkret_wire::StrandId>().is_err()),
                                PolicyResourceKind::Space => resource
                                    .resource_ref
                                    .as_ref()
                                    .is_some_and(|id| id.parse::<arkret_wire::SpaceId>().is_err()),
                                PolicyResourceKind::Object => resource
                                    .resource_ref
                                    .as_ref()
                                    .is_some_and(|id| !arkret_wire::is_object_ref(id)),
                                // Service scope cannot be used as a content-resource selector.
                                // No registered Agent management service matcher supplies its
                                // facts.
                                PolicyResourceKind::Service => true,
                            }
                    })
                })
        })
    {
        return Err(refused(
            "Agent management configuration lacks a registered matcher or review carrier",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn agent_policy_is_refused_even_without_an_agent_rule() {
        let payload: PolicySetStatePayload = serde_json::from_value(serde_json::json!({
            "policy_id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
            "expected_revision": null,
            "value": {
                "schema": "ak.schema.policy.v1",
                "id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
                "realm_id": "ak:realm:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-",
                "policy_kind": "agent",
                "rules": [{"rule_id": "ordinary", "kind": "action", "effect": "allow", "actions": ["ak.message.create"]}],
                "default_effect": "deny",
                "created_by": {"kind": "account", "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixturecontroller",
                    "station_id": "ak:did_core:webvh:z6mkfixturestation"
                }},
                "created_at": "2026-10-05T11:15:00.000Z"
            }
        })).unwrap();
        payload.validate().unwrap();
        let PolicySetValue::Governance(document) = payload.value else {
            panic!("expected governance policy");
        };
        assert!(
            require_supported_policy(
                &document,
                &arkret_wire::ScopeRef::Realm {
                    realm_id: document.realm_id.clone().unwrap()
                }
            )
            .is_err()
        );
    }

    fn join_policy() -> arkret_models_collaboration::governance::operation_wire::Policy {
        serde_json::from_value(serde_json::json!({
            "schema":"ak.schema.policy.v1",
            "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "realm_id":"ak:realm:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-",
            "policy_kind":"agent",
            "rules":[{"rule_id":"new_agents","kind":"agent","effect":"deny",
                "agent_target":{"kind":"all"},"agent_operations":["join"]}],
            "default_effect":"allow",
            "created_by":{"kind":"account","account_id":{
                "principal_id":"ak:did_core:web:controller.example",
                "station_id":"ak:did_core:web:station.example"}},
            "created_at":"2026-10-11T12:00:00.000Z"
        }))
        .unwrap()
    }

    #[test]
    fn realm_join_and_publish_policy_preserve_continuous_gate() {
        use arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation;
        let policy = join_policy();
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: policy.realm_id.clone().unwrap(),
        };
        assert!(require_supported_policy(&policy, &scope).is_ok());
        let mut publish = policy.clone();
        publish.rules[0].agent_operations = Some(vec![AgentPolicyOperation::Publish]);
        assert!(require_supported_policy(&publish, &scope).is_ok());
        let mut reviewed = publish.clone();
        reviewed.rules[0].effect = arkret_wire::PolicyEffect::RequireReview;
        reviewed.rules[0].review_requirement = Some(
            arkret_models_collaboration::governance::operation_wire::ManagementReviewRequirement {
                approver_actor_ids: vec![arkret_wire::ActorId::account(
                    arkret_wire::AccountId::new(
                        "ak:did_core:web:administrator.example".parse().unwrap(),
                        "ak:did_core:web:station.example".parse().unwrap(),
                    ),
                )],
                threshold: 1,
                max_age_seconds: 60,
            },
        );
        reviewed.validate().unwrap();
        assert!(require_supported_policy(&reviewed, &scope).is_ok());
        for operation in [
            AgentPolicyOperation::Authorize,
            AgentPolicyOperation::Execute,
            AgentPolicyOperation::Read,
            AgentPolicyOperation::Deliver,
            AgentPolicyOperation::Serve,
        ] {
            let mut other = policy.clone();
            other.rules[0].agent_operations = Some(vec![operation]);
            assert!(require_supported_policy(&other, &scope).is_ok());
        }
        publish.rules[0].agent_operations = Some(vec![
            AgentPolicyOperation::Join,
            AgentPolicyOperation::Publish,
        ]);
        assert!(require_supported_policy(&publish, &scope).is_ok());
        for effect in [
            arkret_wire::PolicyEffect::Deny,
            arkret_wire::PolicyEffect::Quarantine,
        ] {
            let mut other = policy.clone();
            other.default_effect = effect;
            assert!(require_supported_policy(&other, &scope).is_ok());
        }
        let mut review = policy.clone();
        review.rules[0].effect = arkret_wire::PolicyEffect::Quarantine;
        assert!(require_supported_policy(&review, &scope).is_ok());
        let mut actions = policy.clone();
        actions.rules[0].actions = Some(vec!["ak.message.create".into()]);
        assert!(require_supported_policy(&actions, &scope).is_err());
        let circle = arkret_wire::ScopeRef::Circle {
            realm_id: policy.realm_id.clone().unwrap(),
            circle_id: "ak:circle:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
                .parse()
                .unwrap(),
        };
        assert!(require_supported_policy(&policy, &circle).is_ok());
        assert!(require_supported_policy(&reviewed, &circle).is_err());
        let mut applet = policy;
        applet.policy_kind = arkret_wire::PolicyKind::Applet;
        assert!(require_supported_policy(&applet, &scope).is_err());
    }

    #[test]
    fn join_only_ban_leaves_continuous_operations_allowed_and_binds_realm_resources() {
        use arkret_models_collaboration::governance::operation_wire::{
            AgentPolicyOperation, PolicyResourceKind, PolicyResourceSelector,
        };
        use arkret_policy::agent_management::{AgentManagementContext, evaluate_agent_management};
        let mut policy = join_policy();
        let realm = policy.realm_id.clone().unwrap();
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let controller = policy.created_by.as_account_id().unwrap().clone();
        let agent = arkret_wire::AccountId::new(
            "ak:did_core:web:agent.example".parse().unwrap(),
            controller.station_id.clone(),
        );
        let resources = [PolicyResourceSelector {
            kind: PolicyResourceKind::Realm,
            realm_id: Some(realm.clone()),
            resource_ref: Some(realm.to_string()),
        }];
        policy.rules[0].resources = Some(resources.to_vec());
        assert!(require_supported_policy(&policy, &scope).is_ok());
        for operation in [
            AgentPolicyOperation::Read,
            AgentPolicyOperation::Execute,
            AgentPolicyOperation::Deliver,
            AgentPolicyOperation::Serve,
        ] {
            let effect = evaluate_agent_management(
                Some(std::slice::from_ref(&policy)),
                &AgentManagementContext {
                    realm_id: &realm,
                    ownership: Some((&controller, &agent)),
                    operation,
                    content_action: Some(
                        arkret_wire::CapabilityActionId::from_wire("ak.event.read").unwrap(),
                    ),
                    resources: Some(&resources),
                    at: policy.created_at,
                },
            )
            .unwrap();
            assert_eq!(effect, arkret_wire::PolicyEffect::Allow);
        }
        let wrong = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x42; 32],
        ));
        policy.rules[0].resources.as_mut().unwrap()[0].realm_id = Some(wrong.clone());
        assert!(require_supported_policy(&policy, &scope).is_err());
        policy.rules[0].resources.as_mut().unwrap()[0].realm_id = Some(realm);
        policy.rules[0].resources.as_mut().unwrap()[0].resource_ref = Some(wrong.to_string());
        assert!(require_supported_policy(&policy, &scope).is_err());
    }

    #[test]
    fn ordinary_policy_kinds_keep_their_existing_admission() {
        for kind in [
            arkret_wire::PolicyKind::Access,
            arkret_wire::PolicyKind::Join,
        ] {
            let mut policy = join_policy();
            policy.policy_kind = kind;
            let scope = arkret_wire::ScopeRef::Realm {
                realm_id: policy.realm_id.clone().unwrap(),
            };
            assert!(require_supported_policy(&policy, &scope).is_ok());
        }
    }
}
fn payload<T: serde::de::DeserializeOwned>(event: &Event) -> PersistenceResult<T> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(schema)?).map_err(schema)
}

/// Shared Agent policy values may be carried by verified scope snapshots.
/// This does not recreate their private admission Event or enable writes.
pub(crate) fn validate_disclosed_agent_policy(
    realm: &arkret_wire::RealmId,
    policy_id: &arkret_wire::PolicyId,
    source: &CommitStreamRef,
    value: &Value,
) -> PersistenceResult<()> {
    let document: PolicySetValue = serde_json::from_value(value.clone()).map_err(schema)?;
    document.validate().map_err(schema)?;
    match document {
        PolicySetValue::Governance(policy)
            if policy.id == *policy_id
                && policy.realm_id.as_ref() == Some(realm)
                && policy.policy_kind == PolicyKind::Agent
                && source.realm_id() == realm
                && matches!(
                    source,
                    CommitStreamRef::Realm { .. } | CommitStreamRef::Circle { .. }
                ) =>
        {
            Ok(())
        }
        _ => Err(schema(
            "Policy current has no proved shared Agent scope binding",
        )),
    }
}

#[cfg(test)]
mod pg_tests;

/// Resolve the precise declared scope from current authority, rather than
/// weakening an object scope into Realm-wide authorization.
pub(crate) async fn resolve_scope(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &str,
) -> PersistenceResult<WireResourceSelector> {
    if let Ok(id) = arkret_wire::RealmId::new(scope) {
        if &id != realm {
            return Err(refused("Policy scope belongs to another Realm"));
        }
        return Ok(WireResourceSelector::realm(id));
    }
    let (table, column, target) = if let Ok(id) = arkret_wire::SpaceId::new(scope) {
        (
            "space_current_results",
            "space_id",
            WireResourceSelector::space(realm.clone(), id),
        )
    } else if let Ok(id) = arkret_wire::StrandId::new(scope) {
        (
            "strand_current_results",
            "strand_id",
            WireResourceSelector::strand(realm.clone(), id),
        )
    } else if let Ok(id) = arkret_wire::CircleId::new(scope) {
        (
            "circle_current_results",
            "circle_id",
            WireResourceSelector::circle(realm.clone(), id),
        )
    } else if let Ok(id) = arkret_wire::PolicyId::new(scope) {
        (
            "policy_current_results",
            "policy_id",
            serde_json::from_value(
                serde_json::json!({"kind":"policy","realm_id":realm,"policy_id":id}),
            )
            .map_err(schema)?,
        )
    } else if let Ok(did) = arkret_wire::Did::new(scope) {
        let principal = arkret_wire::project_did_to_core_id(&did).map_err(schema)?;
        #[derive(QueryableByName)]
        struct Exists {
            #[diesel(sql_type=diesel::sql_types::Bool)]
            present: bool,
        }
        let exists=sql_query("SELECT EXISTS(SELECT 1 FROM member_state_current_results WHERE realm_id=$1 AND ((member_id::jsonb->'account_id'->>'principal_id')=$2 OR (member_id::jsonb->>'service_id')=$2)) AS present")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(principal.as_str())
            .get_result::<Exists>(&mut *conn).await.map_err(PersistenceError::database)?;
        if !exists.present {
            return Err(refused(
                "Policy DID scope has no member authority in this Realm",
            ));
        }
        return serde_json::from_value(
            serde_json::json!({"kind":"actor","realm_id":realm,"actor_id":principal}),
        )
        .map_err(schema);
    } else {
        return Err(refused("Policy scope has no resolvable typed authority"));
    };
    let row = sql_query(format!(
        "SELECT realm_id,value FROM {table} WHERE {column}=$1"
    ))
    .bind::<Text, _>(scope)
    .get_result::<Stored>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| refused("Policy scope current object is unavailable"))?;
    if row.realm_id != realm.as_str() {
        return Err(refused("Policy scope belongs to another Realm"));
    }
    Ok(target)
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<Option<WireResourceSelector>> {
    match event.kind {
        EventKind::PolicySet => {
            let value: PolicySetStatePayload = payload(event)?;
            value.validate().map_err(schema)?;
            check_policy_cas_in_connection(conn, event, commit, &value).await?;
            if let PolicySetValue::Governance(document) = value.value {
                // Do not acknowledge a restriction that the current read and
                // delivery paths cannot yet enforce at their actual cut.
                require_supported_policy(&document, &event.scope_ref)?;
                if document
                    .realm_id
                    .as_ref()
                    .is_some_and(|id| id != &event.realm_id)
                {
                    return Err(schema(
                        "Policy document Realm differs from its accepting Realm",
                    ));
                }
                return Ok(Some(match &event.scope_ref {
                    arkret_wire::ScopeRef::Circle {
                        realm_id,
                        circle_id,
                    } => WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
                    _ => WireResourceSelector::realm(event.realm_id.clone()),
                }));
            }
            Err(refused(
                "Recovery Policy is admitted through its dedicated PCR unit",
            ))
        }
        EventKind::PolicyAction => {
            let config: PolicyActionStatePayload = payload(event)?;
            config.validate().map_err(schema)?;
            let action = CapabilityActionId::from_wire(config.value.action.as_str())
                .ok_or_else(|| schema("Policy action is not registered"))?;
            if config.value.approval_required {
                crate::policy_action_admission::require_registered_carrier(action)?;
            }
            let target = resolve_scope(conn, &event.realm_id, &config.value.policy_scope).await?;
            match config.subject().map_err(schema)? {
                PolicyActionSubject::Policy(id) => {
                    let policy = sql_query(
                        "SELECT realm_id,value FROM policy_current_results WHERE policy_id=$1",
                    )
                    .bind::<Text, _>(id.as_str())
                    .get_result::<Stored>(&mut *conn)
                    .await
                    .optional()
                    .map_err(PersistenceError::database)?
                    .ok_or_else(|| refused("Policy action dependency is unavailable"))?;
                    if policy.realm_id != event.realm_id.as_str() {
                        return Err(refused("Policy action dependency is outside this Realm"));
                    }
                    let value: PolicySetValue =
                        serde_json::from_value(policy.value).map_err(schema)?;
                    if !matches!(value, PolicySetValue::Governance(_)) {
                        return Err(refused(
                            "Recovery Policy cannot carry governance approval configuration",
                        ));
                    }
                }
                PolicyActionSubject::Action(id) => {
                    let previous=sql_query("SELECT realm_id,value FROM policy_action_current_results WHERE realm_id=$1 AND subject_kind='realm_action' AND subject_id=$2 AND action_key=''")
                        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(id.as_str())
                        .get_result::<Stored>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                    if let Some(previous) = previous {
                        let value:arkret_models_collaboration::events_payloads::PolicyActionDocument=serde_json::from_value(previous.value).map_err(schema)?;
                        if value.action != config.value.action
                            || value.policy_scope != config.value.policy_scope
                        {
                            return Err(refused("Realm-local Policy action cannot be rebound"));
                        }
                    }
                }
            }
            Ok(Some(target))
        }
        _ => Ok(None),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PolicyWriteContext {
    Admission,
    AcceptedReplica,
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    commit_in_connection_inner(conn, event, commit, PolicyWriteContext::Admission).await
}

// The caller has verified the accepted originals, native revision and prefix.
// A disclosed snapshot does not fabricate the producer's local CAS predecessor.
pub(crate) async fn commit_replica_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    commit_in_connection_inner(conn, event, commit, PolicyWriteContext::AcceptedReplica).await
}

async fn commit_in_connection_inner(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    context: PolicyWriteContext,
) -> PersistenceResult<()> {
    match event.kind {
        EventKind::PolicySet => {
            let payload: PolicySetStatePayload = payload(event)?;
            payload.validate().map_err(schema)?;
            let value = serde_json::to_value(&payload.value).map_err(schema)?;
            let count = if context == PolicyWriteContext::Admission
                && let Some(expected) = &payload.expected_revision
            {
                // CAS predecessors order writes even when the new accepted
                // stream position is lower than the previous stream's value.
                let expected_position = expected
                    .as_ref()
                    .map(|r| i64::try_from(r.stream_position))
                    .transpose()
                    .map_err(schema)?;
                sql_query("INSERT INTO policy_current_results(realm_id,policy_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) \
                    SELECT $1,$2,$3,$4,$5,$6,$7 WHERE $8 IS NULL OR EXISTS(SELECT 1 FROM policy_current_results \
                    WHERE policy_id=$2 AND realm_id=$1 AND current_commit_id=$8 AND current_stream_position=$9) \
                    ON CONFLICT(policy_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id, \
                    current_stream_position=EXCLUDED.current_stream_position,current_event_id=EXCLUDED.current_event_id, \
                    value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE policy_current_results.realm_id=EXCLUDED.realm_id \
                    AND policy_current_results.current_commit_id=$8 AND policy_current_results.current_stream_position=$9 \
                    AND policy_current_results.value->>'schema'='ak.schema.policy.v1' \
                    AND policy_current_results.value->>'policy_kind'=EXCLUDED.value->>'policy_kind'")
                    .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.policy_id.as_str())
                    .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(schema)?)
                    .bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(commit.committed_at)
                    .bind::<diesel::sql_types::Nullable<Text>,_>(expected.as_ref().map(|r| r.commit_id.as_str()))
                    .bind::<diesel::sql_types::Nullable<BigInt>,_>(expected_position)
                    .execute(&mut *conn).await.map_err(PersistenceError::database)?
            } else {
                sql_query("INSERT INTO policy_current_results(realm_id,policy_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(policy_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE policy_current_results.realm_id=EXCLUDED.realm_id AND policy_current_results.current_stream_position<EXCLUDED.current_stream_position AND (policy_current_results.value->>'schema' IS DISTINCT FROM 'ak.schema.policy.v1' OR COALESCE(policy_current_results.value->>'policy_kind','') NOT IN ('agent','applet') OR (EXCLUDED.value->>'schema'='ak.schema.policy.v1' AND EXCLUDED.value->>'policy_kind'=policy_current_results.value->>'policy_kind'))")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.policy_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
                .bind::<BigInt,_>(commit.stream_position as i64).bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(&value)
                .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?
            };
            if count != 1 {
                return Err(refused(
                    "Policy current cannot cross Realm or replace a different accepted revision",
                ));
            }
        }
        EventKind::PolicyAction => {
            let payload: PolicyActionStatePayload = payload(event)?;
            payload.validate().map_err(schema)?;
            let (kind, id, key) = match payload.subject().map_err(schema)? {
                PolicyActionSubject::Policy(id) => (
                    "policy_ref",
                    id.to_string(),
                    payload.value.action.as_str().to_owned(),
                ),
                PolicyActionSubject::Action(id) => {
                    ("realm_action", id.as_str().to_owned(), String::new())
                }
            };
            let value = serde_json::to_value(payload.value).map_err(schema)?;
            let count=sql_query("INSERT INTO policy_action_current_results(realm_id,subject_kind,subject_id,action_key,current_commit_id,current_stream_position,current_event_id,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(realm_id,subject_kind,subject_id,action_key) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE policy_action_current_results.current_stream_position<EXCLUDED.current_stream_position")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(kind).bind::<Text,_>(id).bind::<Text,_>(key)
                .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(commit.stream_position as i64)
                .bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(commit.committed_at)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if count != 1 {
                return Err(refused("Policy action current cannot move backwards"));
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod scoped_current_tests {
    use diesel::sql_types::{Binary, Nullable};
    use serde_json::json;

    use super::*;
    use crate::test_database::TestDatabase;

    fn fixture(kind: EventKind, scope: arkret_wire::ScopeRef, body: Value, n: u64) -> Event {
        arkret_wire::test_support::raw_event_at(
            kind.as_str(),
            scope,
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
            body,
            chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
                + chrono::TimeDelta::seconds(n as i64),
        )
        .unwrap()
    }
    fn genesis() -> Event {
        fixture(
            EventKind::RealmCreate,
            arkret_wire::ScopeRef::RealmGenesis,
            json!({}),
            0,
        )
    }
    fn realm() -> arkret_wire::RealmId {
        genesis().realm_id
    }
    fn basis(
        event: &Event,
        position: u64,
        previous: Option<&RealmCommit>,
        salt: u8,
    ) -> RealmCommit {
        RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([salt; 32]),
            realm_id: event.realm_id.clone(),
            stream_ref: CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .unwrap(),
            stream_position: position,
            previous_commit_ref: previous.map(|p| p.commit_id.clone()),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            committed_at: event.created_at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new("did:web:station.example#authority")
                    .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "ab".repeat(32)))
                    .unwrap(),
                created_at: event.created_at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        }
    }
    async fn insert(conn: &mut AsyncPgConnection, event: &Event, commit: &RealmCommit) {
        sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,'committed',$9)")
            .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).bind::<Binary,_>(event.event_id.digest_bytes().to_vec())
            .bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(event.realm_id.as_str())
            .bind::<Jsonb,_>(json!(event.scope_ref)).bind::<Text,_>(event.kind.as_str())
            .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(event).unwrap()).bind::<Jsonb,_>(json!(event))
            .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9")
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(commit.realm_id.as_str())
            .bind::<Text,_>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap()).bind::<Jsonb,_>(json!(commit.stream_ref))
            .bind::<BigInt,_>(commit.stream_position as i64).bind::<Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id|id.as_str()))
            .bind::<Jsonb,_>(json!(commit)).bind::<Timestamptz,_>(commit.committed_at).bind::<Binary,_>(event.event_id.token_bytes().to_vec())
            .execute(&mut *conn).await.unwrap();
    }
    async fn seed(conn: &mut AsyncPgConnection) -> (RealmCommit, arkret_wire::CircleId) {
        sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,'ak:did_core:web:station.example','{}')")
            .bind::<Text,_>(realm().as_str()).execute(&mut *conn).await.unwrap();
        let genesis = genesis();
        let zero = basis(&genesis, 0, None, 80);
        insert(conn, &genesis, &zero).await;
        let create = fixture(
            EventKind::CircleCreate,
            arkret_wire::ScopeRef::Realm { realm_id: realm() },
            json!({}),
            1,
        );
        let circle = arkret_wire::CircleId::from_event_id(&create.event_id);
        let first = basis(&create, 1, Some(&zero), 81);
        insert(conn, &create, &first).await;
        sql_query("INSERT INTO circle_current_results(realm_id,circle_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,short_name_folded,value,updated_at) VALUES($1,$2,$3,$4,1,$5,'scope-cas',$6,$7)")
            .bind::<Text,_>(realm().as_str()).bind::<Text,_>(circle.as_str()).bind::<Text,_>(create.event_id.as_str())
            .bind::<Text,_>(first.commit_id.as_str()).bind::<Jsonb,_>(json!(first.stream_ref))
            .bind::<Jsonb,_>(json!({"id":circle,"realm_id":realm()})).bind::<Timestamptz,_>(create.created_at)
            .execute(&mut *conn).await.unwrap();
        (first, circle)
    }
    fn policy(previous: Option<&RealmCommit>, suffix: &str) -> PolicySetStatePayload {
        serde_json::from_value(json!({
            "policy_id":format!("ak:policy:0198ff00-0000-7000-8000-00000000000{suffix}"),
            "expected_revision":previous.map(|p| CurrentRevision { commit_id:p.commit_id.clone(), stream_position:p.stream_position }),
            "value": {
                "schema":"ak.schema.policy.v1", "id":format!("ak:policy:0198ff00-0000-7000-8000-00000000000{suffix}"),
                "realm_id":realm(),"policy_kind":"agent","default_effect":"allow",
                "rules":[{"rule_id":"all","kind":"agent","effect":"deny","agent_target":{"kind":"all"},"agent_operations":["execute"]}],
                "created_by":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:controller.example","station_id":"ak:did_core:web:station.example"}},
                "created_at":"2026-10-12T00:00:00.000Z"
            }
        })).unwrap()
    }
    async fn accepted(
        conn: &mut AsyncPgConnection,
        payload: &PolicySetStatePayload,
        scope: arkret_wire::ScopeRef,
        position: u64,
        previous: Option<&RealmCommit>,
        salt: u8,
    ) -> RealmCommit {
        let event = fixture(EventKind::PolicySet, scope, json!(payload), salt.into());
        let commit = basis(&event, position, previous, salt);
        check_policy_cas_in_connection(conn, &event, &commit, payload)
            .await
            .unwrap();
        insert(conn, &event, &commit).await;
        commit_in_connection(conn, &event, &commit).await.unwrap();
        commit
    }
    fn history(
        payload: &PolicySetStatePayload,
        scope: arkret_wire::ScopeRef,
        position: u64,
        salt: u8,
    ) -> ManagementPolicyHistory {
        let event = fixture(EventKind::PolicySet, scope, json!(payload), salt.into());
        let commit = basis(&event, position, None, salt);
        ManagementPolicyHistory {
            policy_id: payload.policy_id.to_string(),
            realm_id: realm().to_string(),
            current_commit_id: commit.commit_id.to_string(),
            current_stream_position: position as i64,
            current_event_id: event.event_id.to_string(),
            source_stream: json!(commit.stream_ref),
            event_scope: json!(event.scope_ref),
            expected_revision: Some(json!(payload.expected_revision.as_ref().unwrap())),
            value: json!(payload.value),
        }
    }

    #[test]
    fn accepted_cas_chain_rejects_forks_missing_predecessors_cycles_and_wrong_positions() {
        let first = history(
            &policy(None, "1"),
            arkret_wire::ScopeRef::Realm { realm_id: realm() },
            90,
            90,
        );
        let pointer = policy_revision(&first).unwrap();
        let mut next_payload = policy(None, "1");
        next_payload.expected_revision = Some(Some(pointer.clone()));
        let next = history(
            &next_payload,
            arkret_wire::ScopeRef::Circle {
                realm_id: realm(),
                circle_id: arkret_wire::CircleId::from_event_id(&genesis().event_id),
            },
            0,
            91,
        );
        let mut rows = vec![next, first];
        assert_eq!(
            management_chain(&rows, &realm(), &PolicyKind::Agent)
                .unwrap()
                .last()
                .unwrap()
                .current_stream_position,
            0
        );
        let fork = history(
            &next_payload,
            arkret_wire::ScopeRef::Realm { realm_id: realm() },
            99,
            92,
        );
        rows.push(fork);
        assert!(management_chain(&rows, &realm(), &PolicyKind::Agent).is_err());
        rows.pop();
        rows[0].expected_revision = Some(
            json!({"commit_id":pointer.commit_id,"stream_position":pointer.stream_position+1}),
        );
        assert!(management_chain(&rows, &realm(), &PolicyKind::Agent).is_err());
        rows[0].expected_revision = None;
        assert!(management_chain(&rows, &realm(), &PolicyKind::Agent).is_err());
        rows[0].expected_revision = Some(json!(policy_revision(&rows[0]).unwrap()));
        assert!(management_chain(&rows, &realm(), &PolicyKind::Agent).is_err());
    }

    // Imported accepted history tests the real PostgreSQL reader/writer/CAS,
    // not producer authentication or enabling the closed management gates.
    #[tokio::test]
    async fn realm_circle_realm_updates_follow_exact_cas_not_cross_stream_positions() {
        let database = TestDatabase::lease().await;
        let mut conn = database.pool().get().await.unwrap();
        sql_query("BEGIN").execute(&mut conn).await.unwrap();
        let (head, circle) = seed(&mut conn).await;
        assert!(
            read_scoped_agent_management_policies_in_connection(&mut conn, &realm(), Some(&circle))
                .await
                .unwrap()
                .is_empty()
        );
        let realm_scope = arkret_wire::ScopeRef::Realm { realm_id: realm() };
        let first = accepted(
            &mut conn,
            &policy(None, "1"),
            realm_scope.clone(),
            2,
            Some(&head),
            82,
        )
        .await;
        let circle_scope = arkret_wire::ScopeRef::Circle {
            realm_id: realm(),
            circle_id: circle.clone(),
        };
        let next = accepted(
            &mut conn,
            &policy(Some(&first), "1"),
            circle_scope.clone(),
            0,
            None,
            83,
        )
        .await;
        assert!(
            read_agent_management_policies_in_connection(&mut conn, &realm())
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            read_scoped_agent_management_policies_in_connection(&mut conn, &realm(), Some(&circle))
                .await
                .unwrap()
                .len(),
            1
        );
        match read_management_policy_exact_in_connection(
            &mut conn,
            &realm(),
            &policy(None, "1").policy_id,
        )
        .await
        .unwrap()
        {
            ManagementPolicyCurrentRead::Present {
                source,
                revision,
                head,
                ..
            } => {
                assert_eq!(
                    source,
                    CommitStreamRef::Circle {
                        realm_id: realm(),
                        circle_id: circle.clone()
                    }
                );
                assert_eq!(
                    revision,
                    CurrentRevision {
                        commit_id: next.commit_id.clone(),
                        stream_position: next.stream_position,
                    }
                );
                assert_eq!(head.stream_position, 0);
            }
            _ => panic!("migrated Policy must retain its actual Circle leaf"),
        }
        let parent = accepted(
            &mut conn,
            &policy(None, "2"),
            realm_scope.clone(),
            3,
            Some(&first),
            84,
        )
        .await;
        assert_eq!(
            read_scoped_agent_management_policies_in_connection(&mut conn, &realm(), Some(&circle))
                .await
                .unwrap()
                .len(),
            2
        );
        let stale = policy(Some(&first), "1");
        let event = fixture(EventKind::PolicySet, realm_scope.clone(), json!(stale), 85);
        let candidate = basis(&event, 4, Some(&parent), 85);
        assert!(
            check_policy_cas_in_connection(&mut conn, &event, &candidate, &stale)
                .await
                .is_err()
        );
        let lifted = policy(Some(&next), "1");
        let final_revision = accepted(&mut conn, &lifted, realm_scope, 4, Some(&parent), 86).await;
        match read_management_policy_exact_in_connection(&mut conn, &realm(), &lifted.policy_id)
            .await
            .unwrap()
        {
            ManagementPolicyCurrentRead::Present {
                source,
                revision,
                head,
                ..
            } => {
                assert_eq!(source, CommitStreamRef::Realm { realm_id: realm() });
                assert_eq!(
                    revision,
                    CurrentRevision {
                        commit_id: final_revision.commit_id.clone(),
                        stream_position: final_revision.stream_position,
                    }
                );
                assert_eq!(head.stream_position, 4);
            }
            _ => panic!("migrated Policy must retain its actual Realm leaf"),
        }
        assert_eq!(
            read_agent_management_policies_in_connection(&mut conn, &realm())
                .await
                .unwrap()
                .len(),
            2
        );
        // Removing an accepted predecessor or current is never policy absence.
        sql_query("SAVEPOINT tamper")
            .execute(&mut conn)
            .await
            .unwrap();
        sql_query("DELETE FROM realm_commits WHERE commit_id=$1")
            .bind::<Text, _>(next.commit_id.as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            read_agent_management_policies_in_connection(&mut conn, &realm())
                .await
                .is_err()
        );
        sql_query("ROLLBACK TO SAVEPOINT tamper")
            .execute(&mut conn)
            .await
            .unwrap();
        sql_query("DELETE FROM policy_current_results WHERE policy_id=$1")
            .bind::<Text, _>(lifted.policy_id.as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            read_scoped_agent_management_policies_in_connection(&mut conn, &realm(), Some(&circle))
                .await
                .is_err()
        );
        assert!(
            read_management_policy_exact_in_connection(&mut conn, &realm(), &lifted.policy_id)
                .await
                .is_err()
        );
        sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
    }

    #[tokio::test]
    async fn unrelated_circle_current_is_not_a_parent_but_its_exact_pointer_cannot_be_forged() {
        let database = TestDatabase::lease().await;
        let mut conn = database.pool().get().await.unwrap();
        sql_query("BEGIN").execute(&mut conn).await.unwrap();
        let (_, circle) = seed(&mut conn).await;
        let scope = arkret_wire::ScopeRef::Circle {
            realm_id: realm(),
            circle_id: circle.clone(),
        };
        let first = accepted(&mut conn, &policy(None, "1"), scope, 0, None, 87).await;
        assert!(
            read_agent_management_policies_in_connection(&mut conn, &realm())
                .await
                .unwrap()
                .is_empty()
        );
        let other = arkret_wire::CircleId::from_event_id(&genesis().event_id);
        assert!(
            read_scoped_agent_management_policies_in_connection(&mut conn, &realm(), Some(&other))
                .await
                .is_err()
        );
        sql_query("UPDATE policy_current_results SET current_stream_position=current_stream_position+1 WHERE current_commit_id=$1")
            .bind::<Text,_>(first.commit_id.as_str()).execute(&mut conn).await.unwrap();
        assert!(
            read_scoped_agent_management_policies_in_connection(&mut conn, &realm(), Some(&circle))
                .await
                .is_err()
        );
        sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
    }
}
