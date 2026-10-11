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
    value: Value,
}

/// Governing admission only, under the same Realm lock as all current writers.
/// A replica/cache must not use its held prefix to claim authoritative absence.
/// Non-Realm Agent Policy sources remain unresolved, never silently absent.
#[cfg(test)]
async fn read_agent_management_policies_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<Vec<arkret_models_collaboration::governance::operation_wire::Policy>> {
    read_scoped_agent_management_policies_in_connection(conn, realm, None).await
}

/// Read only the enforcing operation's parent Realm and actual Circle prefix.
/// Unrelated private stream gaps do not poison this cut. Known non-Realm Agent
/// Policy writes still fail closed until their layer selection is implemented.
pub(crate) async fn read_scoped_agent_management_policies_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    circle: Option<&arkret_wire::CircleId>,
) -> PersistenceResult<Vec<arkret_models_collaboration::governance::operation_wire::Policy>> {
    read_scoped_agent_management_policies_at_cut(conn, realm, circle, true).await
}

/// Governing visibility only, from an enclosing repeatable-read snapshot.
/// This does not prove authorization at a later network delivery point.
pub(crate) async fn read_scoped_agent_management_policy_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    circle: Option<&arkret_wire::CircleId>,
) -> PersistenceResult<Vec<arkret_models_collaboration::governance::operation_wire::Policy>> {
    read_scoped_agent_management_policies_at_cut(conn, realm, circle, false).await
}

async fn read_scoped_agent_management_policies_at_cut(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    circle: Option<&arkret_wire::CircleId>,
    lock: bool,
) -> PersistenceResult<Vec<arkret_models_collaboration::governance::operation_wire::Policy>> {
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
    let circle_source = circle
        .map(|circle_id| {
            serde_json::to_value(CommitStreamRef::Circle {
                realm_id: realm.clone(),
                circle_id: circle_id.clone(),
            })
            .map_err(schema)
        })
        .transpose()?;
    let complete = sql_query(
        "WITH nodes AS (SELECT c.*,e.state,e.kind AS event_kind,e.realm_id AS event_realm,e.envelope, \
         ROW_NUMBER() OVER (PARTITION BY c.stream_ref ORDER BY c.stream_position)-1 AS expected_position, \
         LAG(c.commit_id) OVER (PARTITION BY c.stream_ref ORDER BY c.stream_position) AS predecessor \
         FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 \
         AND (c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) OR c.stream_ref=$2)) \
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
              OR (envelope->>'realm_id'=$1 AND NOT \
                  (stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND stream_position=0))),false)) \
         AND BOOL_OR(stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND stream_position=0) \
         AND ($2 IS NULL OR BOOL_OR(stream_ref=$2 AND stream_position=0)),false) \
         AS present FROM nodes",
    )
    .bind::<Text,_>(realm.as_str()).bind::<diesel::sql_types::Nullable<Jsonb>,_>(circle_source)
    .get_result::<Present>(&mut *conn)
    .await.map_err(PersistenceError::database)?.present;
    if !complete {
        return Err(refused(
            "complete Agent management governance history is unavailable",
        ));
    }
    let history = sql_query(
        "SELECT e.envelope->'payload'->>'policy_id' AS policy_id,c.realm_id, \
         c.commit_id AS current_commit_id,c.stream_position AS current_stream_position, \
         e.envelope->>'event_id' AS current_event_id,c.stream_ref AS source_stream, \
         e.envelope->'payload'->'value' AS value FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk WHERE e.kind='ak.policy.set' AND e.state='committed' \
         AND (c.realm_id=$1 OR e.envelope->'payload'->'value'->>'realm_id'=$1) \
         ORDER BY c.realm_id,c.stream_position,c.commit_id",
    )
    .bind::<Text,_>(realm.as_str()).load::<ManagementPolicyHistory>(&mut *conn)
    .await.map_err(PersistenceError::database)?;
    let agent_value =
        |value: &Value| value.get("policy_kind").and_then(Value::as_str) == Some("agent");
    let mut agent_ids = BTreeSet::new();
    let mut latest = BTreeMap::new();
    let realm_source = serde_json::to_value(CommitStreamRef::Realm {
        realm_id: realm.clone(),
    })
    .map_err(schema)?;
    for row in history {
        if agent_value(&row.value) {
            agent_ids.insert(row.policy_id.clone());
        }
        latest
            .entry(row.policy_id.clone())
            .or_insert_with(Vec::new)
            .push(row);
    }
    let ids = agent_ids.iter().cloned().collect::<Vec<_>>();
    let rows = sql_query(format!(
        "SELECT policy_id,realm_id,current_commit_id,current_stream_position,current_event_id,value \
         FROM policy_current_results WHERE realm_id=$1 OR value->>'realm_id'=$1 OR policy_id=ANY($2) \
         ORDER BY policy_id{}", if lock { " FOR SHARE" } else { "" },
    ))
    .bind::<Text,_>(realm.as_str()).bind::<diesel::sql_types::Array<Text>,_>(&ids)
    .load::<ManagementPolicyRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut current = BTreeMap::new();
    for row in rows {
        if agent_value(&row.value) {
            agent_ids.insert(row.policy_id.clone());
        }
        current.insert(row.policy_id.clone(), row);
    }
    let mut policies = Vec::new();
    for id in agent_ids {
        let accepted = latest
            .get(&id)
            .ok_or_else(|| refused("Agent Policy current has no accepted history"))?;
        if accepted
            .iter()
            .any(|row| row.realm_id != realm.as_str() || row.source_stream != realm_source)
        {
            return Err(refused(
                "Agent Policy scope needs unresolved governance evidence",
            ));
        }
        let accepted = accepted
            .last()
            .ok_or_else(|| refused("Agent Policy history is unavailable"))?;
        let row = current
            .get(&id)
            .ok_or_else(|| refused("accepted Agent Policy current is missing"))?;
        if row.realm_id != realm.as_str()
            || row.current_commit_id != accepted.current_commit_id
            || row.current_stream_position != accepted.current_stream_position
            || row.current_event_id != accepted.current_event_id
            || row.value != accepted.value
        {
            return Err(refused(
                "Agent Policy current differs from its last accepted write",
            ));
        }
        let document: PolicySetValue = serde_json::from_value(row.value.clone()).map_err(schema)?;
        document.validate().map_err(schema)?;
        match document {
            PolicySetValue::Governance(policy)
                if policy.policy_kind == PolicyKind::Agent
                    && policy.id.as_str() == id
                    && policy.realm_id.as_ref() == Some(realm) =>
            {
                policies.push(*policy)
            }
            _ => return Err(refused("Agent Policy binding or family changed")),
        }
    }
    Ok(policies)
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
        if row.value.get("schema").and_then(Value::as_str) != Some("ak.schema.policy.v1") {
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
    if commit.realm_id != event.realm_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(refused(
            "Management Policy CAS requires a held Realm governance stream",
        ));
    }
    let head = commit
        .stream_position
        .checked_sub(1)
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| refused("Management Policy CAS needs an established governance prefix"))?;
    let complete = sql_query(
        "WITH prefix AS (SELECT c.*,e.state,e.kind AS event_kind,e.realm_id AS event_realm,e.envelope, \
         LAG(c.commit_id) OVER (ORDER BY c.stream_position) AS predecessor \
         FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1)) \
         SELECT COALESCE(COUNT(*)=$2+1 AND MIN(stream_position)=0 AND MAX(stream_position)=$2 \
         AND BOOL_AND(COALESCE(state='committed' AND event_realm=$1 \
         AND ((stream_position=0 AND NOT (envelope ? 'realm_id') \
               AND envelope->'scope_ref'=jsonb_build_object('kind','realm_genesis')) \
              OR (stream_position>0 AND envelope->>'realm_id'=$1)) \
         AND envelope->>'kind'=event_kind \
         AND (stream_position<>0 OR event_kind='ak.realm.create') \
         AND commit_json->>'event_ref'=envelope->>'event_id' \
         AND previous_commit_ref IS NOT DISTINCT FROM predecessor,false)) \
         AND BOOL_OR(stream_position=$2 AND commit_id=$3),false) AS present FROM prefix")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<BigInt,_>(head)
        .bind::<diesel::sql_types::Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
        .get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !complete {
        return Err(refused(
            "Management Policy current governance prefix is unavailable",
        ));
    }
    let unresolved_stream = sql_query(
        "WITH nodes AS (SELECT c.*,e.state,e.realm_id AS event_realm,e.envelope, \
         ROW_NUMBER() OVER (PARTITION BY c.stream_key ORDER BY c.stream_position)-1 AS expected_position, \
         LAG(c.commit_id) OVER (PARTITION BY c.stream_key ORDER BY c.stream_position) AS predecessor \
         FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_ref<>jsonb_build_object('kind','realm','realm_id',$1)) \
         SELECT EXISTS(SELECT 1 FROM nodes WHERE stream_position<>expected_position \
         OR previous_commit_ref IS DISTINCT FROM predecessor OR state IS DISTINCT FROM 'committed' \
         OR event_realm IS DISTINCT FROM $1 OR commit_json->>'event_ref' IS DISTINCT FROM envelope->>'event_id') AS present")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<Present>(&mut *conn)
        .await.map_err(PersistenceError::database)?.present;
    if unresolved_stream {
        return Err(refused(
            "Policy absence has unresolved sibling stream evidence",
        ));
    }
    // Other stream evidence cannot be silently treated as Realm-row absence.
    let other_stream = sql_query("SELECT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.state='committed' AND e.kind='ak.policy.set' AND e.envelope->'payload'->>'policy_id'=$1 AND (c.realm_id<>$2 OR c.stream_ref<>jsonb_build_object('kind','realm','realm_id',$2))) AS present")
        .bind::<Text,_>(payload.policy_id.as_str()).bind::<Text,_>(event.realm_id.as_str())
        .get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if other_stream {
        return Err(refused("Policy binding requires other governance evidence"));
    }
    let latest = sql_query("SELECT c.realm_id,c.commit_id AS current_commit_id,c.stream_position AS current_stream_position,e.envelope->>'event_id' AS current_event_id,e.envelope->'payload'->'value' AS value FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND e.kind='ak.policy.set' AND e.state='committed' AND e.envelope->'payload'->>'policy_id'=$2 ORDER BY c.stream_position DESC LIMIT 1")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.policy_id.as_str())
        .get_result::<PolicyRevisionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    match (&current, &latest) {
        (None, None) => {}
        (Some(row), Some(accepted))
            if row.current_commit_id == accepted.current_commit_id
                && row.current_stream_position == accepted.current_stream_position
                && row.current_event_id == accepted.current_event_id
                && row.value == accepted.value => {}
        _ => {
            return Err(refused(
                "Policy current does not match its last accepted write",
            ));
        }
    }
    let revision = current
        .map(|row| -> PersistenceResult<CurrentRevision> {
            Ok(CurrentRevision {
                commit_id: row.current_commit_id.parse().map_err(schema)?,
                stream_position: u64::try_from(row.current_stream_position).map_err(schema)?,
            })
        })
        .transpose()?;
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
fn require_supported_policy_kind(kind: arkret_wire::PolicyKind) -> PersistenceResult<()> {
    if matches!(
        kind,
        arkret_wire::PolicyKind::Agent | arkret_wire::PolicyKind::Applet
    ) {
        return Err(refused(
            "Management execution and delivery gates are not established",
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
        assert!(require_supported_policy_kind(document.policy_kind).is_err());
    }

    #[test]
    fn applet_policy_is_refused_until_execution_gates_are_established() {
        assert!(require_supported_policy_kind(arkret_wire::PolicyKind::Applet).is_err());
    }

    #[test]
    fn ordinary_policy_kinds_keep_their_existing_admission() {
        assert!(require_supported_policy_kind(arkret_wire::PolicyKind::Access).is_ok());
        assert!(require_supported_policy_kind(arkret_wire::PolicyKind::Join).is_ok());
    }
}
fn payload<T: serde::de::DeserializeOwned>(event: &Event) -> PersistenceResult<T> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(schema)?).map_err(schema)
}

/// Shared Realm Agent policy values may be carried by verified snapshots.
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
                && source
                    == &(CommitStreamRef::Realm {
                        realm_id: realm.clone(),
                    }) =>
        {
            Ok(())
        }
        _ => Err(schema(
            "Policy current has no proved shared Agent Realm binding",
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
                require_supported_policy_kind(document.policy_kind)?;
                if document
                    .realm_id
                    .as_ref()
                    .is_some_and(|id| id != &event.realm_id)
                {
                    return Err(schema(
                        "Policy document Realm differs from its accepting Realm",
                    ));
                }
                return Ok(Some(WireResourceSelector::realm(event.realm_id.clone())));
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

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    match event.kind {
        EventKind::PolicySet => {
            let payload: PolicySetStatePayload = payload(event)?;
            payload.validate().map_err(schema)?;
            let value = serde_json::to_value(&payload.value).map_err(schema)?;
            let count=sql_query("INSERT INTO policy_current_results(realm_id,policy_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(policy_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE policy_current_results.realm_id=EXCLUDED.realm_id AND policy_current_results.current_stream_position<EXCLUDED.current_stream_position AND (policy_current_results.value->>'schema' IS DISTINCT FROM 'ak.schema.policy.v1' OR COALESCE(policy_current_results.value->>'policy_kind','') NOT IN ('agent','applet') OR (EXCLUDED.value->>'schema'='ak.schema.policy.v1' AND EXCLUDED.value->>'policy_kind'=policy_current_results.value->>'policy_kind'))")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.policy_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
                .bind::<BigInt,_>(commit.stream_position as i64).bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(&value)
                .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if count != 1 {
                return Err(refused(
                    "Policy current cannot cross Realm or move backwards",
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
