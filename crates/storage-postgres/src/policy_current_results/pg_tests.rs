//! Imported accepted-history fixtures exercise the real PostgreSQL CAS boundary.
use arkret_event_draft::EventPayloadExt as _;
use diesel::sql_types::{Binary, Nullable};
use serde_json::json;

use super::*;
use crate::test_database::TestDatabase;

fn realm() -> arkret_wire::RealmId {
    event(EventKind::RealmCreate, json!({}), 0).realm_id
}

fn policy(revision: Option<CurrentRevision>, agent: bool) -> PolicySetStatePayload {
    let mut value = json!({
        "policy_id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
        "value": {
            "schema":"ak.schema.policy.v1", "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "realm_id":realm(), "policy_kind": if agent { "agent" } else { "access" },
            "rules":[{"rule_id":"allow", "kind":"action", "effect":"allow", "actions":["ak.message.create"]}],
            "default_effect":"allow", "created_by":{"kind":"account", "account_id":{
                "principal_id":"ak:did_core:web:controller.example", "station_id":"ak:did_core:web:station.example"
            }}, "created_at":"2026-10-05T12:00:00.000Z"
        }
    });
    if agent {
        value["expected_revision"] = json!(revision);
    }
    serde_json::from_value(value).unwrap()
}

fn event(kind: EventKind, payload: Value, position: u64) -> Event {
    arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        if kind == EventKind::RealmCreate {
            arkret_wire::ScopeRef::RealmGenesis
        } else {
            arkret_wire::ScopeRef::Realm { realm_id: realm() }
        },
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
        payload,
        chrono::DateTime::parse_from_rfc3339("2026-10-05T12:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
            + chrono::TimeDelta::seconds(position as i64),
    )
    .unwrap()
}

fn commit(event: &Event, position: u64) -> RealmCommit {
    RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: arkret_wire::RealmCommitId::from_digest([position as u8 + 80; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        stream_position: position,
        previous_commit_ref: position
            .checked_sub(1)
            .map(|p| arkret_wire::RealmCommitId::from_digest([p as u8 + 80; 32])),
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
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32))).unwrap(),
            created_at: event.created_at,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
        },
    }
}

fn revision(commit: &RealmCommit) -> CurrentRevision {
    CurrentRevision {
        commit_id: commit.commit_id.clone(),
        stream_position: commit.stream_position,
    }
}

async fn insert_history(conn: &mut AsyncPgConnection, event: &Event, commit: &RealmCommit) {
    sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,'committed',$9)")
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).bind::<Binary,_>(event.event_id.digest_bytes().to_vec())
        .bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(event.realm_id.as_str())
        .bind::<Jsonb,_>(json!(event.scope_ref)).bind::<Text,_>(event.kind.as_str())
        .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(event).unwrap()).bind::<Jsonb,_>(json!(event))
        .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(commit.realm_id.as_str())
        .bind::<Text,_>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap())
        .bind::<Jsonb,_>(json!(commit.stream_ref)).bind::<BigInt,_>(commit.stream_position as i64)
        .bind::<Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id|id.as_str()))
        .bind::<Jsonb,_>(json!(commit)).bind::<Timestamptz,_>(commit.committed_at)
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).execute(&mut *conn).await.unwrap();
}

async fn seed_genesis(conn: &mut AsyncPgConnection) {
    sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,'ak:did_core:web:station.example','{}')")
        .bind::<Text,_>(realm().as_str()).execute(&mut *conn).await.unwrap();
    let genesis = event(EventKind::RealmCreate, json!({}), 0);
    insert_history(conn, &genesis, &commit(&genesis, 0)).await;
}

/// Accepted-history import for the genuine parent Circle creation. The
/// original Circle current materializer supplies its event-derived identity;
/// an empty Circle stream is never proved by an arbitrary CircleId alone.
/// This fixture does not exercise producer verification or Circle-create HTTP.
async fn seed_management_circle(conn: &mut AsyncPgConnection) -> arkret_wire::CircleId {
    let create = event(
        EventKind::CircleCreate,
        json!({"object": {
            "schema":"ak.schema.circle.v1", "realm_id":realm(),
            "title":"Management policy history", "summary":null,
            "display":{"short_name":"Management","color_token":"slate","symbol":{"glyph":"shield"}},
            "directory_visibility":"members", "join_rule":"invite", "history_access":"since_join",
            "state":"active", "created_by":event(EventKind::RealmCreate,json!({}),0).actor_id,
            "created_at":"2026-10-05T12:00:01.000Z"
        }}),
        1,
    );
    let payload = create.as_circle_create().unwrap();
    assert!(payload.object.id.is_none());
    assert_eq!(payload.object.realm_id, create.realm_id);
    assert_eq!(payload.object.created_by, create.actor_id);
    assert_eq!(payload.object.created_at, create.created_at);
    let basis = commit(&create, 1);
    insert_history(conn, &create, &basis).await;
    crate::circle_current_results::commit_in_connection(conn, &create, &basis)
        .await
        .unwrap();
    let circle = arkret_wire::CircleId::from_event_id(&create.event_id);
    require_complete_policy_stream(
        conn,
        &realm(),
        &CommitStreamRef::Realm { realm_id: realm() },
        Some(&revision(&basis)),
    )
    .await
    .unwrap();
    require_complete_policy_stream(
        conn,
        &realm(),
        &CommitStreamRef::Circle {
            realm_id: realm(),
            circle_id: circle.clone(),
        },
        None,
    )
    .await
    .unwrap();
    circle
}

/// Imported accepted history exercises the real scoped fanout gate; the joint
/// suite supplies the producer verification and complete management HTTP path.
#[tokio::test]
async fn circle_management_policy_fanout_accepts_an_original_source_submission() {
    // Imported signed-history shape isolates the fanout kind gate. The joint
    // test separately exercises real authoring, admission and Circle privacy.
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let circle = seed_management_circle(&mut conn).await;
    let accepted = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::PolicySet.as_str(),
        arkret_wire::ScopeRef::Circle {
            realm_id: realm(),
            circle_id: circle.clone(),
        },
        event(EventKind::RealmCreate, json!({}), 0).actor_id,
        json!(management_policy(None, "deny")),
        chrono::DateTime::parse_from_rfc3339("2026-10-05T12:00:02Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    )
    .unwrap();
    let mut basis = commit(&accepted, 2);
    basis.stream_ref = CommitStreamRef::Circle {
        realm_id: realm(),
        circle_id: circle,
    };
    basis.stream_position = 0;
    basis.previous_commit_ref = None;
    admit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let source: arkret_wire::EventAdmissionSubmission =
        serde_json::from_value(json!({"event":accepted})).unwrap();
    let targets = crate::realm_fanout::plan_realm_fanout_in_connection(
        &mut conn,
        &source.event,
        &basis,
        &"ak:did_core:web:station.example".parse().unwrap(),
        Some(&source),
        &[],
        basis.committed_at.timestamp_millis(),
    )
    .await
    .unwrap_or_else(|error| panic!("{}", error.into_persistence()));
    assert_eq!(
        targets, 0,
        "an empty Circle never falls back to Realm members"
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

/// Imported accepted history isolates the classifier; this is not a claim
/// that producer verification or the complete management HTTP path ran.
#[tokio::test]
async fn owned_agent_classification_survives_missing_projections_and_binds_exact_station() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    seed_genesis(&mut conn).await;
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let provision = event(
        EventKind::AgentProvision,
        json!({
            "schema":"ak.schema.agent_provision.v1", "agent_id":agent.principal_id,
            "controller_principal_id":"ak:did_core:web:controller.example",
            "principal_control_realm_id":realm(),
            "controller_authorization_ref":"did:web:agent.example#managed-controller",
            "agent_slug":"classification-agent", "accountability_scope":"agent_operator",
            "requested_scope_digest":format!("sha256:{}","b".repeat(64)),
            "selector_visibility":"private", "created_at":"2026-10-05T12:00:01.000Z"
        }),
        1,
    );
    let payload: arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload =
        serde_json::from_value(json!(provision.payload)).unwrap();
    payload.validate().unwrap();
    payload.validate_envelope(&provision).unwrap();
    let classification = crate::realm_authorization_cut::is_owned_agent_in_connection;
    assert!(!classification(&mut conn, &realm(), &agent).await.unwrap());
    insert_history(&mut conn, &provision, &commit(&provision, 1)).await;
    assert!(classification(&mut conn, &realm(), &agent).await.unwrap());
    let mut foreign = agent.clone();
    foreign.station_id = "ak:did_core:web:foreign.example".parse().unwrap();
    assert!(!classification(&mut conn, &realm(), &foreign).await.unwrap());
    assert!(
        !classification(
            &mut conn,
            &realm(),
            provision.actor_id.as_account_id().unwrap()
        )
        .await
        .unwrap()
    );
    let error = crate::realm_authorization_cut::owned_controller_in_connection(
        &mut conn,
        &realm(),
        &arkret_wire::ActorId::account(agent.clone()),
        provision.created_at,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("current controller binding is unavailable"),
        "{error}"
    );
    drop(conn);
    let mut reopened = database.pool().get().await.unwrap();
    assert!(
        classification(&mut reopened, &realm(), &agent)
            .await
            .unwrap()
    );
}

async fn check(
    conn: &mut AsyncPgConnection,
    payload: &PolicySetStatePayload,
    position: u64,
) -> PersistenceResult<()> {
    let candidate = event(EventKind::PolicySet, json!(payload), position);
    check_policy_cas_in_connection(conn, &candidate, &commit(&candidate, position), payload).await
}

fn management_policy(revision: Option<CurrentRevision>, effect: &str) -> PolicySetStatePayload {
    let mut payload = policy(revision, true);
    let PolicySetValue::Governance(document) = &mut payload.value else {
        unreachable!()
    };
    document.rules = serde_json::from_value(json!([{
        "rule_id":"execution", "kind":"agent", "effect":effect,
        "agent_target":{"kind":"all"}, "agent_operations":["execute"]
    }]))
    .unwrap();
    payload
}

/// Imported accepted current rows isolate reference matching at a fixed cut.
/// Missing/expired references are non-matches; malformed current is not absence.
#[tokio::test]
async fn governance_approval_reference_matching_distinguishes_absence_from_corruption() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    seed_genesis(&mut conn).await;
    let config = event(
        EventKind::PolicyAction,
        json!({
            "policy_id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "value":{"action":"ak.message.create","approval_required":true,
                "approval_quorum":7,"policy_scope":realm()}
        }),
        1,
    );
    insert_history(&mut conn, &config, &commit(&config, 1)).await;
    commit_in_connection(&mut conn, &config, &commit(&config, 1))
        .await
        .unwrap();
    let candidate = event(EventKind::MessageCreate, json!({}), 10);
    let target: WireResourceSelector = serde_json::from_value(json!({
        "kind":"realm", "realm_id":realm()
    }))
    .unwrap();
    let facts = coland_storage::OperationFacts::default();
    let at = candidate.created_at;
    assert_eq!(
        crate::policy_action_admission::current_quorum(
            &mut conn,
            &candidate,
            CapabilityActionId::MessageCreate,
            &target,
            &facts,
            at,
        )
        .await
        .unwrap(),
        None
    );

    let mut payload = policy(None, false);
    let PolicySetValue::Governance(document) = &mut payload.value else {
        unreachable!()
    };
    document.not_before = Some(at);
    document.expires_at = Some(at + chrono::TimeDelta::seconds(1));
    let accepted = event(EventKind::PolicySet, json!(payload), 2);
    insert_history(&mut conn, &accepted, &commit(&accepted, 2)).await;
    commit_in_connection(&mut conn, &accepted, &commit(&accepted, 2))
        .await
        .unwrap();
    for (time, expected) in [
        (at - chrono::TimeDelta::seconds(1), None),
        (at, Some(7)),
        (at + chrono::TimeDelta::seconds(1), None),
    ] {
        assert_eq!(
            crate::policy_action_admission::current_quorum(
                &mut conn,
                &candidate,
                CapabilityActionId::MessageCreate,
                &target,
                &facts,
                time,
            )
            .await
            .unwrap(),
            expected
        );
    }
    assert_eq!(
        crate::policy_action_admission::current_quorum(
            &mut conn,
            &candidate,
            CapabilityActionId::StrandMove,
            &target,
            &facts,
            at,
        )
        .await
        .unwrap(),
        None
    );

    // A Realm-local row remains applicable when the Policy reference expires.
    let independent = event(
        EventKind::PolicyAction,
        json!({
            "action_id":"independent_review", "value":{"action":"ak.message.create",
                "approval_required":true,"approval_quorum":2,"policy_scope":realm()}
        }),
        3,
    );
    insert_history(&mut conn, &independent, &commit(&independent, 3)).await;
    commit_in_connection(&mut conn, &independent, &commit(&independent, 3))
        .await
        .unwrap();
    assert_eq!(
        crate::policy_action_admission::current_quorum(
            &mut conn,
            &candidate,
            CapabilityActionId::MessageCreate,
            &target,
            &facts,
            at + chrono::TimeDelta::seconds(1),
        )
        .await
        .unwrap(),
        Some(2)
    );
    sql_query("UPDATE policy_current_results SET value='{}'::jsonb WHERE realm_id=$1")
        .bind::<Text, _>(realm().as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    let error = crate::policy_action_admission::current_quorum(
        &mut conn,
        &candidate,
        CapabilityActionId::MessageCreate,
        &target,
        &facts,
        at,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    assert!(!error.to_string().contains("ak:policy:"));
    sql_query("DELETE FROM policy_current_results WHERE realm_id=$1")
        .bind::<Text, _>(realm().as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    sql_query("UPDATE policy_action_current_results SET value=value-'approval_required' WHERE realm_id=$1")
        .bind::<Text,_>(realm().as_str()).execute(&mut conn).await.unwrap();
    assert_eq!(
        crate::policy_action_admission::current_quorum(
            &mut conn,
            &candidate,
            CapabilityActionId::MessageCreate,
            &target,
            &facts,
            at,
        )
        .await
        .unwrap_err()
        .conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
}

#[tokio::test]
async fn management_absence_requires_authoritative_complete_history() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    assert!(
        read_agent_management_policies_in_connection(&mut conn, &realm())
            .await
            .is_err()
    );
    seed_genesis(&mut conn).await;
    assert!(
        read_agent_management_policies_in_connection(&mut conn, &realm())
            .await
            .unwrap()
            .is_empty()
    );
    let payload = management_policy(None, "deny");
    let accepted = event(EventKind::PolicySet, json!(payload), 1);
    // A private current row without its accepted Event cannot prove a policy set.
    commit_in_connection(&mut conn, &accepted, &commit(&accepted, 1))
        .await
        .unwrap();
    assert!(
        read_agent_management_policies_in_connection(&mut conn, &realm())
            .await
            .is_err()
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_current_must_match_last_accepted_policy_and_cannot_disappear() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let payload = management_policy(None, "deny");
    let accepted = event(EventKind::PolicySet, json!(payload), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let policies = read_agent_management_policies_in_connection(&mut conn, &realm())
        .await
        .unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(json!(policies[0]), json!(payload.value));
    for update in [
        "UPDATE policy_current_results SET current_stream_position=0",
        "UPDATE policy_current_results SET current_commit_id='wrong-commit'",
        "UPDATE policy_current_results SET current_event_id='wrong-event'",
        "UPDATE policy_current_results SET value=jsonb_set(value,'{default_effect}','\"deny\"')",
        "UPDATE policy_current_results SET realm_id='another-realm'",
    ] {
        sql_query("SAVEPOINT tamper")
            .execute(&mut conn)
            .await
            .unwrap();
        sql_query(update).execute(&mut conn).await.unwrap();
        assert!(
            read_agent_management_policies_in_connection(&mut conn, &realm())
                .await
                .is_err(),
            "{update}"
        );
        sql_query("ROLLBACK TO SAVEPOINT tamper")
            .execute(&mut conn)
            .await
            .unwrap();
    }
    sql_query("DELETE FROM policy_current_results")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        read_agent_management_policies_in_connection(&mut conn, &realm())
            .await
            .is_err()
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_unrelated_gap_is_isolated_but_required_scope_and_realm_fork_refuse() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    sql_query("SAVEPOINT tamper")
        .execute(&mut conn)
        .await
        .unwrap();
    let circle =
        arkret_wire::CircleId::from_event_id(&event(EventKind::RealmCreate, json!({}), 0).event_id);
    sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) VALUES('opaque-management-sibling',$1,'sibling',$2,0,NULL,NULL,0,'{}',now())")
        .bind::<Text,_>(realm().as_str()).bind::<Jsonb,_>(json!(CommitStreamRef::Circle { realm_id:realm(), circle_id:circle.clone() })).execute(&mut conn).await.unwrap();
    assert!(
        read_agent_management_policies_in_connection(&mut conn, &realm())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        read_scoped_agent_management_policies_in_connection(&mut conn, &realm(), Some(&circle))
            .await
            .is_err()
    );
    sql_query("ROLLBACK TO SAVEPOINT tamper")
        .execute(&mut conn)
        .await
        .unwrap();
    sql_query(
        "UPDATE realm_commits SET commit_json=jsonb_set(commit_json,'{commit_id}','\"fork\"')",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(
        read_agent_management_policies_in_connection(&mut conn, &realm())
            .await
            .is_err()
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_non_realm_policy_source_is_unresolved_not_absent() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let payload = management_policy(None, "deny");
    let accepted = event(EventKind::PolicySet, json!(payload), 1);
    let mut basis = commit(&accepted, 1);
    basis.stream_ref = CommitStreamRef::Circle {
        realm_id: realm(),
        circle_id: arkret_wire::CircleId::from_event_id(&accepted.event_id),
    };
    basis.stream_position = 0;
    basis.previous_commit_ref = None;
    insert_history(&mut conn, &accepted, &basis).await;
    let error = read_agent_management_policies_in_connection(&mut conn, &realm())
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("unresolved governance evidence"),
        "{error}"
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_policy_id_cannot_hide_its_agent_history_by_changing_family() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let first = management_policy(None, "deny");
    let accepted = event(EventKind::PolicySet, json!(first), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let rebound = policy(None, false);
    let accepted = event(EventKind::PolicySet, json!(rebound), 2);
    let basis = commit(&accepted, 2);
    insert_history(&mut conn, &accepted, &basis).await;
    sql_query("UPDATE policy_current_results SET current_commit_id=$1,current_stream_position=$2,current_event_id=$3,value=$4")
        .bind::<Text,_>(basis.commit_id.as_str()).bind::<BigInt,_>(basis.stream_position as i64)
        .bind::<Text,_>(accepted.event_id.as_str()).bind::<Jsonb,_>(json!(rebound.value)).execute(&mut conn).await.unwrap();
    assert!(
        read_agent_management_policies_in_connection(&mut conn, &realm())
            .await
            .is_err()
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_reader_waits_for_policy_writer_and_observes_committed_deny() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut writer = pool.get().await.unwrap();
    seed_genesis(&mut writer).await;
    sql_query("BEGIN").execute(&mut writer).await.unwrap();
    crate::realm_authorization_cut::lock_realm_authorization_cut(&mut writer, &realm())
        .await
        .unwrap();
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let mode_payload = arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        agent_account_id: agent,
        controller_account_id: event(EventKind::RealmCreate, json!({}), 0)
            .actor_id
            .as_account_id()
            .unwrap()
            .clone(),
        interaction_mode:
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
        expected_revision: None,
    };
    let mode = event(EventKind::AgentInteractionSet, json!(mode_payload), 1);
    let mode_commit = commit(&mode, 1);
    insert_history(&mut writer, &mode, &mode_commit).await;
    crate::agent_interaction_current_results::project_in_connection(
        &mut writer,
        &mode,
        &mode_commit,
    )
    .await
    .unwrap();
    let payload = management_policy(None, "deny");
    let accepted = event(EventKind::PolicySet, json!(payload), 2);
    let basis = commit(&accepted, 2);
    insert_history(&mut writer, &accepted, &basis).await;
    commit_in_connection(&mut writer, &accepted, &basis)
        .await
        .unwrap();
    let other_pool = pool.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
    let reader = tokio::spawn(async move {
        let mut reader = other_pool.get().await.unwrap();
        sql_query("BEGIN").execute(&mut reader).await.unwrap();
        started_tx.send(()).unwrap();
        let policies = read_agent_management_policies_in_connection(&mut reader, &realm())
            .await
            .unwrap();
        done_tx.send(()).unwrap();
        let controller = arkret_wire::AccountId::new(
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        );
        let agent = arkret_wire::AccountId::new(
            "ak:did_core:web:agent.example".parse().unwrap(),
            controller.station_id.clone(),
        );
        let actor = arkret_wire::ActorId::account(agent.clone());
        let target = arkret_wire::WireResourceSelector::realm(realm());
        let facts = coland_storage::OperationFacts::default();
        let operation = coland_storage::AuthorizationOperation {
            actor: &actor,
            actions: &["ak.message.create"],
            target: &target,
            facts: &facts,
            at: chrono::Utc::now(),
        };
        let candidate = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.message.create",
            arkret_wire::ScopeRef::Realm { realm_id: realm() },
            actor.clone(),
            json!({}),
            operation.at,
        )
        .unwrap();
        let verdict = crate::agent_management_admission::executable_actions_in_connection(
            &mut reader,
            &realm(),
            &controller,
            &agent,
            &operation,
            &candidate,
        )
        .await;
        assert_eq!(policies[0].rules[0].effect, arkret_wire::PolicyEffect::Deny);
        assert!(verdict.unwrap().is_empty());
        sql_query("ROLLBACK").execute(&mut reader).await.unwrap();
    });
    started_rx.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut done_rx)
            .await
            .is_err()
    );
    sql_query("COMMIT").execute(&mut writer).await.unwrap();
    reader.await.unwrap();
}

#[tokio::test]
async fn first_write_needs_a_complete_held_prefix_and_rolls_back_without_effects() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let payload = policy(None, true);
    check(&mut conn, &payload, 1).await.unwrap();
    sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) VALUES('opaque-sibling',$1,'sibling','{\"kind\":\"circle\"}',0,NULL,NULL,0,'{}',now())")
        .bind::<Text,_>(realm().as_str()).execute(&mut conn).await.unwrap();
    assert!(check(&mut conn, &payload, 1).await.is_err());
    sql_query("DELETE FROM realm_commits WHERE commit_id='opaque-sibling'")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &payload, 2).await.is_err());
    let candidate = event(EventKind::PolicySet, json!(payload), 1);
    let mut wrong_predecessor = commit(&candidate, 1);
    wrong_predecessor.previous_commit_ref = Some(arkret_wire::RealmCommitId::from_digest([99; 32]));
    assert!(
        check_policy_cas_in_connection(&mut conn, &candidate, &wrong_predecessor, &payload)
            .await
            .is_err()
    );
    sql_query("UPDATE realm_commits SET event_pk=NULL WHERE stream_position=0")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &payload, 1).await.is_err());
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
    let absent = sql_query("SELECT NOT EXISTS(SELECT 1 FROM policy_current_results) AND NOT EXISTS(SELECT 1 FROM realm_commits) AS present")
        .get_result::<Present>(&mut conn).await.unwrap();
    assert!(absent.present);
}

#[tokio::test]
async fn exact_revision_last_accepted_row_and_terminal_policy_binding_are_required() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let first = policy(None, true);
    let accepted = event(EventKind::PolicySet, json!(first), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let exact = policy(Some(revision(&basis)), true);
    check(&mut conn, &exact, 2).await.unwrap();
    sql_query("UPDATE policy_current_results SET realm_id='foreign-realm'")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &exact, 2).await.is_err());
    sql_query("UPDATE policy_current_results SET realm_id=$1")
        .bind::<Text, _>(realm().as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &policy(None, true), 2).await.is_err());
    let mut wrong = exact.clone();
    wrong
        .expected_revision
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .stream_position = 0;
    assert!(check(&mut conn, &wrong, 2).await.is_err());
    wrong = exact.clone();
    wrong
        .expected_revision
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .commit_id = arkret_wire::RealmCommitId::from_digest([99; 32]);
    assert!(check(&mut conn, &wrong, 2).await.is_err());
    let other_family = policy(None, false);
    assert!(check(&mut conn, &other_family, 2).await.is_err());
    let rebound = event(EventKind::PolicySet, json!(other_family), 2);
    assert!(
        commit_in_connection(&mut conn, &rebound, &commit(&rebound, 2))
            .await
            .is_err()
    );
    sql_query(
        "UPDATE policy_current_results SET value=jsonb_set(value,'{default_effect}','\"deny\"')",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(check(&mut conn, &exact, 2).await.is_err());
    sql_query("DELETE FROM policy_current_results")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &policy(None, true), 2).await.is_err());
    assert!(check(&mut conn, &other_family, 2).await.is_err());
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn exact_accepted_retry_does_not_recheck_the_later_current_revision() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let first = policy(None, true);
    let accepted = event(EventKind::PolicySet, json!(first), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let next = policy(Some(revision(&basis)), true);
    let accepted_next = event(EventKind::PolicySet, json!(next), 2);
    let next_commit = commit(&accepted_next, 2);
    insert_history(&mut conn, &accepted_next, &next_commit).await;
    commit_in_connection(&mut conn, &accepted_next, &next_commit)
        .await
        .unwrap();
    check_policy_cas_in_connection(&mut conn, &accepted, &basis, &first)
        .await
        .unwrap();
    let later_candidate = commit(&accepted, 3);
    check_policy_cas_in_connection(&mut conn, &accepted, &later_candidate, &first)
        .await
        .unwrap();
    let mut changed_event = accepted.clone();
    changed_event.created_at += chrono::TimeDelta::milliseconds(1);
    assert!(
        check_policy_cas_in_connection(&mut conn, &changed_event, &basis, &first)
            .await
            .is_err()
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_stale_editor_observes_the_winners_revision_after_the_lock() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut winner = pool.get().await.unwrap();
    seed_genesis(&mut winner).await;
    let first = policy(None, true);
    let accepted = event(EventKind::PolicySet, json!(first), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut winner, &accepted, &basis).await;
    commit_in_connection(&mut winner, &accepted, &basis)
        .await
        .unwrap();
    let update = policy(Some(revision(&basis)), true);
    sql_query("BEGIN").execute(&mut winner).await.unwrap();
    check(&mut winner, &update, 2).await.unwrap();
    let pool = pool.clone();
    let stale = update.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let reader = tokio::spawn(async move {
        let mut conn = pool.get().await.unwrap();
        sql_query("BEGIN").execute(&mut conn).await.unwrap();
        started_tx.send(()).unwrap();
        let result = check(&mut conn, &stale, 3).await;
        sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
        result
    });
    started_rx.await.unwrap();
    let next = event(EventKind::PolicySet, json!(update), 2);
    let next_commit = commit(&next, 2);
    insert_history(&mut winner, &next, &next_commit).await;
    commit_in_connection(&mut winner, &next, &next_commit)
        .await
        .unwrap();
    sql_query("COMMIT").execute(&mut winner).await.unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(10), reader)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        error.to_string().contains("expected_revision differs"),
        "{error}"
    );
    let latest = sql_query("SELECT realm_id,current_commit_id,current_stream_position,current_event_id,value FROM policy_current_results")
        .get_result::<PolicyRevisionRow>(&mut winner).await.unwrap();
    assert_eq!(latest.current_commit_id, next_commit.commit_id.as_str());
}

#[tokio::test]
async fn management_authorization_uses_accepted_current_and_refuses_missing_projection() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let controller = arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        controller.station_id.clone(),
    );
    let actions = ["ak.message.create".to_owned()];
    let resources = [arkret_wire::WireResourceSelector::realm(realm())];
    crate::agent_management_admission::require_authorization_in_connection(
        &mut conn,
        &realm(),
        &controller,
        &agent,
        &actions,
        &resources,
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    let mut payload = json!(policy(None, true));
    payload["value"]["rules"] = json!([{
        "rule_id":"ban", "kind":"agent", "agent_target":{"kind":"controller","controller_account_id":controller},
        "agent_operations":["authorize"], "effect":"deny"
    }]);
    let accepted = event(EventKind::PolicySet, payload, 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let error = crate::agent_management_admission::require_authorization_in_connection(
        &mut conn,
        &realm(),
        &controller,
        &agent,
        &actions,
        &resources,
        chrono::Utc::now(),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("forbids authorization"),
        "{error}"
    );
    sql_query("DELETE FROM policy_current_results")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        crate::agent_management_admission::require_authorization_in_connection(
            &mut conn,
            &realm(),
            &controller,
            &agent,
            &actions,
            &resources,
            chrono::Utc::now(),
        )
        .await
        .is_err()
    );
    let empty =
        sql_query("SELECT NOT EXISTS(SELECT 1 FROM capability_grant_current_results) AS present")
            .get_result::<Present>(&mut conn)
            .await
            .unwrap();
    assert!(empty.present);
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

/// Imported accepted history exercises the actual grant-admission management
/// hook and current lookup, not the full signed grant HTTP consumer.
#[tokio::test]
async fn join_only_current_preserves_scoped_authorization_and_missing_current_refuses() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let controller = arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        controller.station_id.clone(),
    );
    let resources = [
        arkret_wire::WireResourceSelector::strand(
            realm(),
            "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
                .parse()
                .unwrap(),
        ),
        arkret_wire::WireResourceSelector::space(
            realm(),
            "ak:space:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
                .parse()
                .unwrap(),
        ),
    ];
    for install_ban in [false, true] {
        if install_ban {
            let mut payload = json!(policy(None, true));
            payload["value"]["rules"] = json!([{
                "rule_id":"new_agents", "kind":"agent", "agent_target":{"kind":"all"},
                "agent_operations":["join"], "effect":"deny"
            }]);
            let accepted = event(EventKind::PolicySet, payload, 1);
            let basis = commit(&accepted, 1);
            insert_history(&mut conn, &accepted, &basis).await;
            commit_in_connection(&mut conn, &accepted, &basis)
                .await
                .unwrap();
        }
        for resource in &resources {
            for action in ["ak.message.create", "ak.realm.owner"] {
                crate::agent_management_admission::require_authorization_in_connection(
                    &mut conn,
                    &realm(),
                    &controller,
                    &agent,
                    &[action.to_owned()],
                    std::slice::from_ref(resource),
                    chrono::Utc::now(),
                )
                .await
                .unwrap();
            }
        }
    }
    sql_query("DELETE FROM policy_current_results")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        crate::agent_management_admission::require_authorization_in_connection(
            &mut conn,
            &realm(),
            &controller,
            &agent,
            &["ak.message.create".to_owned()],
            &resources,
            chrono::Utc::now(),
        )
        .await
        .is_err()
    );
    let empty =
        sql_query("SELECT NOT EXISTS(SELECT 1 FROM capability_grant_current_results) AS present")
            .get_result::<Present>(&mut conn)
            .await
            .unwrap();
    assert!(empty.present);
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_join_rechecks_current_ban_and_explicit_lifting_without_membership_effects() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    let controller = arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        controller.station_id.clone(),
    );
    let at = chrono::Utc::now();
    let candidate = event(
        EventKind::MemberState,
        json!({"member_id":arkret_wire::ActorId::account(agent.clone()),"membership":"join","reason":"self"}),
        1,
    );
    assert!(
        crate::agent_management_admission::require_join_in_connection(
            &mut conn,
            &realm(),
            &controller,
            &agent,
            at,
            &candidate,
            None,
        )
        .await
        .is_err()
    );
    seed_genesis(&mut conn).await;
    crate::agent_management_admission::require_join_in_connection(
        &mut conn,
        &realm(),
        &controller,
        &agent,
        at,
        &candidate,
        None,
    )
    .await
    .unwrap();
    let mut payload = management_policy(None, "deny");
    let PolicySetValue::Governance(document) = &mut payload.value else {
        unreachable!()
    };
    document.rules[0].agent_operations = Some(vec![
        arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation::Join,
    ]);
    let accepted = event(EventKind::PolicySet, json!(payload), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let error = crate::agent_management_admission::require_join_in_connection(
        &mut conn,
        &realm(),
        &controller,
        &agent,
        at,
        &candidate,
        None,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("forbids joining"), "{error}");
    payload.expected_revision = Some(Some(revision(&basis)));
    let PolicySetValue::Governance(document) = &mut payload.value else {
        unreachable!()
    };
    document.rules[0].effect = arkret_wire::PolicyEffect::Allow;
    let lifted = event(EventKind::PolicySet, json!(payload), 2);
    let next = commit(&lifted, 2);
    insert_history(&mut conn, &lifted, &next).await;
    commit_in_connection(&mut conn, &lifted, &next)
        .await
        .unwrap();
    crate::agent_management_admission::require_join_in_connection(
        &mut conn,
        &realm(),
        &controller,
        &agent,
        at,
        &candidate,
        None,
    )
    .await
    .unwrap();
    sql_query("DELETE FROM policy_current_results")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        crate::agent_management_admission::require_join_in_connection(
            &mut conn,
            &realm(),
            &controller,
            &agent,
            at,
            &candidate,
            None,
        )
        .await
        .is_err()
    );
    let untouched = sql_query("SELECT NOT EXISTS(SELECT 1 FROM member_state_current_results) AND NOT EXISTS(SELECT 1 FROM mls_group_current_results) AS present")
        .get_result::<Present>(&mut conn).await.unwrap();
    assert!(untouched.present);
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_member_event_read_uses_current_and_never_assumes_missing_projection_is_allow() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let controller = arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        controller.station_id.clone(),
    );
    let at = chrono::Utc::now();
    crate::agent_management_admission::require_member_event_read_in_connection(
        &mut conn,
        &realm(),
        None,
        &controller,
        &agent,
        at,
    )
    .await
    .unwrap();
    let mut payload = management_policy(None, "deny");
    let PolicySetValue::Governance(document) = &mut payload.value else {
        unreachable!()
    };
    document.rules[0].agent_operations = Some(vec![
        arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation::Read,
    ]);
    let accepted = event(EventKind::PolicySet, json!(payload), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let error = crate::agent_management_admission::require_member_event_read_in_connection(
        &mut conn,
        &realm(),
        None,
        &controller,
        &agent,
        at,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("forbids Event reading"),
        "{error}"
    );
    sql_query("DELETE FROM policy_current_results")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        crate::agent_management_admission::require_member_event_read_in_connection(
            &mut conn,
            &realm(),
            None,
            &controller,
            &agent,
            at,
        )
        .await
        .is_err()
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_member_event_read_checks_accepted_policy_in_a_read_only_snapshot() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let mut payload = management_policy(None, "deny");
    let PolicySetValue::Governance(document) = &mut payload.value else {
        unreachable!()
    };
    document.rules[0].agent_operations = Some(vec![
        arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation::Read,
    ]);
    let accepted = event(EventKind::PolicySet, json!(payload), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    sql_query("COMMIT").execute(&mut conn).await.unwrap();
    sql_query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut conn)
        .await
        .unwrap();
    let controller = arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        controller.station_id.clone(),
    );
    let error = crate::agent_management_admission::require_member_event_read_in_connection(
        &mut conn,
        &realm(),
        None,
        &controller,
        &agent,
        chrono::Utc::now(),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("forbids Event reading"),
        "{error}"
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

/// Imported canonical accepted sources exercise the actual Policy admission/CAS
/// and materializer hooks. Producer signatures/full HTTP are a separate suite.
#[tokio::test]
async fn management_writer_all_operations_realm_circle_and_review_carrier_boundary() {
    use arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation;
    use arkret_policy::agent_management::{AgentManagementContext, evaluate_agent_management};
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let controller = arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        controller.station_id.clone(),
    );
    let circle = seed_management_circle(&mut conn).await;
    for operation in [
        AgentPolicyOperation::Join,
        AgentPolicyOperation::Authorize,
        AgentPolicyOperation::Execute,
        AgentPolicyOperation::Read,
        AgentPolicyOperation::Deliver,
        AgentPolicyOperation::Publish,
        AgentPolicyOperation::Serve,
    ] {
        for in_circle in [false, true] {
            sql_query("SAVEPOINT candidate")
                .execute(&mut conn)
                .await
                .unwrap();
            let mut payload = json!(policy(None, true));
            payload["value"]["rules"] = json!([{"rule_id":"managed","kind":"agent","agent_target":{"kind":"all"},"agent_operations":[operation],"effect":"deny"}]);
            payload["value"]["default_effect"] = json!("allow");
            let scope = if in_circle {
                arkret_wire::ScopeRef::Circle {
                    realm_id: realm(),
                    circle_id: circle.clone(),
                }
            } else {
                arkret_wire::ScopeRef::Realm { realm_id: realm() }
            };
            let accepted = arkret_wire::test_support::raw_event_for_actor_at(
                EventKind::PolicySet.as_str(),
                scope,
                arkret_wire::ActorId::account(controller.clone()),
                payload,
                chrono::DateTime::parse_from_rfc3339("2026-10-05T12:00:02Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            )
            .unwrap();
            let mut basis = commit(&accepted, 2);
            if in_circle {
                basis.stream_ref = CommitStreamRef::Circle {
                    realm_id: realm(),
                    circle_id: circle.clone(),
                };
                basis.stream_position = 0;
                basis.previous_commit_ref = None;
            }
            let target = admit_in_connection(&mut conn, &accepted, &basis)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(target.circle_id.is_some(), in_circle);
            insert_history(&mut conn, &accepted, &basis).await;
            commit_in_connection(&mut conn, &accepted, &basis)
                .await
                .unwrap();
            let policies = read_scoped_agent_management_policies_in_connection(
                &mut conn,
                &realm(),
                in_circle.then_some(&circle),
            )
            .await
            .unwrap();
            let resources=[arkret_models_collaboration::governance::operation_wire::PolicyResourceSelector{kind:arkret_models_collaboration::governance::operation_wire::PolicyResourceKind::Realm,realm_id:Some(realm()),resource_ref:Some(realm().to_string())}];
            let realm = realm();
            assert_eq!(
                evaluate_agent_management(
                    Some(&policies),
                    &AgentManagementContext {
                        realm_id: &realm,
                        ownership: Some((&controller, &agent)),
                        operation,
                        content_action: if matches!(
                            operation,
                            AgentPolicyOperation::Join | AgentPolicyOperation::Publish
                        ) {
                            None
                        } else {
                            Some(CapabilityActionId::from_wire("ak.message.create").unwrap())
                        },
                        resources: Some(&resources),
                        at: basis.committed_at
                    }
                )
                .unwrap(),
                arkret_wire::PolicyEffect::Deny
            );
            let mut invalid = accepted.clone();
            invalid.payload.get_mut("value").unwrap()["default_effect"] = json!("require_review");
            if in_circle {
                assert!(
                    admit_in_connection(&mut conn, &invalid, &basis)
                        .await
                        .is_err()
                );
            }
            let zero=sql_query("SELECT NOT EXISTS(SELECT 1 FROM capability_grant_current_results) AND NOT EXISTS(SELECT 1 FROM agent_interaction_current_results) AS present").get_result::<Present>(&mut conn).await.unwrap();
            assert!(zero.present);
            sql_query("ROLLBACK TO SAVEPOINT candidate")
                .execute(&mut conn)
                .await
                .unwrap();
        }
    }
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

/// Raw configuration bypasses the UI and still reaches the shared check inside
/// the real admission transaction. Accepted-history fixtures isolate this hook.
#[tokio::test]
async fn management_support_rejects_raw_unsupported_configuration_without_effects() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let circle = seed_management_circle(&mut conn).await;
    for in_circle in [false, true] {
        let mut candidate = management_policy(None, "allow");
        let PolicySetValue::Governance(document) = &mut candidate.value else {
            unreachable!()
        };
        if in_circle {
            document.rules[0].agent_operations = Some(vec![
                arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation::Join,
            ]);
            document.rules[0].effect = arkret_wire::PolicyEffect::RequireReview;
            document.rules[0].review_requirement = Some(arkret_models_collaboration::governance::operation_wire::ManagementReviewRequirement {
                approver_actor_ids: vec![document.created_by.clone()], threshold: 1, max_age_seconds: 60,
            });
        } else {
            document.rules[0].actions = Some(vec!["ak.unknown.action".into()]);
        }
        candidate.validate().unwrap();
        let scope = if in_circle {
            arkret_wire::ScopeRef::Circle {
                realm_id: realm(),
                circle_id: circle.clone(),
            }
        } else {
            arkret_wire::ScopeRef::Realm { realm_id: realm() }
        };
        let original = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::PolicySet.as_str(),
            scope,
            event(EventKind::RealmCreate, json!({}), 0).actor_id,
            json!(candidate),
            chrono::DateTime::parse_from_rfc3339("2026-10-05T12:00:02Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .unwrap();
        let mut basis = commit(&original, 2);
        if in_circle {
            basis.stream_ref = CommitStreamRef::Circle {
                realm_id: realm(),
                circle_id: circle.clone(),
            };
            basis.stream_position = 0;
            basis.previous_commit_ref = None;
        }
        let error = admit_in_connection(&mut conn, &original, &basis)
            .await
            .unwrap_err();
        assert!(
            matches!(error, PersistenceError::Conflict(ref message)
            if message == "failed_precondition: Agent management configuration lacks a registered matcher or review carrier"),
            "{error}"
        );
        let clean = sql_query("SELECT NOT EXISTS(SELECT 1 FROM policy_current_results) AND NOT EXISTS(SELECT 1 FROM canonical_events WHERE kind='ak.policy.set') AS present")
            .get_result::<Present>(&mut conn).await.unwrap();
        assert!(clean.present);
    }
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_authorize_full_selector_priority_and_circle_current_are_not_realm_anchor() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let controller = arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    let agent = arkret_wire::AccountId::new(
        "ak:did_core:web:agent.example".parse().unwrap(),
        controller.station_id.clone(),
    );
    let strand: arkret_wire::StrandId = "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
        .parse()
        .unwrap();
    let circle = seed_management_circle(&mut conn).await;
    let mut payload = json!(policy(None, true));
    payload["value"]["default_effect"] = json!("deny");
    payload["value"]["rules"] = json!([
      {"rule_id":"narrow_deny","kind":"agent","agent_target":{"kind":"all"},"agent_operations":["authorize"],"actions":["ak.message.create"],"priority":1,"effect":"deny","resources":[{"kind":"strand","realm_id":realm(),"resource_ref":strand}]},
      {"rule_id":"whole_allow","kind":"agent","agent_target":{"kind":"all"},"agent_operations":["authorize"],"priority":2,"effect":"allow"}]);
    let accepted = event(EventKind::PolicySet, payload, 2);
    let basis = commit(&accepted, 2);
    admit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let resources = [WireResourceSelector::realm(realm())];
    crate::agent_management_admission::require_authorization_in_connection(
        &mut conn,
        &realm(),
        &controller,
        &agent,
        &["ak.message.create".into(), "ak.reaction.add".into()],
        &resources,
        basis.committed_at,
    )
    .await
    .unwrap();
    let mut circle_payload = json!(policy(None, true));
    circle_payload["policy_id"] = json!("ak:policy:0198ff00-0000-7000-8000-000000000002");
    circle_payload["value"]["id"] = circle_payload["policy_id"].clone();
    circle_payload["value"]["rules"] = json!([{"rule_id":"circle_deny","kind":"agent","agent_target":{"kind":"all"},"agent_operations":["authorize"],"effect":"deny"}]);
    let accepted = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::PolicySet.as_str(),
        arkret_wire::ScopeRef::Circle {
            realm_id: realm(),
            circle_id: circle.clone(),
        },
        arkret_wire::ActorId::account(controller.clone()),
        circle_payload,
        basis.committed_at,
    )
    .unwrap();
    let mut circle_basis = commit(&accepted, 3);
    circle_basis.stream_ref = CommitStreamRef::Circle {
        realm_id: realm(),
        circle_id: circle.clone(),
    };
    circle_basis.stream_position = 0;
    circle_basis.previous_commit_ref = None;
    admit_in_connection(&mut conn, &accepted, &circle_basis)
        .await
        .unwrap();
    insert_history(&mut conn, &accepted, &circle_basis).await;
    commit_in_connection(&mut conn, &accepted, &circle_basis)
        .await
        .unwrap();
    assert!(
        crate::agent_management_admission::require_authorization_in_connection(
            &mut conn,
            &realm(),
            &controller,
            &agent,
            &["ak.message.create".into()],
            &resources,
            basis.committed_at
        )
        .await
        .is_err()
    );
    let sibling = arkret_wire::CircleId::from_event_id(
        &event(EventKind::CircleCreate, json!({}), 3).event_id,
    );
    crate::agent_management_admission::require_authorization_in_connection(
        &mut conn,
        &realm(),
        &controller,
        &agent,
        &["ak.message.create".into()],
        &[WireResourceSelector::circle(realm(), sibling)],
        basis.committed_at,
    )
    .await
    .unwrap();
    sql_query("DELETE FROM policy_current_results WHERE policy_id='ak:policy:0198ff00-0000-7000-8000-000000000002'").execute(&mut conn).await.unwrap();
    assert!(
        crate::agent_management_admission::require_authorization_in_connection(
            &mut conn,
            &realm(),
            &controller,
            &agent,
            &["ak.message.create".into()],
            &resources,
            basis.committed_at
        )
        .await
        .is_err()
    );
    assert!(sql_query("SELECT NOT EXISTS(SELECT 1 FROM capability_grant_current_results) AND NOT EXISTS(SELECT 1 FROM agent_interaction_current_results) AS present").get_result::<Present>(&mut conn).await.unwrap().present);
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn management_authorization_object_scope_requires_exact_accepted_creation_and_current_binding()
 {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let accepted = event(
        EventKind::StrandCreate,
        json!({"object":{"realm_id":realm(),"scope_circle_id":null}}),
        1,
    );
    let basis = commit(&accepted, 1);
    let id = arkret_wire::StrandId::from_event_id(&accepted.event_id);
    let target = WireResourceSelector::strand(realm(), id.clone());
    let value = json!({"id":id,"realm_id":realm(),"scope_circle_id":null});
    sql_query("INSERT INTO strand_current_results(realm_id,strand_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6)")
      .bind::<Text,_>(realm().as_str()).bind::<Text,_>(id.as_str()).bind::<Text,_>(basis.commit_id.as_str())
      .bind::<BigInt,_>(basis.stream_position as i64).bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(basis.committed_at).execute(&mut conn).await.unwrap();
    assert!(
        authorization_object_scope_in_connection(&mut conn, &realm(), &target)
            .await
            .is_err()
    );
    // Historical accepted source import deliberately isolates immutable binding;
    // it does not claim the raw fixture is a full signed Strand-create request.
    insert_history(&mut conn, &accepted, &basis).await;
    assert!(matches!(
        authorization_object_scope_in_connection(&mut conn, &realm(), &target)
            .await
            .unwrap(),
        Some(arkret_wire::ScopeRef::Realm { .. })
    ));
    let circle = arkret_wire::CircleId::from_event_id(&accepted.event_id);
    sql_query("UPDATE strand_current_results SET value=jsonb_set(value,'{scope_circle_id}',$2) WHERE strand_id=$1")
      .bind::<Text,_>(id.as_str()).bind::<Jsonb,_>(json!(circle)).execute(&mut conn).await.unwrap();
    assert!(
        authorization_object_scope_in_connection(&mut conn, &realm(), &target)
            .await
            .is_err()
    );
    assert!(
        sql_query("SELECT NOT EXISTS(SELECT 1 FROM capability_grant_current_results) AS present")
            .get_result::<Present>(&mut conn)
            .await
            .unwrap()
            .present
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}
