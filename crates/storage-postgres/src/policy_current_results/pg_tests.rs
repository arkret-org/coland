//! Imported accepted-history fixtures exercise the real PostgreSQL CAS boundary.
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
    let payload = management_policy(None, "deny");
    let accepted = event(EventKind::PolicySet, json!(payload), 1);
    let basis = commit(&accepted, 1);
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
        let verdict = crate::agent_management_admission::executable_actions_in_connection(
            &mut reader,
            &realm(),
            &controller,
            &agent,
            &operation,
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
    assert!(
        crate::agent_management_admission::require_join_in_connection(
            &mut conn,
            &realm(),
            &controller,
            &agent,
            at,
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
