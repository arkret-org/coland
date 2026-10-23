//! Real PostgreSQL capacity matrix for the per-stream read paths (0436).
//!
//! Every Realm gets a short Realm stream and one hot Realm a long one; the
//! matrix grows the number of Realms through 1, 100 and 1000. Each hot read
//! is run under `EXPLAIN (ANALYZE, FORMAT JSON)`, and the rows its scans
//! of `realm_commits` and `canonical_events` actually produced must stay
//! within a bound set by the page size or the stream count, never by the
//! hot Realm's history or the number of Realms. A sequential scan of either
//! table fails the matrix outright.

use diesel::sql_types::{Array, BigInt, Json, Text};
use diesel_async::SimpleAsyncConnection;
use horme::RunQueryDsl;
use serde_json::Value;

use crate::{AsyncPgConnection, QueryableByName, pg_conn, sql_query};

const HOT_HISTORY: i64 = 20_000;
const COLD_HISTORY: i64 = 20;
const PAGE: i64 = 100;

#[derive(QueryableByName)]
struct PlanRow {
    #[diesel(sql_type = Json)]
    #[diesel(column_name = "QUERY PLAN")]
    plan: Value,
}

/// Rows every scan node over the two history tables produced or discarded,
/// and the execution time in milliseconds.
struct Measured {
    history_rows: f64,
    execution_ms: f64,
}

fn walk(node: &Value, rows: &mut f64, label: &str) {
    let relation = node.get("Relation Name").and_then(Value::as_str);
    let node_type = node.get("Node Type").and_then(Value::as_str).unwrap_or("");
    if let Some(relation @ ("realm_commits" | "canonical_events")) = relation {
        assert!(
            node_type != "Seq Scan",
            "{label}: sequential scan of {relation}"
        );
        // Rows an index or filter visited and discarded are read too.
        let visited = [
            "Actual Rows",
            "Rows Removed by Filter",
            "Rows Removed by Index Recheck",
        ]
        .into_iter()
        .filter_map(|field| node.get(field).and_then(Value::as_f64))
        .sum::<f64>();
        let loops = node
            .get("Actual Loops")
            .and_then(Value::as_f64)
            .unwrap_or(1.0);
        *rows += visited * loops;
    }
    for child in node
        .get("Plans")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk(child, rows, label);
    }
}

fn measure(plan: Value, label: &str) -> Measured {
    let root = &plan[0];
    let mut history_rows = 0.0;
    walk(&root["Plan"], &mut history_rows, label);
    Measured {
        history_rows,
        execution_ms: root["Execution Time"].as_f64().unwrap_or(f64::NAN),
    }
}

async fn seed(conn: &mut AsyncPgConnection, first: i64, last: i64, history: i64) {
    seed_history(conn, first, last, history, false).await;
}

async fn seed_history(
    conn: &mut AsyncPgConnection,
    first: i64,
    last: i64,
    history: i64,
    diverse_kinds: bool,
) {
    // Physical query-plan fixtures, not semantically admitted Events. Cold
    // Realms exercise a populated kind-summary index through the real Commit
    // trigger, rather than an unrealistically two-kind, two-page summary.
    // The hot Realm and the history-read matrix retain their original skew.
    let event_kind = if diverse_kinds {
        let kinds = crate::snapshot_disclosure_gate::DISCLOSED_EVENT_KINDS
            .iter()
            .take(COLD_HISTORY as usize)
            .map(|kind| format!("'{}'", kind.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(kinds.len(), COLD_HISTORY as usize);
        assert_eq!(
            kinds
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            kinds.len()
        );
        format!("(ARRAY[{}])[p::integer + 1]", kinds.join(","))
    } else {
        "CASE WHEN p = 0 THEN 'ak.realm.create' ELSE 'ak.message.create' END".to_owned()
    };
    conn.batch_execute(&format!(
        "INSERT INTO canonical_events \
           (id, digest_suite, digest, actor_id, realm_id, scope_ref, kind, canonical_bytes, \
            envelope, state, committed_at) \
         SELECT '\\x01'::bytea || d.digest, 1, d.digest, 'actor', 'ak:realm:capacity-' || r, \
                '{{}}'::jsonb, \
                {event_kind}, \
                '\\x00'::bytea, \
                jsonb_build_object('event_id', 'ak:event:capacity-' || r || '-' || p, \
                                   'payload', '{{}}'::jsonb), \
                'committed', now() \
         FROM generate_series({first}, {last}) r, generate_series(0, {history} - 1) p, \
              LATERAL (SELECT sha256(convert_to(r || ':' || p, 'UTF8')) AS digest) d; \
         INSERT INTO realm_commits \
           (commit_id, realm_id, stream_key, stream_ref, stream_position, previous_commit_ref, \
            event_pk, governance_generation, commit_json, committed_at) \
         SELECT 'capacity-' || r || '-' || p, 'ak:realm:capacity-' || r, 'stream-' || r, \
                '{{}}'::jsonb, p, \
                CASE WHEN p = 0 THEN NULL ELSE 'capacity-' || r || '-' || (p - 1) END, \
                e.pk, 0, '{{}}'::jsonb, now() \
         FROM generate_series({first}, {last}) r CROSS JOIN generate_series(0, {history} - 1) p \
         JOIN canonical_events e ON e.digest_suite = 1 \
           AND e.digest = sha256(convert_to(r || ':' || p, 'UTF8'));"
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn per_stream_reads_stay_bounded_across_one_hundred_and_one_thousand_realms() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pg_conn(&pool).await.unwrap();
    seed(&mut *conn, 1, 1, HOT_HISTORY).await;
    let mut seeded = 1;
    let hot_realm = "ak:realm:capacity-1";
    let hot_stream = "stream-1";
    for realms in [1_i64, 100, 1000] {
        if realms > seeded {
            seed(&mut *conn, seeded + 1, realms, COLD_HISTORY).await;
            seeded = realms;
        }
        conn.batch_execute(
            "ANALYZE canonical_events; ANALYZE realm_commits; ANALYZE realm_commit_event_kinds;",
        )
        .await
        .unwrap();
        let explain = |sql: &str| format!("EXPLAIN (ANALYZE, FORMAT JSON) {sql}");
        let mut report = Vec::new();

        // The first and the last Realm in key order: neither may walk the
        // hot history or the other Realms' streams.
        let last_realm = format!("ak:realm:capacity-{realms}");
        for (label, realm) in [
            ("stream heads (hot Realm)", hot_realm),
            ("stream heads (last Realm)", last_realm.as_str()),
        ] {
            let plan = sql_query(explain(crate::authority_commit::REALM_STREAM_HEADS_SQL))
                .bind::<Text, _>(realm)
                .get_result::<PlanRow>(&mut *conn)
                .await
                .unwrap()
                .plan;
            let heads = measure(plan.clone(), label);
            assert!(
                heads.history_rows <= 8.0,
                "{label} in {realms} Realms read {}: {plan}",
                heads.history_rows
            );
            report.push((label, heads));
        }

        let floor = measure(
            sql_query(explain(crate::authority_commit::STREAM_FLOOR_SQL))
                .bind::<Text, _>(hot_stream)
                .get_result::<PlanRow>(&mut *conn)
                .await
                .unwrap()
                .plan,
            "stream floor",
        );
        assert!(
            floor.history_rows <= 2.0,
            "stream floor read {}",
            floor.history_rows
        );
        report.push(("stream floor", floor));

        for (label, sql, position) in [
            (
                "page after",
                crate::authority_commit::STREAM_PAGE_AFTER_SQL,
                Some(HOT_HISTORY / 2),
            ),
            (
                "page before",
                crate::authority_commit::STREAM_PAGE_BEFORE_SQL,
                Some(HOT_HISTORY / 2),
            ),
            (
                "page newest",
                crate::authority_commit::STREAM_PAGE_NEWEST_SQL,
                None,
            ),
        ] {
            let query = sql_query(explain(sql)).bind::<Text, _>(hot_stream);
            let plan = match position {
                Some(position) => {
                    query
                        .bind::<BigInt, _>(position)
                        .bind::<BigInt, _>(PAGE + 1)
                        .get_result::<PlanRow>(&mut *conn)
                        .await
                }
                None => {
                    query
                        .bind::<BigInt, _>(PAGE + 1)
                        .get_result::<PlanRow>(&mut *conn)
                        .await
                }
            }
            .unwrap()
            .plan;
            let measured = measure(plan, label);
            assert!(
                measured.history_rows <= 2.0 * (PAGE as f64 + 1.0),
                "{label} read {}",
                measured.history_rows
            );
            report.push((label, measured));
        }

        let page_commits = (HOT_HISTORY - PAGE..HOT_HISTORY)
            .map(|position| format!("capacity-1-{position}"))
            .collect::<Vec<_>>();
        let withheld = measure(
            sql_query(explain(crate::committed_disclosure::WITHHELD_COMMITS_SQL))
                .bind::<Array<Text>, _>(&page_commits)
                .get_result::<PlanRow>(&mut *conn)
                .await
                .unwrap()
                .plan,
            "withheld decision",
        );
        assert!(
            withheld.history_rows <= 3.0 * PAGE as f64,
            "withheld decision read {}",
            withheld.history_rows
        );
        report.push(("withheld decision", withheld));

        for (label, sql) in [
            (
                "undisclosed kind audit",
                crate::snapshot_disclosure_gate::undisclosed_kind_sql(),
            ),
            (
                "unsettled commit audit",
                crate::snapshot_disclosure_gate::UNSETTLED_COMMIT_SQL.to_owned(),
            ),
        ] {
            let measured = measure(
                sql_query(explain(&sql))
                    .bind::<Text, _>(hot_realm)
                    .get_result::<PlanRow>(&mut *conn)
                    .await
                    .unwrap()
                    .plan,
                label,
            );
            assert!(
                measured.history_rows <= 2.0,
                "{label} read {}",
                measured.history_rows
            );
            report.push((label, measured));
        }

        for (label, measured) in report {
            println!(
                "capacity realms={realms} hot_history={HOT_HISTORY} {label}: history_rows={} execution_ms={:.3}",
                measured.history_rows, measured.execution_ms
            );
        }
    }

    // A hot stream need not precede other Realms' streams in key order.
    // Two sparse withheld streams also prove that head enumeration needs
    // neither a position-zero Commit nor a retained canonical Event.
    conn.batch_execute(
        "UPDATE realm_commits SET stream_key='zz-hot-stream' \
         WHERE realm_id='ak:realm:capacity-1'; \
         INSERT INTO realm_commits \
           (commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref, \
            event_pk,governance_generation,commit_json,committed_at) \
         VALUES ('head-sparse-a','ak:realm:capacity-1','aa-sparse-stream','{}',7, \
                 'head-unretained-a',NULL,0,'{}',now()), \
                ('head-sparse-z','ak:realm:capacity-1','zzz-sparse-stream','{}',11, \
                 'head-unretained-z',NULL,0,'{}',now()); \
         ANALYZE realm_commits;",
    )
    .await
    .unwrap();
    let plan = sql_query(format!(
        "EXPLAIN (ANALYZE, FORMAT JSON) {}",
        crate::authority_commit::REALM_STREAM_HEADS_SQL
    ))
    .bind::<Text, _>(hot_realm)
    .get_result::<PlanRow>(&mut *conn)
    .await
    .unwrap()
    .plan;
    assert_eq!(plan[0]["Plan"]["Actual Rows"].as_f64(), Some(3.0));
    let heads = measure(plan.clone(), "stream heads (sparse and reordered)");
    assert!(
        heads.history_rows <= 8.0,
        "sparse and reordered stream heads read {}: {plan}",
        heads.history_rows
    );
}

// These are query-plan fixtures, not admission evidence. The larger member
// and message families expose a scan hidden by tiny bootstrap-only Realms.
async fn seed_current(conn: &mut AsyncPgConnection, first: i64, last: i64, width: i64) {
    conn.batch_execute(&format!(
        "INSERT INTO member_state_current_results
           (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at)
         SELECT 'ak:realm:capacity-' || r, jsonb_build_object('member',m)::text, 'join',
                'capacity-' || r || '-0', 0, '{{\"membership\":\"join\"}}'::jsonb, now()
         FROM generate_series({first},{last}) r, generate_series(1,{width}) m;
         INSERT INTO message_revision_current_results
           (realm_id,message_id,current_commit_id,current_stream_position,value,updated_at)
         SELECT 'ak:realm:capacity-' || r, 'message-' || r || '-' || m,
                'capacity-' || r || '-0', 0,
                '{{\"strand_id\":\"strand\",\"track_name\":\"discussion\"}}'::jsonb, now()
         FROM generate_series({first},{last}) r, generate_series(1,{width}) m;
         INSERT INTO relation_current_results
           (realm_id,domain_key,domain,relation_id,state,current_commit_id,current_stream_position,value,updated_at)
         SELECT 'ak:realm:capacity-' || r, 'domain-' || m, '{{}}'::jsonb, 'relation-' || r || '-' || m,
                'active', 'capacity-' || r || '-0', 0,
                jsonb_build_object('id','relation-' || r || '-' || m,'state','active'), now()
         FROM generate_series({first},{last}) r, generate_series(1,{width}) m;
         INSERT INTO moderation_state_current_results
           (realm_id,target_ref,current_commit_id,current_stream_position,value,updated_at)
         SELECT 'ak:realm:capacity-' || r, 'target-' || m, 'capacity-' || r || '-0', 0,
                '{{}}'::jsonb, now()
         FROM generate_series({first},{last}) r, generate_series(1,{width}) m;"
    )).await.unwrap();
    seed_snapshot_families(conn, first, last, width).await;
}

// Every table in the production snapshot union is populated. These are
// physical query-plan fixtures, not signed admission or disclosure evidence.
async fn seed_snapshot_families(conn: &mut AsyncPgConnection, first: i64, last: i64, width: i64) {
    let rows = format!("FROM generate_series({first},{last}) r, generate_series(1,{width}) m");
    let realm = "'ak:realm:capacity-' || r";
    let commit = "'capacity-' || r || '-0'";
    let key = "r || '-' || m";
    conn.batch_execute(&format!("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) SELECT '\\x01'::bytea || d.digest,1,d.digest,jsonb_build_object('watcher','actor-' || {key})::text,{realm},'{{}}','ak.strand.watch.set','\\x00'::bytea,jsonb_build_object('event_id','watch-event-' || {key},'payload',jsonb_build_object('strand_id','strand-' || {key},'watcher_actor_id',jsonb_build_object('watcher','actor-' || {key}))),'committed',now() {rows},LATERAL(SELECT sha256(convert_to('watch-' || {key},'UTF8')) AS digest)d"))
        .await.unwrap();
    if first == 1 {
        // A nonempty hot watch index must retain bounded exact-selector reads
        // even after many accepted replacements of the same cell.
        conn.batch_execute(&format!("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) SELECT '\\x01'::bytea || d.digest,1,d.digest,jsonb_build_object('watcher','actor-1-1')::text,'ak:realm:capacity-1','{{}}','ak.strand.watch.set','\\x00'::bytea,jsonb_build_object('event_id','watch-hot-' || p,'payload',jsonb_build_object('strand_id','strand-1-1','watcher_actor_id',jsonb_build_object('watcher','actor-1-1'))),'committed',now() FROM generate_series(1,{HOT_HISTORY}) p,LATERAL(SELECT sha256(convert_to('watch-hot-' || p,'UTF8')) AS digest)d"))
            .await.unwrap();
    }
    for (table, columns, expressions, value) in [
        ("actor_profile_current_results", "actor_profile_id,actor_id,scope_ref", format!("'profile-' || {key},jsonb_build_object('kind','account','account_id',jsonb_build_object('principal_id','actor-' || {key},'station_id','station')),jsonb_build_object('kind','realm','realm_id',{realm})"), format!("jsonb_build_object('id','profile-' || {key},'realm_id',{realm},'schema','ak.schema.actor_profile.v1')")),
        ("call_component_current_results", "call_id,selector,source_stream_ref", format!("'call-' || {key},jsonb_build_object('kind','call_focus','call_id','call-' || {key}),jsonb_build_object('kind','realm','realm_id',{realm})"), "'{}'::jsonb".to_owned()),
        ("applet_registration_current_results", "applet_id,service_id,instance_event_ref", format!("'applet-' || {key},'ak:did_core:web:capacity-service-' || {key} || '.example','registration-event-' || {key}"), format!("jsonb_build_object('applet_id','applet-' || {key},'service_id','ak:did_core:web:capacity-service-' || {key} || '.example')")),
        ("member_identity_updates_current_results", "member_id,segment", "jsonb_build_object('member',m)::text,'member_identity'".to_owned(), "jsonb_build_object('assertions','[]'::jsonb)".to_owned()),
        ("circle_current_results", "circle_id,create_event_id,source_stream_ref,short_name_folded", format!("'circle-' || {key},'circle-event-' || {key},jsonb_build_object('kind','realm','realm_id',{realm}),'circle-' || m"), format!("jsonb_build_object('id','circle-' || {key},'realm_id',{realm})")),
        ("circle_member_state_current_results", "circle_id,member_id,membership,source_stream_ref", format!("'circle-' || {key},jsonb_build_object('member',m)::text,'join',jsonb_build_object('kind','circle','realm_id',{realm},'circle_id','circle-' || {key})"), format!("jsonb_build_object('membership','join','parent_membership_revision',jsonb_build_object('commit_id',{commit},'stream_position',0))")),
        ("call_state_current_results", "call_id,create_event_id,source_stream_ref", format!("'call-' || {key},'call-event-' || {key},jsonb_build_object('kind','realm','realm_id',{realm})"), "jsonb_build_object('from',NULL,'to','ringing')".to_owned()),
        ("moderation_franking_proof_current_results", "target_event_id,source_stream_ref", format!("'franking-target-' || {key},jsonb_build_object('kind','realm','realm_id',{realm})"), "'{}'::jsonb".to_owned()),
        ("realm_organization_current_results", "organization_id,relationship,organization_public_key", format!("'organization-' || {key},'owner',decode(repeat('00',32),'hex')"), format!("jsonb_build_object('realm_id',{realm},'organization_id','organization-' || {key},'relationship','owner')")),
        ("schema_definition_current_results", "schema_id", format!("'schema-' || {key}"), format!("jsonb_build_object('$id','schema-' || {key},'type','object')")),
        ("pin_current_results", "pin_scope_key,pin_scope,source_stream_ref", format!("'pin-' || {key},jsonb_build_object('kind','strand','id','strand-' || {key}),jsonb_build_object('kind','realm','realm_id',{realm})"), "jsonb_build_object('assertions',jsonb_build_array(jsonb_build_object('tag_id','pin-dot')))".to_owned()),
        ("policy_current_results", "policy_id,current_event_id", format!("'policy-' || {key}, 'event-' || {key}"), "'{}'::jsonb".to_owned()),
        ("sidecar_current_results", "sidecar_id,controller_account_id,create_event_id,source_stream_ref", format!("'sidecar-' || {key},jsonb_build_object('principal_id','controller-' || {key},'station_id','station'),'sidecar-event-' || {key},jsonb_build_object('kind','realm','realm_id',{realm})"), format!("jsonb_build_object('id','sidecar-' || {key},'realm_id',{realm},'controller_account_id',jsonb_build_object('principal_id','controller-' || {key},'station_id','station'))")),
        ("sidecar_context_current_results", "sidecar_id,context_ref_digest,context_ref,version,predecessor_event_ref,attach_event_id,source_stream_ref", format!("'sidecar-' || {key},'context-' || {key},jsonb_build_object('kind','strand','strand_id','strand-' || {key}),1,NULL,'attach-event-' || {key},jsonb_build_object('kind','sidecar','realm_id',{realm},'sidecar_id','sidecar-' || {key})"), format!("jsonb_build_object('sidecar_id','sidecar-' || {key},'source_context_ref',jsonb_build_object('kind','strand','strand_id','strand-' || {key}),'version',1)")),
        ("policy_action_current_results", "subject_kind,subject_id,action_key,current_event_id", format!("'realm_action','action-' || {key},'','action-event-' || {key}"), "'{}'::jsonb".to_owned()),
        ("strand_current_results", "strand_id,calendar_schedule_source_value", format!("'strand-' || {key},jsonb_build_object('effective_scope',jsonb_build_object('kind','realm','realm_id',{realm}),'source',NULL,'strand_revision',jsonb_build_object('commit_id',{commit},'stream_position',0),'metadata_context',NULL)"), format!("jsonb_build_object('id','strand-' || {key},'realm_id',{realm})")),
        ("rsvp_current_results", "event_ref,occurrence,responder_actor_id,source_stream_ref", format!("'strand-' || {key},'null'::jsonb,jsonb_build_object('actor',m),jsonb_build_object('kind','realm','realm_id',{realm})"), "jsonb_build_object('response','accepted')".to_owned()),
        ("strand_watch_current_results", "strand_id,watcher_actor_id", format!("'strand-' || {key},jsonb_build_object('watcher','actor-' || {key})::text"), "jsonb_build_object('level','all')".to_owned()),
        ("strand_position_current_results", "board_space_id,strand_id", format!("'board-' || {key},'strand-' || {key}"), "jsonb_build_object('list_space_id','list','rank','a')".to_owned()),
        ("space_current_results", "space_id", format!("'space-' || {key}"), format!("jsonb_build_object('id','space-' || {key},'realm_id',{realm})")),
        ("space_parent_current_results", "space_id", format!("'space-' || {key}"), "jsonb_build_object('parent_space_id',NULL)".to_owned()),
        ("space_child_scope_policy_current_results", "space_id", format!("'space-' || {key}"), "'null'::jsonb".to_owned()),
        ("mls_group_current_results", "scope_key,mls_group_id,public_state", format!("'scope-' || {key},'group-' || {key},'\\x00'::bytea"), format!("jsonb_build_object('effective_scope',jsonb_build_object('kind','realm','realm_id',{realm}),'covered_key_access_revision',0,'current_key_access_revision',0)")),
        // Reports have distinct covering Commits. They cannot all share position 0.
        ("moderation_report_current_results", "report_event_id", format!("'report-' || {key}"), format!("jsonb_build_object('realm_id',{realm},'target_ref','target-' || m,'reporter_id','reporter')")),
        ("object_redaction_current_results", "target_ref", "'target-' || m".to_owned(), "jsonb_build_object('assertions',jsonb_build_array(jsonb_build_object('tag_id','dot')))".to_owned()),
        ("message_reactions_current_results", "target_ref", "'target-' || m".to_owned(), "jsonb_build_object('assertions',jsonb_build_array(jsonb_build_object('tag_id','dot')))".to_owned()),
        ("sidecar_exchange_controls_current_results", "sidecar_id,context_ref_digest,context_ref,source_stream_ref", format!("'sidecar-' || {key},'context-' || {key},jsonb_build_object('kind','strand','strand_id','strand-' || {key}),jsonb_build_object('kind','sidecar','realm_id',{realm},'sidecar_id','sidecar-' || {key})"), "jsonb_build_object('assertions',jsonb_build_array(jsonb_build_object('tag_id','control-dot')))".to_owned()),
        ("invite_lifecycle_current_results", "invite_id", format!("'invite-' || {key}"), "'\"pending\"'::jsonb".to_owned()),
        ("invite_live_target_current_results", "invitee_account_id", "jsonb_build_object('account',m)::text".to_owned(), format!("jsonb_build_object('create_event_id','create-' || {key})")),
        ("invite_directed_invitee_current_results", "invite_id", format!("'invite-' || {key}"), "jsonb_build_object('invitee_account_id',jsonb_build_object('account',m))".to_owned()),
        ("capability_grant_current_results", "grant_id,status,current_event_id,current_stream_ref", format!("'grant-' || {key},'active','event-' || {key},'{{}}'::jsonb"), format!("jsonb_build_object('id','grant-' || {key},'schema','ak.schema.capability.v1','status','active')")),
        ("mimi_room_binding_current_results", "mimi_room_uri,current_event_id", format!("'mimi-' || {key},'event-' || {key}"), format!("jsonb_build_object('mimi_room_uri','mimi-' || {key},'binding_scope',jsonb_build_object('realm_id',{realm}))")),
        ("agent_interaction_current_results", "current_key,agent_account_id", format!("'interaction-' || {key},jsonb_build_object('principal_id','agent-' || {key},'station_id','station')"), "jsonb_build_object('interaction_mode','private')".to_owned()),
        ("agent_status_current_results", "current_key,agent_id,actor_id", format!("'agent-' || {key},'agent-' || {key},'{{}}'::jsonb"), "'\"active\"'::jsonb".to_owned()),
        ("agent_key_current_results", "current_key,agent_id,agent_key_id", format!("'key-' || {key},'agent-' || {key},'key-' || {key}"), "jsonb_build_object('authorizations','[]'::jsonb)".to_owned()),
    ] {
        let (covering, position) = if table == "moderation_report_current_results" {
            ("'capacity-' || r || '-' || (m-1)", "m-1")
        } else if matches!(table, "schema_definition_current_results" | "pin_current_results" | "actor_profile_current_results" | "call_component_current_results") {
            ("'capacity-' || r || '-1'", "1")
        } else {
            (commit, "0")
        };
        conn.batch_execute(&format!("INSERT INTO {table}(realm_id,{columns},current_commit_id,current_stream_position,value,updated_at) SELECT {realm},{expressions},{covering},{position},{value},now() {rows}"))
            .await.unwrap_or_else(|error| panic!("capacity seed {table}: {error}"));
    }
    conn.batch_execute(&format!(
        "INSERT INTO realm_bootstrap_current_results(realm_id,result_family,current_commit_id,current_stream_position,value,updated_at)
         SELECT {realm},f,{commit},0,CASE WHEN f='realm_genesis' THEN jsonb_build_object('purpose','collaboration') ELSE '{{}}'::jsonb END,now() FROM generate_series({first},{last}) r,
         unnest(ARRAY['realm_genesis','realm_profile','realm_join_rule','realm_history_access','realm_discovery','realm_alias','realm_plaintext_visible_services']) f;
         INSERT INTO realm_media_service_current_results(realm_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at)
         SELECT {realm},jsonb_build_object('kind','realm','realm_id',{realm}),'capacity-' || r || '-1',1,'{{}}'::jsonb,now() FROM generate_series({first},{last}) r;
         INSERT INTO scope_read_receipt_policy_current_results(realm_id,scope_ref,source_stream_ref,current_commit_id,current_stream_position,value,updated_at)
         SELECT {realm},jsonb_build_object('kind','realm','realm_id',{realm}),jsonb_build_object('kind','realm','realm_id',{realm}),
                'capacity-' || r || '-1',1,jsonb_build_object('disclosure','optional'),now() FROM generate_series({first},{last}) r;
         INSERT INTO realm_authority_root_current_results(realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at)
         SELECT {realm},'{{}}'::jsonb,0,0,'event',{commit},0,now() FROM generate_series({first},{last}) r;
         INSERT INTO realm_policy_bundle_current_results(realm_id,current_commit_id,current_stream_position,value,updated_at)
         SELECT {realm},{commit},0,'{{}}'::jsonb,now() FROM generate_series({first},{last}) r;
         INSERT INTO realm_set_default_strand_current_results(realm_id,current_commit_id,current_stream_position,value,updated_at)
         SELECT {realm},{commit},0,jsonb_build_object('default_strand_id','strand'),now() FROM generate_series({first},{last}) r;
         INSERT INTO direct_conversation_binding_current_results(realm_id,pair_key,current_commit_id,current_stream_position,value,updated_at)
         SELECT {realm},'pair-' || r,'capacity-' || r || '-1',1,jsonb_build_object('binding_event_ref','event','binding','{{}}'::jsonb),now() FROM generate_series({first},{last}) r;"
    )).await.unwrap();
}

fn measured_current(plan: Value, label: &str, bound: f64) {
    fn visit(node: &Value, label: &str, rows: &mut f64) {
        if let Some(relation) = node.get("Relation Name").and_then(Value::as_str) {
            let visited = [
                "Actual Rows",
                "Rows Removed by Filter",
                "Rows Removed by Index Recheck",
            ]
            .into_iter()
            .filter_map(|field| node.get(field).and_then(Value::as_f64))
            .sum::<f64>()
                * node["Actual Loops"].as_f64().unwrap_or(1.0);
            // Current-table scans are judged by the total output-relative
            // row budget below: PostgreSQL can prefer one when the requested
            // Realm is a large fraction of the table. History scans must
            // never grow with its length. Do not disable seqscan.
            let current_table = relation.ends_with("_current_results");
            assert!(
                node["Node Type"] != "Seq Scan" || visited <= 32.0 || current_table,
                "{label}: unbounded sequential scan of {relation}: {visited}: {node}"
            );
            *rows += visited;
        }
        for child in node["Plans"].as_array().into_iter().flatten() {
            visit(child, label, rows);
        }
    }
    let mut rows = 0.0;
    visit(&plan[0]["Plan"], label, &mut rows);
    assert!(
        rows <= bound,
        "{label}: visited {rows} rows, bound {bound}: {plan}"
    );
    println!(
        "{label}: visited={rows} execution_ms={}",
        plan[0]["Execution Time"]
    );
}

fn assert_each_snapshot_family_bounded(
    node: &Value,
    width: f64,
    observed: &mut std::collections::BTreeSet<String>,
) {
    if let Some(table) = node["Relation Name"]
        .as_str()
        .filter(|table| table.ends_with("_current_results"))
    {
        observed.insert(table.to_owned());
        let genesis_lookup =
            table == "realm_bootstrap_current_results" && node["Alias"].as_str() == Some("g");
        let output = match table {
            "realm_bootstrap_current_results" if genesis_lookup => 1.0,
            "realm_bootstrap_current_results" => 7.0,
            "scope_read_receipt_policy_current_results"
            | "realm_media_service_current_results"
            | "realm_authority_root_current_results"
            | "realm_policy_bundle_current_results"
            | "realm_set_default_strand_current_results"
            | "direct_conversation_binding_current_results" => 1.0,
            _ => width,
        };
        let visited = [
            "Actual Rows",
            "Rows Removed by Filter",
            "Rows Removed by Index Recheck",
        ]
        .into_iter()
        .filter_map(|field| node[field].as_f64())
        .sum::<f64>()
            * node["Actual Loops"].as_f64().unwrap_or(1.0);
        let produced = node["Actual Rows"].as_f64().unwrap_or(0.0)
            * node["Actual Loops"].as_f64().unwrap_or(1.0);
        if genesis_lookup {
            // This is the exact genesis eligibility probe, not a union family.
            // Its visits still count toward both existing scan budgets.
            assert!(produced <= 1.0, "genesis eligibility probe: {node}");
        } else {
            assert_eq!(produced, output, "nonempty family {table}: {node}");
        }
        // A small singleton table can fit in two heap pages at 100 Realms,
        // where a sequential scan is cheaper than an index probe. Its fixed
        // 128-row allowance stays independent of Realm count; 1000 Realms
        // must switch to a bounded probe, without disabling seqscan.
        assert!(
            visited <= 4.0 * output + 128.0,
            "{table}: visited={visited}, output={output}: {node}"
        );
    }
    for child in node["Plans"].as_array().into_iter().flatten() {
        assert_each_snapshot_family_bounded(child, width, observed);
    }
}

#[tokio::test]
async fn typed_current_and_self_reads_stay_bounded_across_one_hundred_and_one_thousand_realms() {
    let database = crate::test_database::TestDatabase::lease().await;
    let mut conn = pg_conn(&database.pool()).await.unwrap();
    seed(&mut conn, 1, 1, HOT_HISTORY).await;
    seed_current(&mut conn, 1, 1, 1000).await;
    let mut seeded = 1;
    for realms in [1_i64, 100, 1000] {
        if realms > seeded {
            seed_history(&mut conn, seeded + 1, realms, COLD_HISTORY, true).await;
            seed_current(&mut conn, seeded + 1, realms, 20).await;
            seeded = realms;
        }
        conn.batch_execute("ANALYZE").await.unwrap();
        for realm in [
            "ak:realm:capacity-1".to_owned(),
            format!("ak:realm:capacity-{realms}"),
        ] {
            let label = format!("typed current realms={realms} realm={realm}");
            let plan = sql_query(format!(
                "EXPLAIN (ANALYZE, FORMAT JSON) {}",
                crate::authority_commit::SNAPSHOT_CURRENT_SQL
            ))
            .bind::<Text, _>(&realm)
            .get_result::<PlanRow>(&mut *conn)
            .await
            .unwrap()
            .plan;
            let width = if realm == "ak:realm:capacity-1" {
                1000.0
            } else {
                20.0
            };
            let mut observed = std::collections::BTreeSet::new();
            assert_each_snapshot_family_bounded(&plan[0]["Plan"], width, &mut observed);
            // Derive the expected table inventory from the actual production
            // SQL: a new union branch cannot silently retain an empty fixture.
            let expected = crate::authority_commit::SNAPSHOT_CURRENT_SQL
                .split("FROM ")
                .skip(1)
                .filter_map(|part| part.split_whitespace().next())
                .filter(|table| table.ends_with("_current_results"))
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(observed, expected);
            // The current union has 39 width-sized branches, including the
            // paired Calendar row on each Strand and the existing ordinary
            // Actor Profile and Call component families. Its seven singleton
            // tables emit seven bootstrap facets and six other rows.
            assert_eq!(observed.len(), 45);
            let output = 39.0 * width + 13.0;
            assert_eq!(plan[0]["Plan"]["Actual Rows"].as_f64(), Some(output));
            // Up to four visited rows per output permits the planner's
            // low-selectivity current-table scan, but never a history scan
            // or a scan that grows with unrelated Realms.
            measured_current(plan, &label, 4.0 * output + 32.0);
            for (name, sql, key) in [
                (
                    "member present",
                    crate::self_current_reads::MEMBER_PRESENT_SQL,
                    "{\"member\": 1}",
                ),
                (
                    "member absent",
                    crate::self_current_reads::MEMBER_PRESENT_SQL,
                    "{\"member\": 0}",
                ),
                (
                    "no scoped stream",
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-1",
                ),
                (
                    "stream above",
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-0",
                ),
                (
                    "stream below",
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-zzzz",
                ),
                (
                    "media absent",
                    crate::self_current_reads::MEDIA_ANCHOR_SQL,
                    "ak.realm.media_service",
                ),
                (
                    "media present",
                    crate::self_current_reads::MEDIA_ANCHOR_SQL,
                    "ak.realm.create",
                ),
                (
                    "relation present",
                    crate::self_current_reads::RELATION_CURRENT_SQL,
                    "domain-1",
                ),
                (
                    "relation absent",
                    crate::self_current_reads::RELATION_CURRENT_SQL,
                    "domain-0",
                ),
                (
                    "moderation present",
                    crate::self_current_reads::MODERATION_CURRENT_SQL,
                    "target-1",
                ),
                (
                    "moderation absent",
                    crate::self_current_reads::MODERATION_CURRENT_SQL,
                    "target-0",
                ),
            ] {
                let label = format!("self current realms={realms} realm={realm} {name}");
                let realm_stream = realm.replace("ak:realm:capacity-", "stream-");
                let key = if name == "no scoped stream" {
                    realm_stream.as_str()
                } else {
                    key
                };
                let plan = sql_query(format!("EXPLAIN (ANALYZE, FORMAT JSON) {sql}"))
                    .bind::<Text, _>(&realm)
                    .bind::<Text, _>(key)
                    .get_result::<PlanRow>(&mut *conn)
                    .await
                    .unwrap()
                    .plan;
                measured_current(plan, &label, 4.0);
            }
            let number = realm.strip_prefix("ak:realm:capacity-").unwrap();
            for (suffix, expected_rows) in [("1", 1.0), ("0", 0.0)] {
                let strand = format!("strand-{number}-{suffix}");
                let actor = format!("{{\"watcher\": \"actor-{number}-{suffix}\"}}");
                let label = format!("watch current realms={realms} realm={realm} {suffix}");
                let plan = sql_query(format!(
                    "EXPLAIN (ANALYZE, FORMAT JSON) {}",
                    crate::self_current_reads::WATCH_CURRENT_SQL
                ))
                .bind::<Text, _>(&realm)
                .bind::<Text, _>(&strand)
                .bind::<Text, _>(&actor)
                .get_result::<PlanRow>(&mut *conn)
                .await
                .unwrap()
                .plan;
                assert_eq!(plan[0]["Plan"]["Actual Rows"].as_f64(), Some(expected_rows));
                measured_current(plan, &label, 4.0);
                let result = sql_query(crate::strand_watch_current_results::WATCH_HISTORY_SQL)
                    .bind::<Text, _>(&realm)
                    .bind::<Text, _>(&strand)
                    .bind::<Text, _>(&actor)
                    .bind::<Text, _>("")
                    .get_result::<crate::ExistsRow>(&mut *conn)
                    .await
                    .unwrap();
                assert_eq!(result.present, expected_rows == 1.0);
                let plan = sql_query(format!(
                    "EXPLAIN (ANALYZE, FORMAT JSON) {}",
                    crate::strand_watch_current_results::WATCH_HISTORY_SQL
                ))
                .bind::<Text, _>(&realm)
                .bind::<Text, _>(&strand)
                .bind::<Text, _>(&actor)
                .bind::<Text, _>("")
                .get_result::<PlanRow>(&mut *conn)
                .await
                .unwrap()
                .plan;
                measured_current(plan, &format!("watch accepted history {label}"), 4.0);
            }
            for (sql, key, expected) in [
                (
                    crate::self_current_reads::MEMBER_PRESENT_SQL,
                    "{\"member\": 1}".to_owned(),
                    true,
                ),
                (
                    crate::self_current_reads::MEMBER_PRESENT_SQL,
                    "{\"member\": 0}".to_owned(),
                    false,
                ),
                (
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    realm.replace("ak:realm:capacity-", "stream-"),
                    false,
                ),
                (
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-0".to_owned(),
                    true,
                ),
                (
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-zzzz".to_owned(),
                    true,
                ),
                (
                    crate::self_current_reads::MEDIA_ANCHOR_SQL,
                    "ak.realm.media_service".to_owned(),
                    false,
                ),
                (
                    crate::self_current_reads::MEDIA_ANCHOR_SQL,
                    "ak.realm.create".to_owned(),
                    true,
                ),
            ] {
                let result = sql_query(sql)
                    .bind::<Text, _>(&realm)
                    .bind::<Text, _>(key)
                    .get_result::<crate::ExistsRow>(&mut *conn)
                    .await
                    .unwrap();
                assert_eq!(
                    result.present, expected,
                    "realms={realms} realm={realm} {sql}"
                );
            }
        }
    }
}
