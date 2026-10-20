//! Seed an independent test database with the already accepted ordinary
//! fixture. This is not an implementation or test of the ordinary operational
//! migration: only the management-private import under test crosses its real
//! production API. No private management rows are seeded here.
use std::collections::{BTreeMap, BTreeSet};

use coland_storage_postgres::PgPool;
use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;

#[derive(QueryableByName)]
struct Table {
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Jsonb)]
    columns: Value,
    #[diesel(sql_type = Jsonb)]
    json_columns: Value,
    #[diesel(sql_type = Jsonb)]
    sequences: Value,
}
#[derive(QueryableByName)]
struct ForeignKey {
    #[diesel(sql_type = Text)]
    child: String,
    #[diesel(sql_type = Text)]
    parent: String,
}
#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

pub async fn seed_ordinary(
    source: &PgPool,
    destination: &PgPool,
    private_tables: &serde_json::Map<String, Value>,
) {
    let mut source = source.get().await.unwrap();
    let tables=sql_query("SELECT c.relname AS name,jsonb_agg(a.attname ORDER BY a.attnum) AS columns,COALESCE(jsonb_agg(a.attname ORDER BY a.attnum) FILTER (WHERE a.atttypid='jsonb'::regtype),'[]'::jsonb) AS json_columns,COALESCE(jsonb_agg(jsonb_build_object('column',a.attname,'sequence',pg_get_serial_sequence(format('public.%I',c.relname),a.attname))) FILTER (WHERE pg_get_serial_sequence(format('public.%I',c.relname),a.attname) IS NOT NULL),'[]'::jsonb) AS sequences FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attgenerated='' WHERE n.nspname='public' AND c.relkind='r' AND c.relname<>'__diesel_schema_migrations' GROUP BY c.relname ORDER BY c.relname")
        .get_results::<Table>(&mut *source).await.unwrap();
    let foreign=sql_query("SELECT c.relname AS child,p.relname AS parent FROM pg_constraint f JOIN pg_class c ON c.oid=f.conrelid JOIN pg_class p ON p.oid=f.confrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE f.contype='f' AND n.nspname='public'")
        .get_results::<ForeignKey>(&mut *source).await.unwrap();
    let all = tables
        .iter()
        .map(|t| quoted(&t.name))
        .collect::<Vec<_>>()
        .join(",");
    let mut remaining = tables
        .into_iter()
        .filter(|t| {
            !private_tables.contains_key(&t.name)
                || matches!(
                    t.name.as_str(),
                    "canonical_events"
                        | "realm_commits"
                        | "account_device_committed_evidence"
                        | "agent_producer_signer_keys"
                        | "forwarded_producer_device_evidence"
                        | "applet_managed_creation_service_sources"
                )
        })
        .map(|t| (t.name.clone(), t))
        .collect::<BTreeMap<_, _>>();
    let included = remaining.keys().cloned().collect::<BTreeSet<_>>();
    let mut ordered = Vec::new();
    while !remaining.is_empty() {
        let next = remaining
            .keys()
            .find(|name| {
                !foreign.iter().any(|f| {
                    &f.child == *name
                        && f.parent != f.child
                        && included.contains(&f.parent)
                        && remaining.contains_key(&f.parent)
                })
            })
            .cloned()
            .expect("ordinary fixture tables must have a noncyclic FK order");
        ordered.push(remaining.remove(&next).unwrap());
    }
    let mut destination = destination.get().await.unwrap();
    destination.transaction::<_,diesel::result::Error,_>(async |target| {
        sql_query(format!("TRUNCATE {all} RESTART IDENTITY CASCADE")).execute(&mut *target).await?;
        for table in ordered {
            let names=table.columns.as_array().unwrap();
            let json_names=table.json_columns.as_array().unwrap();
            let columns=names.iter().map(|n|quoted(n.as_str().unwrap())).collect::<Vec<_>>().join(",");
            let nulls=json_names.iter().map(|n| {
                let name=n.as_str().unwrap();
                format!("CASE WHEN t.{} IS NULL THEN '{name}'::text END",quoted(name))
            }).collect::<Vec<_>>().join(",");
            let predicate=match table.name.as_str() {
                "canonical_events"=>"WHERE t.scope_ref->>'kind'<>'realm_control'",
                "realm_commits"=>"WHERE t.stream_ref->>'kind'<>'realm_control'",
                "account_device_committed_evidence" | "agent_producer_signer_keys" | "forwarded_producer_device_evidence" => "WHERE NOT EXISTS(SELECT 1 FROM realm_commits c WHERE c.commit_id=t.commit_id AND c.stream_ref->>'kind'='realm_control')",
                "applet_managed_creation_service_sources" => "WHERE NOT EXISTS(SELECT 1 FROM canonical_events e WHERE e.pk=t.provision_event_pk AND e.scope_ref->>'kind'='realm_control')",
                _=>"",
            };
            let rows=sql_query(format!("SELECT jsonb_build_object('row',to_jsonb(t),'nulls',array_remove(ARRAY[{nulls}]::text[],NULL)) AS value FROM {} t {predicate}",quoted(&table.name)))
                .get_results::<Row>(&mut *source).await.unwrap();
            let projection=names.iter().map(|n| {
                let name=n.as_str().unwrap();
                if json_names.contains(n) {
                    format!("CASE WHEN src->'nulls' ? '{name}' THEN NULL::jsonb ELSE src->'row'->'{name}' END")
                } else {format!("r.{}",quoted(name))}
            }).collect::<Vec<_>>().join(",");
            sql_query(format!("INSERT INTO {0} ({columns}) OVERRIDING SYSTEM VALUE SELECT {projection} FROM jsonb_array_elements($1) src, LATERAL jsonb_populate_record(NULL::{0},src->'row') r",quoted(&table.name)))
                .bind::<Jsonb,_>(Value::Array(rows.into_iter().map(|r|r.value).collect()))
                .execute(&mut *target).await?;
            for sequence in table.sequences.as_array().unwrap() {
                let column=quoted(sequence["column"].as_str().unwrap());
                let sequence=sequence["sequence"].as_str().unwrap();
                sql_query(format!("SELECT setval($1::regclass,COALESCE(MAX({column}),0)+1,false) FROM {}",quoted(&table.name)))
                    .bind::<Text,_>(sequence).execute(&mut *target).await?;
            }
        }
        Ok(())
    }).await.unwrap();
}
