//! Private operational migration of Realm actor control and management ledgers.
//! Ordinary Realm originals and projections must be installed independently.
//! This module is deliberately absent from member and peer read surfaces.

use arkret_models_collaboration::authority_commit::ManagementPrivateHandoffManifest;
use arkret_wire::{Hash, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Array, BigInt, Jsonb, Text};
use diesel::{OptionalExtension as _, QueryableByName, sql_query};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

use crate::{PgAuthorityCommitStore, PgTransactionError, pg_conn};

// Predicates are static SQL. Every exported row must survive the same scoped
// query after import; unknown tables, columns and out-of-scope rows are rejected.
const TABLES: &[(&str, &str)] = &[
    (
        "canonical_events",
        "t.realm_id=$1 AND t.scope_ref->>'kind'='realm_control'",
    ),
    (
        "realm_commits",
        "t.realm_id=$1 AND t.stream_ref->>'kind'='realm_control'",
    ),
    (
        "agent_producer_signer_keys",
        "EXISTS(SELECT 1 FROM realm_commits c WHERE c.realm_id=$1 AND c.stream_ref->>'kind'='realm_control' AND c.commit_id=t.commit_id)",
    ),
    (
        "realm_account_device_evidence",
        "EXISTS(SELECT 1 FROM realm_commits c WHERE c.realm_id=$1 AND c.stream_ref->>'kind'='realm_control' AND c.commit_id=t.commit_id)",
    ),
    (
        "forwarded_producer_device_evidence",
        "EXISTS(SELECT 1 FROM realm_commits c WHERE c.realm_id=$1 AND c.stream_ref->>'kind'='realm_control' AND c.commit_id=t.commit_id)",
    ),
    (
        "applet_managed_creation_service_sources",
        "EXISTS(SELECT 1 FROM canonical_events e WHERE e.realm_id=$1 AND e.scope_ref->>'kind'='realm_control' AND e.pk=t.provision_event_pk)",
    ),
    ("realm_actor_creations", "t.realm_id=$1"),
    ("realm_actor_current_results", "t.realm_id=$1"),
    ("realm_actor_private_signer_facts", "t.realm_id=$1"),
    ("management_private_handoff_imports", "t.realm_id=$1"),
    ("realm_actor_recovery_intents", "t.realm_id=$1"),
    ("realm_actor_mls_cleanup", "t.realm_id=$1"),
    ("realm_actor_operation_outcomes", "t.realm_id=$1"),
    ("realm_actor_device_revoke_results", "t.realm_id=$1"),
    ("realm_actor_device_revoke_cleanup", "t.realm_id=$1"),
    (
        "realm_actor_control_nonces",
        "t.actor_id#>>'{realm_actor_id,realm_id}'=$1",
    ),
    (
        "applet_managed_device_nonces",
        "t.actor_id#>>'{realm_actor_id,realm_id}'=$1",
    ),
    ("applet_registration_instances", "t.realm_id=$1"),
    ("applet_registration_current_results", "t.realm_id=$1"),
    (
        "applet_managed_identities",
        "EXISTS(SELECT 1 FROM applet_registration_instances r WHERE r.realm_id=$1 AND r.applet_id=t.applet_id)",
    ),
    (
        "applet_namespace_claims",
        "EXISTS(SELECT 1 FROM applet_registration_instances r WHERE r.realm_id=$1 AND r.applet_id=t.applet_id)",
    ),
    (
        "applet_installations",
        "t.record#>>'{effective_scope,realm_id}'=$1",
    ),
    (
        "applet_widget_tokens",
        "t.record#>>'{install,effective_scope,realm_id}'=$1",
    ),
    (
        "applet_authoring_previews",
        "t.signed_request#>>'{basis,effective_scope,realm_id}'=$1",
    ),
    (
        "applet_authoring_completions",
        "t.context#>>'{material,realm_id}'=$1",
    ),
    (
        "applet_authoring_units",
        "EXISTS(SELECT 1 FROM jsonb_array_elements(t.committed_event_refs) r WHERE r#>>'{stream_ref,realm_id}'=$1)",
    ),
    ("management_review_requests", "t.realm_id=$1"),
    ("event_approval_private_audit", "t.realm_id=$1"),
    (
        "capability_quota_counters",
        "EXISTS(SELECT 1 FROM capability_grant_current_results g WHERE g.realm_id=$1 AND g.grant_id=t.grant_id)",
    ),
    (
        "capability_quota_buckets",
        "EXISTS(SELECT 1 FROM capability_grant_current_results g WHERE g.realm_id=$1 AND g.grant_id=t.grant_id)",
    ),
    (
        "capability_quota_consumptions",
        "EXISTS(SELECT 1 FROM capability_grant_current_results g WHERE g.realm_id=$1 AND g.grant_id=t.grant_id)",
    ),
    (
        "mls_key_packages",
        "t.owner_actor_id#>>'{realm_actor_id,realm_id}'=$1",
    ),
    ("keypackage_claim_sources", "t.governing_realm_id=$1"),
    (
        "keypackage_claim_attempts",
        "EXISTS(SELECT 1 FROM keypackage_claim_sources s WHERE s.governing_realm_id=$1 AND s.source_id=t.source_id AND s.claim_request_id=t.claim_request_id)",
    ),
    (
        "peer_keypackage_claims",
        "EXISTS(SELECT 1 FROM keypackage_claim_sources s WHERE s.governing_realm_id=$1 AND s.source_id=t.source_id AND s.claim_request_id=t.claim_request_id) OR EXISTS(SELECT 1 FROM mls_key_packages k WHERE k.owner_actor_id#>>'{realm_actor_id,realm_id}'=$1 AND k.id=t.keypackage_id)",
    ),
    (
        "keypackage_claim_welcome_bindings",
        "EXISTS(SELECT 1 FROM peer_keypackage_claims c JOIN mls_key_packages k ON k.id=c.keypackage_id WHERE k.owner_actor_id#>>'{realm_actor_id,realm_id}'=$1 AND c.source_id=t.source_id AND c.claim_request_id=t.claim_request_id)",
    ),
    ("realm_claim_issuer_histories", "t.realm_id=$1"),
    ("mls_add_authority_attestations", "t.realm_id=$1"),
    ("mls_add_authority_attestation_outbox", "t.realm_id=$1"),
    (
        "mls_welcome_deliveries",
        "t.delivery_json#>>'{recipient_actor_id,realm_actor_id,realm_id}'=$1",
    ),
    (
        "sync_cursor_handles",
        "t.target#>>'{endpoint,0,realm_actor_id,realm_id}'=$1",
    ),
    (
        "device_message_ack_tokens",
        "t.recipient_device_authorization#>>'{actor_id,realm_actor_id,realm_id}'=$1",
    ),
];

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("Realm management archive: {detail}"))
}
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct AuthorityRow {
    #[diesel(sql_type = BigInt)]
    generation: i64,
}
#[derive(QueryableByName)]
struct Pk {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}
#[derive(QueryableByName)]
struct Columns {
    #[diesel(sql_type = Text)]
    columns: String,
    #[diesel(sql_type = Jsonb)]
    names: Value,
    #[diesel(sql_type = Jsonb)]
    json_columns: Value,
}
#[derive(QueryableByName)]
struct RealmRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

/// Maintenance takes the same writer cut as admission and handoff. The
/// returned allowlist must constrain the subsequent mutation, so a newly
/// appearing candidate cannot be changed without its Realm lock.
pub(crate) async fn mutable_realms(
    conn: &mut AsyncPgConnection,
    realms: &[String],
) -> PersistenceResult<Vec<String>> {
    let rows=sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=ANY($1) ORDER BY realm_id FOR UPDATE")
        .bind::<Array<Text>,_>(realms).get_results::<RealmRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut result = Vec::new();
    for row in rows {
        let realm = RealmId::new(row.realm_id.clone()).map_err(invalid)?;
        if !is_frozen(conn, &realm).await? {
            result.push(row.realm_id);
        }
    }
    Ok(result)
}

/// Call while holding the Realm authority row, before changing private state.
pub(crate) async fn require_unfrozen(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<()> {
    if is_frozen(conn, realm).await? {
        return Err(PersistenceError::Conflict(
            "temporarily_unavailable: Realm governance is frozen for private handoff".into(),
        ));
    }
    Ok(())
}

async fn is_frozen(conn: &mut AsyncPgConnection, realm: &RealmId) -> PersistenceResult<bool> {
    let row = sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM realm_authorities a JOIN realm_commits c ON c.realm_id=a.realm_id AND c.governance_generation=a.generation JOIN canonical_events e ON e.pk=c.event_pk WHERE a.realm_id=$1 AND e.kind='ak.realm.governance_station.change')) AS value")
        .bind::<Text,_>(realm.as_str()).get_result::<JsonRow>(conn).await.map_err(PersistenceError::database)?;
    Ok(row.value != json!(false))
}

async fn frozen_cut(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<(u64, Hash)> {
    let authority =
        sql_query("SELECT generation FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
            .bind::<Text, _>(realm.as_str())
            .get_result::<AuthorityRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| invalid("the governing authority has not been imported"))?;
    let row = sql_query("SELECT c.commit_json AS value FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.stream_ref->>'kind'='realm' ORDER BY c.stream_position DESC LIMIT 1")
        .bind::<Text, _>(realm.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let commit: arkret_wire::RealmCommit = serde_json::from_value(row.value).map_err(invalid)?;
    let change = sql_query("SELECT envelope AS value FROM canonical_events WHERE envelope->>'event_id'=$1 AND kind='ak.realm.governance_station.change' AND state='committed'")
        .bind::<Text, _>(commit.event_ref.as_str()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let generation = u64::try_from(authority.generation).map_err(invalid)?;
    if change.is_none() || commit.governance_generation != generation {
        return Err(invalid(
            "export requires the actual outgoing terminal change",
        ));
    }
    let rows = sql_query("SELECT DISTINCT ON (stream_key) jsonb_build_object('stream_ref',stream_ref,'stream_position',stream_position,'commit_id',commit_id) AS value FROM realm_commits WHERE realm_id=$1 ORDER BY stream_key,stream_position DESC")
        .bind::<Text, _>(realm.as_str()).get_results::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut heads = rows
        .into_iter()
        .map(|row| {
            serde_json::from_value::<arkret_wire::CommitStreamHead>(row.value).map_err(invalid)
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    heads.sort_by(|a, b| a.stream_ref.cmp(&b.stream_ref));
    Ok((
        generation,
        Hash::new(arkret_canonical::canonical_sha256(&heads).map_err(invalid)?).map_err(invalid)?,
    ))
}

async fn state(conn: &mut AsyncPgConnection, realm: &RealmId) -> PersistenceResult<Value> {
    sql_query("SET LOCAL TIME ZONE 'UTC'")
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

    let claims = sql_query("SELECT jsonb_build_object('source_id',c.source_id,'claim_request_id',c.claim_request_id,'has_request',EXISTS(SELECT 1 FROM keypackage_claim_sources s WHERE s.source_id=c.source_id AND s.claim_request_id=c.claim_request_id AND s.request_body#>>'{target_actor_id,realm_actor_id,realm_id}'=$1)) AS value FROM peer_keypackage_claims c WHERE c.outcome#>>'{claim_receipt,request,target_actor_id,realm_actor_id,realm_id}'=$1")
        .bind::<Text,_>(realm.as_str()).get_results::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for claim in claims {
        if claim.value["has_request"] != json!(true)
            || crate::realm_claim_history::read(
                conn,
                claim.value["source_id"]
                    .as_str()
                    .ok_or_else(|| invalid("claim source missing"))?,
                claim.value["claim_request_id"]
                    .as_str()
                    .ok_or_else(|| invalid("claim id missing"))?,
            )
            .await?
            .is_none()
        {
            return Err(invalid(
                "claim original request or issuing history is absent",
            ));
        }
    }
    let mut tables = serde_json::Map::new();
    for (table, predicate) in TABLES {
        let columns = column_inventory(conn, table).await?;
        let nulls = columns
            .json_columns
            .as_array()
            .ok_or_else(|| invalid("invalid JSON columns"))?
            .iter()
            .map(|name| {
                let name = name.as_str().expect("database column name");
                format!("CASE WHEN t.\"{name}\" IS NULL THEN '{name}'::text END")
            })
            .collect::<Vec<_>>()
            .join(",");
        let source = if *table == "realm_account_device_evidence" {
            "(SELECT a.commit_id,e.evidence_ref,e.authorization_commit_id,e.evidence_json FROM account_device_committed_evidence a JOIN account_device_signer_evidence e ON e.evidence_ref=a.evidence_ref UNION SELECT commit_id,evidence_ref,authorization_commit_id,evidence_json FROM realm_account_device_evidence)"
        } else {
            table
        };
        let rows = sql_query(format!(
            "SELECT to_jsonb(t) || jsonb_build_object('__sql_nulls',array_remove(ARRAY[{nulls}]::text[],NULL)) AS value FROM {source} t WHERE {predicate}"
        ))
        .bind::<Text, _>(realm.as_str())
        .get_results::<JsonRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut normalized = Vec::with_capacity(rows.len());
        for row in rows {
            let mut value = row.value;
            if *table == "canonical_events" {
                let object = value
                    .as_object_mut()
                    .ok_or_else(|| invalid("invalid Event row"))?;
                object.remove("pk");
                // The local surrogate is recovered from the already installed
                // canonical Realm. It is not part of the portable identity.
                object.remove("realm_pk");
            }
            if matches!(
                *table,
                "realm_commits"
                    | "mls_welcome_deliveries"
                    | "applet_managed_creation_service_sources"
            ) {
                let field = if *table == "realm_commits" {
                    "event_pk"
                } else if *table == "mls_welcome_deliveries" {
                    "commit_event_pk"
                } else {
                    "provision_event_pk"
                };
                let pk = value[field]
                    .as_i64()
                    .ok_or_else(|| invalid("private Commit lacks its original Event"))?;
                let event = sql_query("SELECT envelope AS value FROM canonical_events WHERE pk=$1")
                    .bind::<BigInt, _>(pk)
                    .get_result::<JsonRow>(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?;
                value[field] = event.value["event_id"].clone();
            }
            normalized.push((
                arkret_canonical::canonical_json_bytes(&value).map_err(invalid)?,
                value,
            ));
        }
        if *table == "realm_account_device_evidence" {
            let mut commits = std::collections::BTreeSet::new();
            if normalized
                .iter()
                .any(|(_, v)| !commits.insert(v["commit_id"].as_str()))
            {
                return Err(invalid(
                    "conflicting local and imported Account Device originals",
                ));
            }
        }
        normalized.sort_by(|a, b| a.0.cmp(&b.0));
        tables.insert(
            (*table).into(),
            Value::Array(normalized.into_iter().map(|(_, value)| value).collect()),
        );
    }
    Ok(json!({"format":"realm-management-postgres-v1","realm_id":realm,"tables":tables}))
}

pub(crate) async fn verify_import(
    conn: &mut AsyncPgConnection,
    manifest: &ManagementPrivateHandoffManifest,
) -> PersistenceResult<()> {
    manifest.validate().map_err(invalid)?;
    let (generation, heads) = frozen_cut(conn, &manifest.realm_id).await?;
    if generation != manifest.governance_generation || heads != manifest.final_stream_heads_digest {
        return Err(invalid(
            "manifest differs from the actual imported frozen cut",
        ));
    }
    let actual = state(conn, &manifest.realm_id).await?;
    if arkret_canonical::canonical_sha256(&actual).map_err(invalid)?
        != manifest.state_digest.as_str()
    {
        return Err(invalid(
            "actual durable private state differs from the frozen export",
        ));
    }
    Ok(())
}

impl PgAuthorityCommitStore {
    /// Only an authenticated operational migration may carry these bytes.
    /// No Applet private key or ordinary Account private state is exported.
    pub async fn export_management_private_state(
        &self,
        realm: &RealmId,
    ) -> PersistenceResult<(ManagementPrivateHandoffManifest, Vec<u8>)> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            let (generation, heads) = frozen_cut(conn, realm).await?;
            let bytes = arkret_canonical::canonical_json_bytes(&state(conn, realm).await?)
                .map_err(invalid)?;
            let manifest = ManagementPrivateHandoffManifest {
                realm_id: realm.clone(),
                governance_generation: generation,
                final_stream_heads_digest: heads,
                nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
                state_digest: Hash::new(arkret_canonical::sha256_digest(&bytes))
                    .map_err(invalid)?,
            };
            manifest.validate().map_err(invalid)?;
            Ok((manifest, bytes))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    /// Insert the closed private inventory without overwriting any conflicting
    /// row. Re-export comparison is inside the same transaction as all inserts.
    pub async fn import_management_private_state(
        &self,
        manifest: &ManagementPrivateHandoffManifest,
        bytes: &[u8],
    ) -> PersistenceResult<()> {
        manifest.validate().map_err(invalid)?;
        let archive: Value = serde_json::from_slice(bytes).map_err(invalid)?;
        if arkret_canonical::canonical_json_bytes(&archive).map_err(invalid)? != bytes
            || arkret_canonical::sha256_digest(bytes) != manifest.state_digest.as_str()
            || archive["format"] != "realm-management-postgres-v1"
            || archive["realm_id"] != json!(manifest.realm_id)
            || archive.as_object().is_none_or(|value| value.len() != 3)
        {
            return Err(invalid(
                "archive identity, canonical bytes or digest mismatch",
            ));
        }
        let tables = archive["tables"]
            .as_object()
            .ok_or_else(|| invalid("missing private inventory"))?;
        if tables.len() != TABLES.len()
            || TABLES.iter().any(|(table, _)| !tables.contains_key(*table))
        {
            return Err(invalid("unknown or missing private domain"));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            sql_query("SELECT generation FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
                .bind::<Text, _>(manifest.realm_id.as_str()).get_result::<AuthorityRow>(&mut *conn).await?;
            let realm_pk=sql_query("SELECT pk FROM canonical_realms WHERE wire_id=$1")
                .bind::<Text,_>(manifest.realm_id.as_str()).get_result::<Pk>(&mut *conn).await?.pk;
            for (table,_) in TABLES {
                let columns=column_inventory(conn,table).await?;
                for source in tables[*table].as_array().ok_or_else(|| invalid("private domain is not rows"))? {
                    let mut row=source.clone();
                    if *table=="canonical_events" { row["realm_pk"]=json!(realm_pk); }
                    if matches!(*table,"realm_commits"|"mls_welcome_deliveries"|"applet_managed_creation_service_sources") {
                        let field=if *table=="realm_commits" {"event_pk"} else if *table=="mls_welcome_deliveries" {"commit_event_pk"} else {"provision_event_pk"};
                        let id=row[field].as_str().ok_or_else(|| invalid("private Commit Event identity missing"))?;
                        let pk=sql_query("SELECT pk FROM canonical_events WHERE envelope->>'event_id'=$1 AND realm_id=$2")
                            .bind::<Text,_>(id).bind::<Text,_>(manifest.realm_id.as_str()).get_result::<Pk>(&mut *conn).await?.pk;
                        row[field]=json!(pk);
                    }
                    let sql_nulls=row.as_object_mut().ok_or_else(|| invalid("private row is not an object"))?
                        .remove("__sql_nulls").ok_or_else(|| invalid("missing SQL null inventory"))?;
                    let null_names=sql_nulls.as_array().ok_or_else(|| invalid("invalid SQL null inventory"))?;
                    let json_names=columns.json_columns.as_array().ok_or_else(|| invalid("invalid JSON column inventory"))?;
                    if null_names.iter().any(|name|!json_names.contains(name)) {
                        return Err(invalid("SQL null inventory names an unknown column").into());
                    }
                    let object=row.as_object().ok_or_else(|| invalid("private row is not an object"))?;
                    let names=columns.names.as_array().ok_or_else(|| invalid("column inventory unavailable"))?;
                    if object.len()!=names.len() || names.iter().any(|name|name.as_str().is_none_or(|name|!object.contains_key(name))) {
                        return Err(invalid("unknown or missing private row column").into());
                    }
                    let projection=names.iter().map(|name| {
                        let key=name.as_str().expect("database column name");
                        if json_names.contains(name) {
                            if null_names.contains(name) { format!("NULL::jsonb AS \"{key}\"") }
                            else { format!("$1->'{key}' AS \"{key}\"") }
                        } else {format!("r.\"{key}\"")}
                    }).collect::<Vec<_>>().join(",");
                    let query=format!("INSERT INTO {table} ({}) SELECT {projection} FROM jsonb_populate_record(NULL::{table},$1) r ON CONFLICT DO NOTHING",columns.columns);
                    sql_query(query).bind::<Jsonb,_>(&row).execute(&mut *conn).await?;
                }
            }
            verify_import(conn,manifest).await?;
            Ok(())
        }).await.map_err(PgTransactionError::into_persistence)
    }
}

async fn column_inventory(conn: &mut AsyncPgConnection, table: &str) -> PersistenceResult<Columns> {
    sql_query("SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) AS columns,jsonb_agg(attname ORDER BY attnum) AS names,COALESCE(jsonb_agg(attname ORDER BY attnum) FILTER (WHERE atttypid='jsonb'::regtype),'[]'::jsonb) AS json_columns FROM pg_attribute WHERE attrelid=to_regclass($1) AND attnum>0 AND NOT attisdropped AND attidentity='' AND attgenerated=''")
        .bind::<Text,_>(format!("public.{table}")).get_result::<Columns>(conn).await.map_err(PersistenceError::database)
}
