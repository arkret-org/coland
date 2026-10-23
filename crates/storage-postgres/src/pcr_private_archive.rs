//! Scoped native PCR migration. This is an operational port, never a peer read.

use std::collections::BTreeMap;

use arkret_models_collaboration::authority_commit::PcrPrivateHandoffManifest;
use arkret_wire::{AccountId, ActorId, Hash, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::{AsyncConnection as _, AsyncPgConnection};
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::{Value, json};

use crate::{PgAuthorityCommitStore, PgTransactionError, pg_conn};

const TABLES: &[(&str, &str)] = &[
    ("accounts", "t.pk=v.account_pk"),
    ("canonical_realms", "t.wire_id=v.realm_id"),
    ("canonical_events", "t.realm_id=v.realm_id"),
    ("realm_authorities", "t.realm_id=v.realm_id"),
    ("realm_commits", "t.realm_id=v.realm_id"),
    ("realm_commit_event_kinds", "t.realm_id=v.realm_id"),
    ("realm_authority_handoffs", "t.realm_id=v.realm_id"),
    ("pcr_private_handoff_imports", "t.realm_id=v.realm_id"),
    ("realm_state_snapshots", "t.realm_id=v.realm_id"),
    ("realm_bootstrap_current_results", "t.realm_id=v.realm_id"),
    (
        "realm_authority_root_current_results",
        "t.realm_id=v.realm_id",
    ),
    (
        "realm_policy_bundle_current_results",
        "t.realm_id=v.realm_id",
    ),
    ("member_state_current_results", "t.realm_id=v.realm_id"),
    ("current_result_heads", "t.realm_id=v.realm_id"),
    ("current_result_versions", "t.realm_id=v.realm_id"),
    ("relation_current_results", "t.realm_id=v.realm_id"),
    ("governance_current_ready", "t.realm_id=v.realm_id"),
    ("realm_meta", "t.realm_id=v.realm_id"),
    ("principal_resolutions", "t.pcr_realm_id=v.realm_id"),
    (
        "principal_resolution_events",
        "t.principal_id=v.holder->>'principal_id' AND t.station_id=v.holder->>'station_id'",
    ),
    (
        "pcr_device_generation_current_results",
        "t.realm_id=v.realm_id",
    ),
    (
        "pcr_device_authorization_current_results",
        "t.realm_id=v.realm_id",
    ),
    ("pcr_device_revocation_proposals", "t.realm_id=v.realm_id"),
    ("actor_profile_current_results", "t.realm_id=v.realm_id"),
    (
        "actor_profile_result_versions",
        "EXISTS(SELECT 1 FROM realm_commits c WHERE c.realm_id=v.realm_id AND c.commit_id=t.commit_id)",
    ),
    ("consent_current_results", "t.realm_id=v.realm_id"),
    (
        "consent_result_versions",
        "EXISTS(SELECT 1 FROM realm_commits c WHERE c.realm_id=v.realm_id AND c.commit_id=t.commit_id)",
    ),
    (
        "agent_producer_signer_keys",
        "EXISTS(SELECT 1 FROM realm_commits c WHERE c.realm_id=v.realm_id AND c.commit_id=t.commit_id)",
    ),
    (
        "account_datas",
        "t.actor_id=v.actor_id AND t.account_data_key IN ('ak.account.holder_quarantine','ak.account.invite_delivery')",
    ),
    (
        "actor_private_events",
        "t.actor_id=v.actor_id AND t.kind='ak.account_data.set' AND t.envelope->'payload'->>'key' IN ('ak.account.holder_quarantine','ak.account.invite_delivery')",
    ),
    (
        "account_global_versions",
        "t.actor_key=v.actor_id AND t.channel='account_data_events' AND t.item_key IN ('event:ak.account.holder_quarantine','event:ak.account.invite_delivery')",
    ),
    ("invite_receive_policies", "t.account_pk=v.account_pk"),
    ("invite_new_source_hmac_keys", "t.account_pk=v.account_pk"),
    ("invite_new_source_ledgers", "t.account_pk=v.account_pk"),
    (
        "consent_private_effect_jobs",
        "t.holder_account_id=v.holder",
    ),
    (
        "consent_private_proxy_fences",
        "t.holder_account_id=v.holder",
    ),
    (
        "mimi_consent_correlations",
        "t.holder_account_id::jsonb=v.holder",
    ),
    (
        "mimi_consent_decision_attempts",
        "EXISTS(SELECT 1 FROM mimi_consent_correlations c WHERE c.consent_id=t.consent_id AND c.holder_account_id::jsonb=v.holder)",
    ),
];
fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("native PCR archive: {detail}"))
}
#[derive(diesel::QueryableByName)]
struct NativeRows {
    #[diesel(sql_type=Jsonb)]
    rows: Value,
}
#[derive(diesel::QueryableByName)]
struct Pk {
    #[diesel(sql_type=BigInt)]
    pk: i64,
}
#[derive(diesel::QueryableByName)]
struct ForeignKey {
    #[diesel(sql_type=Text)]
    table_name: String,
    #[diesel(sql_type=Text)]
    column_name: String,
    #[diesel(sql_type=Text)]
    parent_name: String,
}
#[derive(diesel::QueryableByName)]
struct Columns {
    #[diesel(sql_type=Text)]
    columns: String,
}
async fn foreign_keys(conn: &mut AsyncPgConnection) -> PersistenceResult<Vec<ForeignKey>> {
    sql_query("SELECT child.relname::text AS table_name,a.attname::text AS column_name,parent.relname::text AS parent_name FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid JOIN pg_namespace n ON n.oid=child.relnamespace JOIN pg_class parent ON parent.oid=c.confrelid JOIN pg_attribute a ON a.attrelid=child.oid AND a.attnum=c.conkey[1] JOIN pg_attribute p ON p.attrelid=parent.oid AND p.attnum=c.confkey[1] WHERE c.contype='f' AND n.nspname='public' AND array_length(c.conkey,1)=1 AND parent.relname IN ('accounts','canonical_realms','canonical_events') AND p.attname='pk'")
        .get_results(conn).await.map_err(PersistenceError::database)
}
fn identity(table: &str, row: &Value) -> PersistenceResult<String> {
    match table {
        "accounts" => arkret_canonical::canonical_json_string(
            &json!({"principal_id":row["principal_id"],"station_id":row["station_id"]}),
        )
        .map_err(invalid),
        "canonical_realms" => row["wire_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("Realm wire identity missing")),
        "canonical_events" => row["envelope"]["event_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("Event identity missing")),
        _ => Err(invalid("unknown surrogate identity domain")),
    }
}
async fn native_state(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    realm: &RealmId,
) -> PersistenceResult<Value> {
    crate::pcr_private_authority::ensure_export_supported(conn, realm).await?;
    let pk = sql_query("SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2")
        .bind::<Text, _>(holder.principal_id.as_str())
        .bind::<Text, _>(holder.station_id.as_str())
        .get_result::<Pk>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| invalid("native holder account missing"))?;
    let mut tables = BTreeMap::new();
    for (table, predicate) in TABLES {
        let query = format!(
            "WITH input AS (SELECT $1::text AS realm_id,$2::jsonb AS holder,$3::text AS actor_id,$4::bigint AS account_pk) SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) AS rows FROM {table} t CROSS JOIN input v WHERE {predicate}"
        );
        let rows = sql_query(query)
            .bind::<Text, _>(realm.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(holder).map_err(invalid)?)
            .bind::<Text, _>(ActorId::account(holder.clone()).to_string())
            .bind::<BigInt, _>(pk.pk)
            .get_result::<NativeRows>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        tables.insert(table.to_string(), rows.rows);
    }
    let mut identities = BTreeMap::new();
    for table in ["accounts", "canonical_realms", "canonical_events"] {
        for row in tables[table]
            .as_array()
            .ok_or_else(|| invalid("native rows missing"))?
        {
            identities.insert(
                (
                    table.to_owned(),
                    row["pk"]
                        .as_i64()
                        .ok_or_else(|| invalid("surrogate missing"))?,
                ),
                identity(table, row)?,
            );
        }
    }
    let keys = foreign_keys(conn).await?;
    for (table, rows) in &mut tables {
        for row in rows
            .as_array_mut()
            .ok_or_else(|| invalid("native rows invalid"))?
        {
            let object = row
                .as_object_mut()
                .ok_or_else(|| invalid("native row invalid"))?;
            if matches!(
                table.as_str(),
                "accounts" | "canonical_realms" | "canonical_events"
            ) {
                object.remove("pk");
            }
            for key in keys.iter().filter(|key| key.table_name == *table) {
                if let Some(pk) = object.get(&key.column_name).filter(|v| !v.is_null()) {
                    let value = identities
                        .get(&(
                            key.parent_name.clone(),
                            pk.as_i64()
                                .ok_or_else(|| invalid("native foreign key invalid"))?,
                        ))
                        .ok_or_else(|| {
                            invalid("foreign key leaves the supported private archive")
                        })?;
                    object.insert(key.column_name.clone(), json!(value));
                }
            }
        }
        rows.as_array_mut().unwrap().sort_by_cached_key(|row| {
            arkret_canonical::canonical_json_bytes(row).unwrap_or_default()
        });
    }
    Ok(
        json!({"format":"postgres-native-v1","holder_account_id":holder,"realm_id":realm,"tables":tables}),
    )
}

pub(crate) async fn validate_export_ready(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    realm: &RealmId,
) -> PersistenceResult<()> {
    let state = native_state(conn, holder, realm).await?;
    if state["tables"]["invite_new_source_hmac_keys"]
        .as_array()
        .is_none_or(|rows| rows.len() != 1)
    {
        return Err(invalid("durable independent holder quota key is missing"));
    }
    arkret_canonical::canonical_json_bytes(&state).map_err(invalid)?;
    Ok(())
}

pub(crate) async fn verify_import(
    conn: &mut AsyncPgConnection,
    manifest: &PcrPrivateHandoffManifest,
) -> PersistenceResult<()> {
    manifest.validate().map_err(invalid)?;
    let cut =
        crate::pcr_private_authority::lock_frozen_holder(conn, &manifest.holder_account_id).await?;
    if cut.realm_id != manifest.realm_id
        || cut.generation != manifest.governance_generation
        || cut.head != manifest.effective_stream_head
    {
        return Err(invalid(
            "manifest differs from the actual frozen holder inception cut",
        ));
    }
    let state = native_state(conn, &manifest.holder_account_id, &manifest.realm_id).await?;
    if Hash::new(arkret_canonical::canonical_sha256(&state).map_err(invalid)?).map_err(invalid)?
        != manifest.state_digest
    {
        return Err(invalid(
            "durable scoped private state differs from frozen manifest",
        ));
    }
    Ok(())
}

impl PgAuthorityCommitStore {
    /// Read the actual frozen private state under its outgoing authority lock.
    /// The returned bytes contain private keys and must use a private transport.
    pub async fn export_pcr_private_state(
        &self,
        holder: &AccountId,
    ) -> PersistenceResult<(PcrPrivateHandoffManifest, Vec<u8>)> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            let cut = crate::pcr_private_authority::lock_frozen_holder(conn, holder).await?;
            let state = native_state(conn, holder, &cut.realm_id).await?;
            let bytes = arkret_canonical::canonical_json_bytes(&state).map_err(invalid)?;
            let manifest = PcrPrivateHandoffManifest {
                realm_id: cut.realm_id,
                holder_account_id: holder.clone(),
                governance_generation: cut.generation,
                effective_stream_head: cut.head,
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
    /// Import into this deployment without replacing its Station identity,
    /// unrelated holders, authentication sessions, or local surrogate identities.
    pub async fn import_pcr_private_state(
        &self,
        manifest: &PcrPrivateHandoffManifest,
        bytes: &[u8],
    ) -> PersistenceResult<()> {
        manifest.validate().map_err(invalid)?;
        let archive: Value = serde_json::from_slice(bytes).map_err(invalid)?;
        if arkret_canonical::canonical_json_bytes(&archive).map_err(invalid)? != bytes
            || Hash::new(arkret_canonical::sha256_digest(bytes)).map_err(invalid)?
                != manifest.state_digest
            || archive["format"] != "postgres-native-v1"
            || archive["holder_account_id"]
                != serde_json::to_value(&manifest.holder_account_id).map_err(invalid)?
            || archive["realm_id"] != json!(manifest.realm_id)
            || archive.as_object().is_none_or(|o| o.len() != 4)
        {
            return Err(invalid(
                "format, holder, canonical bytes or digest mismatch",
            ));
        }
        let tables = archive["tables"]
            .as_object()
            .ok_or_else(|| invalid("closed table inventory missing"))?;
        if tables.len() != TABLES.len()
            || TABLES.iter().any(|(table, _)| !tables.contains_key(*table))
        {
            return Err(invalid("incomplete or unknown domain inventory"));
        }
        let genesis = tables["canonical_events"]
            .as_array()
            .ok_or_else(|| invalid("genesis inventory missing"))?
            .iter()
            .filter_map(|row| row.get("envelope"))
            .map(|value| {
                serde_json::from_value::<arkret_wire::Event>(value.clone()).map_err(invalid)
            })
            .collect::<PersistenceResult<Vec<_>>>()?
            .into_iter()
            .find(|event| {
                event.kind == arkret_wire::EventKind::RealmCreate
                    && event.realm_id == manifest.realm_id
            })
            .ok_or_else(|| invalid("exact PCR inception missing"))?;
        if RealmId::from_event_id(&genesis.event_id) != manifest.realm_id {
            return Err(invalid("genesis does not derive the manifest Realm"));
        }
        arkret_wire::GenesisGovernance::from_genesis(&genesis)
            .map_err(crate::pcr_private_authority::refused)?
            .require_transferable()
            .map_err(crate::pcr_private_authority::refused)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
            let lock=format!("pcr-native-import:{}",manifest.realm_id);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(lock).execute(&mut *conn).await?;
            let keys=foreign_keys(conn).await?;
            let mut identities=BTreeMap::new();
            for (table,_) in TABLES {
                let columns=sql_query("SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) AS columns FROM pg_attribute WHERE attrelid=to_regclass($1) AND attnum>0 AND NOT attisdropped AND attidentity='' AND attgenerated=''")
                    .bind::<Text,_>(format!("public.{table}")).get_result::<Columns>(&mut *conn).await?;
                let source=tables[*table].as_array().ok_or_else(||invalid("native table is not rows"))?;
                for row in source {
                    let mut row=row.clone();
                    let identity=if matches!(*table,"accounts"|"canonical_realms"|"canonical_events") {Some(identity(table,&row)?)} else {None};
                    for key in keys.iter().filter(|key|key.table_name==*table) {
                        if let Some(value)=row.get(&key.column_name).filter(|v|!v.is_null()) {
                            let pk=identities.get(&(key.parent_name.clone(),value.as_str().ok_or_else(||invalid("normalized foreign key missing"))?.to_owned()))
                                .ok_or_else(||invalid("normalized parent has not been imported"))?;
                            row[&key.column_name]=json!(pk);
                        }
                    }
                    let query=format!("INSERT INTO {table} ({0}) SELECT {0} FROM jsonb_populate_record(NULL::{table},$1) ON CONFLICT DO NOTHING",columns.columns);
                    sql_query(query).bind::<Jsonb,_>(&row).execute(&mut *conn).await?;
                    if let Some(identity)=identity {
                        let pk=match *table {
                            "accounts"=>sql_query("SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2")
                                .bind::<Text,_>(manifest.holder_account_id.principal_id.as_str()).bind::<Text,_>(manifest.holder_account_id.station_id.as_str()).get_result::<Pk>(&mut *conn).await?,
                            "canonical_realms"=>sql_query("SELECT pk FROM canonical_realms WHERE wire_id=$1").bind::<Text,_>(&identity).get_result::<Pk>(&mut *conn).await?,
                            "canonical_events"=>sql_query("SELECT pk FROM canonical_events WHERE envelope->>'event_id'=$1").bind::<Text,_>(&identity).get_result::<Pk>(&mut *conn).await?,
                            _=>unreachable!(),
                        };
                        identities.insert((table.to_string(),identity),pk.pk);
                    }
                }
            }
            sql_query("UPDATE account_global_clock SET revision=GREATEST(revision,COALESCE((SELECT max(revision) FROM account_global_versions),0)) WHERE singleton")
                .execute(&mut *conn).await?;
            sql_query("INSERT INTO account_global_channel_clocks(actor_key,channel,position) SELECT actor_key,channel,max(channel_position) FROM account_global_versions WHERE actor_key=$1 GROUP BY actor_key,channel ON CONFLICT(actor_key,channel) DO UPDATE SET position=GREATEST(account_global_channel_clocks.position,EXCLUDED.position)")
                .bind::<Text,_>(ActorId::account(manifest.holder_account_id.clone()).to_string()).execute(&mut *conn).await?;
            verify_import(conn,manifest).await?;
            Ok(())
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
