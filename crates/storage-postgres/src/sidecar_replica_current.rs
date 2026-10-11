//! Install source-signed Sidecar current values without replaying admission.
use arkret_wire::{CommitStreamRef, CurrentSelector, RealmId, TypedCurrentRow};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::RunQueryDsl;

#[derive(QueryableByName)]
struct Covered {
    #[diesel(sql_type=Text)]
    event_id: String,
    #[diesel(sql_type=Jsonb)]
    envelope: serde_json::Value,
}

fn invalid(message: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(message.to_owned())
}

pub(crate) async fn install_in_connection(
    conn: &mut crate::AsyncPgConnection,
    realm: &RealmId,
    entry: &TypedCurrentRow,
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let TypedCurrentRow::Value {
        selector,
        source_stream_ref,
        revision,
        value,
    } = entry;
    let position = i64::try_from(revision.stream_position).map_err(PersistenceError::database)?;
    let source = serde_json::to_value(source_stream_ref).map_err(PersistenceError::database)?;
    let changed = match selector {
        CurrentSelector::Sidecar { sidecar_id } => {
            let current: arkret_models_collaboration::agent_sidecar::AgentSidecar =
                serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            current
                .validate_shape()
                .map_err(PersistenceError::database)?;
            if &current.id != sidecar_id
                || &current.realm_id != realm
                || source_stream_ref
                    != &(CommitStreamRef::Realm {
                        realm_id: realm.clone(),
                    })
            {
                return Err(invalid(
                    "Sidecar snapshot selector, source and current value differ",
                ));
            }
            let create = arkret_wire::EventId::new(sidecar_id.as_str().replacen(
                "ak:sidecar:",
                "ak:event:",
                1,
            ))
            .map_err(PersistenceError::database)?;
            diesel::sql_query("INSERT INTO sidecar_current_results (realm_id,sidecar_id,controller_account_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(sidecar_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
                WHERE sidecar_current_results.realm_id=EXCLUDED.realm_id AND sidecar_current_results.controller_account_id=EXCLUDED.controller_account_id \
                AND sidecar_current_results.create_event_id=EXCLUDED.create_event_id AND sidecar_current_results.source_stream_ref=EXCLUDED.source_stream_ref \
                AND (sidecar_current_results.current_stream_position<EXCLUDED.current_stream_position OR (sidecar_current_results.current_stream_position=EXCLUDED.current_stream_position AND sidecar_current_results.current_commit_id=EXCLUDED.current_commit_id AND sidecar_current_results.value=EXCLUDED.value))")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(sidecar_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(current.controller_account_id).map_err(PersistenceError::database)?)
                .bind::<Text,_>(create.as_str()).bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(position).bind::<Jsonb,_>(&source).bind::<Jsonb,_>(value).bind::<Timestamptz,_>(installed_at)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?
        }
        CurrentSelector::SidecarContext {
            sidecar_id,
            source_context_ref: context_ref,
        } => {
            let current:arkret_models_collaboration::events_payloads::sidecar::SidecarContextAttachPayload=serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            current.validate().map_err(PersistenceError::database)?;
            if &current.sidecar_id != sidecar_id
                || &current.source_context_ref != context_ref
                || source_stream_ref
                    != &(CommitStreamRef::Sidecar {
                        realm_id: realm.clone(),
                        sidecar_id: sidecar_id.clone(),
                    })
            {
                return Err(invalid(
                    "Sidecar context snapshot selector, source and current differ",
                ));
            }
            // The selector has no attach Event identity. Never invent it from
            // a Commit id or use a source Strand's Event as the private dot.
            let covered=diesel::sql_query("SELECT c.commit_json->>'event_ref' AS event_id,e.envelope FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.envelope->>'event_id'=c.commit_json->>'event_ref' WHERE c.commit_id=$1 AND c.realm_id=$2 AND c.stream_position=$3 AND c.stream_ref=$4")
                .bind::<Text,_>(revision.commit_id.as_str()).bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(position).bind::<Jsonb,_>(&source)
                .get_result::<Covered>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            let Some(covered) = covered else {
                // Snapshot installation already preserves the formal selector,
                // source revision and value in replica_authorization_rows.
                // Its native tail supplies the immutable Event identity later;
                // advance_in_connection then folds that accepted full Event.
                return Ok(());
            };
            let accepted: arkret_wire::Event =
                serde_json::from_value(covered.envelope).map_err(PersistenceError::database)?;
            if accepted.kind != arkret_wire::EventKind::SidecarContextAttach
                || CommitStreamRef::from_scope(&accepted.scope_ref, None)
                    .map_err(PersistenceError::database)?
                    != *source_stream_ref
                || serde_json::to_value(&accepted.payload).map_err(PersistenceError::database)?
                    != *value
            {
                return Err(invalid(
                    "Sidecar context snapshot differs from its accepted covering Event",
                ));
            }
            let event =
                arkret_wire::EventId::new(covered.event_id).map_err(PersistenceError::database)?;
            let digest = arkret_canonical::canonical_sha256(context_ref)
                .map_err(PersistenceError::database)?;
            diesel::sql_query("INSERT INTO sidecar_context_current_results (realm_id,sidecar_id,context_ref_digest,context_ref,version,predecessor_event_ref,attach_event_id,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(sidecar_id,context_ref_digest) DO UPDATE SET version=EXCLUDED.version,predecessor_event_ref=EXCLUDED.predecessor_event_ref,attach_event_id=EXCLUDED.attach_event_id,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
                WHERE sidecar_context_current_results.realm_id=EXCLUDED.realm_id AND sidecar_context_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND (sidecar_context_current_results.current_stream_position<EXCLUDED.current_stream_position OR (sidecar_context_current_results.current_stream_position=EXCLUDED.current_stream_position AND sidecar_context_current_results.current_commit_id=EXCLUDED.current_commit_id AND sidecar_context_current_results.value=EXCLUDED.value))")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(sidecar_id.as_str()).bind::<Text,_>(digest).bind::<Jsonb,_>(serde_json::to_value(context_ref).map_err(PersistenceError::database)?)
                .bind::<BigInt,_>(i64::try_from(current.version).map_err(PersistenceError::database)?).bind::<diesel::sql_types::Nullable<Text>,_>(current.predecessor_event_ref.as_ref().map(|id|id.as_str()))
                .bind::<Text,_>(event.as_str()).bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(position).bind::<Jsonb,_>(source).bind::<Jsonb,_>(value).bind::<Timestamptz,_>(installed_at)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?
        }
        _ => return Ok(()),
    };
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: Sidecar snapshot current source revision or value differs".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod recovery_fixture;

#[cfg(test)]
mod tests {
    use arkret_wire::{ActorId, EventKind, ScopeRef, SemanticRef, SidecarId};
    use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};

    use super::*;
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }

    /// A signed snapshot precedes its native tail. No private dot is invented;
    /// the real accepted tail subsequently populates the exact Event-derived row.
    #[tokio::test]
    async fn context_snapshot_before_tail_keeps_metadata_then_real_event_folds_current() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station = recovery_fixture::station();
        let did = crate::device_authorization_history::did_web_station(&station);
        let principal = crate::pcr_genesis::PcrGenesisFixture::new(did.clone());
        let controller = &principal.history.account;
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)",
        )
        .bind::<Text, _>(controller.station_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
        drop(conn);
        principal
            .admit_founding_device(&crate::PgPersistenceStore::new(pool.clone()))
            .await
            .unwrap();
        recovery_fixture::human_profile::register_fixture_signer(
            controller,
            principal.history.device_verification_method.clone(),
            principal.history.founding_device_signing_seed,
        );
        let unit = recovery_fixture::bootstrap_unit_for_account(
            "sidecar-metadata-first-recovery",
            controller,
            &did,
        );
        let unit = recovery_fixture::source_bootstrap(&pool, unit).await;
        let store = crate::PgAuthorityCommitStore { pool: pool.clone() };
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
            .await
            .unwrap();
        let parent = unit.transactions.last().unwrap();
        let uow = crate::PgEventCommitUnitOfWork::new(pool.clone());
        let strand = recovery_fixture::next_request(
            parent,
            EventKind::StrandCreate,
            &controller.principal_id,
            serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":parent.event.realm_id,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Sidecar recovery source"},"created_by":ActorId::account(controller.clone()),"created_at":arkret_canonical::format_timestamp_canonical(parent.commit.committed_at),"state":"active"}}),
            parent.commit.committed_at,
        );
        let strand = recovery_fixture::source_request(&pool, strand).await;
        uow.commit_event(strand.clone()).await.unwrap();
        let source = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
        let create = recovery_fixture::next_request(
            &strand.authority_commit,
            EventKind::SidecarCreate,
            &controller.principal_id,
            serde_json::json!({}),
            parent.commit.committed_at,
        );
        let create = recovery_fixture::source_request(&pool, create).await;
        uow.commit_event(create.clone()).await.unwrap();
        let realm = &create.authority_commit.event.realm_id;
        let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
        let stream = CommitStreamRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        };
        let context = arkret_wire::SidecarContextRef::Strand { strand_id: source };
        let mut event = recovery_fixture::event_for_actor(
            EventKind::SidecarContextAttach,
            ScopeRef::Sidecar {
                realm_id: realm.clone(),
                sidecar_id: sidecar.clone(),
            },
            ActorId::account(controller.clone()),
            serde_json::json!({"sidecar_id":sidecar,"source_context_ref":context,"version":1}),
            parent.commit.committed_at,
        );
        event.semantic_refs = vec![SemanticRef::new(
            create.authority_commit.event.event_id.to_string(),
            "after",
        )];
        recovery_fixture::reseal(&mut event);
        let mut attach = recovery_fixture::request_for_event(
            &create.authority_commit,
            event,
            parent.commit.committed_at,
        );
        attach.authority_commit.commit.stream_ref = stream.clone();
        attach.authority_commit.commit.stream_position = 0;
        attach.authority_commit.commit.previous_commit_ref = None;
        let attach = recovery_fixture::source_request(&pool, attach).await;
        let entry = TypedCurrentRow::Value {
            selector: CurrentSelector::SidecarContext {
                sidecar_id: sidecar.clone(),
                source_context_ref: context,
            },
            source_stream_ref: stream.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: attach.authority_commit.commit.commit_id.clone(),
                stream_position: 0,
            },
            value: serde_json::to_value(&attach.authority_commit.event.payload).unwrap(),
        };
        let mut conn = pool.get().await.unwrap();
        crate::replica_authorization::save_row(
            &mut conn,
            realm,
            &entry,
            parent.commit.committed_at,
        )
        .await
        .unwrap();
        install_in_connection(&mut conn, realm, &entry, parent.commit.committed_at)
            .await
            .unwrap();
        assert_eq!(
            diesel::sql_query(
                "SELECT COUNT(*) AS count FROM replica_authorization_rows WHERE realm_id=$1"
            )
            .bind::<Text, _>(realm.as_str())
            .get_result::<Count>(&mut conn)
            .await
            .unwrap()
            .count,
            1
        );
        assert_eq!(
            diesel::sql_query(
                "SELECT COUNT(*) AS count FROM sidecar_context_current_results WHERE sidecar_id=$1"
            )
            .bind::<Text, _>(sidecar.as_str())
            .get_result::<Count>(&mut conn)
            .await
            .unwrap()
            .count,
            0
        );
        drop(conn);
        uow.commit_event(attach.clone()).await.unwrap();
        let mut conn = pool.get().await.unwrap();
        install_in_connection(&mut conn, realm, &entry, parent.commit.committed_at)
            .await
            .unwrap();
        let actual=diesel::sql_query("SELECT attach_event_id AS event_id FROM sidecar_context_current_results WHERE sidecar_id=$1").bind::<Text,_>(sidecar.as_str()).get_result::<EventIdentity>(&mut conn).await.unwrap();
        assert_eq!(
            actual.event_id,
            attach.authority_commit.event.event_id.as_str()
        );
        // Exercise the real floor provider against accepted full native rows,
        // then replace its covering link with the legitimate withheld shape.
        let key = crate::authority_commit::stream_key(&stream).unwrap();
        diesel::sql_query("INSERT INTO replica_stream_anchors(stream_key,realm_id,join_commit_id,member_account_id,anchor_commit_id,anchor_stream_position,anchored_at) VALUES($1,$2,$3,$4,$3,0,$5)").bind::<Text,_>(&key).bind::<Text,_>(realm.as_str()).bind::<Text,_>(attach.authority_commit.commit.commit_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(controller).unwrap()).bind::<Timestamptz,_>(parent.commit.committed_at).execute(&mut conn).await.unwrap();
        let actor = ActorId::account(controller.clone());
        assert!(
            crate::sidecar_replica_authority::floor_in_connection(
                &mut conn, realm, &sidecar, &actor
            )
            .await
            .unwrap()
            .unwrap()
            .is_some()
        );
        diesel::sql_query("UPDATE realm_commits SET event_pk=NULL WHERE commit_id=$1")
            .bind::<Text, _>(attach.authority_commit.commit.commit_id.as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            crate::sidecar_replica_authority::floor_in_connection(
                &mut conn, realm, &sidecar, &actor
            )
            .await
            .unwrap()
            .is_err()
        );
    }
    #[derive(diesel::QueryableByName)]
    struct EventIdentity {
        #[diesel(sql_type=Text)]
        event_id: String,
    }
}
