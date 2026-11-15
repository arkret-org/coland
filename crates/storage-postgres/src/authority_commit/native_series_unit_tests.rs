//! Structural private-unit guard tests on a real leased database. These do not
//! claim native admission: the complete HTTP producer corpus proves that path.
use std::collections::BTreeMap;

use super::*;

fn original_transaction() -> AuthorityCommitTransaction {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json"
    )))
    .unwrap();
    let manifest: arkret_models_integration::RealmActorArchiveInventoryManifest =
        serde_json::from_value(fixture["archive_inventory"].clone()).unwrap();
    let original = manifest
        .entries
        .into_iter()
        .find_map(|entry| match entry {
            arkret_models_integration::RealmActorArchiveInventoryEntry::Series(entry) => {
                Some(entry.source)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(
        original.event.kind,
        arkret_wire::EventKind::KeyBackupActiveSeries
    );
    assert_eq!(
        original.event.scope_ref,
        arkret_wire::ScopeRef::RealmControl {
            realm_id: original.event.realm_id.clone(),
        }
    );
    AuthorityCommitTransaction {
        expected_authority: CurrentRealmAuthority {
            realm_id: original.commit.realm_id.clone(),
            generation: original.commit.governance_generation,
            service_id: arkret_wire::detached_signature_service_id(&original.commit.signature)
                .unwrap(),
            authority_ref: original.commit.authority_ref.clone(),
            last_handoff_ref: None,
        },
        event: original.event,
        commit: original.commit,
        producer_signer_fact: Some(original.producer_signer_fact),
        content_backup_source: None,
        mls_state: None,
        welcomes: vec![],
        recipient_queue_capacity: 0,
    }
}

async fn database_state(conn: &mut AsyncPgConnection) -> BTreeMap<String, Value> {
    #[derive(QueryableByName)]
    struct Named {
        #[diesel(sql_type = Text)]
        value: String,
    }
    #[derive(QueryableByName)]
    struct Data {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    let names = sql_query(
        "SELECT tablename AS value FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
    )
    .load::<Named>(&mut *conn)
    .await
    .unwrap();
    let mut state = BTreeMap::new();
    for name in names {
        // Identifiers come only from PostgreSQL's own catalog for this lease.
        let table = name.value.replace('"', "\"\"");
        let row = sql_query(format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS value FROM public.\"{table}\" t"))
            .get_result::<Data>(&mut *conn).await.unwrap();
        state.insert(name.value, row.value);
    }
    let sequences = sql_query("SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.sequencename),'[]'::jsonb) AS value FROM pg_sequences s WHERE schemaname='public'")
        .get_result::<Data>(&mut *conn).await.unwrap();
    state.insert("__public_sequences".into(), sequences.value);
    state
}

#[tokio::test]
async fn native_series_marker_rejects_other_units_kinds_and_scopes_without_writes() {
    let database = crate::test_database::TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let original = original_transaction();
    let before = database_state(&mut conn).await;
    for case in [
        "ordinary",
        "pcr_pointer",
        "kind",
        "event_scope",
        "event_realm",
        "commit_stream",
        "commit_realm",
    ] {
        let mut transaction = original.clone();
        match case {
            "kind" => transaction.event.kind = arkret_wire::EventKind::MessageCreate,
            "event_scope" => {
                transaction.event.scope_ref = arkret_wire::ScopeRef::Realm {
                    realm_id: transaction.event.realm_id.clone(),
                }
            }
            "event_realm" => {
                transaction.event.realm_id =
                    arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [99; 32],
                    ))
            }
            "commit_stream" => {
                transaction.commit.stream_ref = arkret_wire::CommitStreamRef::Realm {
                    realm_id: transaction.event.realm_id.clone(),
                }
            }
            "commit_realm" => {
                transaction.commit.realm_id =
                    arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [99; 32],
                    ))
            }
            _ => {}
        }
        let result = match case {
            "ordinary" => {
                commit_transaction_in_connection_with_device_guard(
                    &mut conn,
                    &transaction,
                    VerifiedPcrUnit::None,
                    None,
                )
                .await
            }
            "pcr_pointer" => {
                commit_verified_key_backup_pointer_in_connection(&mut conn, &transaction).await
            }
            _ => {
                commit_verified_realm_actor_backup_series_in_connection(&mut conn, &transaction)
                    .await
            }
        };
        let message = result.unwrap_err().into_persistence().to_string();
        let expected = if matches!(case, "ordinary" | "pcr_pointer") {
            "realm_control_atomic_unit_required"
        } else {
            "realm_actor_backup_series_unit_scope_mismatch"
        };
        assert!(message.contains(expected), "{case}: {message}");
        assert_eq!(
            database_state(&mut conn).await,
            before,
            "{case} wrote data or consumed a sequence"
        );
    }
}
